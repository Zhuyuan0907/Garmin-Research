#!/usr/bin/env python3
"""Pass raw host PCM through unchanged and retain bounded scalar diagnostics."""
import argparse
import array
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import signal
import sys
import time


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


class Stopped(Exception):
    def __init__(self, signum):
        self.signum = signum


class Levels:
    def __init__(self, channels):
        self.channels = channels
        self.frames = 0
        self.squares = [0] * channels
        self.sums = [0] * channels
        self.peaks = [0] * channels
        self.clips = [0] * channels
        self.cross = 0
        self.mixed_squares = 0

    def add(self, frame):
        self.frames += 1
        for index, sample in enumerate(frame):
            self.squares[index] += sample * sample
            self.sums[index] += sample
            self.peaks[index] = max(self.peaks[index], abs(sample))
            self.clips[index] += int(sample in (-32768, 32767))
        if self.channels == 2:
            left, right = frame
            self.cross += left * right
            self.mixed_squares += (left + right) ** 2

    def values(self):
        denominator = max(1, self.frames)
        channels = []
        for index in range(self.channels):
            channels.append({'rms_s16': round(math.sqrt(self.squares[index] / denominator), 4),
                             'peak_s16': self.peaks[index],
                             'mean_s16': round(self.sums[index] / denominator, 4),
                             'full_scale_sample_count': self.clips[index]})
        result = {'frames': self.frames, 'channels': channels}
        if self.channels == 2:
            energy = math.sqrt(self.squares[0] * self.squares[1])
            result['stereo_normalized_cross_product'] = round(self.cross / energy, 6) if energy else None
            result['equal_weight_mono_rms_s16'] = round(math.sqrt(self.mixed_squares / (4 * denominator)), 4)
        return result


class ScalarReport:
    """A private new file with a reserved final summary; never replace a file."""
    RESERVED = 4096

    def __init__(self, path, byte_cap):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NOCTTY
        self.fd = os.open(path, flags, 0o600)
        self.byte_cap = byte_cap
        self.bytes = 0
        self.skipped = 0

    def row(self, value, final=False):
        raw = (json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n').encode()
        if not final and self.bytes + len(raw) > self.byte_cap - self.RESERVED:
            self.skipped += 1
            return
        if final and (len(raw) > self.RESERVED or self.bytes + len(raw) > self.byte_cap):
            raise RuntimeError('Scalar summary exceeded the reserved diagnostic capacity.')
        view = memoryview(raw)
        while view:
            count = os.write(self.fd, view)
            if count <= 0:
                raise OSError('Diagnostic write made no progress.')
            self.bytes += count
            view = view[count:]

    def close(self):
        if self.fd is not None:
            try:
                os.fsync(self.fd)
            finally:
                os.close(self.fd)
                self.fd = None


def meter(input_fd, output_fd, report, rate, channels, window_ms, label, diagnostic_run_id=None):
    stride = channels * 2
    window_frames = max(1, rate * window_ms // 1000)
    total = Levels(channels)
    window = Levels(channels)
    carry = b''
    carry_begin_ns = None
    window_begin_ns = window_end_ns = window_forward_ns = None
    read_bytes = forwarded = windows = 0
    max_forward_wait = total_forward_wait = 0.0
    started = utc()
    started_mono = time.monotonic_ns()
    def timed_row(value, final=False):
        value.update({'monotonic_ns': time.monotonic_ns(), 'clock_kind': 'host_monotonic_ns',
                      'diagnostic_run_id': diagnostic_run_id})
        report.row(value, final=final)
    def window_row(partial=False, read_batch_utc=None):
        row = {'type': 'window', 'index': windows, 'utc': utc(),
               'start_frame': total.frames - window.frames, 'end_frame': total.frames,
               'sample_time_seconds': round(total.frames / rate, 6),
               'arrival_begin_monotonic_ns': window_begin_ns,
               'arrival_end_monotonic_ns': window_end_ns,
               'forward_end_monotonic_ns': window_forward_ns, 'levels': window.values()}
        if partial:
            row['partial_window'] = True
        if read_batch_utc is not None:
            row['read_batch_utc'] = read_batch_utc
        timed_row(row)
    code, reason = 0, 'input_eof'
    timed_row({'type': 'start', 'schema': 'garmin-host-pcm-meter/v1', 'label': label,
                'utc': started, 'sampling': rate, 'channels': channels, 'format': 's16le',
                'window_ms': window_ms, 'audio_samples_retained': False,
                'tap': {'phone_input': 'after BlueALSA/arecord; receiver volume may already apply',
                        'garmin_output': 'after FFmpeg, before aplay/SCO/speaker gain',
                        'offline': 'ordinary host PCM fixture'}.get(label, label),
                'arrival_clock_scope': 'host read begin/end, including source wait; not sample or acoustic timestamps',
                'scope': 'Pi-stage scalar PCM levels and pipe-forward wait; not speaker or Bluetooth transport measurement'})
    try:
        while True:
            read_at = utc()
            read_begin_ns = time.monotonic_ns()
            data = os.read(input_fd, 4096)
            read_end_ns = time.monotonic_ns()
            if not data:
                break
            read_bytes += len(data)
            before_write = time.monotonic()
            try:
                view = memoryview(data)
                while view:
                    count = os.write(output_fd, view)
                    if count <= 0:
                        raise OSError('PCM forward made no progress.')
                    forwarded += count
                    view = view[count:]
            finally:
                elapsed = time.monotonic() - before_write
                max_forward_wait = max(max_forward_wait, elapsed)
                total_forward_wait += elapsed
            forward_end_ns = time.monotonic_ns()
            old_carry = len(carry)
            combined_begin_ns = carry_begin_ns if old_carry else read_begin_ns
            combined = carry + data
            complete = len(combined) - len(combined) % stride
            carry = combined[complete:]
            carry_begin_ns = (read_begin_ns if complete else combined_begin_ns) if carry else None
            samples = array.array('h')
            samples.frombytes(combined[:complete])
            if sys.byteorder != 'little':
                samples.byteswap()
            for offset in range(0, len(samples), channels):
                frame = samples[offset:offset + channels]
                frame_begin_ns = combined_begin_ns if offset == 0 and old_carry else read_begin_ns
                if window_begin_ns is None:
                    window_begin_ns = frame_begin_ns
                window_end_ns, window_forward_ns = read_end_ns, forward_end_ns
                total.add(frame)
                window.add(frame)
                if window.frames == window_frames:
                    windows += 1
                    window_row(read_batch_utc=read_at)
                    window = Levels(channels)
                    window_begin_ns = window_end_ns = window_forward_ns = None
        if carry:
            code, reason = 2, 'truncated_sample_frame'
    except BrokenPipeError:
        reason = 'downstream_closed'
    except Stopped as exc:
        code, reason = 128 + exc.signum, 'signal_' + str(exc.signum)
    except (OSError, RuntimeError) as exc:
        code, reason = 1, 'host_io_error' if isinstance(exc, OSError) else 'diagnostic_capacity_error'
    finally:
        if window.frames:
            windows += 1
            window_row(partial=True)
        timed_row({'type': 'summary', 'label': label, 'started_utc': started, 'completed_utc': utc(),
                    'elapsed_wall_seconds': round((time.monotonic_ns() - started_mono) / 1000000000, 6),
                    'stop_reason': reason, 'returncode': code, 'input_bytes': read_bytes,
                    'forwarded_bytes': forwarded, 'unmeasured_frame_tail_bytes': len(carry),
                    'levels_scope': 'fully_forwarded_batches; complete sample frames only',
                    'input_bytes_not_in_levels': read_bytes - total.frames * stride,
                    'levels': total.values(), 'windows_total': windows,
                    'diagnostic_rows_skipped_at_byte_cap': report.skipped,
                    'maximum_pipe_forward_wait_ms': round(max_forward_wait * 1000, 3),
                    'total_pipe_forward_wait_ms': round(total_forward_wait * 1000, 3),
                    'audio_samples_retained': False, 'physical_speaker_or_packet_loss_measured': False}, final=True)
    return code


def main():
    parser = argparse.ArgumentParser(description='Raw PCM pipe tee with bounded scalar-only diagnostics; never opens an audio device.')
    parser.add_argument('--rate', required=True, type=int)
    parser.add_argument('--channels', required=True, type=int, choices=(1, 2))
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--label', choices=('phone_input', 'garmin_output', 'offline'), default='offline')
    parser.add_argument('--window-ms', type=int, default=1000)
    parser.add_argument('--report-byte-cap', type=int, default=1048576)
    parser.add_argument('--diagnostic-run-id', help='Optional common host-run token for scalar trace correlation.')
    args = parser.parse_args()
    if not 8000 <= args.rate <= 192000 or not 100 <= args.window_ms <= 10000:
        parser.error('Rate must be 8000..192000; window-ms must be 100..10000.')
    if not 8192 <= args.report_byte_cap <= 1048576:
        parser.error('report-byte-cap must be 8192..1048576.')
    if args.diagnostic_run_id is not None and not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', args.diagnostic_run_id):
        parser.error('diagnostic-run-id must be a 1..64 character ASCII token.')
    if sys.stdin.isatty() or sys.stdout.isatty():
        parser.error('Raw PCM input and output must be pipes or regular files.')
    def stopped(signum, _frame):
        raise Stopped(signum)
    signal.signal(signal.SIGINT, stopped)
    signal.signal(signal.SIGTERM, stopped)
    try:
        report = ScalarReport(args.report, args.report_byte_cap)
    except OSError:
        parser.error('Cannot create a new private diagnostic report.')
    try:
        return meter(sys.stdin.fileno(), sys.stdout.fileno(), report, args.rate, args.channels, args.window_ms, args.label,
                     args.diagnostic_run_id)
    finally:
        report.close()


if __name__ == '__main__':
    sys.exit(main())
