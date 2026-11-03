#!/usr/bin/env python3
"""Exercise real host pipes; no Bluetooth, D-Bus, PCM device or speaker I/O."""
import array
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/music-pcm-meter-host-v1'
METER = ROOT / 'scripts/garmin_pcm_meter.py'


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def main():
    OUT.mkdir(mode=0o700)
    results = []
    pids = []
    processes = []
    input_bytes = output_bytes = 0
    source_sha = hashlib.sha256(METER.read_bytes()).hexdigest()
    def command(report, rate, channels, cap=1048576):
        return [sys.executable, str(METER), '--rate', str(rate), '--channels', str(channels),
                '--window-ms', '100', '--report', str(report), '--report-byte-cap', str(cap)]
    def check(label, body):
        body()
        results.append({'case': label, 'passed': True})
    try:
        with tempfile.TemporaryDirectory(prefix='garmin-pcm-meter-check-') as temp:
            directory = Path(temp)
            def run(name, pcm, rate=8000, channels=1, cap=1048576, chunked=False):
                nonlocal input_bytes, output_bytes
                report = directory / (name + '.jsonl')
                if not chunked:
                    proc = subprocess.Popen(command(report, rate, channels, cap), stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                    pids.append(proc.pid); processes.append(proc)
                    actual, error = proc.communicate(pcm, timeout=5)
                else:
                    with tempfile.TemporaryFile() as saved:
                        proc = subprocess.Popen(command(report, rate, channels, cap), stdin=subprocess.PIPE,
                                                stdout=saved, stderr=subprocess.PIPE, start_new_session=True)
                        pids.append(proc.pid); processes.append(proc)
                        sizes = [1, 7, 255, 4095, 13]
                        index = offset = 0
                        while offset < len(pcm):
                            count = sizes[index % len(sizes)]
                            proc.stdin.write(pcm[offset:offset + count]); proc.stdin.flush()
                            offset += count; index += 1
                        proc.stdin.close(); proc.wait(timeout=5)
                        error = proc.stderr.read(); proc.stderr.close()
                        saved.seek(0); actual = saved.read()
                input_bytes += len(pcm); output_bytes += len(actual)
                assert actual == pcm, name + ': byte identity'
                assert not error, error.decode(errors='replace')
                data = rows(report)
                assert data[0]['type'] == 'start' and data[-1]['type'] == 'summary'
                assert not data[-1]['audio_samples_retained'] and report.stat().st_size <= cap
                assert report.stat().st_mode & 0o777 == 0o600
                return proc.returncode, data[-1], data
            mono = b''.join(struct.pack('<h', int(6000 * math.sin(2 * math.pi * 1000 * n / 8000)))
                            for n in range(2000))
            def mono_test():
                code, summary, data = run('mono', mono)
                expected = math.sqrt(sum(v * v for v in struct.unpack('<' + 'h' * 2000, mono)) / 2000)
                assert code == 0 and summary['levels']['frames'] == 2000
                assert abs(summary['levels']['channels'][0]['rms_s16'] - expected) < 0.0001
                assert sum(row['levels']['frames'] for row in data if row['type'] == 'window') == 2000
            check('actual_mono_tone_levels_and_byte_identity', mono_test)
            stereo = b''.join(struct.pack('<hh', 2000 if n % 2 else -2000,
                                           -2000 if n % 2 else 2000) for n in range(8820))
            def stereo_test():
                code, summary, _ = run('stereo', stereo, 44100, 2, chunked=True)
                assert code == 0 and summary['levels']['frames'] == 8820
                assert summary['levels']['stereo_normalized_cross_product'] == -1
                assert summary['levels']['equal_weight_mono_rms_s16'] == 0
                assert all(c['rms_s16'] == 2000 for c in summary['levels']['channels'])
            check('irregular_byte_fragments_and_antiphase_stereo', stereo_test)
            def clips_test():
                code, summary, _ = run('clips', struct.pack('<hhhh', 32767, -32768, -32768, 32767), channels=2)
                assert code == 0
                assert all(c['peak_s16'] == 32768 and c['full_scale_sample_count'] == 2
                           for c in summary['levels']['channels'])
            check('signed_full_scale_extrema', clips_test)
            def tail_test():
                code, summary, _ = run('tail', b'\x01\x00\x02\x00\x03\x00\x04')
                assert code == 2 and summary['stop_reason'] == 'truncated_sample_frame'
                assert summary['levels']['frames'] == 3 and summary['input_bytes_not_in_levels'] == 1
            check('unaligned_EOF_preserved_but_reported', tail_test)
            def cap_test():
                code, summary, _ = run('cap', mono * 8, cap=8192)
                assert code == 0 and summary['diagnostic_rows_skipped_at_byte_cap'] > 0
                assert summary['levels']['frames'] == 16000 and summary['forwarded_bytes'] == 32000
            check('bounded_report_keeps_forwarding_and_full_summary', cap_test)
            def existing_test():
                report = directory / 'existing.jsonl'; report.write_text('protected\n')
                result = subprocess.run(command(report, 8000, 1), input=mono[:8], capture_output=True, timeout=5)
                assert result.returncode == 2 and not result.stdout and report.read_text() == 'protected\n'
            check('new_report_never_overwrites_existing_file', existing_test)
            def stopped_test():
                report = directory / 'stopped.jsonl'
                proc = subprocess.Popen(command(report, 8000, 1), stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                pids.append(proc.pid); processes.append(proc)
                end = time.monotonic() + 3
                while not report.exists() or not report.stat().st_size:
                    assert time.monotonic() < end and proc.poll() is None
                    time.sleep(0.01)
                proc.send_signal(signal.SIGTERM)
                actual, error = proc.communicate(timeout=3)
                assert proc.returncode == 143 and not actual and not error
                assert rows(report)[-1]['stop_reason'] == 'signal_15'
            check('SIGTERM_while_waiting_input_finalizes_report', stopped_test)
            def downstream_test():
                report = directory / 'downstream.jsonl'
                proc = subprocess.Popen(command(report, 8000, 1), stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                pids.append(proc.pid); processes.append(proc); proc.stdout.close()
                proc.stdin.write(mono[:64]); proc.stdin.close(); proc.wait(timeout=3)
                error = proc.stderr.read(); proc.stderr.close()
                assert proc.returncode == 0 and not error
                summary = rows(report)[-1]
                assert summary['stop_reason'] == 'downstream_closed' and summary['forwarded_bytes'] == 0
            check('downstream_hangup_is_distinct_from_conversion_error', downstream_test)
            def wait_test():
                report = directory / 'wait.jsonl'
                proc = subprocess.Popen(command(report, 8000, 1), stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                pids.append(proc.pid); processes.append(proc)
                capacity = fcntl.fcntl(proc.stdout, fcntl.F_SETPIPE_SZ, 4096)
                assert capacity == 4096
                errors = []
                def writer():
                    try:
                        proc.stdin.write(mono * 8); proc.stdin.close()
                    except BaseException as exc:
                        errors.append(str(exc))
                thread = threading.Thread(target=writer); thread.start()
                end = time.monotonic() + 3
                while not report.exists() or not report.stat().st_size:
                    assert time.monotonic() < end and proc.poll() is None
                    time.sleep(0.005)
                time.sleep(0.05)
                actual = proc.stdout.read(); proc.stdout.close(); thread.join(timeout=3)
                proc.wait(timeout=3); error = proc.stderr.read(); proc.stderr.close()
                assert not thread.is_alive() and not errors and not error and actual == mono * 8
                assert proc.returncode == 0 and rows(report)[-1]['maximum_pipe_forward_wait_ms'] >= 10
            check('real_pipe_backpressure_is_visible_without_altering_bytes', wait_test)
        missing = []
        for pid in pids:
            try:
                os.kill(pid, 0); missing.append(pid)
            except ProcessLookupError:
                pass
        assert not missing
        assert source_sha == hashlib.sha256(METER.read_bytes()).hexdigest()
        proof = {'all_passed': True, 'source': str(METER.relative_to(ROOT)), 'source_sha256': source_sha,
                 'cases': results, 'real_child_processes_checked_terminal': len(pids), 'remaining_PIDs': missing,
                 'input_PCM_bytes_counted': input_bytes, 'output_PCM_bytes_counted': output_bytes,
                 'persistent_PCM_fixture_bytes': 0, 'private_scalar_reports_only': True,
                 'device_Bluetooth_DBus_service_or_playback_IO': False,
                 'speaker_quality_or_cause_verified': False}
        (OUT / 'proof.json').write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps(proof, ensure_ascii=False))
    except BaseException as exc:
        (OUT / 'failed-proof.json').write_text(json.dumps({'all_passed': False, 'passed_cases': results,
            'error': type(exc).__name__ + ': ' + str(exc), 'source_sha256': source_sha}, indent=2) + '\n')
        raise
    finally:
        for proc in processes:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL); proc.wait(timeout=2)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None and not stream.closed:
                    stream.close()


if __name__ == '__main__':
    main()
