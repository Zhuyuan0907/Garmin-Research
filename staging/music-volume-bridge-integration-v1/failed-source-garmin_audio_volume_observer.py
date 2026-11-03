#!/usr/bin/env python3
"""Optional, read-only BlueALSA metadata observer; offline trace by default.

No media stdin/stdout, PCM opening, audio playback, or property mutation.
The live provider is constructed only by explicitly selecting --live.
"""
import argparse
from collections.abc import Mapping
import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'garmin-audio-volume-observer-row/v1'
ROLES = ('phone', 'garmin')
CODECS = {'CVSD', 'mSBC', 'SBC', 'AAC', 'aptX', 'aptX-HD', 'LDAC', 'LC3', 'FastStream', 'Opus', 'MP3'}
STATES = {'ok', 'role_missing', 'role_ambiguous', 'parse_error', 'rpc_unavailable'}
MAX_OUTPUT_BYTES = 1048576
TAIL_RESERVE = 1024


def row_base(role, event, diagnostic_run_id=None):
    row = {'schema': SCHEMA, 'timestamp_utc': dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds'),
            'monotonic_ns': time.monotonic_ns(), 'clock_kind': 'host_monotonic_ns',
            'role': role, 'event': event}
    if diagnostic_run_id is not None:
        row['diagnostic_run_id'] = diagnostic_run_id
    return row


def decode_properties(properties):
    """Normalize only known typed scalars, with no identifiers or dB inference."""
    if not isinstance(properties, Mapping):
        raise ValueError('invalid_properties')
    volume, channels = properties.get('Volume'), properties.get('Channels')
    if type(volume) is not int or not 0 <= volume <= 65535:
        raise ValueError('invalid_volume')
    if type(channels) is not int or channels not in (1, 2):
        raise ValueError('invalid_channels')
    decoded = []
    for index, packed in ((1, volume >> 8), (2, volume & 255))[:channels]:
        decoded.append({'index': index, 'gain_0_127': packed & 127, 'mute': bool(packed & 128)})
    out = {'state': 'ok', 'volume': {'raw_q': volume, 'channels': decoded}}
    if 'SoftVolume' in properties:
        if type(properties['SoftVolume']) is not bool:
            raise ValueError('invalid_soft_volume')
        out['soft_volume'] = properties['SoftVolume']
    if 'Codec' in properties:
        if type(properties['Codec']) is not str:
            raise ValueError('invalid_codec')
        codec = properties['Codec']
        out['codec'] = codec if codec in CODECS else 'other'
        out['codec_recognized'] = codec in CODECS
    return out


def sanitize_pcm_properties(properties, dbus_types=None):
    """Reusable typed sanitizer; callers may explicitly supply DBus scalar classes.

    dbus_types maps Volume/Channels/SoftVolume/Codec to their exact wrapper
    classes. No dbus module import occurs here; arbitrary strings never become
    booleans and only known codec tokens survive in output.
    """
    if dbus_types is None:
        return decode_properties(properties)
    if not isinstance(properties, Mapping):
        raise ValueError('invalid_properties')
    normalized = {}
    for name, cast in (('Volume', int), ('Channels', int), ('SoftVolume', bool), ('Codec', str)):
        if name not in properties:
            if name in ('Volume', 'Channels'):
                raise ValueError('missing_property')
            continue
        expected = dbus_types.get(name)
        if expected is None or not isinstance(properties[name], expected):
            raise ValueError('invalid_typed_property')
        normalized[name] = cast(properties[name])
    return decode_properties(normalized)


def normalize_role(value):
    if not isinstance(value, Mapping):
        return {'state': 'parse_error'}
    if value.get('status') in ('rpc_unavailable', 'parse_error'):
        return {'state': value['status']}
    candidates = value.get('candidates')
    if not isinstance(candidates, list):
        return {'state': 'parse_error'}
    if not candidates:
        return {'state': 'role_missing'}
    if len(candidates) > 1:
        return {'state': 'role_ambiguous'}
    try:
        return decode_properties(candidates[0])
    except (ValueError, TypeError):
        return {'state': 'parse_error'}


def select_candidates(objects, expected_device, transport, mode):
    """Pure selector; results are internal and are never written verbatim."""
    if not isinstance(objects, Mapping) or len(objects) > 512:
        raise ValueError('invalid_object_manager_reply')
    selected = []
    for interfaces in objects.values():
        if not isinstance(interfaces, Mapping):
            continue
        props = interfaces.get('org.bluealsa.PCM1')
        if (isinstance(props, Mapping) and props.get('Device') == expected_device
                and props.get('Transport') == transport and props.get('Mode') == mode):
            selected.append(props)
            if len(selected) == 2:
                break  # Two is enough to classify ambiguity, not select one.
    return selected


class UnavailableProvider:
    def read_snapshot(self):
        return {role: {'status': 'rpc_unavailable'} for role in ROLES}


class TraceProvider:
    def __init__(self, path):
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('invalid_trace_file')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
        with os.fdopen(fd, 'rb') as source:
            after = os.fstat(source.fileno())
            if not stat.S_ISREG(after.st_mode) or before.st_dev != after.st_dev or before.st_ino != after.st_ino:
                raise ValueError('trace_identity_changed')
            raw = source.read(262145)
        if len(raw) > 262144:
            raise ValueError('trace_budget')
        trace = json.loads(raw)
        frames = trace.get('frames') if isinstance(trace, dict) else None
        if not isinstance(frames, list) or not 1 <= len(frames) <= 1024:
            raise ValueError('invalid_trace')
        self.frames = frames
        self.index = 0

    def read_snapshot(self):
        frame = self.frames[min(self.index, len(self.frames)-1)]
        self.index += 1
        if isinstance(frame, dict) and frame.get('raise_rpc_error'):
            raise RuntimeError('synthetic_rpc_failure')
        return frame


class LiveProvider:
    """READ ONLY. Private configuration and dbus imports are confined here."""
    def __init__(self, rpc_timeout_seconds):
        import dbus
        self.dbus = dbus
        self.rpc_timeout = rpc_timeout_seconds
        def config(name):
            with (ROOT / 'evidence' / name).open('rb') as source:
                raw = source.read(65537)
            if len(raw) > 65536:
                raise ValueError('config_budget')
            return json.loads(raw)
        phone = config('authorized-phone.json')['address']
        devices = config('bluetooth-followup-scan.json')['matching_devices']
        garmins = {row['address'] for row in devices}
        if len(garmins) != 1:
            raise ValueError('ambiguous_authorized_garmin')
        garmin = next(iter(garmins))
        if any(type(address) is not str or not re.fullmatch(r'[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}', address)
               for address in (phone, garmin)):
            raise ValueError('invalid_authorized_configuration')
        self.devices = {role: '/org/bluez/hci0/dev_' + address.upper().replace(':', '_')
                        for role, address in (('phone', phone), ('garmin', garmin))}
        bus = dbus.SystemBus()
        self.managers = {}
        for role, name in (('phone', 'org.bluealsa.phone'), ('garmin', 'org.bluealsa')):
            obj = bus.get_object(name, '/org/bluealsa', introspect=False)
            self.managers[role] = dbus.Interface(obj, 'org.freedesktop.DBus.ObjectManager')

    def _typed(self, props):
        dbus = self.dbus
        safe = sanitize_pcm_properties(props, {'Volume': dbus.UInt16, 'Channels': dbus.Byte,
                                               'SoftVolume': dbus.Boolean, 'Codec': dbus.String})
        # Core normalizer expects these plain Python types, not DBus wrappers.
        out = {'Volume': safe['volume']['raw_q'], 'Channels': len(safe['volume']['channels'])}
        if 'soft_volume' in safe:
            out['SoftVolume'] = safe['soft_volume']
        if 'codec' in safe:
            out['Codec'] = safe['codec']
        return out

    def read_snapshot(self):
        snapshot = {}
        for role, transport, mode in (('phone', 'A2DP-sink', 'source'), ('garmin', 'HFP-AG', 'sink')):
            try:
                objects = self.managers[role].GetManagedObjects(timeout=self.rpc_timeout)
                matches = select_candidates(objects, self.devices[role], transport, mode)
                # Do not pick a candidate in an ambiguous role.
                snapshot[role] = {'candidates': [self._typed(matches[0])] if len(matches) == 1 else [{}] * len(matches)}
            except (ValueError, TypeError):
                snapshot[role] = {'status': 'parse_error'}
            except Exception:
                snapshot[role] = {'status': 'rpc_unavailable'}
        return snapshot


class BoundedWriter:
    def __init__(self, path, max_bytes=MAX_OUTPUT_BYTES):
        if type(max_bytes) is not int or not 2048 <= max_bytes <= MAX_OUTPUT_BYTES:
            raise ValueError('invalid_output_budget')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            self.file = os.fdopen(fd, 'wb')
        except BaseException:
            os.close(fd)
            raise
        self.max_bytes = max_bytes
        self.bytes_written = 0
        self.events_written = 0
        self.events_dropped = 0
        self.cap_reached = False

    def emit(self, row):
        raw = (json.dumps(row, separators=(',', ':'), allow_nan=False) + '\n').encode()
        if len(raw) > 1024 or self.bytes_written + len(raw) > self.max_bytes-TAIL_RESERVE:
            self.events_dropped += 1
            self.cap_reached = True
            return
        self.file.write(raw); self.file.flush()
        self.bytes_written += len(raw); self.events_written += 1

    def finish(self, summary):
        raw = (json.dumps(summary, separators=(',', ':'), allow_nan=False) + '\n').encode()
        if len(raw) > TAIL_RESERVE or self.bytes_written + len(raw) > self.max_bytes:
            raise ValueError('invalid_summary_budget')
        try:
            self.file.write(raw); self.file.flush(); os.fsync(self.file.fileno())
            self.bytes_written += len(raw)
        finally:
            self.file.close()


def collect(provider, writer, *, duration_seconds, interval_seconds=.5, stop_event=None, stop_reason=None,
            diagnostic_run_id=None):
    if not math.isfinite(duration_seconds) or not 0 < duration_seconds <= 3645:
        raise ValueError('invalid_duration')
    if not math.isfinite(interval_seconds) or not .01 <= interval_seconds <= .5:
        raise ValueError('invalid_interval')
    if diagnostic_run_id is not None and (type(diagnostic_run_id) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', diagnostic_run_id)):
        raise ValueError('invalid_diagnostic_run_id')
    stop_event = stop_event if stop_event is not None else threading.Event()
    last = {}; polls = 0; started = time.monotonic(); reason = 'duration_complete'
    try:
        while not stop_event.is_set() and time.monotonic()-started < duration_seconds:
            poll_start = time.monotonic()
            try:
                snapshot = provider.read_snapshot()
                if not isinstance(snapshot, Mapping):
                    raise ValueError('invalid_snapshot')
            except Exception:
                snapshot = {role: {'status': 'rpc_unavailable'} for role in ROLES}
            polls += 1
            for role in ROLES:
                safe = normalize_role(snapshot.get(role, {'candidates': []}))
                initial = role not in last
                event = safe['state'] if safe['state'] != 'ok' else ('initial' if initial else 'snapshot_change' if safe != last[role] else 'snapshot')
                row = row_base(role, event, diagnostic_run_id); row.update(safe); row['initial'] = initial
                writer.emit(row); last[role] = safe
            remaining = min(interval_seconds-(time.monotonic()-poll_start), duration_seconds-(time.monotonic()-started))
            if remaining > 0:
                stop_event.wait(remaining)
        if stop_event.is_set():
            reason = stop_reason() if stop_reason is not None else 'stopped'
    except Exception:
        reason = 'observer_unavailable'
    summary = row_base('observer', 'final_summary', diagnostic_run_id)
    summary.update({'stop_reason': reason if reason in ('duration_complete', 'sigterm', 'sigint', 'stopped', 'observer_unavailable') else 'stopped',
                    'polls': polls, 'events_written': writer.events_written, 'events_dropped': writer.events_dropped,
                    'output_cap_reached': writer.cap_reached, 'role_states': {role: last.get(role, {}).get('state', 'rpc_unavailable') for role in ROLES},
                    'elapsed_seconds': round(time.monotonic()-started, 6), 'sample_time_kind': 'after_read_snapshot',
                    'acoustic_or_device_volume_dB_inferred': False})
    writer.finish(summary)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description='可選的唯讀音量metadata紀錄；不開啟或播放PCM。')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--trace-input', type=Path, help='離線合成trace；不匯入dbus或讀裝置設定')
    mode.add_argument('--live', action='store_true', help='明示唯讀查詢已授權兩裝置的BlueALSA metadata')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--duration', type=float, default=345)
    parser.add_argument('--interval', type=float, default=.5)
    parser.add_argument('--rpc-timeout', type=float, default=.15)
    parser.add_argument('--max-bytes', type=int, default=MAX_OUTPUT_BYTES)
    parser.add_argument('--diagnostic-run-id', help='同一診斷的ASCII匿名token；不讀boot或裝置ID')
    args = parser.parse_args(argv)
    if (not math.isfinite(args.duration) or not 0 < args.duration <= 3645
            or not math.isfinite(args.interval) or not .01 <= args.interval <= .5
            or not math.isfinite(args.rpc_timeout) or not .001 <= args.rpc_timeout <= .2):
        parser.error('Invalid bounded timing options.')
    if args.diagnostic_run_id is not None and not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', args.diagnostic_run_id):
        parser.error('Invalid diagnostic run token.')
    stop = threading.Event(); signal_reason = ['stopped']
    def request_stop(number, frame):
        signal_reason[0] = 'sigterm' if number == signal.SIGTERM else 'sigint'; stop.set()
    old_handlers = {number: signal.signal(number, request_stop) for number in (signal.SIGTERM, signal.SIGINT)}
    writer = None
    try:
        try:
            # Trace mode is chosen before any live import/config/bus access.
            provider = TraceProvider(args.trace_input) if args.trace_input is not None else LiveProvider(args.rpc_timeout)
        except Exception:
            provider = UnavailableProvider()
        try:
            writer = BoundedWriter(args.output, args.max_bytes)
        except Exception:
            return 2  # Optional observer cannot create its NEW output; no raw exception.
        try:
            collect(provider, writer, duration_seconds=args.duration, interval_seconds=args.interval,
                    stop_event=stop, stop_reason=lambda: signal_reason[0], diagnostic_run_id=args.diagnostic_run_id)
        except Exception:
            return 0  # Nonfatal metadata backend/output loss; no identifiers on stderr.
        return 0
    finally:
        if writer is not None and not writer.file.closed:
            writer.file.close()
        for number, handler in old_handlers.items():
            signal.signal(number, handler)


if __name__ == '__main__':
    raise SystemExit(main())
