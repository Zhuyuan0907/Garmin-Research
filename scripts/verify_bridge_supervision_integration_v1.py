#!/usr/bin/env python3
"""Run real host PCM/FFmpeg pipelines with an inert capture and file sink."""
import contextlib
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/music-host-bridge-integration-v1'
sys.path.insert(0, str(ROOT / 'scripts'))
from garmin_audio_conversion import conversion_plan, raw_ffmpeg_command


def main():
    OUT.mkdir(mode=0o700)
    scripts = ['garmin_phone_audio_bridge.py', 'garmin_music_player.py', 'garmin_pcm_meter.py',
               'garmin_host_audio_pipeline.py', 'garmin_audio_conversion.py']
    bindings = {name: hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() for name in scripts}
    spec = importlib.util.spec_from_file_location('bridge_root_host_check', ROOT / 'scripts/garmin_phone_audio_bridge.py')
    bridge = importlib.util.module_from_spec(spec); spec.loader.exec_module(bridge)
    assert 'dbus' not in sys.modules
    cases = []
    peaks = []
    with tempfile.TemporaryDirectory(prefix='garmin-bridge-supervision-') as temp:
        folder = Path(temp); (folder / 'evidence').mkdir()
        raw = b''.join(struct.pack('<hh', int(8000 * math.sin(2 * math.pi * 880 * n / 44100)),
                                   int(8000 * math.sin(2 * math.pi * 880 * n / 44100))) for n in range(13230))
        source = folder / 'source.s16le'; source.write_bytes(raw)
        plan = conversion_plan(0.5, input_rate=44100, input_channels=2)
        reference = subprocess.run(raw_ffmpeg_command(plan), input=raw, capture_output=True, check=True, timeout=5).stdout
        for diagnostic in (False, True):
            stamp = 'offline-diagnostic' if diagnostic else 'offline-default'
            entries = bridge.pipeline_commands(44100, 2, '00:11:22:33:44:55', 1, False, plan, stamp, diagnostic)
            assert entries[0][1][0] == 'arecord' and entries[-1][0] == 'player'
            assert entries[-1][1][-2:] == ['--call-sequence', 'incoming']
            assert [role for role, _ in entries] == (['capture', 'input_meter', 'convert', 'output_meter', 'player']
                                                   if diagnostic else ['capture', 'convert', 'player'])
            # Retain converter/meter commands; substitute only the two physical endpoints.
            sink = folder / (stamp + '.pcm')
            entries[0] = ('capture', [sys.executable, '-c',
                                      'import sys;sys.stdout.buffer.write(open(sys.argv[1],"rb").read())', str(source)])
            entries[-1] = ('player', [sys.executable, '-c',
                                     'import sys;open(sys.argv[1],"wb").write(sys.stdin.buffer.read())', str(sink)])
            if diagnostic:
                adjusted = []
                for role, command in entries:
                    if role.endswith('_meter'):
                        command = command.copy()
                        index = command.index('--report') + 1
                        command[index] = str(folder / 'evidence' / (role + '.jsonl'))
                    adjusted.append((role, command))
                entries = adjusted
            bridge.ROOT = folder
            before_fds = len(os.listdir('/proc/self/fd'))
            result = bridge.run_audio_pipeline(entries, 1, stamp)
            assert result['returncode'] == 0 and result['stop_reason'] == 'natural_eof'
            assert result['all_children_reaped'] and result['all_owned_handles_closed']
            assert result['all_owned_process_groups_exited'] and not result['CIND_restoration_verified']
            assert len(os.listdir('/proc/self/fd')) == before_fds and sink.read_bytes() == reference
            for child in result['children'].values():
                try:
                    os.kill(child['pid'], 0)
                except ProcessLookupError:
                    pass
                else:
                    raise AssertionError('Registered child remains alive')
            if diagnostic:
                for role in ['input_meter', 'output_meter']:
                    records = [json.loads(line) for line in (folder / 'evidence' / (role + '.jsonl')).read_text().splitlines()]
                    summary = records[-1]
                    assert summary['returncode'] == 0 and not summary['audio_samples_retained']
                    expected = 13230 if role == 'input_meter' else len(reference) // 2
                    assert summary['levels']['frames'] == expected
                    peaks.append({'role': role, 'frames': expected, 'levels': summary['levels']})
            cases.append({'case': stamp, 'passed': True, 'roles': list(result['children']),
                          'PCM_output_frames': len(reference) // 2, 'byte_identical_to_original_conversion': True,
                          'FD_count_restored': True, 'all_owned_PIDs_and_groups_gone': True})
        # Prove the integrated bridge no longer converts an upstream error to success.
        entries = [('capture', [sys.executable, '-c', 'raise SystemExit(7)']),
                   ('convert', [sys.executable, '-c', 'import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())']),
                   ('player', [sys.executable, '-c', 'import sys;sys.stdin.buffer.read()'])]
        result = bridge.run_audio_pipeline(entries, 1, 'offline-upstream-failure')
        assert result['returncode'] == 1 and result['stop_reason'] == 'upstream_failure'
        assert result['failed_role'] == 'capture' and result['all_children_reaped']
        cases.append({'case': 'capture7_cannot_be_hidden_by_sink0', 'passed': True})
        # Offline plan must still return before import or service lookup.
        for name in ['garmin_phone_audio_bridge.py', 'garmin_music_player.py']:
            completed = subprocess.run([sys.executable, str(ROOT / 'scripts' / name), '--plan-conversion'],
                                       capture_output=True, text=True, timeout=5, check=True)
            value = json.loads(completed.stdout)
            assert value['output']['sampling'] == 8000 and not value['automatic_level_control']
        cases.append({'case': 'both_offline_plan_modes_unchanged', 'passed': True})
        assert 'dbus' not in sys.modules
    assert all(hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == pin
               for name, pin in bindings.items())
    proof = {'all_passed': True, 'source_bindings': bindings, 'cases': cases, 'meter_measurements': peaks,
             'ordinary_host_FIFO_FFmpeg_file_sinks_only': True, 'real_live_endpoints_executed': False,
             'Bluetooth_DBus_services_speakers_or_native_guests_IO': False,
             'default_audio_argv_format_and_fixed_gain_retained': True,
             'metering_is_opt_in': True, 'persistent_PCM_fixture_bytes': 0,
             'real_CIND_restoration_or_music_quality_verified': False}
    with (OUT / 'proof.json').open('x') as stream:
        json.dump(proof, stream, indent=2); stream.write('\n')
    print(json.dumps(proof))


if __name__ == '__main__':
    main()
