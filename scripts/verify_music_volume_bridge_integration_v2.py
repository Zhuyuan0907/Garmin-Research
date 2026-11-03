#!/usr/bin/env python3
"""Host-only PCM integration with trace observer and inert audio endpoints."""
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/music-volume-bridge-integration-v2'
sys.path.insert(0, str(ROOT / 'scripts'))
from garmin_audio_conversion import conversion_plan, raw_ffmpeg_command


def main():
    OUT.mkdir(mode=0o700)
    sources = ['garmin_phone_audio_bridge.py', 'garmin_pcm_meter.py', 'garmin_host_audio_pipeline.py',
               'garmin_audio_conversion.py', 'garmin_audio_volume_observer.py']
    proof = {'schema': 'music-volume-bridge-integration-proof/v1', 'cases': [],
             'source_bindings': {name: hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() for name in sources},
             'Bluetooth_service_IO': False, 'physical_speaker_audio_or_native_execution': False,
             'persistent_PCM_fixture_bytes': 0}
    def audit(event, arguments):
        if event.startswith('socket.') or event == 'import' and arguments[0] == 'dbus':
            raise RuntimeError('Forbidden hardware or DBus access in fixture')
        if event == 'open' and isinstance(arguments[0], str):
            name = arguments[0]
            if '/evidence/authorized-phone.json' in name or '/evidence/bluetooth-followup-scan.json' in name:
                raise RuntimeError('Forbidden private device configuration read')
            if name.startswith('/dev/') and name != '/dev/null':
                raise RuntimeError('Forbidden device open')
        if event == 'subprocess.Popen':
            command = arguments[1]
            if command[0] not in (sys.executable, 'ffmpeg'):
                raise RuntimeError('Only inert Python and FFmpeg subprocesses allowed')
            if '--live' in command or any('test_hfp_call_audio.py' in part for part in command):
                raise RuntimeError('Forbidden live helper execution')
    sys.addaudithook(audit)
    try:
        import garmin_phone_audio_bridge as bridge
        assert 'dbus' not in sys.modules
        with tempfile.TemporaryDirectory(prefix='garmin-volume-pipeline-') as temporary:
            folder = Path(temporary); (folder / 'evidence').mkdir()
            payload = b''.join(struct.pack('<hh', int(6000 * math.sin(2 * math.pi * 660 * n / 44100)),
                                           int(6000 * math.sin(2 * math.pi * 660 * n / 44100))) for n in range(13230))
            source = folder / 'source.raw'; source.write_bytes(payload)
            plan = conversion_plan(0.5, input_rate=44100, input_channels=2)
            reference = subprocess.run(raw_ffmpeg_command(plan), input=payload, capture_output=True, check=True, timeout=5).stdout
            good = {'phone': {'candidates': [{'Volume': 0x6464, 'Channels': 2, 'SoftVolume': True, 'Codec': 'SBC'}]},
                    'garmin': {'candidates': [{'Volume': 0x0f00, 'Channels': 1, 'SoftVolume': False, 'Codec': 'CVSD'}]}}
            changed = json.loads(json.dumps(good)); changed['phone']['candidates'][0]['Volume'] = 0x5050
            trace_path = folder / 'trace.json'
            trace_path.write_text(json.dumps({'frames': [good, changed, {'raise_rpc_error': True}, good]}))
            for mode in ('diagnostic_trace', 'diagnostic_missing_observer', 'default_route'):
                stamp = 'host_' + mode
                diagnostic = mode != 'default_route'
                bridge.ROOT = ROOT
                entries = bridge.pipeline_commands(44100, 2, '00:11:22:33:44:55', 1, False, plan, stamp, diagnostic)
                expected_roles = ['capture', 'input_meter', 'convert', 'output_meter', 'player'] if diagnostic else ['capture', 'convert', 'player']
                assert [name for name, _ in entries] == expected_roles
                assert entries[-1][1][-2:] == ['--call-sequence', 'incoming']
                sink = folder / (mode + '.raw')
                entries[0] = ('capture', [sys.executable, '-c', 'import sys;sys.stdout.buffer.write(open(sys.argv[1],"rb").read())', str(source)])
                entries[-1] = ('player', [sys.executable, '-c', 'import sys,time;open(sys.argv[1],"wb").write(sys.stdin.buffer.read());time.sleep(0.3)', str(sink)])
                reports = {}
                for role, command in entries:
                    if role.endswith('_meter'):
                        reports[role] = folder / 'evidence' / (stamp + '-' + role + '.jsonl')
                        command[command.index('--report') + 1] = str(reports[role])
                observer = None
                if mode == 'diagnostic_trace':
                    observer = bridge.volume_observer_command(stamp, 1, trace_input=trace_path)
                    observer[observer.index('--interval') + 1] = '0.05'
                    reports['volume_observer'] = folder / 'evidence' / (stamp + '-observer.jsonl')
                    observer[observer.index('--output') + 1] = str(reports['volume_observer'])
                    assert '--live' not in observer and '--trace-input' in observer
                elif mode == 'diagnostic_missing_observer':
                    observer = ['/garmin-host-fixture-no-observer-executable']
                bridge.ROOT = folder
                before_fds = len(os.listdir('/proc/self/fd'))
                result = bridge.run_audio_pipeline(entries, 1, stamp, observer_command=observer)
                (OUT / (mode + '-pipeline.json')).write_text(json.dumps(result, indent=2) + '\n')
                assert result['returncode'] == 0 and sink.read_bytes() == reference
                assert result['all_children_reaped'] and result['all_owned_process_groups_exited'] and result['all_owned_handles_closed']
                assert len(os.listdir('/proc/self/fd')) == before_fds
                assert all(not Path('/proc/' + str(child['pid'])).exists() for child in result['children'].values())
                for role, path in reports.items():
                    rows = [json.loads(line) for line in path.read_text().splitlines()]
                    assert rows[-1].get('type', rows[-1].get('event')) in ('summary', 'final_summary')
                    assert all(row.get('diagnostic_run_id') == stamp for row in rows)
                    assert all(row['clock_kind'] == 'host_monotonic_ns' for row in rows)
                    # Preserve scalar-only diagnostics for the offline timeline check.
                    (OUT / (mode + '-' + role + '.jsonl')).write_text(path.read_text())
                if mode == 'diagnostic_trace':
                    assert 'volume_observer' in result['children'] and not result['children']['volume_observer']['critical']
                    rows = [json.loads(line) for line in reports['volume_observer'].read_text().splitlines()]
                    assert any(row.get('state') == 'rpc_unavailable' for row in rows)
                    assert any(row.get('role') == 'phone' and row.get('event') == 'snapshot_change' for row in rows)
                if mode == 'diagnostic_missing_observer':
                    assert result['optional_start_failures'] and 'volume_observer' not in result['children']
                proof['cases'].append({'name': mode, 'passed': True, 'audio_frames': len(reference) // 2,
                                       'byte_identical_to_original_fixed_conversion': True,
                                       'FDs_and_owned_process_groups_closed': True, 'roles': list(result['children'])})
            safe = bridge.scalar_pcm_properties({'Volume': 0x0f00, 'Channels': 1, 'SoftVolume': False, 'Codec': 'CVSD', 'Sampling': 8000, 'Format': 0x8210})
            assert len(safe['volume']['channels']) == 1 and safe['soft_volume'] is False
            assert bridge.scalar_pcm_properties({'Volume': 0, 'Channels': 1, 'SoftVolume': 'false'}) == {'state': 'parse_error'}
            assert bridge.scalar_pcm_properties({'Volume': [], 'Channels': 1}) == {'state': 'parse_error'}
            assert bridge.scalar_pcm_properties({'Volume': 0, 'Channels': 1, 'Codec': 'private-token-' * 1000})['codec'] == 'other'
            proof['cases'].append({'name': 'strict_initial_metadata_and_absent_mono_channel', 'passed': True})
            bridge.ROOT = ROOT
            runner = ('import sys,runpy\n'
                      'def audit(event,args):\n'
                      ' if event.startswith("socket.") or (event=="import" and args[0]=="dbus"): raise RuntimeError("offline mode accessed Bluetooth")\n'
                      ' if event=="open" and isinstance(args[0],str) and ("authorized-phone.json" in args[0] or "bluetooth-followup-scan.json" in args[0]): raise RuntimeError("offline mode read device configuration")\n'
                      'sys.addaudithook(audit)\n'
                      'sys.argv=sys.argv[1:]\nrunpy.run_path(sys.argv[0],run_name="__main__")\n')
            planned = subprocess.run([sys.executable, '-c', runner, str(ROOT / 'scripts/garmin_phone_audio_bridge.py'), '--plan-conversion', '--diagnostics'], capture_output=True, check=True, timeout=5)
            assert not json.loads(planned.stdout)['automatic_level_control']
            offline_wav = folder / 'offline.wav'
            offline = subprocess.run([sys.executable, '-c', runner, str(ROOT / 'scripts/garmin_phone_audio_bridge.py'), '--offline-only', '--diagnostics', '--offline-input', str(source), '--offline-output', str(offline_wav)], capture_output=True, check=True, timeout=5)
            assert offline_wav.exists() and not list((folder / 'evidence').glob('volume-controls-*'))
            proof['cases'].append({'name': 'offline_plan_and_conversion_return_before_private_config_or_DBus', 'passed': True})
            assert 'dbus' not in sys.modules
        assert all(hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest() == pin for name, pin in proof['source_bindings'].items())
        proof['all_passed'] = True
    finally:
        with (OUT / 'proof.json').open('x') as stream:
            json.dump(proof, stream, indent=2); stream.write('\n')
    print(json.dumps({'all_passed': proof.get('all_passed', False), 'cases': len(proof['cases']), 'proof': str(OUT / 'proof.json')}))


if __name__ == '__main__':
    main()
