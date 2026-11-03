#!/usr/bin/env python3
"""Real Linux pipes and inert children only; never opens an audio device."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from garmin_host_audio_pipeline import PipelineSupervisor


def main():
    destination = ROOT / 'staging/music-diagnostic-clocks-optional-v1'
    destination.mkdir(exist_ok=False)
    proof = {'schema': 'music-diagnostic-clocks-optional-proof/v1', 'cases': [],
             'hardware_or_bluetooth_called': False, 'audio_played': False,
             'native_guest_or_firmware_execution': False,
             'inputs': {name: hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest()
                        for name in ('garmin_host_audio_pipeline.py', 'garmin_pcm_meter.py')}}
    try:
        with tempfile.TemporaryDirectory(prefix='garmin-host-clock-') as temporary:
            folder = Path(temporary)
            payload = b''.join(int(value).to_bytes(2, 'little', signed=True)
                               for value in [1000, -2000, 3000, -4000] * 400)
            report = folder / 'levels.jsonl'
            command = [sys.executable, str(ROOT / 'scripts/garmin_pcm_meter.py'), '--rate', '8000',
                       '--channels', '1', '--window-ms', '100', '--label', 'offline',
                       '--report', str(report), '--diagnostic-run-id', 'clock_fixture_v1']
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            child.stdin.write(payload[:1]); child.stdin.flush(); time.sleep(0.03)
            child.stdin.write(payload[1:7]); child.stdin.flush(); time.sleep(0.02)
            output, error = child.communicate(payload[7:], timeout=5)
            assert child.returncode == 0 and output == payload and not error
            rows = [json.loads(line) for line in report.read_text().splitlines()]
            assert len(rows) == 4 and rows[-1]['levels']['frames'] == 1600
            assert all(row['clock_kind'] == 'host_monotonic_ns' and row['diagnostic_run_id'] == 'clock_fixture_v1' for row in rows)
            assert [row['monotonic_ns'] for row in rows] == sorted(row['monotonic_ns'] for row in rows)
            for index, row in enumerate(rows[1:-1]):
                assert row['start_frame'] == index * 800 and row['end_frame'] == (index + 1) * 800
                assert rows[0]['monotonic_ns'] <= row['arrival_begin_monotonic_ns'] <= row['arrival_end_monotonic_ns']
                assert row['arrival_end_monotonic_ns'] <= row['forward_end_monotonic_ns'] <= row['monotonic_ns']
            proof['cases'].append({'name': 'irregular_byte_pipe_carry_and_host_read_intervals', 'passed': True,
                                   'frames': 1600, 'output_byte_identical': True,
                                   'retained_audio_content': False, 'acoustic_timestamps': False})
            assert not Path('/proc/' + str(child.pid)).exists()

        for case in ('optional_nonzero', 'optional_start_failure', 'critical_failure_with_optional'):
            supervisor = PipelineSupervisor(duration_seconds=2, shutdown_grace_seconds=0.2, kill_grace_seconds=0.2)
            with supervisor:
                optional = [sys.executable, '-c', 'import time; time.sleep(0.03); raise SystemExit(9)']
                if case == 'optional_start_failure':
                    optional = ['/garmin-host-fixture-no-such-executable']
                supervisor.start('volume_observer', optional, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, critical=False)
                if case == 'critical_failure_with_optional':
                    supervisor.start('capture', [sys.executable, '-c', 'raise SystemExit(7)'], stdout=subprocess.DEVNULL)
                supervisor.start('player', [sys.executable, '-c', 'import time; time.sleep(0.12)'], stdout=subprocess.DEVNULL)
                result = supervisor.wait()
            assert result['all_children_reaped'] and result['all_owned_process_groups_exited'] and result['all_owned_handles_closed']
            assert all(not Path('/proc/' + str(row['pid'])).exists() for row in result['children'].values())
            if case == 'critical_failure_with_optional':
                assert result['returncode'] == 1 and result['failed_role'] == 'capture'
            else:
                assert result['returncode'] == 0
                if case == 'optional_start_failure':
                    assert result['optional_start_failures'][0]['error_kind'] == 'FileNotFoundError'
                else:
                    assert result['optional_observer_failures'] == ['volume_observer']
            proof['cases'].append({'name': case, 'passed': True, 'pipeline_result': result})
        proof['all_passed'] = True
    finally:
        with (destination / 'proof.json').open('x') as handle:
            json.dump(proof, handle, indent=2); handle.write('\n')
    print(json.dumps({'all_passed': proof.get('all_passed', False), 'cases': len(proof['cases']),
                      'proof': str(destination / 'proof.json')}, separators=(',', ':')))


if __name__ == '__main__':
    main()
