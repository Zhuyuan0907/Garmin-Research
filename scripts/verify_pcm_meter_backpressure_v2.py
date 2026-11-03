#!/usr/bin/env python3
"""Resolve the real pipe-capacity control without repeating eight passed cases."""
import fcntl
import hashlib
import json
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


def main():
    previous = json.loads((OUT / 'failed-proof.json').read_bytes())
    assert not previous['all_passed'] and len(previous['passed_cases']) == 8
    meter = ROOT / 'scripts/garmin_pcm_meter.py'
    assert hashlib.sha256(meter.read_bytes()).hexdigest() == previous['source_sha256']
    proc = None
    thread = None
    try:
        with tempfile.TemporaryDirectory(prefix='garmin-meter-backpressure-') as temp:
            report = Path(temp) / 'wait.jsonl'
            proc = subprocess.Popen([sys.executable, str(meter), '--rate', '8000', '--channels', '1',
                                     '--report', str(report), '--window-ms', '100'],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    start_new_session=True)
            capacity = fcntl.fcntl(proc.stdout, fcntl.F_SETPIPE_SZ, 4096)
            # Linux rounds to its page size. This host uses a larger page.
            assert capacity >= 4096 and capacity <= 65536
            frame_count = capacity
            payload = struct.pack('<hh', -1234, 1234) * (frame_count // 2)
            assert len(payload) == 2 * capacity and len(payload) <= 131072
            errors = []
            def writer():
                try:
                    proc.stdin.write(payload); proc.stdin.close()
                except BaseException as exc:
                    errors.append(type(exc).__name__ + ': ' + str(exc))
            thread = threading.Thread(target=writer); thread.start()
            deadline = time.monotonic() + 3
            while not report.exists() or not report.stat().st_size:
                assert time.monotonic() < deadline and proc.poll() is None
                time.sleep(0.005)
            time.sleep(0.05)
            actual = proc.stdout.read(); proc.stdout.close(); thread.join(timeout=3)
            proc.wait(timeout=3); error = proc.stderr.read(); proc.stderr.close()
            assert not thread.is_alive() and not errors and not error and proc.returncode == 0
            assert actual == payload
            summary = json.loads(report.read_text().splitlines()[-1])
            assert summary['maximum_pipe_forward_wait_ms'] >= 10
            assert summary['levels']['frames'] == frame_count
            try:
                os.kill(proc.pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError('Meter child remains alive')
            proof = {'all_assigned_checks_passed': True, 'initial_suite_actual_exit': 1,
                     'initial_failure_was_pipe_capacity_assumption': True,
                     'successful_initial_cases_repeated': False, 'actual_followup_cases': 1,
                     'initial_passed_cases': previous['passed_cases'],
                     'followup': {'case': 'real_pipe_backpressure', 'passed': True,
                                  'requested_capacity': 4096, 'actual_capacity': capacity,
                                  'host_page_size': os.sysconf('SC_PAGESIZE'), 'PCM_bytes': len(payload),
                                  'byte_identical_forwarding': True,
                                  'maximum_forward_wait_ms': summary['maximum_pipe_forward_wait_ms']},
                     'source_sha256': previous['source_sha256'], 'owned_child_reaped': True,
                     'all_handles_closed': True, 'persistent_PCM_fixture_bytes': 0,
                     'device_Bluetooth_DBus_services_playback_or_native_guest_IO': False}
        with (OUT / 'proof-v2.json').open('x') as stream:
            json.dump(proof, stream, indent=2); stream.write('\n')
        print(json.dumps(proof))
    finally:
        if proc is not None:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL); proc.wait(timeout=2)
            if thread is not None:
                thread.join(timeout=2)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None and not stream.closed:
                    stream.close()


if __name__ == '__main__':
    main()
