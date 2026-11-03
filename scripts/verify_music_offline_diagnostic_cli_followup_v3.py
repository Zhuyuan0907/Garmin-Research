#!/usr/bin/env python3
"""Only the previously incomplete offline diagnostic CLI checks; no rerun of PCM cases."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/music-volume-bridge-offline-cli-v3'


def main():
    OUT.mkdir(mode=0o700)
    proof = {'cases': [], 'all_passed': False, 'actual_device_or_dbus_or_native_IO': False,
             'source_bindings': {name: hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest()
                                 for name in ('garmin_phone_audio_bridge.py', 'garmin_audio_volume_observer.py',
                                              'garmin_audio_conversion.py', 'garmin_host_audio_pipeline.py')}}
    runner = ('import sys,runpy\n'
              'def audit(event,args):\n'
              ' if event.startswith("socket.") or (event=="import" and args[0]=="dbus"): raise RuntimeError("offline mode accessed Bluetooth")\n'
              ' if event=="open" and isinstance(args[0],str) and ("authorized-phone.json" in args[0] or "bluetooth-followup-scan.json" in args[0]): raise RuntimeError("offline mode read device configuration")\n'
              'sys.addaudithook(audit)\n'
              'sys.argv=sys.argv[1:]\nrunpy.run_path(sys.argv[0],run_name="__main__")\n')
    script = str(ROOT / 'scripts/garmin_phone_audio_bridge.py')
    try:
        failed = subprocess.run([sys.executable, '-c', runner, script, '--plan-conversion', '--diagnostics'], capture_output=True, timeout=5)
        assert failed.returncode == 1 and b"No module named 'garmin_audio_conversion'" in failed.stderr
        (OUT / 'actual-original-runner-error.json').write_text(json.dumps({'returncode': failed.returncode,
            'stdout': failed.stdout.decode(), 'stderr': failed.stderr.decode()}, indent=2) + '\n')
        fixed = runner.replace('import sys,runpy\n', 'import sys,runpy\nfrom pathlib import Path\nsys.path.insert(0,str(Path(sys.argv[1]).parent))\n')
        planned = subprocess.run([sys.executable, '-c', fixed, script, '--plan-conversion', '--diagnostics'], capture_output=True, check=True, timeout=5)
        assert not json.loads(planned.stdout)['automatic_level_control']
        proof['cases'].append({'name': 'plan_diagnostics_no_DBus_or_private_configuration', 'passed': True})
        with tempfile.TemporaryDirectory(prefix='garmin-offline-diagnostic-cli-') as temporary:
            folder = Path(temporary); source = folder / 'source.raw'; output = folder / 'output.wav'
            source.write_bytes(b'\0' * (44100 * 4 // 10))
            result = subprocess.run([sys.executable, '-c', fixed, script, '--offline-only', '--diagnostics',
                                     '--offline-input', str(source), '--offline-output', str(output)],
                                    capture_output=True, check=True, timeout=5)
            assert output.exists() and json.loads(result.stdout)['bluetooth_or_speaker_IO'] is False
            assert {p.name for p in folder.iterdir()} == {'source.raw', 'output.wav'}
            proof['cases'].append({'name': 'offline_conversion_diagnostics_no_observer_or_DBus', 'passed': True})
        proof['all_passed'] = True
    finally:
        with (OUT / 'proof.json').open('x') as stream:
            json.dump(proof, stream, indent=2); stream.write('\n')
    print(json.dumps({'all_passed': proof['all_passed'], 'cases': len(proof['cases']), 'proof': str(OUT / 'proof.json')}))


if __name__ == '__main__':
    main()
