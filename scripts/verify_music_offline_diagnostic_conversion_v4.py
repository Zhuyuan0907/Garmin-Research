#!/usr/bin/env python3
"""Complete only the remaining file-conversion CLI check with actual response keys."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/music-volume-bridge-offline-conversion-v4'


def main():
    OUT.mkdir(mode=0o700)
    proof = {'all_passed': False, 'cases': [], 'device_IO': False,
             'source_bindings': {name: hashlib.sha256((ROOT / 'scripts' / name).read_bytes()).hexdigest()
                                 for name in ('garmin_phone_audio_bridge.py', 'garmin_audio_volume_observer.py',
                                              'garmin_audio_conversion.py', 'garmin_host_audio_pipeline.py')}}
    runner = ('import sys,runpy\nfrom pathlib import Path\nsys.path.insert(0,str(Path(sys.argv[1]).parent))\n'
              'def audit(event,args):\n'
              ' if event.startswith("socket.") or (event=="import" and args[0]=="dbus"): raise RuntimeError("offline mode accessed Bluetooth")\n'
              ' if event=="open" and isinstance(args[0],str) and ("authorized-phone.json" in args[0] or "bluetooth-followup-scan.json" in args[0]): raise RuntimeError("offline mode read device configuration")\n'
              'sys.addaudithook(audit)\nsys.argv=sys.argv[1:]\nrunpy.run_path(sys.argv[0],run_name="__main__")\n')
    try:
        with tempfile.TemporaryDirectory(prefix='garmin-offline-conversion-check-') as temporary:
            folder = Path(temporary); source = folder / 'source.raw'; output = folder / 'output.wav'
            source.write_bytes(b'\0' * (44100 * 4 // 10))
            completed = subprocess.run([sys.executable, '-c', runner, str(ROOT / 'scripts/garmin_phone_audio_bridge.py'),
                                       '--offline-only', '--diagnostics', '--offline-input', str(source),
                                       '--offline-output', str(output)], capture_output=True, timeout=5)
            with (OUT / 'actual-child-result.json').open('x') as stream:
                json.dump({'returncode': completed.returncode, 'stderr': completed.stderr.decode()}, stream)
            assert completed.returncode == 0
            actual = json.loads(completed.stdout)
            assert output.exists() and actual['device_IO'] is False and actual['played'] is False
            assert hashlib.sha256(output.read_bytes()).hexdigest() == actual['sha256']
            assert {p.name for p in folder.iterdir()} == {'source.raw', 'output.wav'}
            proof['cases'].append({'name': 'offline_conversion_diagnostics_no_observer_or_DBus',
                                   'passed': True, 'output_bytes': actual['bytes'], 'output_sha256': actual['sha256'],
                                   'audio_content_retained': False})
        proof['all_passed'] = True
    finally:
        with (OUT / 'proof.json').open('x') as stream:
            json.dump(proof, stream, indent=2); stream.write('\n')
    print(json.dumps({'all_passed': proof['all_passed'], 'cases': len(proof['cases']), 'proof': str(OUT / 'proof.json')}))


if __name__ == '__main__':
    main()
