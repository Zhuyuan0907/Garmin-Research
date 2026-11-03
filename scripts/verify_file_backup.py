#!/usr/bin/env python3
"""Extract and validate a verified image; do not open the Garmin block device."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    metadata = json.loads((directory / 'sda.json').read_text())
    image = directory / metadata['image']
    if metadata['state'] != 'verified' or image.stat().st_size != metadata['size']:
        raise RuntimeError('Image backup is not verified')
    fsck = subprocess.run(['fsck.fat', '-n', str(image)], capture_output=True, text=True)
    (directory / 'filesystem-check.txt').write_text(fsck.stdout + fsck.stderr)
    dest = directory / 'files'
    if dest.exists():
        raise RuntimeError('Extraction destination already exists')
    dest.mkdir(mode=0o700)
    extraction = subprocess.run(['7z', 'x', '-tFAT', str(image), '-o' + str(dest), '-y'], capture_output=True, text=True)
    (directory / 'file-extraction.txt').write_text(extraction.stdout + extraction.stderr)
    if extraction.returncode != 0:
        raise RuntimeError('Image extraction failed')
    inventory = json.loads((ROOT / 'evidence/live-file-inventory.json').read_text())
    expected = {x['Path']: int(x['Size']) for x in inventory if x.get('Folder') == '-'}
    actual = {str(p.relative_to(dest)): p for p in dest.rglob('*') if p.is_file()}
    if set(expected) != set(actual):
        raise RuntimeError('File names differ from live FAT inventory')
    manifest = []
    for name in sorted(actual):
        p = actual[name]
        if p.stat().st_size != expected[name]:
            raise RuntimeError('File size mismatch: ' + name)
        digest = hashlib.sha256()
        with p.open('rb') as f:
            for chunk in iter(lambda: f.read(4 * 1024 * 1024), b''):
                digest.update(chunk)
        manifest.append({'path': name, 'size': p.stat().st_size, 'sha256': digest.hexdigest()})
    critical = {}
    for name, live in {'Garmin/GarminDevice.xml': ROOT / 'evidence/live-device/GarminDevice.xml', '.System/GUPDATE.GCD': ROOT / 'evidence/live-device/GUPDATE.GCD', 'Themes/Map/United Kingdom.kmtf': ROOT / 'evidence/device-research/Themes/Map/United Kingdom.kmtf'}.items():
        critical[name] = hashlib.sha256(live.read_bytes()).hexdigest() == next(x['sha256'] for x in manifest if x['path'] == name)
    if not all(critical.values()):
        raise RuntimeError('Critical files differ from live extraction')
    # Counts only: no coordinates, saved names, unit IDs, or licence keys in reports.
    gpx_summary = {'files': 0, 'waypoints': 0, 'tracks': 0, 'track_points': 0, 'routes': 0, 'parse_failures': []}
    for name in expected:
        if name.lower().endswith('.gpx'):
            try:
                r = ET.parse(actual[name]).getroot()
                tags = [e.tag.rsplit('}', 1)[-1] for e in r.iter()]
                gpx_summary['files'] += 1
                for key, tag in [('waypoints','wpt'),('tracks','trk'),('track_points','trkpt'),('routes','rte')]:
                    gpx_summary[key] += tags.count(tag)
            except ET.ParseError:
                gpx_summary['parse_failures'].append(name)
    (directory / 'files-manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
    result = {'completed': dt.datetime.now(dt.timezone.utc).isoformat(), 'state': 'verified', 'image': str(image), 'files': len(manifest), 'total_file_bytes': sum(x['size'] for x in manifest), 'inventory_match': True, 'critical_live_file_match': critical, 'filesystem_check_returncode': fsck.returncode, 'filesystem_check_log': str(directory / 'filesystem-check.txt'), 'gpx_summary': gpx_summary, 'empty_sd_lun': 'No readable media in navigation SD slot; camera SD is separate and not backed up.', 'scope': 'USB-exposed logical disk and all accessible files; not bootloader or non-exposed chip regions.'}
    (directory / 'verification.json').write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
