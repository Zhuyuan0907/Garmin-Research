#!/usr/bin/env python3
"""Repackage compiled map tiles with the user's requested display credit."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import verify_garmin_map

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'staging/maps/Taiwan_OSM_20261001_UTF8/manifest.json'
OUTPUT = ROOT / 'staging/maps/Taiwan_OSM_20261001_ZhuYuan'
CREDIT = '修改者:竺原'


def main():
    original = json.loads(SOURCE.read_text())
    before = verify_garmin_map.verify(SOURCE)
    if OUTPUT.exists():
        raise RuntimeError('Output directory already exists; refusing to overwrite')
    tiles = [SOURCE.parent / 'compiled' / f'{original["map_id_start"] + i}.img'
             for i in range(original['tile_count'])]
    if not all(path.is_file() for path in tiles):
        raise RuntimeError('Compiled tiles are missing')
    OUTPUT.mkdir()
    command = ['nice', '-n', '10', 'java', '-Xmx1800m', '-jar',
               str(ROOT / 'sources/maps/mkgmap-r4924/mkgmap.jar'),
               '--gmapsupp', '--index', '--code-page=65001',
               '--family-id=7051', '--product-id=1',
               '--family-name=OSM Taiwan 2026-10-01 ' + CREDIT,
               '--series-name=OSM Taiwan ' + CREDIT,
               '--description=OSM Taiwan 2026-10-01',
               '--output-dir=' + str(OUTPUT), *map(str, tiles)]
    manifest = dict(original)
    manifest.update(state='repackaging_display_credit', output=str(OUTPUT),
                    base_manifest=str(SOURCE), credit_text=CREDIT,
                    modifier='竺原', credit_display_verified=False,
                    credit_requested_by_user=True, device_installed=False,
                    structural_checks_passed=False, commands=[command],
                    started_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    manifest_path = OUTPUT / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    with (OUTPUT / 'repackage.log').open('wb') as log:
        subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
    image = OUTPUT / 'Taiwan_OSM_20261001.img'
    shutil.copyfile(OUTPUT / 'gmapsupp.img', image)
    for name in ('copyright.txt', 'license.txt'):
        shutil.copyfile(SOURCE.parent / name, OUTPUT / name)
    manifest.update(image=str(image), image_bytes=image.stat().st_size,
                    image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                    state='compiled_pending_structural_and_device_checks',
                    completed_utc=dt.datetime.now(dt.timezone.utc).isoformat())
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    checked = verify_garmin_map.verify(manifest_path)
    before_tiles = {(f['name'], f['extension']): f['sha256'] for f in before['files']
                    if f['extension'] in ('TRE', 'RGN', 'LBL', 'NET', 'NOD')}
    after_tiles = {(f['name'], f['extension']): f['sha256'] for f in checked['files']
                   if f['extension'] in ('TRE', 'RGN', 'LBL', 'NET', 'NOD')}
    if before_tiles != after_tiles:
        raise RuntimeError('Map display or routing components changed unexpectedly')
    checked['all_tile_components_identical_to_base'] = True
    check_path = ROOT / 'evidence/taiwan-map-author-structural-verification.json'
    check_path.write_text(json.dumps(checked, ensure_ascii=False, indent=2) + '\n')
    manifest.update(state='structurally_verified_pending_device_installation',
                    structural_checks_passed=True, structural_evidence=str(check_path))
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: manifest[k] for k in ['state', 'image', 'image_bytes',
                                             'image_sha256', 'credit_text']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
