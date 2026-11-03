#!/usr/bin/env python3
"""Build an indexed routable Taiwan IMG from the verified current OSM extract."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    source = ROOT / 'sources/maps/taiwan-latest.osm.pbf'
    download = json.loads((source.parent / 'taiwan-download.json').read_text())
    sha = hashlib.sha256()
    with source.open('rb') as stream:
        while chunk := stream.read(1024*1024):
            sha.update(chunk)
    if sha.hexdigest() != download['sha256']:
        raise RuntimeError('OSM source differs from the checksum-verified download')
    header = json.loads(subprocess.check_output(['osmium', 'fileinfo', '-j', str(source)]))
    timestamp = header['header']['option']['timestamp']
    date = timestamp[:10]
    output = ROOT / 'staging/maps' / ('Taiwan_OSM_'+date.replace('-', '')+'_UTF8')
    output.mkdir(parents=True, exist_ok=False)
    tiles = output / 'tiles'
    tiles.mkdir()
    compiled = output / 'compiled'
    compiled.mkdir()
    (output / 'copyright.txt').write_text('OpenStreetMap contributors\nMap data: OpenStreetMap contributors, ODbL 1.0\nhttps://www.openstreetmap.org/copyright\n')
    (output / 'license.txt').write_text('Map data copyright OpenStreetMap contributors.\nOpen Database License (ODbL) 1.0: https://opendatacommons.org/licenses/odbl/1-0/\nSource extract: https://download.geofabrik.de/asia/taiwan.html\nSource timestamp: '+timestamp+'\nCompiled with mkgmap; generated map is not a Garmin City Navigator update.\n')
    record = {'started_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'state': 'splitting',
              'source': download, 'osm_data_timestamp': timestamp, 'output': str(output),
              'encoding': 'Unicode UTF-8 (65001); declared by device XML, physical display/search untested',
              'family_id': 7051, 'map_id_start': 70510001, 'routing_requested': True,
              'address_index_requested': True, 'house_numbers_requested': True,
              'device_installed': False, 'stock_maps_modified': False}
    manifest = output / 'manifest.json'

    def save():
        manifest.write_text(json.dumps(record, ensure_ascii=False, indent=2)+'\n')

    def run(command, log, cwd):
        record.setdefault('commands', []).append(command)
        save()
        with log.open('w') as stream:
            result = subprocess.run(command, cwd=cwd, stdout=stream, stderr=stream)
        if result.returncode:
            raise RuntimeError('Map build command failed; inspect '+str(log))

    try:
        run(['nice', '-n', '10', 'java', '-Xmx2800m', '-jar',
             str(ROOT / 'sources/maps/splitter-r654/splitter.jar'), '--max-threads=2',
             '--max-nodes=800000', '--mapid=70510001', '--output=pbf',
             '--output-dir='+str(tiles), str(source)], output / 'splitter.log', output)
        record['state'] = 'compiling'
        save()
        run(['nice', '-n', '10', 'java', '-Xmx2800m', '-jar',
             str(ROOT / 'sources/maps/mkgmap-r4924/mkgmap.jar'), '--max-jobs=2',
             '--route', '--index', '--housenumbers', '--gmapsupp', '--code-page=65001',
             '--name-tag-list=name:zh-Hant,name:zh,name,int_name', '--drive-on=right',
             '--country-name=Taiwan', '--country-abbr=TWN', '--region-name=Taiwan',
             '--region-abbr=TW', '--location-autofill=is_in,nearest',
             '--family-id=7051', '--product-id=1', '--family-name=OSM Taiwan '+date,
             '--series-name=OSM Taiwan', '--description=OSM Taiwan '+date,
             '--copyright-file='+str(output / 'copyright.txt'),
             '--license-file='+str(output / 'license.txt'), '--output-dir='+str(compiled),
             '-c', str(tiles / 'template.args')], output / 'mkgmap.log', output)
        image = compiled / 'gmapsupp.img'
        if not image.exists() or image.stat().st_size < 1024:
            raise RuntimeError('Compiler did not create a usable map image')
        destination = output / ('Taiwan_OSM_'+date.replace('-', '')+'.img')
        destination.write_bytes(image.read_bytes())
        record.update({'state': 'compiled_pending_structural_and_device_checks',
                       'image': str(destination), 'image_bytes': destination.stat().st_size,
                       'image_sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
                       'tile_count': len(list(tiles.glob('*.osm.pbf'))),
                       'completed_utc': dt.datetime.now(dt.timezone.utc).isoformat()})
        save()
        print(json.dumps({k: record[k] for k in ['state', 'osm_data_timestamp', 'image', 'image_bytes', 'tile_count']}), flush=True)
    except BaseException as exc:
        record['state'] = 'failed'
        record['error'] = str(exc)
        save()
        raise


if __name__ == '__main__':
    main()
