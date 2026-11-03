#!/usr/bin/env python3
"""Read public IMG directory/headers and SQLite metadata, never unlock NT data.

Does not copy map payloads, write to mounts, expose MPS unlock records, or
interpret protected TRE/RGN geometry. Results describe the original backup,
not currently installed device contents or successful physical search.
"""
import collections
import datetime as dt
import hashlib
import json
import mmap
from pathlib import Path
import sqlite3
import struct
import xml.etree.ElementTree as ET

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-map-layers-v1'
BACKUP = ROOT / 'backups/20261002T154458Z/files'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def inspect_img(path, verified_hash=None):
    with path.open('rb') as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            require(data[0] == 0, 'Refuse encrypted/XOR disk header')
            require(data[16:23] == b'DSKIMG\0' and data[65:72] == b'GARMIN\0', 'Missing IMG magic')
            block_size = 1 << (data[97] + data[98])
            first = data[64] * 512
            end = struct.unpack_from('<I', data, first + 12)[0]
            require(first < end <= len(data) and end % 512 == 0, 'Bad directory extent')
            files = {}
            for off in range(first, end, 512):
                entry = data[off:off + 512]
                if entry[0] == 0:
                    continue
                require(entry[0] == 1, 'Unsupported directory entry')
                if entry[16] == 3:
                    continue
                name = entry[1:9].decode('ascii').rstrip() + '.' + entry[9:12].decode('ascii').rstrip()
                part = struct.unpack_from('<H', entry, 17)[0]
                if part == 0:
                    require(name not in files, 'Repeated first part')
                    files[name] = {'name': name, 'bytes': struct.unpack_from('<I', entry, 12)[0], 'blocks': [], 'parts': 0}
                require(name in files and part == files[name]['parts'], 'Disordered continuation')
                blocks = [n for n in struct.unpack_from('<240H', entry, 32) if n != 65535]
                require(all(n * block_size < len(data) for n in blocks), 'Block outside image')
                files[name]['blocks'].extend(blocks)
                files[name]['parts'] += 1
            for item in files.values():
                require(len(item['blocks']) == (item['bytes'] + block_size - 1) // block_size, 'Allocation length mismatch')

            def read_part(name, off, size):
                item = files[name]
                require(0 <= off <= off + size <= item['bytes'], 'Read beyond component')
                first_block, last_block = off // block_size, (off + size + block_size - 1) // block_size
                raw = b''.join(data[b * block_size:(b + 1) * block_size] for b in item['blocks'][first_block:last_block])
                return raw[off % block_size:off % block_size + size]

            def public_header(name, component_offset=0):
                header = read_part(name, component_offset, min(512, files[name]['bytes'] - component_offset))
                signature = header[2:12].decode('ascii', errors='replace')
                result = {'offset': component_offset, 'header_bytes': struct.unpack_from('<H', header)[0],
                          'signature': signature, 'flags_byte_13': header[13]}
                if signature == 'GARMIN LBL':
                    result.update(label_encoding_type=header[30], code_page=struct.unpack_from('<H', header, 170)[0],
                                  sort_id1=struct.unpack_from('<H', header, 172)[0],
                                  sort_id2_raw=struct.unpack_from('<H', header, 174)[0])
                elif signature == 'GARMIN MDR':
                    result.update(code_page=struct.unpack_from('<H', header, 21)[0],
                                  sort_id1=struct.unpack_from('<H', header, 23)[0],
                                  sort_id2=struct.unpack_from('<H', header, 25)[0])
                return result

            entries, mps_maps, mps_products, skipped_mps_kinds = [], [], [], []
            for name, item in files.items():
                ext = name.rsplit('.', 1)[1]
                entry = {k: item[k] for k in ('name', 'bytes', 'parts')}
                if ext in ('TRE', 'RGN', 'LBL', 'NET', 'NOD', 'DEM', 'MDR', 'SRT', 'GMP'):
                    entry['public_header'] = public_header(name)
                if ext == 'GMP':
                    header = read_part(name, 0, 57)
                    offsets = struct.unpack_from('<7I', header, 25)
                    entry['gmp_component_headers'] = {}
                    for kind, offset in zip(('TRE', 'RGN', 'LBL', 'NET', 'NOD', 'DEM', 'MAR'), offsets):
                        if offset:
                            h = public_header(name, offset)
                            require(h['signature'] == 'GARMIN ' + kind, 'GMP header pointer signature mismatch')
                            entry['gmp_component_headers'][kind] = h
                if ext == 'MPS':
                    content = read_part(name, 0, item['bytes'])
                    pos = 0
                    while pos < len(content):
                        require(pos + 3 <= len(content), 'Truncated MPS header')
                        kind, size = content[pos], struct.unpack_from('<H', content, pos + 1)[0]
                        body = content[pos + 3:pos + 3 + size]
                        require(len(body) == size, 'Truncated MPS body')
                        # Whitelist public product/map descriptions; no 0x55 unlock data.
                        if kind == 0x4c:
                            pid, fid, map_number = struct.unpack_from('<HHI', body)
                            strings = body[8:].split(b'\0', 3)
                            require(len(strings) == 4, 'Bad MPS map strings')
                            suffix = strings[3]
                            mps_maps.append({'family_id': fid, 'product_id': pid, 'map_number': map_number,
                                             'series_name': strings[0].decode('utf-8', errors='replace'),
                                             'map_description': strings[1].decode('utf-8', errors='replace'),
                                             'hex_map_number': struct.unpack_from('<I', suffix)[0]})
                        elif kind == 0x46:
                            pid, fid = struct.unpack_from('<HH', body)
                            mps_products.append({'family_id': fid, 'product_id': pid,
                                                 'description': body[4:].split(b'\0', 1)[0].decode('utf-8', errors='replace')})
                        else:
                            skipped_mps_kinds.append(hex(kind))
                        pos += 3 + size
                entries.append(entry)
            return {'path': str(path.relative_to(ROOT)), 'bytes': len(data),
                    'backup_verified_sha256': verified_hash,
                    'fresh_public_directory_sha256': hashlib.sha256(data[:end]).hexdigest(),
                    'description': (data[73:93] + data[101:131]).decode('ascii').rstrip(),
                    'block_size': block_size, 'directory_bytes': end,
                    'component_counts': dict(collections.Counter(n.rsplit('.', 1)[1] for n in files)),
                    'mps_maps': mps_maps, 'mps_products': mps_products,
                    'other_mps_record_kinds_skipped_without_content': sorted(set(skipped_mps_kinds)),
                    'components': entries}


def sqlite_metadata(path):
    result = {'path': str(path.relative_to(ROOT)), 'bytes': path.stat().st_size}
    connection = sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
    names = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    result['table_count'] = len(names)
    result['table_names'] = names
    for table in ('garmin_metadata', 'grm_poi_metadata', 'system', 'schema_version', 'version_info', 'jai_metadata', 'jai_map_id', 'map_ids'):
        if table in names:
            connection.row_factory = sqlite3.Row
            result[table] = [dict(r) for r in connection.execute('SELECT * FROM "' + table + '"')]
            connection.row_factory = None
    # Do not export user search history, destinations, POI edits, or personal data.
    if path.parent.name in ('HWM', 'Prefecture'):
        result['public_content_counts'] = {table: connection.execute('SELECT COUNT(*) FROM "' + table + '"').fetchone()[0]
                                          for table in names if not table.startswith('japan_addr_index_')}
        result['quick_check'] = [r[0] for r in connection.execute('PRAGMA quick_check')]
    connection.close()
    return result


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    saved_manifest = json.loads((ROOT / 'backups/20261002T154458Z/files-manifest.json').read_text())
    hashes = {x['path']: x['sha256'] for x in saved_manifest}
    stock_maps = [inspect_img(p, hashes.get(str(p.relative_to(BACKUP)))) for p in sorted((BACKUP / '.System').glob('*.img'))]
    current_build_manifest = json.loads((ROOT / 'staging/maps/Taiwan_OSM_20261001_ZhuYuan/manifest.json').read_text())
    generated_map = inspect_img(Path(current_build_manifest['image']), current_build_manifest['image_sha256'])
    xml = ET.parse(BACKUP / 'Garmin/GarminDevice.xml')
    ns = {'g': 'http://www.garmin.com/xmlschemas/GarminDevice/v2'}
    updates = []
    for entry in xml.findall('.//g:UpdateFile', ns):
        name = entry.findtext('g:FileName', namespaces=ns)
        if name and name.lower().endswith(('.img', '.jcv', '.sid', '.g2s', '.db')):
            updates.append({'name': name, 'path': entry.findtext('g:Path', namespaces=ns),
                            'part_number': entry.findtext('g:PartNumber', namespaces=ns),
                            'version_major': entry.findtext('g:Version/g:Major', namespaces=ns),
                            'version_minor': entry.findtext('g:Version/g:Minor', namespaces=ns)})
    supplementary = []
    for folder in ('.System/JCV', '.System/SID', '.System/G2S', 'POI'):
        for path in sorted((BACKUP / folder).glob('*')):
            if path.is_file():
                with path.open('rb') as stream:
                    header = stream.read(100)
                supplementary.append({'path': str(path.relative_to(BACKUP)), 'bytes': path.stat().st_size,
                                      'backup_verified_sha256': hashes.get(str(path.relative_to(BACKUP))),
                                      'fresh_header_sha256': hashlib.sha256(header).hexdigest(),
                                      'garmin_signature': header[2:12].decode('ascii', errors='replace') if header[2:8] == b'GARMIN' else None})
    dbs = [sqlite_metadata(p) for p in sorted((BACKUP / '.System/SQLite').rglob('*.db'))]
    details = {p['description']: p for p in stock_maps}
    main_map = next(p for p in stock_maps if '2016.11 ALL' in p['description'])
    address_map = next(p for p in stock_maps if 'Address Point' in p['description'])
    main_gmp = next(c for c in main_map['components'] if c['name'].endswith('.GMP'))
    address_gmp = next(c for c in address_map['components'] if c['name'].endswith('.GMP'))
    jai = next(d for d in dbs if '/Prefecture/' in d['path'])
    hwm = next(d for d in dbs if '/HWM/' in d['path'])
    require(set(main_gmp['gmp_component_headers']) >= {'TRE', 'RGN', 'LBL', 'NET', 'NOD'}, 'Main routing components absent')
    require(set(address_gmp['gmp_component_headers']) == {'TRE', 'RGN', 'LBL'}, 'Address layer unexpectedly routable')
    require(jai['jai_map_id'][0]['map_id'] == int(address_gmp['name'][1:8], 16), 'Address DB map id mismatch')
    require(hwm['map_ids'][0]['m_map_id'] == int(main_gmp['name'][1:8], 16), 'Highway DB map id mismatch')
    result = {'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'scope': 'Original logical USB backup plus previously generated OSM IMG, public directories/headers and read-only SQLite metadata; no live device or navigation execution',
              'stock_maps': stock_maps, 'previously_generated_osm': generated_map,
              'xml_update_files': updates, 'supplementary_files': supplementary,
              'sqlite_metadata': dbs,
              'verified_relationships': {'main_has_routing_headers': True, 'address_has_no_routing_headers': True,
                                         'hwm_map_id_equals_main_gmp_id': True, 'jai_map_id_equals_address_gmp_id': True,
                                         'both_stock_public_sqlite_quick_checks_ok': jai['quick_check'] == hwm['quick_check'] == ['ok'],
                                         'base_has_two_dem_components': next(m for m in stock_maps if m['description'].startswith('TWN Navi Base'))['component_counts'].get('DEM') == 2,
                                         'separate_gmap3d_img_in_backup': bool(list(BACKUP.rglob('gmap3d.img')))},
              'limitations': ['NT protected geometry/search payloads are not unlocked or decoded.',
                              'Public header presence and SQLite quick_check do not prove successful or fast device search.',
                              'Original matching address/highway metadata is not compatible proof for OSM or another map version.',
                              'Absence of gmap3d.img does not prove the firmware cannot support any 3D feature.',
                              'Backing loop mount is the backup, not a connected Garmin.']}
    output = OUT / 'layer-inventory.json'
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'output': str(output), 'stock_maps': [{k: m[k] for k in ('description','component_counts','mps_maps')} for m in stock_maps],
                      'verified_relationships': result['verified_relationships']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
