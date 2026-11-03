#!/usr/bin/env python3
"""Build the bounded original-format Minquan supplement and its exact undo delta."""
import gzip
import hashlib
import importlib.util
import json
import os
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-native-address-supplement-v1'
ORIGINAL_SHA = '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'
CANDIDATE_SHA = '8e759a435482e945cf6a936a7f2374fdaf5c42dc8ee70a00bbe36e7eb5436287'
REFS = {'6號': 23, '8號': 25, '138號': 150, '140號': 152, '142號': 154,
        '144號': 783, '146號': 784, '148號': 157, '150號': 787}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not isinstance(data, bytes):
        data = (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o444)


def main():
    assert not OUT.exists(), 'Refusing to replace a previous build'
    source_path = ROOT / 'backups/20261002T154458Z/files/.System/gmapprom1.img'
    before = source_path.stat()
    source = source_path.read_bytes()
    assert len(source) == 96739328 and sha(source) == ORIGINAL_SHA
    image = bytearray(source)
    assert source[16:23] == b'DSKIMG\0' and source[65:72] == b'GARMIN\0'
    block_size = 1 << (source[97] + source[98])
    assert block_size == 4096
    fat_start = source[64] * 512
    fat_end = struct.unpack_from('<I', source, fat_start + 12)[0]
    components = {}
    for pos in range(fat_start, fat_end, 512):
        row = source[pos:pos + 512]
        if row[0] != 1 or row[16] == 3:
            continue
        name = row[1:9].decode().rstrip() + '.' + row[9:12].decode().rstrip()
        part = struct.unpack_from('<H', row, 17)[0]
        item = components.setdefault(name, dict(blocks=[], parts=[], length=None))
        assert part == len(item['parts'])
        if part == 0:
            item.update(length=struct.unpack_from('<I', row, 12)[0], size_offset=pos + 12)
        item['parts'].append(pos)
        item['blocks'].extend(b for b in struct.unpack_from('<240H', row, 32) if b != 65535)
    assert len(components) == 6
    used = []
    for item in components.values():
        assert len(item['blocks']) == (item['length'] + 4095) // 4096
        used.extend(item['blocks'])
    assert len(used) == len(set(used))

    def logical(raw, item, length=None):
        return b''.join(raw[b * block_size:(b + 1) * block_size]
                        for b in item['blocks'])[:item['length'] if length is None else length]

    mdr_item = components['00004171.MDR']
    mdr = bytearray(logical(source, mdr_item))
    assert len(mdr) == 92653600
    assert struct.unpack_from('<4I', mdr, 600) == (92653480, 120, 20, 1)
    gmp = logical(source, components['I053061A.GMP'])
    witness_path = ROOT / 'staging/navigation-AP-MinQuan184-witness-v1/stock-MinQuan184-bounded-source-proof-v1.json'
    witness = json.loads(witness_path.read_text())
    rows = witness['all84_rows_with_frozen_boundaries']
    assert len(rows) == 84
    old_records = b''.join(bytes.fromhex(row['record_hex']) for row in rows)
    assert mdr[72315828:72317172] == old_records
    plan_path = ROOT / 'staging/navigation-native-Minquan-append-plan-v1/Minquan-append-only-record-plan-v1.json'
    plan = json.loads(plan_path.read_text())
    spec = importlib.util.spec_from_file_location('native_records', ROOT / 'scripts/native_address_records.py')
    codec = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = codec
    spec.loader.exec_module(codec)
    layout = codec.RecordLayout((22, 9, 24, 19, 1, 10, 0, 0), (1, 1), 128)
    new = []
    for item in plan['nine_new_source_candidates']:
        label, ref = item['label'], REFS[item['label']]
        raw_label = label.encode('cp950') + b'\0'
        offset = 6566 + (ref << 3)
        assert gmp[offset:offset + len(raw_label)] == raw_label
        point = codec.quantize_point24(*item['source_coordinate_strings'])
        a, b = point['latitude']['wire_u24'], point['longitude']['wire_u24']
        assert [a, b] == item['prospective_raw24_point_host_nearest_policy']
        record = codec.AddressRecord(1, ref, None, 0, 0, 0, a, b)
        encoded = codec.encode_record(layout, record)
        assert len(encoded.payload) == 16
        fields = {'+00': 0, '+04': 0, '+08': 1, '+0c': 0,
                  '+10': ref, '+14': a, '+18': b, '+1c': 0xFFFFFFFF}
        new.append(dict(label=label, number=int(label[:-1]), primary_ref=ref,
                        raw24=[a, b], payload=encoded.payload, expected_native_fields=fields,
                        source_id=item['OSM_id']))
    new.sort(key=lambda item: item['number'])
    merged, index = [], 0
    for row in rows:
        match = re.match(r'^(\d+)', row['label'])
        if match:
            while index < len(new) and new[index]['number'] < int(match.group(1)):
                merged.append(dict(new[index], oldID=None))
                index += 1
        merged.append(dict(label=row['label'], oldID=row['lowID'],
                           expected_native_fields=row['host_fields'],
                           payload=bytes.fromhex(row['record_hex'])))
    merged.extend(dict(item, oldID=None) for item in new[index:])
    assert len(merged) == 93
    assert [r['oldID'] for r in merged if r['oldID'] is not None] == [r['lowID'] for r in rows]
    numbers = [int(m.group(1)) for row in merged if (m := re.match(r'^(\d+)', row['label']))]
    assert numbers == sorted(numbers)
    stream = b''.join(row['payload'] for row in merged)
    assert len(stream) == 1488
    old_mdr = bytes(mdr)
    insert, extra = 91983716, len(stream)
    mdr[insert:insert] = stream
    street = 92215511 + extra
    window = int.from_bytes(mdr[street:street + 16], 'little')
    assert (window >> 26) & ((1 << 22) - 1) == 904706
    assert (window >> 48) & ((1 << 12) - 1) == 84
    mask = (((1 << 22) - 1) << 26) | (((1 << 12) - 1) << 48)
    patched = (window & ~mask) | (2133949 << 26) | (93 << 48)
    assert ((window ^ patched) & ~mask) == 0
    mdr[street:street + 16] = patched.to_bytes(16, 'little')
    new_dir = 92653480 + extra
    for index in range(6):
        pos = new_dir + index * 20
        start, size = struct.unpack_from('<2I', mdr, pos)
        if index < 3:
            struct.pack_into('<I', mdr, pos, start + extra)
        if index == 3:
            struct.pack_into('<I', mdr, pos + 4, size + extra)
    struct.pack_into('<I', mdr, 600, new_dir)
    assert len(mdr) == 92655088 <= len(mdr_item['blocks']) * block_size
    assert mdr[:600] == old_mdr[:600] and mdr[604:insert] == old_mdr[604:insert]
    restored_suffix = bytearray(mdr[insert + extra:])
    restored_suffix[street - (insert + extra):street - (insert + extra) + 16] = old_mdr[92215511:92215527]
    restored_suffix[92653480 - insert:92653600 - insert] = old_mdr[92653480:92653600]
    assert restored_suffix == old_mdr[insert:]
    for ordinal, table in enumerate(plan['MDR_component_relocation_plan']['tables']):
        assert mdr[new_dir + ordinal * 20:new_dir + (ordinal + 1) * 20].hex() == table['proposed_directory_metadata_hex']
    assert mdr[72315828:72317172] == old_records
    for index, row in enumerate(merged):
        row['new_lowID'] = 2133949 + index
        assert mdr[57840548 + (row['new_lowID'] - 1) * 16:57840548 + row['new_lowID'] * 16] == row['payload']
    for index, block in enumerate(mdr_item['blocks']):
        payload = mdr[index * block_size:(index + 1) * block_size]
        image[block * block_size:block * block_size + len(payload)] = payload
    struct.pack_into('<I', image, mdr_item['size_offset'], len(mdr))
    assert mdr_item['size_offset'] == 5132
    assert logical(image, mdr_item, len(mdr)) == mdr
    for name, item in components.items():
        if name != '00004171.MDR':
            assert logical(image, item) == logical(source, item)
    assert image[:fat_start] == source[:fat_start]
    fat = bytearray(image[fat_start:fat_end])
    struct.pack_into('<I', fat, mdr_item['size_offset'] - fat_start, mdr_item['length'])
    assert fat == source[fat_start:fat_end]
    assert len(image) == len(source) == 96739328 and sha(image) == CANDIDATE_SHA

    ranges = [(mdr_item['size_offset'], 4)]
    for logical_offset, length in [(600, 4), (insert, len(mdr) - insert)]:
        end = logical_offset + length
        while logical_offset < end:
            index, within = divmod(logical_offset, block_size)
            length_here = min(end - logical_offset, block_size - within)
            physical = mdr_item['blocks'][index] * block_size + within
            ranges.append((physical, length_here))
            logical_offset += length_here
    ranges.sort()
    joined = []
    for start, length in ranges:
        if joined and joined[-1][0] + joined[-1][1] == start:
            joined[-1] = (joined[-1][0], joined[-1][1] + length)
        else:
            assert not joined or joined[-1][0] + joined[-1][1] < start
            joined.append((start, length))
    rollback = dict(schema='garmin-native-address-rollback/v1', device_path='.System/gmapprom1.img',
                    bytes=len(image), original_sha256=ORIGINAL_SHA, candidate_sha256=CANDIDATE_SHA,
                    ranges=[dict(offset=o, length=n, before_hex=source[o:o + n].hex(),
                                 after_sha256=sha(image[o:o + n])) for o, n in joined])
    restored = bytearray(image)
    for item in rollback['ranges']:
        restored[item['offset']:item['offset'] + item['length']] = bytes.fromhex(item['before_hex'])
    assert restored == source and sha(restored) == ORIGINAL_SHA
    undo = gzip.compress(json.dumps(rollback, separators=(',', ':')).encode(), mtime=0)
    old_manifest = json.loads((ROOT / 'staging/navigation-repair-v2/package/manifest.json').read_text())
    manifest = dict(
        schema='garmin-native-address-supplement/v1', created_utc=datetime.now(timezone.utc).isoformat(),
        scope='台中市中區民權路9筆來源門牌補充候選；非全台2026地址更新',
        device=old_manifest['device'],
        target=dict(device_path='.System/gmapprom1.img', bundle_path='candidate/gmapprom1.img',
                    bytes=len(image), original_sha256=ORIGINAL_SHA, candidate_sha256=CANDIDATE_SHA),
        rollback=dict(schema=rollback['schema'], bundle_path='rollback.json.gz', sha256=sha(undo)),
        preserved_stock_files=[item for item in old_manifest['preserved_stock_files']
                               if item['device_path'] != '.System/gmapprom1.img'],
        required_files=[dict(device_path='Map/Taiwan_OSM_SearchRepair_v2.img', bytes=131829760,
                            sha256='664c46c99697b61ba383b5571b0a49356336746c9bbf3f94403aae583787f117')],
        records=[{key: (value.hex() if key == 'payload' else value)
                  for key, value in row.items()} for row in merged],
        old_84_original_bytes_preserved=True, old_84_relative_order_preserved=True,
        new_child_first=2133949, new_child_count=93, old_street_lowID=16707,
        new_street_MDR_offset=street, new_MDR_bytes=len(mdr), new_directory_MDR_offset=new_dir,
        source_snapshot_utc='2026-10-01T20:22:06Z',
        GMP_and_other_components_unchanged=True, original_JAI_unchanged=True,
        allowed_operation='controlled_physical_test', device_search_verified=False,
        whole_Taiwan_native_address_update_complete=False, firmware_modified=False,
        known_limits=['原門牌比較／flags8／incoming references未完整驗證',
                      '座標來自來源node，尚未實機驗證入口位置及路線', '只补充此街9筆，並非全台地址更新'])
    after = source_path.stat()
    assert (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    save(OUT / 'candidate/gmapprom1.img', bytes(image))
    save(OUT / 'rollback.json.gz', undo)
    save(OUT / 'manifest.json', manifest)
    assert sha((OUT / 'candidate/gmapprom1.img').read_bytes()) == CANDIDATE_SHA
    save(OUT / 'build-verification.json', dict(
        all_passed=True, candidate_sha256=CANDIDATE_SHA, original_sha256=ORIGINAL_SHA,
        original_84_verbatim=True, numeric_merge_order_verified_host_only=True,
        only_MDR_and_its_FAT_size_modified=True, full_rollback_exact=True,
        rollback_ranges=len(joined), rollback_bytes=len(undo), source_unmodified=True,
        native_full_house_query_verified=False, device_IO=False,
        builder_sha256=sha(Path(__file__).read_bytes())))
    print(json.dumps(dict(all_passed=True, candidate=str(OUT / 'candidate/gmapprom1.img'),
                          candidate_sha256=CANDIDATE_SHA, records=len(merged), rollback_bytes=len(undo)), ensure_ascii=False))


if __name__ == '__main__':
    main()
