#!/usr/bin/env python3
"""Read new country outputs independently; bounded original-map windows only."""
import gzip
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent


def need(ok, message):
    if not ok:raise AssertionError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def value(wire, at, width):
    first, shift = divmod(at, 8)
    end = (at + width + 7) // 8
    # Explicit bytes-based extraction independent from production carry writer.
    raw = wire[first:end]
    result = 0
    for index in range(len(raw) - 1, -1, -1):result = (result << 8) | raw[index]
    return (result >> shift) & ((1 << width) - 1)


def canonical(records, width):
    h = hashlib.sha256()
    for v in records:h.update(v.to_bytes((width + 7) // 8, 'little'))
    return h.hexdigest()


def field(number, at, width):return (number >> at) & ((1 << width) - 1)


def main():
    result_path = OUT / 'output-readback-proof.json'
    need(not result_path.exists(), 'New readback result only')
    proof = json.loads((OUT / 'proof.json').read_text())
    streams, maps, source_digests = {}, {}, {}
    for lev in [4, 5, 6]:
        artifact = proof['artifacts'][f'level{lev}']
        path = OUT / artifact['path']
        with path.open('rb') as stream:digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        need(path.stat().st_size == artifact['bytes'] and digest == artifact['sha256'], 'Whole new packed output SHA/bytes')
        f = path.open('rb'); streams[lev] = f
        maps[lev] = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) if artifact['bytes'] else b''
        bits = artifact['bit_length']
        need(bits == artifact['record_count'] * artifact['record_bits'], 'Output count/stride/bit length')
        need(bits % 8 == 0 or maps[lev][-1] >> (bits % 8) == 0, 'Final table padding zero only')
        source_digests[lev] = digest
    representatives, last, largest, alignment, firstfew, raw13 = {}, {}, {}, {}, {4:0, 5:0, 6:0}, {}
    # Output array deliberately has one compact object per line, bounded parser.
    ranges_digest = hashlib.sha256(); range_count = 0
    with (OUT / 'selected-street-ranges.json').open('rb') as f:
        for line in f:
            ranges_digest.update(line)
            text = line.strip().rstrip(b',')
            if text in (b'[', b']', b''):continue
            s = json.loads(text); lev = s['next_level']; key = (lev, s['nativeStreetID'])
            range_count += 1; last[lev] = s
            if firstfew[lev] < 3:representatives[key] = s; firstfew[lev] += 1
            if lev not in largest or s['new_count'] > largest[lev]['new_count']:largest[lev] = s
            shiftkey = (lev, s['appended_bit_offset'] % 8)
            if shiftkey not in alignment:alignment[shiftkey] = s
            if s['original_flags'] == 13 and lev not in raw13:raw13[lev] = s
            if s['nativeStreetID'] == 16707:representatives[key] = s
    need(range_count == proof['artifacts']['selected_ranges']['rows'] and ranges_digest.hexdigest() == proof['artifacts']['selected_ranges']['sha256'], 'Every selected range parsed and bound')
    for s in list(last.values()) + list(largest.values()) + list(alignment.values()) + list(raw13.values()):representatives[(s['next_level'], s['nativeStreetID'])] = s
    inserted = {key: set() for key in representatives}
    checked, rowhash = 0, hashlib.sha256()
    with (OUT / 'new-house-records.jsonl.gz').open('rb') as f:
        ledger_compressed_sha = hashlib.file_digest(f, 'sha256').hexdigest()
    with gzip.open(OUT / 'new-house-records.jsonl.gz', 'rb') as stream:
        for line in stream:
            rowhash.update(line); r = json.loads(line); lev = r['next_level']; width = r['record_bits']
            need(width == {4:128, 5:126, 6:68}[lev], 'Actual new receipt stride')
            raw = bytes.fromhex(r['payload']); expect = int.from_bytes(raw, 'little')
            need(expect >> width == 0 and value(maps[lev], r['appended_bit_offset'], width) == expect, 'Every new leaf actual tightly packed output equals standalone receipt')
            need(field(expect, 0, 1) == 1, 'Every new leaf mapordinal1')
            if lev == 4:
                need(field(expect, 1, 19) == 524287 and field(expect, 20, 19) == r['primary_ref'], 'L4 refs independently decoded')
                need(field(expect, 39, 22) == field(expect, 61, 10) == field(expect, 71, 9) == 0, 'L4 new leaf hierarchy zero')
                point = [field(expect, 80, 24), field(expect, 104, 24)]
            elif lev == 5:
                need(field(expect, 1, 19) == 524287 and field(expect, 20, 19) == r['primary_ref'], 'L5 refs independently decoded')
                need(field(expect, 39, 21) == field(expect, 60, 9) == field(expect, 69, 9) == 0, 'L5 new leaf hierarchy zero')
                point = [field(expect, 78, 24), field(expect, 102, 24)]
            else:
                need(field(expect, 1, 19) == r['primary_ref'], 'L6 actual primary ref at bit1')
                point = [field(expect, 20, 24), field(expect, 44, 24)]
            need(point == r['raw24'], 'Every new point matches independent native field placement')
            key = (lev, r['nativeStreetID'])
            if key in inserted:
                s = representatives[key]
                need(r['appended_bit_offset'] >= s['appended_bit_offset'] and (r['appended_bit_offset'] - s['appended_bit_offset']) % width == 0, 'Representative new position is exact record bit boundary')
                position = (r['appended_bit_offset'] - s['appended_bit_offset']) // width
                need(position not in inserted[key] and position < s['new_count'], 'Representative new position unique/in range')
                inserted[key].add(position)
            checked += 1
    ledger_artifact = proof['artifacts']['new_records']
    need(checked == ledger_artifact['rows'] == 111608 and rowhash.hexdigest() == ledger_artifact['uncompressed_sha256'] and ledger_compressed_sha == ledger_artifact['sha256'], 'Complete actual new ledger EOF/hash/count')
    module_path = ROOT / 'staging/navigation-taichung-merge-review-v1/review_merge.py'
    spec = importlib.util.spec_from_file_location('independent_country_window_reader', module_path)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    image = module.IndependentIMG(ROOT / 'backups/20261002T154458Z/files/.System/gmapprom1.img')
    table = {4:57840548, 5:20968286, 6:4195100}
    bounded = []
    for key, s in sorted(representatives.items()):
        lev, streetID = key; width = s['record_bits']
        start, shift = divmod((s['original_first'] - 1) * width, 8)
        body = image.get('00004171.MDR', table[lev] + start, (shift + s['original_count'] * width + 7) // 8)
        old = [value(body, shift + i * width, width) for i in range(s['original_count'])]
        new = [value(maps[lev], s['appended_bit_offset'] + i * width, width) for i in range(s['new_count'])]
        retained = [v for i, v in enumerate(new) if i not in inserted[key]]
        need(old == retained and canonical(old, width) == s['original_significant_records_sha256'] and canonical(new, width) == s['new_significant_records_sha256'], 'Actual representative original significant bits/order and emitted group hashes')
        old_raw13 = sum(field(v, 71 if lev == 4 else 69, 9) == 13 for v in old) if lev != 6 else 0
        bounded.append(dict(next_level=lev, nativeStreetID=streetID, city=s['city'], street=s['street'],
            original_flags=s['original_flags'], original_count=len(old), new_count=len(new), actual_old_raw13_records=old_raw13,
            output_initial_bit_shift=s['appended_bit_offset'] % 8, actual_original_significant_bits_and_order_equal=True))
    image.close()
    actual_map_bytes = sum(r['bytes'] for r in image.read_log)
    need(actual_map_bytes < 400000, 'Bounded actual original-map review budget')
    for m in maps.values():
        if hasattr(m, 'close'):m.close()
    for f in streams.values():f.close()
    result = dict(all_assigned_checks_passed=True, every_new_output_leaf_checked=checked,
        every_new_output_leaf_refs_hierarchy_and_point_independently_decoded=True,
        complete_append_file_SHA256_readbacks=source_digests, complete_selected_ranges_and_ledger_hashes_checked=True,
        representative_groups=bounded, actual_original_map_bytes_read=actual_map_bytes,
        actual_original_records_directly_compared=sum(r['original_count'] for r in bounded),
        selected_initial_shifts=sorted({(r['next_level'], r['output_initial_bit_shift']) for r in bounded}),
        source_script_sha256=sha(Path(__file__).read_bytes()), device_IO=False, native_CPU_executed=False,
        original_complete_L4_L5_L6_tables_reread=False,
        limits=['Direct original comparison is limited to representative groups; full-source preservation claims additionally use preparation hashes.',
                'No native comparator, profile/IMG assembly, physical USB or navigation acceptance proof.'])
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(all_assigned_checks_passed=True, every_new_leaf_checked=checked,
        representative_groups=len(bounded), actual_original_map_bytes_read=actual_map_bytes,
        actual_old_raw13_records=sum(r['actual_old_raw13_records'] for r in bounded), device_IO=False)))


if __name__ == '__main__':main()
