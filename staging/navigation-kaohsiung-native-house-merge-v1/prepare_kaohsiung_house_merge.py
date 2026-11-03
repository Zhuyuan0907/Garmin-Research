#!/usr/bin/env python3
"""One ready-ledger pass per level; only district-verified Kaohsiung additions.

Append ordinals follow frozen country v1 counts. New bins begin at bit zero;
the following container stage must splice significant bits, never concatenate
v1's padded L5/L6 bytes with these bins.
"""
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal
from functools import lru_cache
import gzip
import hashlib
import importlib.util
import itertools
import json
import resource
from pathlib import Path
import re
import struct
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import merge_policy as policy

ROOT = policy.ROOT
COUNTRY = ROOT / 'staging/navigation-country-native-house-merge-v1'
NATIVE = ROOT / 'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz'
PINS = {
    COUNTRY / 'proof.json': (17508, 'bfc55b01f1f567cbad495ba3e35301d358cf54d1fdddea9fe1b8a9e6c8412a41'),
    ROOT / 'staging/navigation-country-address-ready-join-v1/proof.json':
        (357380, 'b61cd949152fece0548265ccf438c14d3bbeeddfc5e3ae05140df20d3aa0a175'),
}
COUNTRY_SELECTED_BYTES = 14628154
COUNTRY_SELECTED_SHA256 = 'dd42c0e57c96f61ed6d93f0309b4fdd5ae6c98652a937163fd61f494b8e7bbaa'
NATIVE_BYTES = 1210093
NATIVE_SHA256 = '45333390cec4996db40b4a4a987eb421641fec352203bb318aedfd6a6fce2776'
EXPECTED_START = {4: 3425572, 5: 2614789, 6: 1983085}


def main():
    base = policy.country_helpers()
    base.OUT = HERE
    base.INPUTS = []
    need = base.need
    need(not (HERE / 'proof.json').exists() and not (HERE / 'appended-level4.bin').exists(), 'New namespace only')
    started = datetime.now(timezone.utc).isoformat()
    for path, (size, digest) in PINS.items():
        payload = path.read_bytes()
        need(len(payload) == size and base.sha(payload) == digest, 'Pinned upstream proof')
    country = base.small_json(COUNTRY / 'proof.json')
    join = base.small_json(ROOT / 'staging/navigation-country-address-ready-join-v1/proof.json')
    need(country['all_assigned_checks_passed'] and join['all_assigned_checks_passed'], 'Completed frozen upstream data')
    start_counts = {int(level): count for level, count in country['proposed_counts'].items()}
    need(start_counts == EXPECTED_START, 'Append ordinals follow sealed country v1')
    before_country_selected = base.signature(COUNTRY / 'selected-street-ranges.json')
    country_ids, selected_sha, selected_bytes = set(), hashlib.sha256(), 0
    with (COUNTRY / 'selected-street-ranges.json').open('rb') as stream:
        for line in stream:
            selected_sha.update(line); selected_bytes += len(line)
            text = line.strip().rstrip(b',')
            if text in (b'[', b']', b''):continue
            row = json.loads(text)
            need(row['nativeStreetID'] not in country_ids and row['city'] != '高雄市', 'Country v1 selected streets have no Kaohsiung')
            country_ids.add(row['nativeStreetID'])
    need(selected_bytes == COUNTRY_SELECTED_BYTES and selected_sha.hexdigest() == COUNTRY_SELECTED_SHA256 and
         len(country_ids) == 15679 and base.signature(COUNTRY / 'selected-street-ranges.json') == before_country_selected,
         'All country selected IDs bound and immutable')
    base.INPUTS.append(dict(path=str((COUNTRY / 'selected-street-ranges.json').relative_to(ROOT)), bytes=selected_bytes,
        sha256=selected_sha.hexdigest(), rows=len(country_ids), Kaohsiung_selected_count=0, stat_unchanged=True))
    validator = policy.district_validator()
    native, native_lines = {}, 0
    native_before = base.signature(NATIVE)
    with NATIVE.open('rb') as raw:
        reader = base.HashReader(raw)
        with gzip.GzipFile(fileobj=reader) as stream:
            for line in stream:
                native_lines += 1; row = json.loads(line)
                if row['level'] == 3 and row['city'] == '高雄市':
                    need(row['low28_id'] not in native, 'Unique native Kaohsiung street')
                    native[row['low28_id']] = row
        need(reader.bytes == NATIVE_BYTES and reader.digest.hexdigest() == NATIVE_SHA256, 'Pinned original native hierarchy EOF')
    need(base.signature(NATIVE) == native_before, 'Native hierarchy immutable')
    base.INPUTS.append(dict(path=str(NATIVE.relative_to(ROOT)), bytes=reader.bytes, sha256=reader.digest.hexdigest(),
        lines=native_lines, Kaohsiung_native_streets=len(native), gzip_EOF_validated=True, stat_unchanged=True))
    selected = base.JsonArray('selected-street-ranges.json')
    ledger = base.JsonLines('new-house-records.jsonl.gz')
    held = base.JsonLines('held-street-groups.jsonl.gz')
    rejected = base.JsonLines('rejected-new-house-targets.jsonl.gz')
    readlog = base.JsonLines('original-map-read-log.jsonl.gz')
    appended = {level: base.BitAppend(base.OutputHash(HERE / f'appended-level{level}.bin'), width) for level, width in base.STRIDES.items()}
    totals, by_level, by_district = Counter(), {}, {}
    streamed, skipped = {}, {}
    selected_ids = set()
    max_rows = max_old = map_bytes = map_reads = 0
    runtime = []; last_update = time.monotonic()
    before_ap = base.signature(base.AP)
    core = policy.verified_module(base.CORE, base.CORE_SHA, 'kaohsiung_original_StreamIMG_only')
    with base.AP.open('rb') as source:
        image = core.StreamIMG(source)
        def flush_reads():
            nonlocal map_bytes, map_reads
            for record in image.read_log:
                readlog.write(record); map_bytes += record['bytes']; map_reads += 1
            image.read_log.clear()
        def read(name, offset, length):return b''.join(image.iter_component(name, offset=offset, length=length))
        header = read('00004171.MDR', 0, 772)
        need(struct.unpack_from('<4I', header, 600) == (92653480, 120, 20, 1), 'Actual original MDR directory')
        directory = read('00004171.MDR', 92653480, 120)
        tables = {level: struct.unpack_from('<5I', directory, (level - 1) * 20) for level in range(1, 7)}
        need(tables[3][:3] == (91983716, 664197, 111), 'Corrected actual original L3')
        for level in base.STRIDES:
            need(tables[level][:3] == base.DESCRIPTORS[level] and tables[level][1] * 8 == base.TOTALS[level] * base.STRIDES[level], 'Actual original leaf profile')
        pool = read('I053061A.GMP', 6566, 3805432)
        @lru_cache(maxsize=65536)
        def label(reference):
            if reference == 524287 or not 0 <= reference * 8 < len(pool):return None
            at = reference * 8; end = pool.find(b'\0', at, min(len(pool), at + 512))
            if end < 0:return None
            try:return pool[at:end].decode('cp950', errors='strict')
            except UnicodeDecodeError:return None
        flush_reads()
        for level in (4, 5, 6):
            counts = by_level[level] = Counter()
            output, width = appended[level], base.STRIDES[level]
            streamed[level] = skipped[level] = 0
            expected = join['artifacts'][f'exact_{level}_ready']
            def relevant_rows():
                for row in base.source_rows(ROOT / expected['path'], expected, level):
                    streamed[level] += 1
                    if row['native_city'] == '高雄市':yield row
                    else:skipped[level] += 1
            for street_id, group in itertools.groupby(relevant_rows(), key=lambda row: row['nativeStreetID']):
                rows = list(group); witness = rows[0]
                max_rows = max(max_rows, len(rows)); counts['Kaohsiung_source_groups'] += len(rows)
                district = witness['native_district']; district_counts = by_district.setdefault(district, Counter())
                district_counts['source_groups'] += len(rows)
                first, count, flags = [witness[k] for k in ('old_child_first', 'old_child_count', 'old_child_level_and_flags')]
                need(all([row[k] for k in ('native_city', 'native_district', 'native_street', 'old_child_first', 'old_child_count', 'old_child_level_and_flags')] ==
                     [witness[k] for k in ('native_city', 'native_district', 'native_street', 'old_child_first', 'old_child_count', 'old_child_level_and_flags')] for row in rows), 'Same original native parent witness')
                need(1 <= street_id <= 47870 and 0 < count <= 4095 and 1 <= first <= first + count - 1 <= base.TOTALS[level], 'Original group bounded')
                def hold(reason, **extra):
                    counts['held_streets_' + reason] += 1; counts['held_source_groups_' + reason] += len(rows)
                    district_counts['held_streets_' + reason] += 1
                    held.write(dict(nativeStreetID=street_id, native_street_record=witness['native_street_record'], city='高雄市',
                        district=district, street=witness['native_street'], next_level=level, original_first=first,
                        original_count=count, original_flags=flags, source_groups=len(rows), reason=reason, **extra))
                if not all(policy.exact_native_witness(row, native.get(street_id)) for row in rows):
                    hold('original_native_hierarchy_mismatch'); continue
                if district not in validator.geometries:
                    hold('incomplete_旗津_geometry' if district in validator.held else 'unknown_or_missing_district'); continue
                parent_at, parent_shift = divmod((street_id - 1) * 111, 8)
                parent = int.from_bytes(read('00004171.MDR', tables[3][0] + parent_at, 16), 'little') >> parent_shift
                need(((parent >> 20) & ((1 << 22) - 1), (parent >> 42) & 4095, (parent >> 54) & 511) == (first, count, flags), 'Actual original parent fields')
                start, shift = divmod((first - 1) * width, 8)
                body = read('00004171.MDR', tables[level][0] + start, (shift + count * width + 7) // 8)
                old = base.unpack(body, shift, count, width); max_old = max(max_old, count)
                names = [label((value >> (1 if level == 6 else 20)) & 524287) for value in old]
                if any(name is None for name in names):hold('unreadable_original_label'); flush_reads(); continue
                anchors = [int(match.group()) for name in names if (match := re.match(r'^[0-9]+', name))]
                if not anchors or anchors != sorted(anchors):hold('unproved_original_numeric_order'); flush_reads(); continue
                existing, ordinal_one, additions = set(names), all(value & 1 == 1 for value in old), []
                for house, members_group in itertools.groupby(rows, key=lambda row: row['house_label']):
                    members = list(members_group); counts['source_distinct_street_house_targets'] += 1
                    match = base.INTEGER.fullmatch(house)
                    if not match:
                        counts['subnumber_or_other_source_groups_deferred'] += len(members)
                        counts['subnumber_or_other_targets_deferred'] += 1; continue
                    counts['positive_integer_source_groups'] += len(members)
                    if house in existing:
                        counts['original_exact_integer_targets_unchanged'] += 1
                        counts['source_integer_groups_already_original'] += len(members); continue
                    def reject(reason, **extra):
                        counts['new_integer_targets_rejected_' + reason] += 1
                        rejected.write(dict(nativeStreetID=street_id, next_level=level, city='高雄市', district=district,
                            street=witness['native_street'], house_label=house, source_group_ids=[row['group_id'] for row in members],
                            source_ids=sorted({node for row in members for node in row['source_ids']}),
                            source_points=[row['coordinate_strings'] for row in members], reason=reason, **extra))
                    if not all(policy.exact_source_administration(row) for row in members):
                        reject('source_exact_city_district_name_mismatch'); continue
                    references = {row['primary_ref'] for row in members}
                    points = {tuple(map(Decimal, row['coordinate_strings'])) for row in members}
                    if len(references) != 1 or len(points) != 1:
                        reject('same_house_conflicting_ref_or_Decimal_point'); continue
                    need(label(members[0]['primary_ref']) == house, 'Exact reusable original label')
                    if not ordinal_one:
                        reject('original_mapordinal_not_one'); continue
                    point = members[0]['coordinate_strings']
                    source_decision = validator.assess('高雄市', district, *point)
                    if source_decision['status'] != 'inside_verified_district':
                        reject('source_point_not_inside_verified_district', source_decision=source_decision); continue
                    quantization = base.quantize_point24(*point)
                    raw24 = [quantization['latitude']['wire_u24'], quantization['longitude']['wire_u24']]
                    quantized_decision = policy.quantized_assess(validator, '高雄市', district, raw24)
                    if quantized_decision['status'] != 'inside_verified_district':
                        reject('raw24_point_not_inside_same_verified_district', raw24=raw24,
                               quantized_decision=quantized_decision); continue
                    payload = base.encode_record(base.LAYOUTS[level], base.AddressRecord(1, members[0]['primary_ref'], None, 0, 0, 0, *raw24)).payload
                    value = int.from_bytes(payload, 'little'); need(value >> width == 0, 'New unused bits zero')
                    provenance = [dict(group_id=row['group_id'], source_ids=row['source_ids'], raw_address=row['raw_address'],
                        coordinate_strings=row['coordinate_strings'], source_node_count=row['source_node_count'],
                        separate_floor_unit_source_nodes=row['separate_floor_unit_source_nodes'],
                        embedded_floor_unit_first_source_flag=row['embedded_floor_unit_first_source_flag']) for row in members]
                    additions.append(dict(label=house, number=int(match.group(1)), value=value, payload=payload.hex(), raw24=raw24,
                        coordinate_strings=point, primary_ref=members[0]['primary_ref'], source_members=provenance,
                        source_group_ids=[row['group_id'] for row in members], source_ids=sorted({node for row in members for node in row['source_ids']}),
                        source_district_decision=source_decision, quantized_district_decision=quantized_decision))
                    if len(members) > 1:
                        counts['coalesced_same_Decimal_targets'] += 1; counts['coalesced_extra_source_groups'] += len(members) - 1
                if not additions:
                    counts['streets_without_new_eligible_integer'] += 1; flush_reads(); continue
                if count + len(additions) > 4095:
                    hold('merged_parent_count_over_12bit', held_new_integer_targets=len(additions)); flush_reads(); continue
                new_first = start_counts[level] + output.records + 1
                if new_first + count + len(additions) - 1 > 0x7fffff:
                    hold('proposed_first_or_last_over_23bit', held_new_integer_targets=len(additions)); flush_reads(); continue
                merged, positions, ordered = base.merge_numeric(old, names, additions)
                need(street_id not in country_ids and street_id not in selected_ids, 'Country v1/Kaohsiung selected intersection empty')
                selected_ids.add(street_id)
                offset_bits = output.bits
                for value in merged:output.add(value)
                selected.write(dict(nativeStreetID=street_id, native_street_record=witness['native_street_record'], city='高雄市',
                    district=district, street=witness['native_street'], next_level=level, record_bits=width,
                    original_first=first, original_count=count, original_flags=flags, new_first=new_first, new_count=len(merged),
                    base_country_v1_proposed_count=start_counts[level], appended_bit_offset=offset_bits,
                    appended_record_ordinal=offset_bits // width, combined_append_bit_offset=country['artifacts'][f'level{level}']['bit_length'] + offset_bits,
                    new_integer_house_count=len(additions), original_source_window_sha256=base.sha(body), original_source_initial_bit_shift=shift,
                    original_significant_records_sha256=base.record_hash(old, width),
                    new_significant_records_sha256=base.record_hash(merged, width), new_group_tight_packed_sha256=base.sha(base.packed(merged, width)),
                    source_district_relation_id=validator.metadata[district]['source_relation_id'],
                    district_geometry_sha256=validator.metadata[district]['geometry_sha256'],
                    significant_hash_policy='Each significant record serialized in ceil(stride/8) little-endian bytes, per-record high unused bits zero; concatenate for SHA.'))
                for row in ordered:
                    position = positions[row['label']]
                    ledger.write(dict(nativeStreetID=street_id, next_level=level, new_lowID=new_first + position,
                        appended_bit_offset=offset_bits + position * width, record_bits=width,
                        combined_append_bit_offset=country['artifacts'][f'level{level}']['bit_length'] + offset_bits + position * width,
                        house_label=row['label'], primary_ref=row['primary_ref'], source_ids=row['source_ids'],
                        source_group_ids=row['source_group_ids'], source_members=row['source_members'], coordinate_strings=row['coordinate_strings'],
                        raw24=row['raw24'], payload=row['payload'], old_child_first=first, old_child_count=count, old_parent_flags=flags,
                        city='高雄市', district=district, street=witness['native_street'],
                        source_district_decision=row['source_district_decision'], quantized_district_decision=row['quantized_district_decision']))
                counts['updated_streets'] += 1; counts['new_integer_house_records'] += len(additions)
                counts['cloned_original_records'] += count; counts['appended_records'] += len(merged)
                district_counts['updated_streets'] += 1; district_counts['new_integer_house_records'] += len(additions)
                flush_reads()
                if time.monotonic() - last_update > 25:
                    observation = dict(level=level, all_source_rows_streamed=streamed[level], Kaohsiung_source_groups=counts['Kaohsiung_source_groups'],
                        updated_streets=counts['updated_streets'], new_integer_house_records=counts['new_integer_house_records'],
                        max_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
                    runtime.append(observation); print(json.dumps(dict(progress=observation), ensure_ascii=False), flush=True)
                    last_update = time.monotonic()
            totals.update(counts)
            print(json.dumps(dict(level_finished=level, counts=dict(counts), all_source_rows_streamed=streamed[level], other_city_rows_skipped=skipped[level]), ensure_ascii=False), flush=True)
        flush_reads()
    need(base.signature(base.AP) == before_ap, 'Original AP unchanged')
    need(selected_ids.isdisjoint(country_ids), 'Final country v1 selected intersection empty')
    artifacts = {f'level{level}': output.finish() for level, output in appended.items()}
    artifacts.update(selected_ranges=selected.close(), new_records=ledger.close(), held=held.close(),
                     rejected_targets=rejected.close(), read_log=readlog.close())
    need(artifacts['new_records']['rows'] == totals['new_integer_house_records'], 'Every admitted new leaf has one ledger')
    for level in base.STRIDES:
        need(artifacts[f'level{level}']['record_count'] == by_level[level]['appended_records'], 'New append totals agree')
    source_bindings = [dict(path=str(path.relative_to(ROOT)), bytes=path.stat().st_size, sha256=base.sha(path.read_bytes()))
        for path in [Path(__file__), HERE / 'merge_policy.py', policy.BASE_PATH, policy.DISTRICT_PATH,
                     ROOT / 'scripts/native_address_records.py', base.CORE]]
    base.save('proof.json', dict(schema='kaohsiung-original-native-integer-house-merge-preparation/v1',
        started_utc=started, finished_utc=datetime.now(timezone.utc).isoformat(), all_assigned_checks_passed=True,
        original_counts=base.TOTALS, starting_country_v1_counts=start_counts,
        proposed_counts={level:start_counts[level] + appended[level].records for level in base.STRIDES},
        country_v1_append_bit_lengths={level:country['artifacts'][f'level{level}']['bit_length'] for level in base.STRIDES},
        country_v1_unused_final_high_bits={level:country['artifacts'][f'level{level}']['unused_final_high_bits'] for level in base.STRIDES},
        strides=base.STRIDES, counts=dict(totals), counts_by_level={level:dict(c) for level,c in by_level.items()},
        counts_by_district={district:dict(c) for district,c in by_district.items()}, all_source_rows_streamed=streamed,
        other_city_source_rows_skipped=skipped, country_v1_selected_intersection_count=0,
        Kaohsiung_native_street_count=len(native), artifacts=artifacts, inputs=base.INPUTS, source_code_bindings=source_bindings,
        original_map_stat_before=before_ap, original_map_stat_after=base.signature(base.AP),
        original_map_bytes_read=map_bytes, original_map_read_operations=map_reads,
        max_source_street_rows=max_rows, max_original_street_records=max_old,
        max_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, runtime_resource_receipts=runtime,
        source_and_exact_rational_quantized_point_must_both_cover_same_verified_district=True,
        original_significant_bits_order_flags_childrefs_coords_preserved=True,
        original_flag13_cleared_or_converted=False, original_exact_house_coordinates_updated=False,
        subnumber_generation_deferred=True, only_mapordinal1_new_leaves=True,
        incomplete_旗津_and_unknown_district_held=True, city_union_or_city_fallback_used=False,
        tight_table_wide_packing_with_only_final_high_padding_zero=True,
        future_L5_L6_splice_requires_bits_not_byte_concatenation=True,
        full_PBF_or_source_node_ledger_read=False, device_IO=False, native_CPU_executed=False, whole_IMG_written=False,
        full_Taiwan_update_complete=False,
        limits=['New Kaohsiung-only positive-integer existing-label leaves for existing exact-ready native streets.',
            'Source city and district must match original native names exactly; both source and exact raw24 point must be inside that complete district.',
            'Existing house coordinates and raw original significant records remain unchanged; subnumbers and unproved original numeric order held.',
            'Country v1 source/outputs are frozen. This stricter new quantized point policy does not revise v1.',
            'Host numeric-base order is not complete native frontend comparator/query/UI proof.',
            'This is append preparation; no IMG/container, installation, physical navigation or complete country coverage.']))
    print(json.dumps(dict(all_assigned_checks_passed=True, counts=dict(totals), proposed_counts={level:start_counts[level] + appended[level].records for level in base.STRIDES},
        selected_country_intersection=0, max_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss), ensure_ascii=False), flush=True)


if __name__ == '__main__':main()
