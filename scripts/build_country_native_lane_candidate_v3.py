#!/usr/bin/env python3
"""Compose/read back a NEW current-v2 COW AP8K candidate, without device I/O.

Sealed producer owns the copied tree and source provenance. This integration
independently checks complete source significant prefixes and extracted tight
append streams in the actual output. Device and full query acceptance remain
separate, and this file does not package or install anything.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-country-native-lane-candidate-v3'
SOURCE = ROOT / 'staging/navigation-country-native-candidate-v2/gmapprom1.img'
WRITER = ROOT / 'staging/navigation-native-current-profile-cow-writer-v1'
PRODUCER = ROOT / 'staging/navigation-native-lane-tree-cow-append-v1'
RESTORE = ROOT / 'staging/navigation-native-8k-layout-restore-api-v1'
WRITER_SEAL = '2c0f87324b42a9c5434790998da1f6ede1ed20afc6e676645995c8d6d6f238f7'
SOURCE_SHA = '925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'
SOURCE_BYTES = 128356352
EXPECTED_BYTES = 153346048
PINS = []


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stat(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def bind_small(path, expected, maximum=5_000_000):
    before = stat(path)
    need(before[2] <= maximum, 'Metadata read exceeds explicit bound')
    raw = path.read_bytes()
    need(sha(raw) == expected and stat(path) == before, 'Sealed input changed: ' + str(path))
    PINS.append(dict(path=str(path.relative_to(ROOT)), bytes=len(raw), sha256=expected, stat_before=before))
    return raw


def load_seal(directory, expected):
    seal = json.loads(bind_small(directory / 'sealed-files.json', expected))
    passed_key = 'all_fresh_file_hashes_verified' if directory == PRODUCER else 'all_assigned_checks_passed'
    need(seal[passed_key], 'Prerequisite seal not successful')
    return {Path(row['path']).name: row for row in seal['files']}


def module(directory, rows, filename, name):
    path = directory / filename
    bind_small(path, rows[filename]['sha256'])
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def saved(path, value):
    raw = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    with path.open('xb') as f:
        need(f.write(raw) == len(raw), 'Complete evidence write')
        f.flush()
        os.fsync(f.fileno())
    return dict(path=str(path.relative_to(ROOT)), bytes=len(raw), sha256=sha(raw))


def tight_chunks(read, start_bit, valid_bits):
    """Independent absolute-position extraction, one final zero padding tail.

    Each read <=65536 bytes; emit byte-aligned pieces except the very last
    partial byte. This does not reuse the writer's carry/splice implementation.
    """
    used = 0
    while used < valid_bits:
        amount = min(valid_bits - used, 65535 * 8)
        bit = start_bit + used
        first, shift = divmod(bit, 8)
        raw = read(first, (shift + amount + 7) // 8)
        value = (int.from_bytes(raw, 'little') >> shift) & ((1 << amount) - 1)
        yield value.to_bytes((amount + 7) // 8, 'little')
        used += amount


def digest_chunks(chunks):
    h = hashlib.sha256()
    amount = 0
    for raw in chunks:
        h.update(raw)
        amount += len(raw)
    return amount, h.hexdigest()


def main():
    args = argparse.ArgumentParser()
    args.add_argument('--producer-seal-sha256', required=True)
    args.add_argument('--restore-seal-sha256', required=True)
    args = args.parse_args()
    need(not OUT.exists(), 'Refuse overwrite prior candidate namespace')
    started = time.monotonic()
    wrows = load_seal(WRITER, WRITER_SEAL)
    prows = load_seal(PRODUCER, args.producer_seal_sha256)
    rrows = load_seal(RESTORE, args.restore_seal_sha256)
    writer = module(WRITER, wrows, 'current_profile_cow_writer.py', 'v3_sealed_current_writer')
    producer = module(PRODUCER, prows, 'append_api.py', 'v3_sealed_cow_producer_api')
    restore = module(RESTORE, rrows, 'native_8k_stock_restore.py', 'v3_sealed_8k_metadata_parser')
    producer_proof = json.loads(bind_small(PRODUCER / 'proof.json', prows['proof.json']['sha256']))
    need(producer_proof['all_assigned_checks_passed'] and producer_proof['source_candidate_SHA'] == SOURCE_SHA,
         'Prepared tree binds exact current v2')
    for name in ('output-readback-proof.json', 'new-controls-proof.json'):
        bind_small(PRODUCER / name, prows[name]['sha256'])
    appends, selected, producer_binding = producer.load_inputs(writer)
    append_meta = json.loads(bind_small(PRODUCER / 'appends.json', prows['appends.json']['sha256']))
    need(len(selected) == 7650 and producer_binding['final_table_counts'] == {'4': 4896236, '5': 3077845, '6': 2062771},
         'Exact all-root COW closure binding')
    source_before = stat(SOURCE)
    need(source_before[2] == SOURCE_BYTES, 'Exact current v2 source size')
    OUT.mkdir()
    saved(OUT / 'prerequisite-bindings.json', dict(seal_SHA256=dict(writer=WRITER_SEAL,
          producer=args.producer_seal_sha256, restore=args.restore_seal_sha256),
          producer_binding=producer_binding, source_v2_inherited_full_hash=SOURCE_SHA, source_before=source_before))
    target = OUT / 'gmapprom1.img'
    with SOURCE.open('rb') as source_stream:
        image = writer.eight().Source4K(source_stream)
        adapter = writer.Explicit8KAdapter.from_container(image)
        plan = writer.plan_current_mdr(adapter.source, appends=appends, selected_ranges=selected)
        bound = plan.bind_container(adapter)
        need(bound.capacity_plan['image_bytes'] == EXPECTED_BYTES and plan.size == 149220356,
             'Exact explicit8K capacity differs')
        saved(OUT / 'mdr-plan.json', plan.report)
        saved(OUT / 'capacity-plan.json', bound.capacity_plan)
        with target.open('xb') as destination:
            written = bound.repack_stream(destination)
            destination.flush()
            os.fsync(destination.fileno())
        need(stat(SOURCE) == source_before and target.stat().st_size == EXPECTED_BYTES,
             'Source immutable / completed target size')
        saved(OUT / 'stream-write-receipt.json', written)
        # Fresh actual output reads, not planned allocations or preservation booleans.
        with target.open('rb') as output:
            actual_hash = hashlib.file_digest(output, 'sha256').hexdigest()
            layout = restore.parse_layout(output, EXPECTED_BYTES, 8192)
            need(not layout['unused_blocks'], 'Unexpected unused physical output blocks')
            component_checks = []
            for receipt in written['components']:
                name = receipt['name']
                c = layout['components'][name]
                read = lambda at, n, c=c: restore.logical_read(output, c, 8192, at, n)
                actual_bytes, actual_component_sha = digest_chunks(read(at, min(65536, c['size']-at))
                    for at in range(0, c['size'], 65536))
                need(actual_bytes == receipt['bytes'] and actual_component_sha == receipt['sha256'],
                     'Actual complete component differs from completed stream: ' + name)
                allocated_end = c['blocks'][-1] * 8192 + 8192
                padding = (-c['size']) % 8192
                if padding:
                    output.seek(allocated_end - padding)
                    need(output.read(padding) == bytes(padding), 'Nonzero component tail padding')
                component_checks.append(dict(name=name, bytes=actual_bytes, sha256=actual_component_sha,
                    all_actual_component_bytes_readback=True, unchanged=name != '00004171.MDR', tail_padding_zero=True))
            mdr = layout['components']['00004171.MDR']
            read = lambda at, n: restore.logical_read(output, mdr, 8192, at, n)
            need(read(0, 772) == plan.header and read(plan.new_directory_start, 120) == plan.directory,
                 'Actual MDR header/directory differs')
            # Independently compare every significant lower-prefix byte and every
            # prepared append after extracting it at its actual nonbyte-aligned start.
            prefix_checks = []
            append_checks = []
            for level in (6, 5, 4):
                old, new = plan.old_tables[level-1], plan.new_tables[level-1]
                bits = old['count'] * old['stride']
                original_read = lambda at, n, old=old: adapter.source.exact(old['start'] + at, n)
                rebuilt_read = lambda at, n, new=new: read(new['start'] + at, n)
                original = tight_chunks(original_read, 0, bits)
                rebuilt = tight_chunks(rebuilt_read, 0, bits)
                h = hashlib.sha256()
                amount = 0
                for a, b in zip(original, rebuilt, strict=True):
                    need(a == b, 'Current significant lower prefix changed at level' + str(level))
                    h.update(b)
                    amount += len(b)
                prefix_checks.append(dict(level=level, current_records=old['count'], significant_bits=bits,
                    extracted_bytes=amount, extracted_sha256=h.hexdigest(), all_significant_bits_identical=True,
                    final_source_padding_excluded=(8-bits%8)%8))
                artifact = append_meta[str(level)]
                length, digest = digest_chunks(tight_chunks(rebuilt_read, bits, artifact['bit_length']))
                need(length == artifact['bytes'] and digest == artifact['sha256'],
                     'Actual extracted tight append differs at level' + str(level))
                append_checks.append(dict(level=level, actual_start_bit=bits, start_shift=bits%8,
                    records=artifact['record_count'], extracted_bytes=length, extracted_sha256=digest,
                    matches_sealed_producer_stream=True))
            # All current L3 records / unknown prefix / unchanged L2-L1.
            L3 = plan.new_tables[2]
            actual_L3 = b''.join(read(L3['start'] + at, min(65536, L3['bytes']-at))
                                for at in range(0, L3['bytes'], 65536))
            need(actual_L3 == plan.L3, 'All actual L3 bytes differ from bound range-only patches')
            spans = [(772, 772, plan.old_tables[5]['start']-772, 'unknown prefix'),
                     (plan.old_tables[1]['start'], plan.new_tables[1]['start'],
                      plan.old_directory_start-plan.old_tables[1]['start'], 'L2-L1')]
            for old_at, new_at, count, name in spans:
                for at in range(0, count, 65536):
                    n = min(65536, count-at)
                    need(adapter.source.exact(old_at+at, n) == read(new_at+at, n), name+' modified')
            # Descriptor uses only actual FAT row bytes / actual MDR descriptors.
            actual_tables = [dict(level=i+1, **writer.decode_descriptor(plan.directory[i*20:(i+1)*20])) for i in range(6)]
            descriptor = dict(schema='garmin-native-ap-explicit8k-cow-layout/v1',
                profile='AP8K-9+4-32768blocks-524288sectors', block_bytes=8192,
                candidate_bytes=EXPECTED_BYTES, candidate_sha256=actual_hash,
                metadata_bytes=layout['metadata_bytes'], metadata_prefix_sha256=sha(layout['prefix']),
                source_v2=dict(bytes=SOURCE_BYTES, sha256=SOURCE_SHA),
                components=[dict(name=name, size=layout['components'][name]['size'],
                    blocks=layout['components'][name]['blocks'], parts=layout['FAT_parts'][name])
                    for name in writer.eight().AP_NAMES], tables=actual_tables)
            descriptor_artifact = saved(OUT / 'actual-output-layout.json', descriptor)
    need(stat(SOURCE) == source_before, 'Source modified during actual readback')
    for row in PINS:
        need(stat(ROOT / row['path']) == row['stat_before'], 'Prerequisite source modified during composition')
    proof = dict(schema='actual-lane-COW-current-v2-AP8K-candidate-readback/v1',
        created_utc=datetime.now(timezone.utc).isoformat(), candidate_path=str(target.relative_to(ROOT)),
        candidate_bytes=EXPECTED_BYTES, candidate_sha256=actual_hash,
        source_v2=dict(path=str(SOURCE.relative_to(ROOT)), bytes=SOURCE_BYTES, sha256=SOURCE_SHA,
                       full_hash_inherited=True, stat_before=source_before, stat_after=stat(SOURCE)),
        new_lane_integer_houses=58233, prior_v2_new_integer_houses_retained=130637,
        total_supplemented_integer_houses=188870, selected_L3_root_changes=7650,
        selected_L3_classification=producer_binding['selected_L3_classification'],
        cloned_groups=29866, explicitly_patched_lower_parents=22216,
        producer_proof_path=str((PRODUCER/'proof.json').relative_to(ROOT)),
        producer_proof_sha256=prows['proof.json']['sha256'],
        lower_prefix_significant_bit_checks=prefix_checks, actual_append_extraction_checks=append_checks,
        complete_actual_component_checks=component_checks, all_47870_L3_actual_bytes_verified=True,
        unknown_prefix_and_L2_L1_preserved=True, nonallocation_component_metadata_preserved=True,
        final_lower_counts=producer_binding['final_table_counts'], lower_widths_expanded=False,
        output_descriptor=descriptor_artifact, prerequisite_bindings=PINS,
        all_assigned_checks_passed=True, header_checksum_rule_known=False,
        native_CPU_or_complete_query_tested=False, native_write_ready=False,
        device_installed=False, device_IO=False, full_Taiwan_update_complete=False,
        limitations=['Explicit8K modified AP acceptance and checksum are unproved on the actual device.',
          'All source geometry and ancestor/leaf provenance checks are separately inherited from sealed producer.',
          'No full original Garmin search comparator/query/UI, routing, or native CPU test in this integration.',
          'New street/JAI labels, subnumbers and held/conflicting sources remain incomplete.'],
        elapsed_seconds_receipt_only=time.monotonic()-started)
    saved(OUT / 'proof.json', proof)
    print(json.dumps(dict(all_assigned_checks_passed=True, candidate_bytes=EXPECTED_BYTES,
        candidate_sha256=actual_hash, new_lane_houses=58233, total_supplemented_houses=188870,
        device_installed=False), ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
