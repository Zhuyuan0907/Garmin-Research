#!/usr/bin/env python3
"""Compose a local existing-street country house supplement, then read it back.

This script has no device, network, or publishing operations. Country coverage
and physical acceptance remain separate from these structural checks.
"""
import gzip
import hashlib
import importlib.util
import json
import os
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'staging/navigation-country-native-candidate-v1'
MERGE = ROOT/'staging/navigation-country-native-house-merge-v1'
WRITER = ROOT/'staging/navigation-native-multilevel-mdr-writer-v1'
SOURCE = ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img'
WRITER_SHA = '3508e01e8ba6e3fd3388322c8da575f2dff96a4f1dd836b15eeaa25bd88e3958'


def save(path, value):
    raw = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode()
    with path.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    path.chmod(0o444)


def sha_file(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def digest(chunks):
    h = hashlib.sha256(); size = 0
    for data in chunks:
        h.update(data); size += len(data)
    return dict(bytes=size, sha256=h.hexdigest())


def import_writer():
    seal = json.loads((WRITER/'file-seal-v1.json').read_text())
    for row in seal['files']:
        path = ROOT/row['path']
        assert path.stat().st_size == row['bytes'] and sha_file(path) == row['sha256']
    path = WRITER/'multilevel_mdr_writer.py'
    assert sha_file(path) == WRITER_SHA
    spec = importlib.util.spec_from_file_location('country_sealed_multilevel_mdr_v1', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module; spec.loader.exec_module(module)
    return module


def significant_hash(raw, shift, count, stride):
    """Hash significant records, individually padded only for this digest."""
    h = hashlib.sha256(); mask = (1 << stride)-1; row_bytes = (stride+7)//8
    for index in range(count):
        byte, bit = divmod(shift+index*stride, 8)
        value = int.from_bytes(raw[byte:byte+(bit+stride+7)//8], 'little') >> bit & mask
        h.update(value.to_bytes(row_bytes, 'little'))
    return h.hexdigest()


def main():
    assert not OUT.exists(), 'Use a distinct output namespace; never overwrite a prior candidate.'
    seal = json.loads((MERGE/'sealed-files.json').read_text())
    # Bind only the files consumed here; other ledgers have their own review.
    assert seal['all_assigned_checks_passed']
    sealed = {row['path']: row for row in seal['files']}
    proof_path = MERGE/'proof.json'
    proof = json.loads(proof_path.read_text())
    assert proof['all_assigned_checks_passed']
    assert proof['counts']['new_integer_house_records'] == 111608
    required = [proof_path, MERGE/'selected-street-ranges.json']
    required += [MERGE/proof['artifacts']['level'+str(n)]['path'] for n in (4, 5, 6)]
    for path in required:
        row = sealed[str(path.relative_to(MERGE))]
        assert path.stat().st_size == row['bytes'] and sha_file(path) == row['sha256']
    ranges = json.loads((MERGE/'selected-street-ranges.json').read_text())
    assert len(ranges) == proof['counts']['updated_streets'] == 15679
    module = import_writer()
    source_stat = SOURCE.stat()
    input_stats = {str(p):p.stat() for p in required}
    paths = {n:MERGE/proof['artifacts']['level'+str(n)]['path'] for n in (4, 5, 6)}
    def supplier(path):
        def chunks():
            with path.open('rb') as f:
                while data := f.read(65536): yield data
        return chunks
    appends = {n:module.PackedAppend(n, proof['artifacts']['level'+str(n)]['record_count'],
        proof['artifacts']['level'+str(n)]['bit_length'], supplier(paths[n])) for n in (4, 5, 6)}
    changes = tuple(module.SelectedRange(r['nativeStreetID'], r['new_first'], r['new_count'],
        r['next_level'], r['original_flags']) for r in ranges)
    OUT.mkdir()
    target = OUT/'gmapprom1.img'
    with SOURCE.open('rb') as sf:
        source = module.core.StreamIMG(sf)
        adapter = module.ContainerAdapter.original_4k(source)
        plan = module.plan_multilevel_mdr(adapter.mdr_source, appends=appends, selected_ranges=changes)
        prepared = plan.bind_container(adapter)
        # Reject here instead of changing container geometry or checksum rules.
        assert adapter.kind == 'original4K' and source.capacity == 134217728
        save(OUT/'mdr-plan.json', plan.report)
        save(OUT/'explicit-container-capacity-plan.json', prepared.capacity_plan)
        with target.open('xb') as f:
            receipt = prepared.repack_stream(f)
            f.flush(); os.fsync(f.fileno())
        save(OUT/'stream-write-receipt.json', receipt)
        component_checks = []; table_checks = []; groups_checked = {4:0, 5:0, 6:0}
        by_name = {r['name']:r for r in receipt['components']}
        def read(image, start, count):
            return b''.join(image.iter_component('00004171.MDR', offset=start, length=count))
        with target.open('rb') as cf:
            candidate = module.core.StreamIMG(cf)
            assert candidate.prefix == source.prefix
            assert target.stat().st_size == receipt['image_bytes']
            assert candidate.capacity == source.capacity
            for name in candidate.order:
                actual = digest(candidate.iter_component(name))
                assert actual == {k:by_name[name][k] for k in ('bytes', 'sha256')}
                if name != '00004171.MDR': assert actual == digest(source.iter_component(name))
                component_checks.append(dict(name=name, **actual, unchanged_from_stock=name!='00004171.MDR'))
            header = read(candidate, 0, 772)
            assert header == plan.header
            descriptor = struct.unpack_from('<4I', header, 600)
            assert descriptor == (plan.new_directory_start, 120, 20, 1)
            assert read(candidate, descriptor[0], 120) == plan.directory
            old_tables = {i+1:t for i,t in enumerate(plan.old_tables)}
            new_tables = {i+1:t for i,t in enumerate(plan.new_tables)}
            assert new_tables[3]['stride'] == 112 and new_tables[3]['widths'][0] == 23
            for n in (4, 5, 6):
                old, new = old_tables[n], new_tables[n]
                assert new['count'] == proof['proposed_counts'][str(n)]
                old_digest = digest(source.iter_component('00004171.MDR', offset=old['start'], length=old['bytes']))
                actual_prefix = digest(candidate.iter_component('00004171.MDR', offset=new['start'], length=old['bytes']))
                assert actual_prefix == old_digest
                actual_append = digest(candidate.iter_component('00004171.MDR', offset=new['start']+old['bytes'],
                    length=proof['artifacts']['level'+str(n)]['bytes']))
                declared = proof['artifacts']['level'+str(n)]
                assert actual_append == {k:declared[k] for k in ('bytes', 'sha256')}
                table_checks.append(dict(level=n, original_byte_prefix=old_digest, actual_append=actual_append,
                    original_count=old['count'], new_count=new['count'], unchanged_original_significant_bits=True))
            # The original unknown prefix, except the declared header field, and
            # the L2/L1 suffix remain exact. No extra reader lookahead is inserted.
            prefix_start, prefix_bytes = 772, old_tables[6]['start']-772
            assert digest(source.iter_component('00004171.MDR', offset=prefix_start, length=prefix_bytes)) == \
                digest(candidate.iter_component('00004171.MDR', offset=prefix_start, length=prefix_bytes))
            suffix_bytes = plan.old_directory_start-old_tables[2]['start']
            assert read(source, old_tables[2]['start'], suffix_bytes) == read(candidate, new_tables[2]['start'], suffix_bytes)
            assert read(candidate, new_tables[2]['start'], 4) == plan.L2_lookahead
            original_L3 = read(source, old_tables[3]['start'], old_tables[3]['bytes'])
            actual_L3 = read(candidate, new_tables[3]['start'], new_tables[3]['bytes'])
            selected = {r['nativeStreetID']:r for r in ranges}
            assert len(selected) == len(ranges)
            for index in range(47870):
                at, initial = divmod(index*111, 8)
                old = int.from_bytes(original_L3[at:at+(initial+111+7)//8], 'little') >> initial & ((1<<111)-1)
                expected = (old & ((1<<42)-1)) | ((old >> 42) << 43)
                if row := selected.get(index+1):
                    mask = ((1<<35)-1) << 20
                    expected = (expected & ~mask) | (row['new_first'] << 20) | (row['new_count'] << 43)
                assert int.from_bytes(actual_L3[index*14:index*14+14], 'little') == expected
            # Each merged group is checked from the new physical file, with its
            # true packed bit offset (68/126-bit records need no per-group pad).
            for row in ranges:
                n = row['next_level']; stride = row['record_bits']; count = row['new_count']
                bit = (row['new_first']-1)*stride; byte, shift = divmod(bit, 8)
                raw = read(candidate, new_tables[n]['start']+byte, (shift+count*stride+7)//8)
                assert significant_hash(raw, shift, count, stride) == row['new_significant_records_sha256']
                oldbit = (row['original_first']-1)*stride; oldbyte, oldshift = divmod(oldbit, 8)
                original = read(source, old_tables[n]['start']+oldbyte, (oldshift+row['original_count']*stride+7)//8)
                assert significant_hash(original, oldshift, row['original_count'], stride) == row['original_significant_records_sha256']
                groups_checked[n] += 1
            assert sum(groups_checked.values()) == len(ranges)
            assert SOURCE.stat() == source_stat
            for path, before in input_stats.items(): assert Path(path).stat() == before
        source_read_log = source.read_log
    file_hash = sha_file(target); target.chmod(0o444)
    log_path = OUT/'source-read-log.jsonl.gz'
    with log_path.open('xb') as f:
        with gzip.GzipFile(filename='', mode='wb', fileobj=f, mtime=0) as gz:
            for row in source_read_log:
                gz.write((json.dumps(row, separators=(',',':'))+'\n').encode())
        f.flush(); os.fsync(f.fileno())
    log_path.chmod(0o444)
    save(OUT/'proof.json', dict(schema='country-existing-street-native-candidate/v1',
        created_utc=datetime.now(timezone.utc).isoformat(), all_assigned_checks_passed=True,
        candidate_path=str(target.relative_to(ROOT)), candidate_bytes=target.stat().st_size, candidate_sha256=file_hash,
        new_integer_house_records=111608, updated_original_streets=len(ranges), proposed_table_counts=proof['proposed_counts'],
        original_4K_container_geometry_capacity_and_header_prefix_unchanged=True,
        explicit_8K_adapter_or_checksum_rules_used=False, other_five_components_unchanged=True,
        original_JAI_and_licenses_unchanged=True, original_L6_L5_L4_full_byte_prefixes_preserved=True,
        original_unknown_MDR_prefix_and_L2_L1_bytes_preserved=True, new_L3_fields_all_47870_checked=True,
        merged_groups_all_15679_readback_checked=True, groups_checked_by_level=groups_checked,
        original_group_significant_bits_readback_checked=True, component_checks=component_checks, table_checks=table_checks,
        source_read_log=dict(path=str(log_path.relative_to(ROOT)), bytes=log_path.stat().st_size,
            sha256=sha_file(log_path), operations=len(source_read_log)),
        dependencies=[str((MERGE/'sealed-files.json').relative_to(ROOT)),
            str((WRITER/'file-seal-v1.json').relative_to(ROOT)), str(Path(__file__).relative_to(ROOT))],
        native_CPU_executed=False, device_IO=False, device_installed=False, full_Taiwan_native_address_update_complete=False,
        limits=['Existing district-verified streets and source-covered missing positive integer house leaves only.',
            'New streets/admins, lane-path matching, subnumbers, coordinate conflicts and incomplete Kaohsiung geometry remain pending.',
            'Stock exact house labels retain stock positions; new source OSM points are not verified entrances or navigation results.',
            'Host numeric ordering and structural readback do not verify the complete original prefix-search comparator or UI.',
            'Actual native CPU, portable rollback/install package and physical search/routing acceptance remain separate.']))
    print(json.dumps(dict(all_assigned_checks_passed=True, candidate_bytes=target.stat().st_size,
        candidate_sha256=file_hash, new_houses=111608, streets=len(ranges), device_installed=False)))


if __name__ == '__main__': main()
