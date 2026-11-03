#!/usr/bin/env python3
"""Compose and read back the broader Taichung native-address candidate.

This writes only a new local IMG; it has no device installation operation.
"""
import hashlib
import importlib.util
import json
import os
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'staging/navigation-taichung-native-candidate-v1'
MERGE = ROOT/'staging/navigation-taichung-address-merge-v1'
SOURCE = ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img'
SUFFIX = ROOT/'staging/navigation-native-mdr-rewrite-v1'


def save(path, value):
    raw = value if isinstance(value, bytes) else (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode()
    with path.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    path.chmod(0o444)


def digest_chunks(chunks):
    h = hashlib.sha256(); size = 0
    for b in chunks: h.update(b); size += len(b)
    return dict(bytes=size, sha256=h.hexdigest())


def import_suffix():
    # Root waits for the primitive's completed seal before composing an IMG.
    sealed = json.loads((SUFFIX/'file-seal-v1.json').read_text())
    for item in sealed['files']:
        p = ROOT/item['path']
        raw = p.read_bytes()
        assert len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256']
    spec = importlib.util.spec_from_file_location('taichung_sealed_mdr_suffix', SUFFIX/'mdr_suffix_writer.py')
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    return module


def main():
    assert not OUT.exists()
    proof = json.loads((MERGE/'proof.json').read_text())
    assert proof['all_assigned_checks_passed'] and proof['counts']['actual_new_integer_house_records'] == 11002
    blob = MERGE/'appended-level4.bin'
    with blob.open('rb') as f: assert hashlib.file_digest(f,'sha256').hexdigest() == proof['appended_data_sha256']
    ranges = json.loads((MERGE/'selected-street-ranges.json').read_text())
    module = import_suffix(); core = module.core
    before = SOURCE.stat(); blob_stat = blob.stat()
    def appended():
        with blob.open('rb') as f:
            while block := f.read(65536): yield block
    OUT.mkdir()
    target = OUT/'gmapprom1.img'
    with SOURCE.open('rb') as sf:
        source = core.StreamIMG(sf)
        changes = tuple(module.SelectedRange(r['nativeStreetID'], r['new_first'], r['new_count']) for r in ranges)
        plan = module.plan_mdr_rewrite(module.MDRSource.from_container(source),
            new_l4_count=proof['new_child_records'], new_l4_supplier=appended, selected_ranges=changes)
        with target.open('xb') as f:
            receipt = core.repack_stream(source, f, {'00004171.MDR':plan.replacement()})
            f.flush(); os.fsync(f.fileno())
        save(OUT/'mdr-plan.json',plan.report)
        save(OUT/'stream-write-receipt.json',receipt)
        # A fresh handle reopens the actual file and parses its FAT before readback.
        checks = []; by_name = {r['name']:r for r in receipt['components']}
        with target.open('rb') as cf:
            candidate = core.StreamIMG(cf)
            assert candidate.prefix == source.prefix
            assert target.stat().st_size == receipt['image_bytes']
            for name in candidate.order:
                actual = digest_chunks(candidate.iter_component(name))
                assert actual == {k:by_name[name][k] for k in ['bytes','sha256']}
                if name != '00004171.MDR': assert actual == digest_chunks(source.iter_component(name))
                checks.append(dict(name=name,**actual,unchanged_from_stock=name!='00004171.MDR'))
            def read(container, offset, count):
                return b''.join(container.iter_component('00004171.MDR',offset=offset,length=count))
            header = read(candidate,0,772)
            assert header == plan.header
            dstart,dbytes,itembytes,flags = struct.unpack_from('<4I',header,600)
            assert (dstart,dbytes,itembytes,flags)==(plan.new_directory_start,120,20,1)
            directory = read(candidate,dstart,120)
            assert directory == plan.directory
            tables = [struct.unpack_from('<5I',directory,i*20) for i in range(6)]
            assert tables[2][2] == 112 and (tables[2][3]>>18)&63 == 23
            assert tables[3][1]//16 == proof['proposed_level4_count']
            old_l3 = read(source,91983716,664197)
            new_l3 = read(candidate,tables[2][0],tables[2][1])
            selected = {r['nativeStreetID']:r for r in ranges}
            for index in range(47870):
                at=index*111; byte,shift=divmod(at,8)
                old=int.from_bytes(old_l3[byte:byte+15],'little')>>shift & ((1<<111)-1)
                new=int.from_bytes(new_l3[index*14:index*14+14],'little')
                low=old&((1<<42)-1); high=old>>42
                expected=low|(high<<43)
                if row:=selected.get(index+1):
                    mask=(((1<<23)-1)<<20)|(4095<<43)
                    expected=(expected&~mask)|(row['new_first']<<20)|(row['new_count']<<43)
                assert new == expected
            # Every rewritten child group matches the separately prepared append stream.
            with blob.open('rb') as bf:
                for row in ranges:
                    assert bf.tell() == row['appended_record_offset']
                    expected = bf.read(row['new_count']*16)
                    actual = read(candidate,tables[3][0]+(row['new_first']-1)*16,len(expected))
                    assert actual == expected
                    assert hashlib.sha256(actual).hexdigest() == row['new_group_sha256']
                    original = read(source,57840548+(row['original_first']-1)*16,row['original_count']*16)
                    assert hashlib.sha256(original).hexdigest() == row['original_group_verbatim_sha256']
                assert bf.read(1) == b''
            assert read(candidate,tables[1][0],4) == bytes.fromhex(plan.report['actual_L2_lookahead_hex'])
            assert SOURCE.stat() == before and blob.stat() == blob_stat
        source_read_log = source.read_log
    with target.open('rb') as f: file_hash = hashlib.file_digest(f,'sha256').hexdigest()
    target.chmod(0o444)
    save(OUT/'proof.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        candidate_path=str(target.relative_to(ROOT)),candidate_bytes=target.stat().st_size,candidate_sha256=file_hash,
        actual_new_integer_house_records=11002,updated_original_streets=len(ranges),
        original_header_geometry_prefix_unchanged=True,other_five_components_unchanged=True,
        new_L3_fields_all_47870_checked=True,merged_groups_all_1693_readback_checked=True,
        original_L4_groups_kept_verbatim=True,original_JAI_and_licenses_unchanged=True,
        original_source_stat_unchanged=True,component_checks=checks,source_read_log=source_read_log,
        dependencies=['staging/navigation-taichung-address-merge-v1/proof.json',
            'staging/navigation-native-mdr-rewrite-v1/file-seal-v1.json',str(Path(__file__).relative_to(ROOT))],
        native_CPU_executed=False,device_IO=False,device_installed=False,
        full_Taiwan_native_address_update_complete=False,
        limits=['Taichung matched existing next4 streets; only source-covered missing integer houses.',
            'New streets/admins, subnumbers, next5/6 and coordinate conflicts remain pending.',
            'Widened 23-bit profile and larger candidate still need bounded native CPU checks and physical UI acceptance.',
            'Stock exact labels keep stock positions; no claim all old addresses have been refreshed.']))
    print(json.dumps(dict(all_assigned_checks_passed=True,candidate_bytes=target.stat().st_size,
        candidate_sha256=file_hash,new_houses=11002,streets=len(ranges),device_installed=False),ensure_ascii=False))


if __name__=='__main__': main()
