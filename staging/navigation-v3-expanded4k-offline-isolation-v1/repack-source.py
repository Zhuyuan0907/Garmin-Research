"""Offline geometry isolation image; never an installation candidate.

Keep all six v3 logical components byte-identical, use original 4K exponents,
and change only the explicitly expanded count/LBA mirror. Checksum, CHS and
actual Garmin admission/rendering remain unknown. Output uses .img.disabled.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
from datetime import datetime, timezone

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/'staging/navigation-v3-expanded4k-offline-isolation-v1'
SOURCE = ROOT/'staging/navigation-country-native-lane-candidate-v3/gmapprom1.img'
STOCK_HEADER_SOURCE = ROOT/'staging/navigation-country-native-candidate-v2/gmapprom1.img'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stat(path):
    s = path.stat()
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]


def load_module(path, digest, name):
    need(sha(path.read_bytes()) == digest, 'Pinned helper source changed')
    spec = importlib.util.spec_from_file_location(name,path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def save(name, value):
    with (OUT/name).open('x') as f:
        json.dump(value,f,ensure_ascii=False,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())


def main():
    os.umask(0o077)
    need(not OUT.exists(), 'Refuse overwrite offline experiment')
    p = ROOT/'staging/navigation-country-address-package-v3/validation/candidate-readback-v3.json'
    raw = p.read_bytes()
    need(sha(raw) == 'b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0', 'Source proof changed')
    proof = json.loads(raw)
    need(proof['candidate_bytes'] == 153346048 and proof['all_assigned_checks_passed'], 'Wrong source scope')
    expected = {c['name']:c for c in proof['complete_actual_component_checks']}
    profile = load_module(ROOT/'staging/navigation-native-img-4k-expanded-profile-api-v1/expanded_4k_profile.py',
        'd0dd93864aa199ae8401a65adb69c9c9cd942e3e331d1c4df8537258b0c3fb5b','expanded4k_isolation_profile')
    reader = load_module(ROOT/'staging/navigation-country-address-package-v3/native_8k_stock_restore.py',
        '43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f','isolation_strict_8k_reader')
    source_before, header_before = stat(SOURCE),stat(STOCK_HEADER_SOURCE)
    need(source_before[2] == 153346048 and header_before[2] == 128356352, 'Wrong source file sizes')
    with STOCK_HEADER_SOURCE.open('rb') as f:
        original_prefix = f.read(4096)
    binding = profile.bind_original_4k_header(original_prefix[:512],source_kind='sealed-stock-header')
    plan = profile.plan_expanded_4k(binding,[(n,expected[n]['bytes']) for n in profile.NAMES],declared_blocks=37436)
    need(plan.image_bytes == 153337856 and plan.metadata_bytes == 90112, 'Unexpected new capacity plan')
    metadata = bytearray(plan.metadata_bytes)
    metadata[:4096] = original_prefix
    metadata[:512] = profile.header_bytes_for_offline_control(plan)
    receipts = []
    OUT.mkdir()
    save('plan.json',plan.report())
    destination = OUT/'v3-content-expanded4k-experiment.img.disabled'
    with SOURCE.open('rb') as source:
        layout = reader.parse_layout(source,source_before[2],8192)
        need(sha(layout['prefix']) == '5b7c539ec872259fb654459f4630d60397496a0ff6948a6b5b38a8d95b0ea59d', 'Exact v3 metadata binding failed')
        root = bytearray(layout['prefix'][4096:4608])
        struct.pack_into('<I',root,12,plan.metadata_bytes)
        struct.pack_into('<240H',root,32,*list(range(plan.metadata_blocks)),*([65535]*(240-plan.metadata_blocks)))
        metadata[4096:4608] = root
        cursor = 4608
        for c in plan.components:
            old = layout['components'][c.name]
            need(old['size'] == c.logical_bytes, 'Logical source size mismatch')
            source_rows = [layout['prefix'][at:at+512] for at in range(4608,len(layout['prefix']),512)
                           if layout['prefix'][at] == 1 and layout['prefix'][at+1:at+12] == c.name.replace('.','').encode()]
            need(len(source_rows) == old['parts'], 'Source row identity mismatch')
            template = source_rows[0]
            need(all(row[:12] == template[:12] and row[16] == template[16] and row[19:32] == template[19:32]
                     for row in source_rows), 'Observed continuation opaque metadata differs')
            for part in range(c.fat_parts):
                metadata[cursor:cursor+512] = profile.fat_row_for_offline_control(plan,c.name,part,template)
                cursor += 512
        need(cursor == 4096+plan.directory_rows*512 and not any(metadata[cursor:]), 'Unexpected metadata tail')
        with destination.open('xb') as target:
            target.write(metadata)
            for c in plan.components:
                need(target.tell() == c.first_block*4096, 'Wrong component physical start')
                h = hashlib.sha256()
                for at in range(0,c.logical_bytes,65536):
                    raw = reader.logical_read(source,layout['components'][c.name],8192,at,min(65536,c.logical_bytes-at))
                    need(target.write(raw) == len(raw), 'Short component write')
                    h.update(raw)
                need(h.hexdigest() == expected[c.name]['sha256'], 'Source logical component hash changed')
                padding = c.block_count*4096-c.logical_bytes
                target.write(bytes(padding))
                receipts.append(dict(name=c.name,logical_bytes=c.logical_bytes,source_sha256=h.hexdigest(),tail_padding_bytes=padding))
            need(target.tell() == plan.image_bytes, 'Unexpected output image length')
            target.flush(); os.fsync(target.fileno())
    need(stat(SOURCE) == source_before and stat(STOCK_HEADER_SOURCE) == header_before, 'Source stat changed')
    # Independent full output readback: decode every FAT row rather than trust planned block lists.
    output_checks, used = [],set(range(plan.metadata_blocks))
    with destination.open('rb') as f:
        fresh_metadata = f.read(plan.metadata_bytes)
        need(fresh_metadata == metadata, 'Fresh metadata readback mismatch')
        need(fresh_metadata[15] == 219 and fresh_metadata[97:99] == b'\x09\x03', 'Opaque/exponent policy changed')
        index = 4608
        for c in plan.components:
            blocks = []
            for part in range(c.fat_parts):
                row = fresh_metadata[index:index+512];index += 512
                need(row[1:12] == c.name.replace('.','').encode() and struct.unpack_from('<H',row,17)[0] == part, 'FAT identity/ordinal mismatch')
                need(struct.unpack_from('<I',row,12)[0] == (c.logical_bytes if part == 0 else 0), 'FAT size mismatch')
                sentinel = False
                for block in struct.unpack_from('<240H',row,32):
                    if block == 65535:
                        sentinel = True;continue
                    need(not sentinel and plan.metadata_blocks <= block < plan.image_blocks and block not in used,
                         'FAT gap, alias or out-of-range block')
                    used.add(block);blocks.append(block)
            need(len(blocks) == (c.logical_bytes+4095)//4096, 'FAT logical block count mismatch')
            h = hashlib.sha256(); remaining = c.logical_bytes
            for block in blocks:
                f.seek(block*4096);raw = f.read(4096)
                need(len(raw) == 4096, 'Truncated output block')
                n = min(remaining,4096);h.update(raw[:n]);remaining -= n
                need(not any(raw[n:]), 'Nonzero component final padding')
            need(remaining == 0 and h.hexdigest() == expected[c.name]['sha256'], 'Fresh logical output differs from v3 content')
            output_checks.append(dict(name=c.name,logical_bytes=c.logical_bytes,sha256=h.hexdigest(),all_actual_output_bytes_read=True))
        need(len(used) == plan.image_blocks, 'Unowned allocated image block')
        f.seek(0); output_sha = hashlib.file_digest(f,'sha256').hexdigest()
    changed = [at for at,(a,b) in enumerate(zip(original_prefix,metadata[:4096])) if a != b]
    need(set(changed) <= {0x63,0x64,0x1ca,0x1cb,0x1cc,0x1cd}, 'Unexpected original header prefix change')
    need(stat(SOURCE) == source_before and stat(STOCK_HEADER_SOURCE) == header_before, 'Source changed during fresh verification')
    save('proof.json',dict(schema='actual-v3-logical-content-expanded4K-offline-isolation/v1',created_utc=datetime.now(timezone.utc).isoformat(),
        all_assigned_checks_passed=True,source_v3_sha256_inherited=proof['candidate_sha256'],source_v3_stat=source_before,
        original_header_source_stat=header_before,output=str(destination.relative_to(ROOT)),output_bytes=plan.image_bytes,
        output_sha256=output_sha,changed_header_byte_offsets=changed,source_copy_receipts=receipts,
        complete_actual_logical_component_readback=output_checks,all_six_logical_components_byte_identical_to_v3=True,
        original_header_prefix_opaque_bytes_preserved=True,checksum_algorithm_or_validity_verified=False,
        CHS_or_expanded_geometry_admission_verified=False,original_AP_renderer_or_complete_query_executed=False,
        live_device_IO=False,installable=False,device_candidate=False,current_display_bug_fixed=False,
        limits=['Offline complete container experiment, never an install candidate; suffix excludes normal IMG loading.',
                'All 188870 supplement records are inherited byte-identically; new data provenance is not rerun.',
                'Original 0x0F byte is preserved, but validity at new geometry is unknown.',
                'CHS and unknown header fields remain original; high continuation native policy/renderer are unverified.',
                'No installer or public download is modified; actual device remains verified v2.']))
    for path in OUT.iterdir():
        path.chmod(0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True,output_bytes=plan.image_bytes,output_sha256=output_sha,
                         installable=False,device_IO=False,checkpoint=str(OUT.relative_to(ROOT)))))


if __name__ == '__main__':
    main()
