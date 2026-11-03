#!/usr/bin/env python3
"""Create/verify a compact rollback recipe for the new larger local AP."""
import gzip
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from native_address_layout_restore_v1 import layout, logical_read, reconstructed_hash

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'staging/navigation-taichung-layout-restore-v1'
ORIGINAL=ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img'
CANDIDATE=ROOT/'staging/navigation-taichung-native-candidate-v1/gmapprom1.img'
ORIGINAL_SHA='864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'


def main():
    assert not OUT.exists()
    proof=json.loads((CANDIDATE.parent/'proof.json').read_text());assert proof['all_assigned_checks_passed']
    plan=json.loads((CANDIDATE.parent/'mdr-plan.json').read_text())
    orig_stat=ORIGINAL.stat();candidate_stat=CANDIDATE.stat()
    with ORIGINAL.open('rb')as original,CANDIDATE.open('rb')as current:
        old=layout(original,orig_stat.st_size);new=layout(current,candidate_stat.st_size)
        tails={};unused={}
        for name,item in old['components'].items():
            rem=item['size']%4096
            if rem:
                original.seek(item['blocks'][-1]*4096+rem);tails[name]=original.read(4096-rem).hex()
        for b in old['unused_blocks']:
            original.seek(b*4096);unused[str(b)]=original.read(4096).hex()
        mdr=old['components']['00004171.MDR']
        old3=plan['original_tables'][2];old2=plan['original_tables'][1]
        new2=plan['new_tables'][1]
        ranges=[dict(original_hex=logical_read(original,mdr,0,772).hex(),length=772),
            dict(candidate_offset=772,length=old3['start']-772),
            dict(original_hex=logical_read(original,mdr,old3['start'],old3['bytes']).hex(),length=old3['bytes']),
            dict(candidate_offset=new2['start'],length=plan['old_directory_start']-old2['start']),
            dict(original_hex=logical_read(original,mdr,plan['old_directory_start'],120).hex(),length=120)]
        recipe=dict(schema='garmin-native-layout-restore/v1',created_utc=datetime.now(timezone.utc).isoformat(),
            original_bytes=orig_stat.st_size,original_sha256=ORIGINAL_SHA,
            candidate_bytes=candidate_stat.st_size,candidate_sha256=proof['candidate_sha256'],
            original_metadata_bytes=len(old['prefix']),original_prefix_hex=old['prefix'].hex(),
            original_components=old['components'],candidate_components=new['components'],MDR_ranges=ranges,
            original_tail_hex=tails,original_unused_blocks_hex=unused)
        restored=reconstructed_hash(current,recipe);assert restored==ORIGINAL_SHA
    assert ORIGINAL.stat()==orig_stat and CANDIDATE.stat()==candidate_stat
    raw=(json.dumps(recipe,ensure_ascii=False,separators=(',',':'))+'\n').encode()
    compressed=gzip.compress(raw,mtime=0)
    OUT.mkdir()
    with (OUT/'restore-layout.json.gz').open('xb')as f:f.write(compressed);f.flush();os.fsync(f.fileno())
    p=OUT/'proof.json';p.write_text(json.dumps(dict(all_assigned_checks_passed=True,
        exact_original_hash_reconstructed=restored,original_image_bytes=orig_stat.st_size,
        candidate_image_bytes=candidate_stat.st_size,recipe_bytes=len(compressed),
        recipe_sha256=hashlib.sha256(compressed).hexdigest(),recipe_uncompressed_bytes=len(raw),
        original_header_FAT_small_L3_and_padding_stored_only=True,
        unchanged_components_and_old_L4_streamed_from_candidate=True,
        original_unused_blocks=len(unused),source_stats_unchanged=True,
        duplicate_full_backup_created=False,full_restored_IMG_written=False,device_IO=False,
        limits=['Exact read-only rollback reconstruction; not an atomic installer or physical rollback test.',
            'Only bound original and Taichung candidate layouts supported; no arbitrary map repair.']),ensure_ascii=False,indent=2)+'\n')
    for p in OUT.iterdir():p.chmod(0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True,recipe_bytes=len(compressed),original_sha256=restored),ensure_ascii=False))


if __name__=='__main__':main()
