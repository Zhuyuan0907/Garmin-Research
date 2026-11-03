#!/usr/bin/env python3
"""Index reusable ASCII-number house labels in the stock CP950 label pool."""
import gzip
import hashlib
import json
import os
import re
import struct
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-native-house-label-index-v1'
AP = ROOT / 'backups/20261002T154458Z/files/.System/gmapprom1.img'
LBL_PROOF = ROOT / 'staging/navigation-AP-LBL-header-v1/AP-LBL-header-evidence.json'
EXPECTED = {'6號':23,'8號':25,'138號':150,'140號':152,'142號':154,
            '144號':783,'146號':784,'148號':157,'150號':787,'184號':808}


def save(path, data):
    if not isinstance(data, bytes): data=(json.dumps(data,ensure_ascii=False,indent=2)+'\n').encode()
    with path.open('xb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
    path.chmod(0o444)


def main():
    assert not OUT.exists()
    stat=AP.stat()
    obs=json.loads(LBL_PROOF.read_text())['public_LBL_header']['field_observations']
    start,length,shift=obs['u32_LE_at21'],obs['u32_LE_at25'],obs['u8_at29']
    assert (start,length,shift,obs['u8_at30'],obs['u16_LE_at170'])==(6566,3805432,3,10,950)
    with AP.open('rb') as f:
        header=f.read(512)
        assert header[0]==0 and header[16:23]==b'DSKIMG\0' and header[65:72]==b'GARMIN\0'
        blocksize=1<<(header[97]+header[98]); assert blocksize==4096
        fatstart=header[64]*512;f.seek(fatstart);first=f.read(512)
        fatend=struct.unpack_from('<I',first,12)[0]
        assert fatend==57344
        f.seek(fatstart);fat=f.read(fatend-fatstart)
        blocks=[];parts=0;size=None
        for pos in range(0,len(fat),512):
            row=fat[pos:pos+512]
            if row[0]!=1 or row[1:12]!=b'I053061AGMP': continue
            assert struct.unpack_from('<H',row,17)[0]==parts; parts+=1
            if parts==1:size=struct.unpack_from('<I',row,12)[0]
            blocks.extend(b for b in struct.unpack_from('<240H',row,32) if b!=65535)
        assert parts==4 and size==3812824 and start+length<size
        payload=bytearray(); cursor=start; end=start+length; reads=[]
        while cursor<end:
            index,within=divmod(cursor,blocksize); amount=min(end-cursor,blocksize-within)
            offset=blocks[index]*blocksize+within
            f.seek(offset); raw=f.read(amount); assert len(raw)==amount
            payload.extend(raw);reads.append([offset,amount]);cursor+=amount
    assert len(payload)==length
    labels={}; refs_examined=0; duplicates=0
    pattern=re.compile(r'[1-9][0-9]*(?:之[1-9][0-9]*)?號')
    for ref,offset in enumerate(range(0,length,1<<shift)):
        refs_examined+=1
        stop=payload.find(0,offset,min(offset+64,length))
        if stop<=offset:continue
        try: label=payload[offset:stop].decode('cp950',errors='strict')
        except UnicodeDecodeError:continue
        if not pattern.fullmatch(label):continue
        assert ref<(1<<19)-1
        if label in labels:duplicates+=1
        else:labels[label]=ref
    # These are original, independently source-bound references already used
    # by the physically accepted Minquan trial, not values inferred from names.
    for label,ref in EXPECTED.items():
        off=ref<<shift; raw=label.encode('cp950')+b'\0'
        assert payload[off:off+len(raw)]==raw and label in labels
    after=AP.stat()
    assert (stat.st_size,stat.st_mtime_ns,stat.st_ctime_ns)==(after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    OUT.mkdir()
    ledger=b''.join((json.dumps(dict(label=k,primary_ref=v),ensure_ascii=False,separators=(',',':'))+'\n').encode()
                    for k,v in sorted(labels.items(),key=lambda kv:kv[1]))
    compressed=gzip.compress(ledger,mtime=0)
    save(OUT/'house-labels.jsonl.gz',compressed)
    save(OUT/'proof.json',dict(schema='garmin-native-house-label-index/v1',created_utc=datetime.now(timezone.utc).isoformat(),
        all_assigned_checks_passed=True,source_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        source_header_proof_sha256=hashlib.sha256(LBL_PROOF.read_bytes()).hexdigest(),
        source_AP='backups/20261002T154458Z/files/.System/gmapprom1.img',source_stat_unchanged=True,
        logical_GMP_pool_start=start,pool_bytes=length,label_shift=shift,codepage=950,
        actual_label_pool_bytes_read=length,FAT_header_bytes_read=512+512+len(fat),bounded_reads=reads,
        aligned_references_examined=refs_examined,distinct_integer_or_subnumber_house_labels=len(labels),
        duplicate_numeric_label_references=duplicates,representative_existing_refs=EXPECTED,
        ledger_bytes=len(compressed),ledger_sha256=hashlib.sha256(compressed).hexdigest(),
        index_scope='Aligned CP950 strings matching positive ASCII integer / 之subnumber＋號; choose lowest existing reference.',
        candidate_data_encoded=False,native_CPU_executed=False,device_IO=False,
        LBL_appended_or_modified=False,full_Taiwan_update_complete=False,
        limits=['No claim of source-house coverage until joined with the complete address preparation.',
                'Other label grammars, full native getter/query and record ordering not validated here.']))
    print(json.dumps(dict(all_assigned_checks_passed=True,distinct_labels=len(labels),references_examined=refs_examined,
        pool_bytes_read=length,ledger_bytes=len(compressed)),ensure_ascii=False))


if __name__=='__main__':main()
