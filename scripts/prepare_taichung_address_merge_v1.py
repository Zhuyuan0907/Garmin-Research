#!/usr/bin/env python3
"""Prepare actual missing integer-house records on matched stock L4 streets.

Original records remain verbatim. Subnumbers and unproved original ordering
are held for later work. This emits append data, not an installable map.
"""
import gzip
import hashlib
import importlib.util
import json
import os
import re
import struct
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from native_address_records import RecordLayout,AddressRecord,encode_record,quantize_point24
from prepare_taichung_city_geometry_v1 import CityGeometry

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'staging/navigation-taichung-address-merge-v1'
AP=ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img'
JOIN=ROOT/'staging/navigation-address-house-join-v1/taichung-next4-existing-label-ready-candidates.jsonl.gz'
GEOMETRY=ROOT/'staging/navigation-taichung-city-geometry-v1/geometry.json'
TRIAL=ROOT/'staging/navigation-native-address-supplement-v1/manifest.json'
PATTERN=re.compile(r'([1-9][0-9]*)號\Z')


def load_writer():
    p=ROOT/'staging/navigation-native-general-writer-v1/native_ap_writer.py'
    spec=importlib.util.spec_from_file_location('native_ap_merge_source',p)
    mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod)
    return mod


def sha(data):return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def save(path,value):
    if not isinstance(value,bytes):value=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    with path.open('xb') as f:f.write(value);f.flush();os.fsync(f.fileno())
    path.chmod(0o444)


def main():
    assert not OUT.exists()
    assert json.loads((ROOT/'staging/navigation-address-house-join-v1/proof.json').read_text())['all_assigned_checks_passed']
    assert json.loads((ROOT/'staging/navigation-taichung-city-geometry-v1/proof.json').read_text())['all_assigned_checks_passed']
    source_stat=AP.stat(); join_stat=JOIN.stat()
    city=CityGeometry(json.loads(GEOMETRY.read_text()))
    groups=defaultdict(list); counts=Counter(); streets=[];held=[]
    # This is the small 9.8MB target subset, not another country/PBF pass.
    with gzip.open(JOIN,'rt') as stream:
        for line in stream:
            row=json.loads(line);counts['source_candidate_groups']+=1
            assert row['old_next_level']==4 and row['native_city'] in ['台中市','臺中市']
            assert row['coordinate_status']=='coordinate_ready_global_bounds' and row['coordinate_strings'] is not None
            if not PATTERN.fullmatch(row['house_label']):counts['subnumber_or_other_house_deferred']+=1;continue
            if not city.covers(*row['coordinate_strings']):counts['source_point_outside_Taichung_city']+=1;continue
            groups[row['nativeStreetID']].append(row)
    writer=load_writer(); layout=RecordLayout((22,9,24,19,1,10,0,0),(1,1),128)
    trial=json.loads(TRIAL.read_text())
    expected={r['label']:r for r in trial['records'] if r['oldID'] is None}
    controls={}
    OUT.mkdir()
    with (
        AP.open('rb') as source,
        (OUT/'appended-level4.bin').open('xb') as data,
        gzip.open(OUT/'new-house-records.jsonl.gz','xb') as record_log,
    ):
        original=writer.StreamIMG(source)
        def bounded(name,offset,length):return b''.join(original.iter_component(name,offset=offset,length=length))
        header=bounded('00004171.MDR',0,772)
        dir_start,dir_bytes,entry_bytes,present=struct.unpack_from('<4I',header,600)
        assert (dir_start,dir_bytes,entry_bytes,present)==(92653480,120,20,1)
        directory=bounded('00004171.MDR',dir_start,120)
        table3=struct.unpack_from('<5I',directory,40);table4=struct.unpack_from('<5I',directory,60)
        assert table3[:3]==(91983716,664197,111) and table4[:3]==(57840548,34143168,128)
        old_total=table4[1]//16;assert old_total==2133948
        pool=bounded('I053061A.GMP',6566,3805432)
        label_cache={}
        def label_at(ref):
            if ref==(1<<19)-1:return None
            if ref not in label_cache:
                offset=ref<<3
                if not 0<=offset<len(pool):raise ValueError('Original label reference outside declared pool')
                end=pool.find(b'\0',offset,min(len(pool),offset+512))
                if end<0:label_cache[ref]=None
                else:
                    try:label_cache[ref]=pool[offset:end].decode('cp950',errors='strict')
                    except UnicodeDecodeError:label_cache[ref]=None
            return label_cache[ref]
        appended=0
        for streetID,rows in sorted(groups.items()):
            witness=rows[0];first,count,flags=[witness[k] for k in ['old_child_first','old_child_count','old_child_level_and_flags']]
            assert count>0 and 1<=first<=old_total and first+count-1<=old_total
            bit=(streetID-1)*111;offset,shift=divmod(bit,8)
            parent=int.from_bytes(bounded('00004171.MDR',table3[0]+offset,16),'little')>>shift
            assert ((parent>>20)&((1<<22)-1),(parent>>42)&4095,(parent>>54)&511)==(first,count,flags)
            assert flags&7==4
            body=bounded('00004171.MDR',table4[0]+(first-1)*16,count*16)
            old=[body[i:i+16] for i in range(0,len(body),16)]
            names=[label_at((int.from_bytes(r,'little')>>20)&((1<<19)-1)) for r in old]
            if any(n is None for n in names):
                counts['streets_deferred_unknown_original_label']+=1;held.append(dict(streetID=streetID,reason='unreadable original primary label'));continue
            anchors=[int(m.group()) for n in names if (m:=re.match(r'^[0-9]+',n))]
            if not anchors or anchors!=sorted(anchors):
                counts['streets_deferred_original_numeric_order']+=1;held.append(dict(streetID=streetID,reason='original numeric-prefix order unproved'));continue
            existing=set(names);new=[];seen=set()
            for row in rows:
                assert [row[k] for k in ['old_child_first','old_child_count','old_child_level_and_flags']]==[first,count,flags]
                label=row['house_label'];assert label not in seen;seen.add(label)
                assert label_at(row['primary_ref'])==label
                if label in existing:counts['source_exact_house_labels_already_in_original']+=1;continue
                if any((int.from_bytes(r,'little')&1)!=1 for r in old):
                    counts['source_new_houses_deferred_non1_original_mapordinal']+=1;continue
                q=quantize_point24(*row['coordinate_strings']);a=q['latitude']['wire_u24'];b=q['longitude']['wire_u24']
                payload=encode_record(layout,AddressRecord(1,row['primary_ref'],None,0,0,0,a,b)).payload
                assert len(payload)==16
                new.append(dict(source=row,label=label,number=int(PATTERN.fullmatch(label).group(1)),payload=payload,
                    raw24=[a,b]))
            if not new:continue
            if count+len(new)>4095:
                counts['streets_deferred_12bit_merged_count']+=1;held.append(dict(streetID=streetID,reason='merged count exceeds12bit'));continue
            new.sort(key=lambda r:r['number'])
            merged=[];new_positions={};index=0
            for raw,name in zip(old,names):
                match=re.match(r'^[0-9]+',name)
                if match:
                    while index<len(new) and new[index]['number']<int(match.group()):
                        new_positions[new[index]['label']]=len(merged);merged.append(new[index]['payload']);index+=1
                merged.append(raw)
            for row in new[index:]:new_positions[row['label']]=len(merged);merged.append(row['payload'])
            new_first=old_total+appended+1
            assert new_first+len(merged)-1<(1<<23)
            assembled=b''.join(merged);assert len(assembled)==len(merged)*16
            inserted_positions=set(new_positions.values())
            old_after=[r for i,r in enumerate(merged) if i not in inserted_positions]
            assert old_after==old
            data.write(assembled)
            for row in new:
                source_row=row['source'];newID=new_first+new_positions[row['label']]
                record=dict(nativeStreetID=streetID,new_lowID=newID,house_label=row['label'],primary_ref=source_row['primary_ref'],
                    source_ids=source_row['source_ids'],coordinate_strings=source_row['coordinate_strings'],raw24=row['raw24'],
                    payload=row['payload'].hex(),old_child_first=first,old_child_count=count)
                record_log.write((json.dumps(record,ensure_ascii=False,separators=(',',':'))+'\n').encode())
                if streetID==16707 and row['label'] in expected:
                    control=expected[row['label']]
                    assert row['payload'].hex()==control['payload'] and int(control['source_id']) in source_row['source_ids']
                    controls[row['label']]=dict(new_lowID=newID,payload_matches_installed_trial=True)
            streets.append(dict(nativeStreetID=streetID,native_street_record=witness['native_street_record'],
                city=witness['native_city'],district=witness['native_district'],street=witness['native_street'],
                original_first=first,original_count=count,original_flags=flags,new_first=new_first,new_count=len(merged),
                appended_record_offset=appended*16,new_integer_house_count=len(new),
                original_group_verbatim_sha256=sha(body),new_group_sha256=sha(assembled)))
            appended+=len(merged);counts['actual_new_integer_house_records']+=len(new);counts['cloned_original_child_records']+=count
        data.flush();os.fsync(data.fileno());actual_reads=original.read_log
    assert set(controls)==set(expected)
    assert AP.stat().st_mtime_ns==source_stat.st_mtime_ns and AP.stat().st_size==source_stat.st_size
    assert JOIN.stat().st_mtime_ns==join_stat.st_mtime_ns and JOIN.stat().st_size==join_stat.st_size
    blob=OUT/'appended-level4.bin';assert blob.stat().st_size==appended*16
    digest=file_sha(blob)
    save(OUT/'selected-street-ranges.json',streets);save(OUT/'held-streets.json',held)
    save(OUT/'proof.json',dict(created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        counts=dict(counts),updated_street_groups=len(streets),new_child_records=appended,
        original_level4_count=old_total,proposed_level4_count=old_total+appended,
        appended_data_bytes=blob.stat().st_size,appended_data_sha256=digest,
        installed_trial_nine_controls=controls,original_records_verbatim_and_relative_order_preserved=True,
        original_coordinates_or_record_bytes_rewritten=False,old_exact_house_source_coordinates_not_updated=True,
        new_subnumber_house_generation_deferred=True,ordering_policy='Host numeric-base interleave; preserve original order, only monotone original prefixes accepted.',
        city_coordinate_policy='Original source point must be covered by complete existing Taichung admin geometry.',
        map_read_log=actual_reads,actual_map_bytes_read=sum(r['bytes']for r in actual_reads),
        dependencies=[dict(path=str(p.relative_to(ROOT)),sha256=file_sha(p))
            for p in [Path(__file__),JOIN,GEOMETRY,TRIAL,ROOT/'staging/navigation-native-general-writer-v1/native_ap_writer.py']],
        device_IO=False,native_CPU_executed=False,full_IMG_written=False,full_Taiwan_native_update_complete=False,
        limits=['Only missing positive integer houses on exact-matched original next4 Taichung streets with reusable labels.',
                'Subnumbers, new streets/admins, next5/6, source coordinate conflicts and unproved ordering remain pending.',
                'Host ordering beyond physically accepted Minquan cases is not a complete native comparator or UI proof.',
                'No destination/route acceptance for this larger candidate; only its nine Minquan payloads match the installed trial.']))
    for p in OUT.iterdir():
        if p.is_file():p.chmod(0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True,updated_streets=len(streets),counts=dict(counts),
        appended_data_bytes=blob.stat().st_size,proposed_level4_count=old_total+appended),ensure_ascii=False))


if __name__=='__main__':main()
