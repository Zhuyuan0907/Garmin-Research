#!/usr/bin/env python3
"""Independently check all new v2 leaves and the exact three-ledger rebase.

Reuses only a sealed independent FAT mapper/descriptor decoder. The old review
main and cases are not executed. Source membership decisions are inherited
from closed country and Kaohsiung reviews and named separately.
"""
from collections import Counter
from datetime import datetime,timezone
from fractions import Fraction
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'staging/navigation-country-native-candidate-v2'
OUT=ROOT/'staging/navigation-country-v2-rebase-review'
OLD_COUNTS={4:2133948,5:2341096,6:1973316}
STRIDES={4:128,5:126,6:68}
DROP_ID=2382209

def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,msg):
    if not ok:raise AssertionError(msg)
def save(path,value):
    raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    path.chmod(0o444)

def model(value,table):
    w=table['widths'];flags=table['flags'];position=0;out={}
    for name,width,present in [('mapordinal',w[4],True),('secondary_ref',w[3],bool(flags[1])),
      ('primary_ref',w[3],bool(flags[0])),('first_child',w[0],bool(w[0])),
      ('child_count',w[5],bool(w[5])),('full_flags',w[1],bool(w[1])),
      ('raw_lat',w[2],bool(w[2])),('raw_lon',w[2],bool(w[2]))]:
        out[name]=(value>>position)&((1<<width)-1) if present else None
        if present:position+=width
    need(position==table['stride'],'Independently projected actual table stride')
    return out

def point24(text):
    value=Fraction(text)*16777216/360;sign=-1 if value<0 else 1;value=abs(value)
    quotient,remainder=divmod(value.numerator,value.denominator)
    quotient+=2*remainder>=value.denominator
    need(-(1<<23)<=sign*quotient<(1<<23),'Signed native24 range')
    return (sign*quotient)&0xffffff

class Hashed:
    def __init__(self,f):self.f=f;self.h=hashlib.sha256();self.n=0
    def read(self,n=-1):
        raw=self.f.read(n);self.h.update(raw);self.n+=len(raw);return raw

def sealed_rows(folder,origin,expected_count,receipts):
    seal=json.loads((folder/'sealed-files.json').read_text())
    row=next(r for r in seal['files'] if r['path']=='new-house-records.jsonl.gz')
    path=folder/row['path'];before=path.stat();count=0;plain=hashlib.sha256();plain_bytes=0
    with path.open('rb') as f:
        reader=Hashed(f)
        with gzip.GzipFile(fileobj=reader) as gz:
            for line in gz:
                plain.update(line);plain_bytes+=len(line);count+=1
                yield origin,json.loads(line)
        need(reader.n==row['bytes'] and reader.h.hexdigest()==row['sha256'],'Prepared source ledger compressed binding')
    need(path.stat()==before and count==expected_count,'Prepared source ledger EOF/count/immutable stat')
    receipts.append(dict(path=str(path.relative_to(ROOT)),origin=origin,rows=count,
      compressed_bytes=reader.n,compressed_sha256=reader.h.hexdigest(),plain_bytes=plain_bytes,
      plain_sha256=plain.hexdigest(),gzip_EOF=True,source_stat_unchanged=True))

def main():
    need(not OUT.exists(),'New review namespace only')
    helper_path=ROOT/'staging/navigation-country-merge-independent-review-v1/review_country_merge.py'
    raw=helper_path.read_bytes()
    need(sha(raw)=='7490c4015dc16f4fa8e69d8bb45cdf3f0c6c2ad93afcf1093c44d0cb3d9852ec','Sealed independent mapper')
    spec=importlib.util.spec_from_file_location('v2_independent_mapper',helper_path)
    helper=importlib.util.module_from_spec(spec);sys.modules[spec.name]=helper;spec.loader.exec_module(helper)
    host_raw=(BASE/'proof.json').read_bytes()
    need(sha(host_raw)=='5c87ea67ad127f981b24a1d6d2f9fb255814695421fa4f915a368157b576ecc3','Final actual v2 builder proof binding')
    host=json.loads(host_raw)
    need(host['all_assigned_checks_passed'] and host['new_integer_house_records']==130637,'Actual v2 proof')
    selected_raw=(BASE/'merged-selected-street-ranges.json').read_bytes()
    need(sha(selected_raw)=='e435dbe0cc6c7157c534cae9d2896e3b93763d034073b93c6ebb36e8905ce3bd','Final v2 selected ranges binding')
    selected=json.loads(selected_raw)
    by_street={r['nativeStreetID']:r for r in selected}
    need(len(by_street)==len(selected)==18823,'Actual v2 parent cardinality')
    seen=set();range_inputs=[]
    for folder,origin in [
      (ROOT/'staging/navigation-country-native-house-merge-v1','country_v1'),
      (ROOT/'staging/navigation-kaohsiung-native-house-merge-v1','kaohsiung_v1'),
      (ROOT/'staging/navigation-flat-city-native-house-merge-v1','flat_city_v1')]:
        seal=json.loads((folder/'sealed-files.json').read_text())
        pin=next(r for r in seal['files'] if r['path']=='selected-street-ranges.json')
        path=folder/pin['path'];before=path.stat();raw=path.read_bytes()
        need(len(raw)==pin['bytes'] and sha(raw)==pin['sha256'] and path.stat()==before,'Sealed original selected ranges')
        rows=json.loads(raw)
        for old in rows:
            ID=old['nativeStreetID'];need(ID not in seen,'Three source selected streets disjoint');seen.add(ID)
            current=by_street[ID]
            for key in ['nativeStreetID','city','district','street','next_level','original_first','original_count',
              'original_flags','record_bits','original_significant_records_sha256','original_source_window_sha256',
              'original_source_initial_bit_shift']:
                need(current.get(key)==old.get(key),'Every source selected range identity remains exact: '+key)
            level=old['next_level'];first=old['new_first']
            delta=-1 if level==4 and (origin!='country_v1' or first>DROP_ID) else 0
            count=old['new_count']-(ID==6676)
            need(current['new_first']==first+delta and current['new_count']==count and
              current['appended_bit_offset']==(first+delta-OLD_COUNTS[level]-1)*STRIDES[level],
              'Independently derived exact selected range rebase/count/combined bit position')
        range_inputs.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),rows=len(rows)))
    need(seen==set(by_street),'No unexpected v2 selected parent')
    image=helper.Image(BASE/'gmapprom1.img')
    table,descriptor=helper.tables(image)
    need(table[3]['stride']==112 and table[3]['widths'][0]==23,'Actual wider parent profile')
    appends={}
    for level in (4,5,6):
        t=table[level];need(t['stride']==STRIDES[level],'Actual child profile unchanged')
        offset=t['start']+OLD_COUNTS[level]*STRIDES[level]//8
        amount=t['bytes']-OLD_COUNTS[level]*STRIDES[level]//8
        appends[level]=image.get('00004171.MDR',offset,amount,'v2 new tightly-packed append level'+str(level))
    gmp=image.get('I053061A.GMP',0,57,'v2 GMP header')
    need(gmp[2:12]==b'GARMIN GMP','Actual GMP')
    lbl_start=struct.unpack_from('<7I',gmp,25)[2]
    lbl=image.get('I053061A.GMP',lbl_start,661,'v2 actual LBL header')
    pool_start,pool_size=struct.unpack_from('<II',lbl,21)
    need((lbl[29],lbl[30],struct.unpack_from('<H',lbl,170)[0])==(3,10,950),'Actual CP950 label profile')
    # This original LBL stores a GMP-relative pool offset, already including
    # the enclosing header position; adding lbl_start again crosses EOF.
    pool=image.get('I053061A.GMP',pool_start,pool_size,'v2 bounded original label pool')
    labels={}
    def label(ref):
        if ref not in labels:
            at=ref<<3;need(0<=at<len(pool),'Original ref pool bound')
            end=pool.find(b'\0',at);need(end>=at,'Label termination')
            labels[ref]=pool[at:end].decode('cp950')
        return labels[ref]
    source_receipts=[];counts=Counter();parents=Counter();drop_count=0;identity=hashlib.sha256()
    target_path=BASE/'kept-new-house-records.jsonl.gz';target_before=target_path.stat()
    with target_path.open('rb') as target_raw, gzip.GzipFile(fileobj=(target_reader:=Hashed(target_raw)),mode='rb') as target:
        for folder,origin,expected_count in [
          (ROOT/'staging/navigation-country-native-house-merge-v1','country_v1',111608),
          (ROOT/'staging/navigation-kaohsiung-native-house-merge-v1','kaohsiung_v1',14530),
          (ROOT/'staging/navigation-flat-city-native-house-merge-v1','flat_city_v1',4500)]:
            for actual_origin,old in sealed_rows(folder,origin,expected_count,source_receipts):
                level=old['next_level'];previous=old['new_lowID']
                if origin=='country_v1' and level==4 and previous==DROP_ID:
                    need((old['nativeStreetID'],old['house_label'],old['raw24'])==(6676,'810號',[1161753,5641748]),
                         'Only the independently named new native-grid edge outlier omitted')
                    drop_count+=1;continue
                line=target.readline();need(bool(line),'V2 kept ledger covers every expected source leaf')
                current=json.loads(line)
                changed={'new_lowID','appended_bit_offset'}
                for key,value in old.items():
                    if key not in changed:need(current.get(key)==value,'Every unchanged prepared source field: '+key)
                delta=-1 if level==4 and (origin in ('kaohsiung_v1','flat_city_v1') or previous>DROP_ID) else 0
                low=previous+delta;bit=(low-OLD_COUNTS[level]-1)*STRIDES[level]
                need(current['source_merge']==actual_origin and current['previous_lowID']==previous and
                     current['remap_delta']==delta and current['new_lowID']==low and current['appended_bit_offset']==bit,
                     'Exact origin, ordinal and combined significant-bit remap')
                need(current['v2_combined_append_bit_offset']==bit,'Actual v2 combined offset equality')
                parent=by_street[current['nativeStreetID']]
                need(parent['next_level']==level and parent['new_first']<=low<parent['new_first']+parent['new_count'],
                     'Every remapped leaf belongs to its actual selected street range')
                width=STRIDES[level];byte,shift=divmod(bit,8)
                value=(int.from_bytes(appends[level][byte:byte+(shift+width+7)//8],'little')>>shift)&((1<<width)-1)
                need(value.to_bytes((width+7)//8,'little').hex()==current['payload'],'Actual v2 packed leaf payload')
                fields=model(value,table[level])
                need(fields['mapordinal']==1 and fields['primary_ref']==current['primary_ref'] and
                     fields['first_child'] in (0,None) and fields['child_count'] in (0,None) and
                     fields['full_flags'] in (0,None),'Actual leaf hierarchy and source ref')
                need(label(fields['primary_ref'])==current['house_label'],'Actual original label resolves exact house')
                raw24=[fields['raw_lat'],fields['raw_lon']]
                need(raw24==current['raw24']==[point24(x) for x in current['coordinate_strings']],
                     'Independent rational source rounding equals actual packed native24')
                counts[(origin,level)]+=1;parents[current['nativeStreetID']]+=1
                identity.update(struct.pack('<IIIIII',level,low,current['nativeStreetID'],current['primary_ref'],*raw24))
        need(not target.readline(),'No extra new v2 leaves outside the three exact prepared sources')
    need(drop_count==1 and sum(counts.values())==130637,'Exact only-one exclusion and complete kept leaf set')
    need(target_reader.n==13174193 and target_reader.h.hexdigest()==
      '4e038d3a25681ad1ed5b27b708eeb6bcfefd7d777d21063e1b64cb4b770ac499','Final v2 kept ledger compressed binding and EOF')
    need(target_path.stat()==target_before,'V2 kept ledger immutable')
    # Check all actual parent pointers independently of the composition writer.
    parent_bytes=image.get('00004171.MDR',table[3]['start'],table[3]['bytes'],'v2 bounded actual parent table')
    for ID,row in by_street.items():
        fields=model(int.from_bytes(parent_bytes[(ID-1)*14:ID*14],'little'),table[3])
        need((fields['first_child'],fields['child_count'],fields['full_flags'])==
             (row['new_first'],row['new_count'],row['original_flags']),'Actual selected native parent pointer/count/flags')
        need(label(fields['primary_ref'])==row['street'],'Actual selected parent street text')
    image_receipt=image.close()
    OUT.mkdir()
    proof=dict(schema='country-v2-exact-source-rebase-review/v1',created_utc=datetime.now(timezone.utc).isoformat(),
      all_assigned_checks_passed=True,candidate_sha256=host['candidate_sha256'],candidate_bytes=host['candidate_bytes'],
      all_new_rows_reviewed=130637,all_selected_parents_reviewed=18823,omitted_exact_outlier_count=1,
      new_rows_by_origin_and_level=[dict(origin=o,level=l,rows=n) for (o,l),n in sorted(counts.items())],
      exact_source_provenance_fields_preserved=True,actual_new_leaf_payload_ref_labels_native24_verified=True,
      all_selected_actual_parent_ranges_flags_and_street_labels_verified=True,
      source_rows_single_pass=True,source_ledger_receipts=source_receipts,selected_range_source_receipts=range_inputs,
      actual_candidate_read_receipt=image_receipt,identity_sha256=identity.hexdigest(),
      reused_mapper=dict(path=str(helper_path.relative_to(ROOT)),sha256=sha(raw),old_main_or_cases_executed=False),
      inherited_source_membership_evidence=['staging/navigation-country-merge-independent-review-v1/proof.json',
        'staging/navigation-kaohsiung-native-house-merge-v1/output-readback-proof.json',
        'staging/navigation-flat-city-native-house-merge-v1/output-readback-proof.json'],
      geometry_recomputed_here=False,source_PBF_group_ready_ledgers_reopened=False,
      whole_candidate_hash_repeated=False,device_IO=False,device_installed=False,
      full_Taiwan_native_address_update_complete=False,
      limits=['Exact three-source leaf rebase and actual parent pointers, not full UI/query/route execution.',
        'City/district membership is inherited from separately sealed source reviews; only quantization was independently recalculated here.',
        'Original preserved-record significant bits and relative ordering have their separate builder/full prior review evidence.'])
    save(OUT/'proof.json',proof)
    save(OUT/'file-seal-v1.json',dict(files=[dict(path=str(p.relative_to(ROOT)),bytes=p.stat().st_size,
      sha256=sha(p.read_bytes())) for p in [Path(__file__),OUT/'proof.json']],all_assigned_checks_passed=True))
    print(json.dumps(dict(all_assigned_checks_passed=True,new_rows=130637,selected_parents=18823,
                         candidate_bytes_read=image_receipt['actual_bytes_read'],device_IO=False)))

if __name__=='__main__':main()
