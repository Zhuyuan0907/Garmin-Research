#!/usr/bin/env python3
"""Seal finite new-v2 CPU inputs after the builder seal; no native CPU here."""
from collections import Counter
from datetime import datetime,timezone
import argparse
import gzip
import hashlib
import json
from pathlib import Path

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
BUILDER=ROOT/'staging/navigation-country-native-candidate-v2'
EXPECTED_FINAL={4:3781594,5:2667573,6:1984066}
ORIGINAL={4:2133948,5:2341096,6:1973316}
STRIDES={4:128,5:126,6:68}


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def stat(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


class Hashed:
    def __init__(self,file):self.file=file;self.bytes=0;self.digest=hashlib.sha256()
    def read(self,n=-1):
        raw=self.file.read(n);self.bytes+=len(raw);self.digest.update(raw);return raw


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--builder-seal-sha256',required=True)
    args=parser.parse_args()
    need(not(HERE/'finite-selection.json').exists(),'Refuse overwrite finite selection')
    seal_path=BUILDER/'sealed-files.json';before=stat(seal_path);raw=seal_path.read_bytes()
    need(sha(raw)==args.builder_seal_sha256 and stat(seal_path)==before,'Builder finalized explicit seal binding')
    seal=json.loads(raw)
    files={Path(item['path']).name:item for item in seal['files']}
    need(len(files)==len(seal['files']),'Builder seal path identity unique')
    receipts=[{'path':str(seal_path.relative_to(ROOT)),'bytes':len(raw),'sha256':sha(raw),'stat_before':before,'stat_after':stat(seal_path)}]
    def read(name,maxbytes):
        binding=files[name];path=ROOT/binding['path'];before=stat(path)
        need(path==BUILDER/name,'Prepared file has the declared builder namespace')
        need(before[2]==binding['bytes']<=maxbytes,'Bounded sealed prepared input '+name)
        raw=path.read_bytes();need(sha(raw)==binding['sha256'] and stat(path)==before,'Prepared final file binding '+name)
        receipts.append({'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':sha(raw),'stat_before':before,'stat_after':stat(path)})
        return json.loads(raw)
    host=read('proof.json',250000)
    need(host['all_assigned_checks_passed'],'Root complete builder checks')
    plan=read('mdr-plan.json',5000000)
    need(len(plan['new_tables'])==6,'Six actual v2 table plans')
    for level,row in enumerate(plan['new_tables'],1):
        if level in EXPECTED_FINAL:need(row['count']==EXPECTED_FINAL[level],'Sealed actual final table count')
    candidate=BUILDER/'gmapprom1.img';image_binding=files['gmapprom1.img']
    need(candidate.stat().st_size==image_binding['bytes']==host['candidate_bytes'],'Actual candidate size equals sealed root proof')
    need(image_binding['sha256']==host['candidate_sha256'],'Inherited complete candidate SHA binding')
    ranges=read('merged-selected-street-ranges.json',25000000)
    selected={r['nativeStreetID']:r for r in ranges}
    need(len(ranges)==len(selected)==18823,'Actual selected v2 streets count')
    need(set(r['source_merge'] for r in ranges)=={'country_v1','kaohsiung_v1','flat_city_v1'},'Exactly three sealed merge sources')
    affected=selected[6676]
    need(affected['new_count']==11 and affected['original_count']==9 and
         affected['new_integer_house_count']==2 and affected['excluded_new_leaf_count']==1,
         'Outlier street6676 final parent retains nine original and two new records after one810 removal')
    affected_new_IDs=set()
    KH_heads={level:min((r for r in ranges if r['source_merge']=='kaohsiung_v1' and r['next_level']==level),
                       key=lambda r:r['new_first']) for level in (5,6)}
    KH_head_new_IDs={5:set(),6:set()};KH_splice_new={}
    binding=files['kept-new-house-records.jsonl.gz'];path=ROOT/binding['path'];before=stat(path)
    need(path==BUILDER/'kept-new-house-records.jsonl.gz','Declared kept output namespace')
    need(before[2]==binding['bytes']<30000000,'Bounded prepared kept-new ledger')
    picks={};last={};rows=0;per_source=Counter();plain=hashlib.sha256()
    with path.open('rb') as file:
        reader=Hashed(file)
        with gzip.GzipFile(fileobj=reader) as stream:
            for line in stream:
                plain.update(line);r=json.loads(line);rows+=1
                source=r['source_merge'];level=r['next_level'];need(source in {'country_v1','kaohsiung_v1','flat_city_v1'} and level in STRIDES,'Prepared source/level identity')
                per_source[source]+=1
                need(r['nativeStreetID']!=6676 or r['house_label']!='810號','Dropped810 never treated as new CPU leaf')
                if r['nativeStreetID']==6676:affected_new_IDs.add(r['new_lowID'])
                need(r['v2_combined_append_bit_offset']==(r['new_lowID']-ORIGINAL[level]-1)*STRIDES[level], 'Every prepared v2 global bit offset')
                need(r['new_lowID']==r['previous_lowID']+r['remap_delta'],'Every explicit previous→actual lowID rebase')
                shift=((r['new_lowID']-1)*STRIDES[level])%8
                if source=='country_v1' and level==4 and r['nativeStreetID']==16707 and r['house_label'] in ('6號','150號'):
                    picks['country_Minquan_'+r['house_label']]=r
                if source in ('country_v1','kaohsiung_v1') and level==5:
                    picks.setdefault(source+'_L5_shift'+str(shift),r);last[(source,5)]=r
                if source in ('country_v1','kaohsiung_v1') and level==6:
                    picks.setdefault(source+'_L6_shift'+str(shift),r);last[(source,6)]=r
                if source=='kaohsiung_v1' and level==4:picks.setdefault('kaohsiung_first_new_L4',r)
                if source=='kaohsiung_v1' and level in KH_heads and r['nativeStreetID']==KH_heads[level]['nativeStreetID']:
                    KH_head_new_IDs[level].add(r['new_lowID'])
                    if r['new_lowID']==KH_heads[level]['new_first']:KH_splice_new[level]=r
                if source=='flat_city_v1':
                    need(r['city'] in ('基隆市','台北市','新竹市','嘉義市') and r['district'] is None and r['native_district_verified'] is False,
                         'Actual flat-city new row retains original null native district')
                    picks.setdefault('flat_city_'+r['city'],r)
        need(reader.bytes==binding['bytes'] and reader.digest.hexdigest()==binding['sha256']
             and plain.hexdigest()==host['kept_new_records']['uncompressed_sha256'],
             'Prepared kept ledger complete compressed/plain hash/EOF')
    need(rows==130637 and dict(per_source)=={'country_v1':111607,'kaohsiung_v1':14530,'flat_city_v1':4500},'Complete kept source counts')
    need(stat(path)==before,'Prepared kept ledger immutable')
    expected={'country_Minquan_6號','country_Minquan_150號','kaohsiung_first_new_L4',
        *['flat_city_'+c for c in ('基隆市','台北市','新竹市','嘉義市')],
        *[source+'_L5_shift'+str(shift) for source in ('country_v1','kaohsiung_v1') for shift in (0,2,4,6)],
        *[source+'_L6_shift'+str(shift) for source in ('country_v1','kaohsiung_v1') for shift in (0,4)]}
    need(set(picks)==expected,'All deterministic true-offset/source/city cases available')
    for (source,level),r in last.items():picks[source+'_L'+str(level)+'_final_new']=r
    for level,r in KH_splice_new.items():picks['first_KH_L'+str(level)+'_new_record_at_significant_bit_splice']=r
    golden_path=ROOT/'staging/navigation-native-address-supplement-v1/manifest.json';gold_before=stat(golden_path);goldraw=golden_path.read_bytes()
    need(sha(goldraw)=='042c8a94b9b50b2ea58881016e5196455269934bf4da5f6bd7ade0692e7d80c5' and stat(golden_path)==gold_before,
         'Installed Minquan source golden manifest binding only, no historical CPU cases')
    gold={r['label']:r for r in json.loads(goldraw)['records'] if r['oldID'] is None}
    receipts.append({'path':str(golden_path.relative_to(ROOT)),'bytes':len(goldraw),'sha256':sha(goldraw),'stat_before':gold_before,'stat_after':stat(golden_path)})
    unique={}
    for name,r in picks.items():
        key=(r['next_level'],r['new_lowID'])
        unique.setdefault(key,{'sample':r,'selection_names':[]})['selection_names'].append(name)
        p=selected[r['nativeStreetID']]
        need(p['next_level']==r['next_level'] and p['original_flags']==p['next_level'] and
             p['new_first']<=r['new_lowID']<p['new_first']+p['new_count'],'Every selected new leaf inside actual final parent')
        if name.startswith('country_Minquan_'):
            g=gold[r['house_label']];need((r['payload'],r['primary_ref'],r['raw24'])==(g['payload'],g['primary_ref'],g['raw24']),'Actual v2 Minquan goldens same installed source payload')
    samples=list(unique.values());need(len(samples)<=30,'Actual finite new leaves cap')
    parents={r['sample']['nativeStreetID']:selected[r['sample']['nativeStreetID']] for r in samples}
    parents[6676]=affected
    old_prefix=[]
    need(len(affected_new_IDs)==2,'Two retained actual new leaves in affected6676 final parent')
    affected_clone_IDs=[ID for ID in range(affected['new_first'],affected['new_first']+affected['new_count'])
                        if ID not in affected_new_IDs]
    need(len(affected_clone_IDs)==9,'Nine original clones remain distinct from actual new affected6676 leaves')
    for label,ID in [('affected6676_first_retained_clone',affected_clone_IDs[0]),
                     ('affected6676_last_retained_clone',affected_clone_IDs[-1])]:
        old_prefix.append({'selection_name':label,'level':4,'lowID':ID,'street_ID':6676,
                           'new_leaf':False,'reason':'Retained original clone identity selected by excluding all actual kept-new lowIDs; rejected810 is absent.'})
    for level in (5,6):
        first=KH_heads[level];parents[first['nativeStreetID']]=first
        cloneID=next(ID for ID in range(first['new_first'],first['new_first']+first['new_count']) if ID not in KH_head_new_IDs[level])
        old_prefix.append({'selection_name':'first_KH_L'+str(level)+'_retained_clone_at_or_after_splice',
            'level':level,'lowID':cloneID,'street_ID':first['nativeStreetID'],'new_leaf':False,
            'record_is_exact_splice_first_record':cloneID==first['new_first'],
            'reason':'First retained original clone of the first KH source group; first splice record is separately a new-leaf sample if actually new.'})
    need(len(parents)<=30,'Actual finite parent cap')
    receipts.append({'path':str(path.relative_to(ROOT)),'bytes':reader.bytes,'sha256':reader.digest.hexdigest(),
        'uncompressed_sha256':plain.hexdigest(),'gzip_EOF_validated':True,'rows':rows,'counts_by_source_merge':dict(per_source),
        'stat_before':before,'stat_after':stat(path),'prepared_kept_output_content_passes':1})
    payload={'schema':'actual-country-v2-native-finite-CPU-selection/v1','created_utc':datetime.now(timezone.utc).isoformat(),
        'prepared_final_builder_seal_sha256':args.builder_seal_sha256,'prepared_producer_input_receipts':receipts,
        'host_candidate_proof':host,'mdr_plan':plan,
        'candidate':{'path':str(candidate.relative_to(ROOT)),'bytes':image_binding['bytes'],
                     'inherited_root_readback_sha256':image_binding['sha256'],'stat_at_selection':stat(candidate)},
        'complete_kept_new_records_count':rows,'complete_selected_street_ranges_count':len(ranges),'kept_counts_by_source_merge':dict(per_source),
        'actual_final_table_counts':EXPECTED_FINAL,'original_counts':ORIGINAL,
        'new_leaf_samples':samples,'parent_samples':list(parents.values()),'separate_old_prefix_samples':old_prefix,
        'expected_role_names':sorted(picks),
        'candidate_image_bytes_read_or_hashed_during_selection':0,'CPU_executed_during_selection':False,
        'source_PBF_node_group_ready_ledgers_opened':False}
    (HERE/'finite-selection.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'finite_selection_prepared':True,'new_leaf_count':len(samples),'parent_count':len(parents),
        'separate_old_prefix_count':len(old_prefix),'complete_kept_rows':rows,'kept_counts':dict(per_source),
        'finite_selection_sha256':sha((HERE/'finite-selection.json').read_bytes()),'candidate_bytes_read':0},ensure_ascii=False))


if __name__=='__main__':main()
