#!/usr/bin/env python3
"""One complete countrywide prepared-group pass, with disk-backed target checks.

No PBF/node ledger/original map/CPU/device/canonical/ZIP access. New scope joins
all original next4/5/6 branches and keeps direct-city districts unverified.
"""
import ast
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import shutil
import sqlite3
import unicodedata

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
GROUPS = ROOT/'staging/navigation-taiwan-address-ingestion-v1/address-planning-groups.jsonl.gz'
ROSTER = ROOT/'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz'
LABELS = ROOT/'staging/navigation-native-house-label-index-v1/house-labels.jsonl.gz'
LABEL_PROOF = LABELS.parent/'proof.json'
PREVIOUS = ROOT/'staging/navigation-address-house-join-v1/proof.json'
HELPERS = PREVIOUS.parent/'join_address_house_labels.py'
HOUSE = re.compile(r'^[1-9][0-9]*(?:之[1-9][0-9]*)?號$')
DIRECT_CITIES = {'基隆市','台北市','新竹市','嘉義市'}


def need(ok,message):
    if not ok:
        raise AssertionError(message)


def stat(path):
    s=path.stat()
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pure_helpers(inputs):
    before=stat(HELPERS)
    raw=HELPERS.read_bytes()
    need(stat(HELPERS)==before,'Reusable helper source unchanged')
    tree=ast.parse(raw)
    names={'need','encoded','stat','norm','HashReader','HashWriter','JsonGzipOutput',
           'gzip_rows','small_json','coordinate'}
    selected=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
    need(len(selected)==len(names),'Exact reusable pure helper definitions')
    namespace={'ROOT':ROOT,'OUT':OUT,'json':json,'hashlib':hashlib,'gzip':gzip,
               'unicodedata':unicodedata,'math':math,'Decimal':Decimal,'InvalidOperation':InvalidOperation}
    exec(compile(ast.Module(body=selected,type_ignores=[]),str(HELPERS),'exec'),namespace)
    inputs.append({'path':str(HELPERS.relative_to(ROOT)),'bytes':len(raw),'sha256':sha(raw),
                   'stat_before':before,'stat_after':stat(HELPERS),'stat_unchanged':True,
                   'source_content_read_passes':1,'reuse_scope':'Selected pure classes/functions only; old main not imported or run.'})
    return namespace


def main():
    started=datetime.now(timezone.utc).isoformat()
    need(not (OUT/'proof.json').exists() and not (OUT/'working-index.sqlite3').exists(),'New country outputs absent')
    inputs=[]
    helpers=pure_helpers(inputs)
    gzip_rows,small_json,coordinate,norm,JsonGzipOutput=(helpers[x] for x in
        ['gzip_rows','small_json','coordinate','norm','JsonGzipOutput'])
    previous=small_json(PREVIOUS,inputs)
    index_proof=small_json(LABEL_PROOF,inputs)
    need(previous['all_assigned_checks_passed'] and previous['source_group_total']==4630959,'Previous complete-group evidence')
    expected_inputs={x['path']:x for x in previous['inputs']}
    def bind_last(path):
        current=inputs[-1];expected=expected_inputs[str(path.relative_to(ROOT))]
        need(current['sha256']==expected['sha256'] and current['bytes']==expected['bytes'],
             'Inherited source content unchanged: '+str(path))
    labels={}
    for row in gzip_rows(LABELS,inputs):
        need(HOUSE.fullmatch(row['label']) and type(row['primary_ref']) is int
             and 0 <= row['primary_ref'] < 524287 and row['label'] not in labels,'Conservative unique stock numeric text ref')
        labels[row['label']]=row['primary_ref']
    bind_last(LABELS)
    need(len(labels)==50567==index_proof['distinct_integer_or_subnumber_house_labels']
         and inputs[-1]['sha256']==index_proof['ledger_sha256'],'Original label-pool index binding')
    cities={};districts=set();exact=defaultdict(list);direct=defaultdict(list)
    street_by_record={};roster_counts=Counter()
    for row in gzip_rows(ROSTER,inputs):
        roster_counts[row['level']]+=1
        city,district=norm(row['city']),norm(row.get('district'))
        if row['level']==1:
            need(city not in cities,'Unique normalized city')
            cities[city]=row['raw_name']
        elif row['level']==2:
            districts.add((city,district))
        elif row['level']==3:
            need(row['record'] not in street_by_record,'Unique original L3 record')
            street_by_record[row['record']]=row
            exact[(city,district,norm(row['street']))].append(row)
            if not district:
                direct[(city,norm(row['street']))].append(row)
    bind_last(ROSTER)
    need(roster_counts=={1:22,2:343,3:47853},'Complete named original hierarchy')
    need({city for city,street in direct}==DIRECT_CITIES,'Exactly four original direct-city layouts')
    need(Counter(r['next_level'] for r in street_by_record.values())=={4:20107,5:19036,6:8710},'Original next4/5/6 profile categories')
    def match(city,district,street):
        if city not in cities:return 'missing_native_city',[]
        if not street:return 'missing_source_street',[]
        if city in DIRECT_CITIES:
            candidates=direct.get((city,street),[])
            return ('matched_direct_city_street_unique_district_unverified' if len(candidates)==1
                    else 'ambiguous_direct_city_street' if candidates
                    else 'missing_native_street_in_direct_city_district_unverified'),candidates
        if not district:return 'missing_source_district',[]
        if (city,district) not in districts:return 'missing_native_district',[]
        candidates=exact.get((city,district,street),[])
        return ('matched_native_street_exact_unique' if len(candidates)==1
                else 'ambiguous_native_street_exact' if candidates else 'missing_native_street'),candidates
    metrics=defaultdict(Counter)
    source_streets=defaultdict(lambda:defaultdict(set))
    native_streets=defaultdict(lambda:defaultdict(set))
    def count(city,metric,key,records=()):
        metrics[city][metric]+=1
        source_streets[city][metric].add(key)
        native_streets[city][metric].update(records)
    def payload(group,native,scope,ref,status):
        ready=status=='coordinate_ready_global_bounds'
        return {'group_id':group['group_id'],'source_ids':group['source_ids'],
            'source_node_count':group['source_node_count'],'raw_address':group['raw_address'],
            'normalized_planning_key':group['normalized_planning_key'],
            'source_original_native_match':group['native_match'],
            'native_match_scope':scope,'district_verified':scope=='exact_city_district_street',
            'coordinate_strings':group['first_coordinate'] if ready else None,
            'coordinate_status':status,'unselected_first_coordinate_strings':group['first_coordinate'] if not ready else None,
            'source_different_coordinate_nodes':group['different_coordinate_nodes'],
            'separate_floor_unit_source_nodes':group['separate_floor_unit_nodes'],
            'embedded_floor_unit_first_source_flag':group['embedded_floor_unit'],
            'native_street_record':native['record'],'nativeStreetID':native['low28_id'],
            'native_city':native['city'],'native_district':native['district'],'native_street':native['street'],
            'old_child_first':native['first_child'],'old_child_count':native['child_count'],
            'old_child_level_and_flags':native['child_level_and_flags'],'old_next_level':native['next_level'],
            'house_label':group['normalized_planning_key'][3],'primary_ref':ref,
            'native_house_overlap_checked':False,'native_new_record_encoded':False}
    working=OUT/'working-index.sqlite3'
    need(shutil.disk_usage(OUT).free>4_000_000_000,'Disk headroom for bounded-memory SQLite')
    con=sqlite3.connect(working)
    for statement in ['PRAGMA journal_mode=OFF','PRAGMA synchronous=OFF','PRAGMA temp_store=FILE',
                      'PRAGMA cache_size=-65536','PRAGMA mmap_size=0','PRAGMA threads=1']:
        con.execute(statement)
    con.execute('CREATE TABLE targets(record INTEGER,house TEXT,coordinate_key TEXT,blocked INTEGER NOT NULL,coordinate_collision INTEGER NOT NULL,groups INTEGER NOT NULL,unready_members INTEGER NOT NULL,PRIMARY KEY(record,house)) WITHOUT ROWID')
    con.execute('CREATE TABLE members(record INTEGER,house TEXT,group_id INTEGER,row_json TEXT NOT NULL,scope TEXT NOT NULL,coordinate_status TEXT NOT NULL,primary_ref INTEGER,PRIMARY KEY(record,house,group_id)) WITHOUT ROWID')
    target_sql='''INSERT INTO targets VALUES(?,?,?,?,?,?,?) ON CONFLICT(record,house) DO UPDATE SET
        coordinate_collision=targets.coordinate_collision OR (targets.coordinate_key IS NOT NULL AND excluded.coordinate_key IS NOT NULL AND targets.coordinate_key<>excluded.coordinate_key),
        blocked=targets.blocked OR excluded.blocked OR (targets.coordinate_key IS NOT NULL AND excluded.coordinate_key IS NOT NULL AND targets.coordinate_key<>excluded.coordinate_key),
        coordinate_key=COALESCE(targets.coordinate_key,excluded.coordinate_key),groups=targets.groups+1,
        unready_members=targets.unready_members+excluded.unready_members'''
    unresolved=JsonGzipOutput(OUT/'unresolved-native-name-group-keys.jsonl.gz')
    nonconservative=JsonGzipOutput(OUT/'matched-nonconservative-house-review.jsonl.gz')
    total=source_nodes=indexed=nonconservative_count=0
    raw_city_counts=Counter();corrections=Counter();branches=Counter();branch_streets=defaultdict(set)
    pending_samples=defaultdict(list)
    previous_nine={x['house_label']:x for x in previous['nine_verified_source_controls']}
    nine_seen=defaultdict(list)
    runtime=[]
    for group in gzip_rows(GROUPS,inputs):
        total+=1
        need(group['group_id']==total and len(group['raw_address'])==len(group['normalized_planning_key'])==4,'Sequential original four-field groups')
        need(len(group['source_ids'])==group['source_node_count'] and all(type(x)is int and x>0 for x in group['source_ids']),'Source node/ID accounting')
        source_nodes+=group['source_node_count']
        raw_city,raw_district,raw_street,raw_house=group['raw_address']
        key=tuple(map(norm,(raw_city,raw_district,raw_street)))
        city,district,street=key;city_label=cities.get(city,city or '<absent>')
        raw_city_counts[raw_city]+=1
        classification,candidates=match(*key)
        one=len(candidates)==1 and classification in ('matched_native_street_exact_unique','matched_direct_city_street_unique_district_unverified')
        records=[r['record'] for r in candidates] if one else ()
        count(city_label,'all_groups',key)
        count(city_label,classification,key,records)
        if group['native_match']=='missing_native_district' and city in DIRECT_CITIES:
            corrections[classification]+=1
        house=group['normalized_planning_key'][3]
        numeric=isinstance(house,str) and HOUSE.fullmatch(house) is not None
        ref=labels.get(house) if numeric else None
        label_status='existing_numeric_label_ref' if ref is not None else 'numeric_label_ref_absent' if numeric else 'nonconservative_house_label'
        count(city_label,label_status,key,records)
        status,coordinate_key=coordinate(group)
        count(city_label,status,key,records)
        if group['separate_floor_unit_nodes']:count(city_label,'group_with_separate_floor_unit_door_level_tags',key,records)
        if group['embedded_floor_unit']:count(city_label,'first_group_source_has_embedded_floor_unit',key,records)
        if group['source_node_count']>1:count(city_label,'multi_source_node_group',key,records)
        if one:
            native=candidates[0];level=native['next_level'];record=native['record']
            need(level in (4,5,6),'Matched original next level')
            scope='exact_city_district_street' if classification=='matched_native_street_exact_unique' else 'direct_city_street_district_unverified'
            branches[level]+=1;branch_streets[level].add(record)
            count(city_label,'matched_unique_next'+str(level),key,records)
            count(city_label,scope+'_next'+str(level),key,records)
            if ref is not None:
                count(city_label,scope+'_next'+str(level)+'_existing_ref_before_coordinate_review',key,records)
                if status=='coordinate_ready_global_bounds':
                    count(city_label,scope+'_next'+str(level)+'_existing_ref_coordinate_ready_before_target_check',key,records)
                if scope=='exact_city_district_street' and level==4:
                    count(city_label,'exact_unique_next4_existing_ref_before_coordinate_review',key,records)
                    if status=='coordinate_ready_global_bounds':count(city_label,'exact_unique_next4_existing_ref_coordinate_ready',key,records)
            if numeric:
                ready=status=='coordinate_ready_global_bounds'
                wire_key=json.dumps(coordinate_key,separators=(',',':')) if ready else None
                con.execute(target_sql,(record,house,wire_key,int(not ready),0,1,int(not ready)))
                con.execute('INSERT INTO members VALUES(?,?,?,?,?,?,?)',
                    (record,house,group['group_id'],json.dumps(group,ensure_ascii=False,separators=(',',':')),scope,status,ref))
                indexed+=1
            else:
                row=payload(group,native,scope,ref,status)
                row.update({'review_reason':'nonconservative_house_label','native_merge_eligible':False,
                            'same_native_street_house_collision_checked':False})
                nonconservative.write(row);nonconservative_count+=1
            if city=='台中市' and district=='中區' and street=='民權路' and house in previous_nine:
                control=previous_nine[house]
                need(control['source_id_from_original_plan'] in group['source_ids'] and ref==control['existing_index_primary_ref']
                     and native['low28_id']==16707 and group['group_id']==control['group_id'],'Inherited nine source/street/text-ref identity')
                need(status=='coordinate_ready_global_bounds' and all(Decimal(str(a))==Decimal(str(b)) for a,b in
                     zip(group['first_coordinate'],control['plan_coordinate_strings'])),'Inherited nine coordinate identity')
                nine_seen[house].append({'group_id':group['group_id'],'source_ids':group['source_ids'],
                    'primary_ref':ref,'coordinate_strings':group['first_coordinate'],'source_street_record':record})
        else:
            row={'group_id':group['group_id'],'raw_address':group['raw_address'],
                 'normalized_planning_key':group['normalized_planning_key'],
                 'native_match':classification,'candidate_native_street_records':[r['record'] for r in candidates],
                 'source_node_count':group['source_node_count'],'coordinate_status':status,
                 'house_label':house,'primary_ref':ref,'label_status':label_status,
                 'source_group_ledger_reference':str(GROUPS.relative_to(ROOT))}
            unresolved.write(row)
            if len(pending_samples[(city_label,classification)])<8:
                pending_samples[(city_label,classification)].append(row)
        if total%100000==0:
            con.commit()
            current={'groups':total,'indexed_groups':indexed,'sqlite_bytes':working.stat().st_size,
                     'disk_free_bytes':shutil.disk_usage(OUT).free,
                     'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
            runtime.append(current)
            need(current['disk_free_bytes']>1_000_000_000,'SQLite disk floor; keep ledger for diagnosis if this guard fails')
            if total%500000==0:print(json.dumps({'progress':current},ensure_ascii=False),flush=True)
    con.commit();bind_last(GROUPS)
    need(total==4630959 and source_nodes==previous['source_nodes_represented_by_groups'],'Complete source groups/nodes reconciled')
    need(con.execute('PRAGMA integrity_check').fetchall()==[('ok',)],'Working target/member SQLite integrity')
    need(indexed==con.execute('SELECT COUNT(*) FROM members').fetchone()[0]
         ==con.execute('SELECT COALESCE(SUM(groups),0) FROM targets').fetchone()[0], 'Disk target/member counts reconcile')
    outputs={}
    for scope in ['exact','directcity']:
        for level in (4,5,6):
            prefix=f'exact-next{level}-existing-label' if scope=='exact' else f'directcity-next{level}-district-unverified'
            outputs[(scope,level,'ready')]=JsonGzipOutput(OUT/(prefix+('-ready-candidates' if scope=='exact' else '-ready-planning')+'.jsonl.gz'))
            outputs[(scope,level,'review')]=JsonGzipOutput(OUT/(prefix+'-coordinate-review.jsonl.gz'))
    label_review=JsonGzipOutput(OUT/'matched-native-street-label-review.jsonl.gz')
    output_metrics=defaultdict(Counter)
    output_streets=defaultdict(lambda:defaultdict(set))
    output_targets=defaultdict(lambda:defaultdict(set))
    out_hash=hashlib.sha256();out_count=0;output_nine=defaultdict(list)
    query='''SELECT m.record,m.house,m.group_id,m.row_json,m.scope,m.coordinate_status,m.primary_ref,
             t.blocked,t.coordinate_collision,t.groups,t.unready_members
             FROM members m JOIN targets t ON t.record=m.record AND t.house=m.house
             ORDER BY m.record,m.house,m.group_id'''
    for record,house,group_id,stored,scope,status,ref,blocked,collision,target_groups,unready_members in con.execute(query):
        group=json.loads(stored);native=street_by_record[record]
        row=payload(group,native,scope,ref,status)
        row.update({'same_native_street_house_group_count':target_groups,
                    'same_native_street_house_coordinate_collision':bool(collision),
                    'same_native_street_house_unready_coordinate_members':unready_members,
                    'same_native_street_house_collision_checked':True})
        if blocked:
            row['review_reason']='different_coordinates_for_same_native_street_house' if collision else (
                status if status!='coordinate_ready_global_bounds' else 'same_native_street_house_has_unready_coordinate_member')
            row['unselected_first_coordinate_strings']=row['coordinate_strings'] or row['unselected_first_coordinate_strings']
            row['coordinate_strings']=None
        scope_short='exact' if scope=='exact_city_district_street' else 'directcity'
        level=native['next_level'];city_label=native['city']
        if ref is None:
            row['label_review_reason']='numeric_label_ref_absent'
            row['native_merge_eligible']=False
            label_review.write(row);category='label_review_next'+str(level)
        else:
            state='review' if blocked else 'ready'
            row['native_merge_eligible']=not blocked and scope_short=='exact'
            if not blocked:
                need(status=='coordinate_ready_global_bounds' and row['coordinate_strings'] is not None and not collision,'Strict ready routing')
            outputs[(scope_short,level,state)].write(row)
            category=scope_short+'_next'+str(level)+'_'+state
        output_metrics[city_label][category]+=1
        output_streets[city_label][category].add(record)
        output_targets[city_label][category].add((record,house))
        out_hash.update(str(group_id).encode()+b'\0'+str(record).encode()+b'\0'+house.encode()+b'\n')
        out_count+=1
        if record==0x30004143 and house in previous_nine:
            output_nine[house].append({'group_id':group_id,'output_category':category,
                'native_merge_eligible':row['native_merge_eligible'],'coordinate_review_reason':row.get('review_reason')})
        if out_count%500000==0:
            print(json.dumps({'output_progress':out_count,'disk_free_bytes':shutil.disk_usage(OUT).free,
                'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}),flush=True)
    artifacts={}
    for key,output in outputs.items():artifacts['_'.join(map(str,key))]=output.close()
    artifacts['matched_label_review']=label_review.close()
    artifacts['matched_nonconservative_house_review']=nonconservative.close()
    artifacts['unresolved_native_names']=unresolved.close()
    need(out_count==indexed and sum(x['rows'] for x in artifacts.values())==total,'Every complete input group routed exactly once')
    duplicate_counts=dict(zip(['targets','multiple_group_targets','coordinate_collision_targets','blocked_targets',
        'groups_in_multiple_group_targets','groups_in_coordinate_collision_targets','groups_in_blocked_targets'],
        con.execute('SELECT COUNT(*),COALESCE(SUM(groups>1),0),COALESCE(SUM(coordinate_collision),0),COALESCE(SUM(blocked),0),COALESCE(SUM(CASE WHEN groups>1 THEN groups ELSE 0 END),0),COALESCE(SUM(CASE WHEN coordinate_collision THEN groups ELSE 0 END),0),COALESCE(SUM(CASE WHEN blocked THEN groups ELSE 0 END),0) FROM targets').fetchone()))
    collision_samples=[]
    for record,house,group_count,collision,blocked in con.execute('SELECT record,house,groups,coordinate_collision,blocked FROM targets WHERE groups>1 ORDER BY record,house LIMIT 30'):
        member_ids=[x[0] for x in con.execute('SELECT group_id FROM members WHERE record=? AND house=? ORDER BY group_id',(record,house))]
        collision_samples.append({'native_street_record':record,'nativeStreetID':record&0x0fffffff,'house_label':house,
            'source_group_ids':member_ids,'coordinate_collision':bool(collision),'blocked':bool(blocked)})
    nine=[]
    for house in sorted(previous_nine,key=lambda x:int(x[:-1])):
        need(len(nine_seen[house])==len(output_nine[house])==1,'Exactly one inherited nine group in source/output index')
        need(output_nine[house][0]['native_merge_eligible'] and output_nine[house][0]['output_category']=='exact_next4_ready','Inherited nine retains exact-next4-ready routing')
        nine.append({'house_label':house,**nine_seen[house][0],'output_routing':output_nine[house]})
    working_bytes=working.stat().st_size
    con.close();working.unlink()
    need(not working.exists(),'Temporary SQLite removed after indexed output')
    totals=Counter()
    for values in metrics.values():totals.update(values)
    for key,value in previous['whole_country_group_metrics'].items():need(totals[key]==value,'Inherited full-country metric consistency '+key)
    city_metrics={city:{metric:{'groups':amount,'unique_source_city_district_street_keys':len(source_streets[city][metric]),
        'unique_matched_native_street_records':len(native_streets[city][metric])} for metric,amount in sorted(values.items())}
        for city,values in sorted(metrics.items())}
    output_city_metrics={city:{category:{'groups':amount,'unique_native_street_records':len(output_streets[city][category]),
        'unique_native_street_house_targets':len(output_targets[city][category])} for category,amount in sorted(values.items())}
        for city,values in sorted(output_metrics.items())}
    output_totals=Counter()
    for values in output_metrics.values():output_totals.update(values)
    proof={'schema':'prepared-country-address-native-ready-join/v1','started_utc':started,
        'finished_utc':datetime.now(timezone.utc).isoformat(),'all_assigned_checks_passed':True,
        'script_sha256':sha(Path(__file__).read_bytes()),'inputs':inputs,
        'input_passes':'Exactly one complete content pass per groups/roster/house index. No PBF, node ledger, original map or native CPU access.',
        'source_group_total':total,'source_nodes_represented_by_groups':source_nodes,
        'source_stat_immutable_all':all(x['stat_unchanged'] for x in inputs),
        'matching_policy':'Host NFKC/outer-whitespace/臺→台 only. Exact city/district/street unique records emitted separately from direct-city city+street matches with source district unverified. No Chinese name aliases, district assignments or new street substitutions.',
        'house_policy':'Strict positive ASCII integer / 之positive-subnumber＋號 prepared keys; lowest existing numeric text ref does not prove street membership. Ambiguous hyphens are not guessed.',
        'coordinate_policy':'Finite global WGS84 bounds and consistent source-ready metadata only; no Taiwan or city polygon inference. Any unready member or differing ready canonical Decimal coordinates blocks the entire native street+house target. No conflicting first point chosen.',
        'floor_unit_scope':'Separate floor/unit/door/level aggregates preserved. Embedded floor/unit flag is first source only; node ledger not reopened.',
        'source_raw_city_group_counts':dict(raw_city_counts),'whole_country_group_metrics':dict(totals),
        'whole_country_city_group_and_street_metrics':city_metrics,
        'four_city_raw_missing_district_group_corrections':dict(corrections),
        'matched_group_next_level_counts':dict(branches),
        'matched_native_street_records_by_next_level':{level:len(records) for level,records in branch_streets.items()},
        'output_group_counts_by_category':dict(output_totals),'output_city_group_street_and_target_counts':output_city_metrics,
        'artifacts':artifacts,'output_order':'Native street record, house label lexical text, original group_id; no native numeric ordering asserted.',
        'multiple_groups_policy':'Rows preserve original groups; identical coordinate targets are not silently coalesced. A writer must coalesce/retain provenance before counting truly new houses. Direct-city outputs remain district-unverified and not formal merge eligible.',
        'indexed_native_street_house_targets':duplicate_counts,'representative_multiple_group_targets':collision_samples,
        'working_index':{'sqlite_integrity_check':'ok','target_member_counts_reconciled':True,'temporary_bytes':working_bytes,
            'removed_after_output':not working.exists(),'configured_cache_KiB':65536,'temp_store':'FILE','mmap_disabled':True,
            'output_member_identity_sha256_computed_during_routing':out_hash.hexdigest(),'output_member_count':out_count},
        'pending_name_examples':[{ 'city':city,'classification':classification,'bounded_examples':examples}
            for (city,classification),examples in sorted(pending_samples.items())],
        'nine_inherited_verified_source_controls':nine,'nine_all_in_exact_next4_ready':True,
        'runtime_resource_receipts':runtime,'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'no_output_full_ledger_readback_parse':True,
        'limits':['No stock original labelled-group overlap or novel-house determination.',
            'No source point is claimed a verified city/Taiwan entrance or routable street location.',
            'Source-missing street/admin and ambiguous matches remain unresolved with their group-ID key ledger and original complete provenance ledger retained.',
            'Current original next4/5/6 metadata is preserved; flag8/13 interpretation and per-level native merge/query validation remain separate work.',
            'No country image/new native record/map/profile/firmware write, CPU, USB, report or installation.'],
        'device_IO':False,'native_CPU_executed':False,'native_house_overlap_checked':False,
        'native_new_records_encoded':False,'full_Taiwan_native_update_complete':False}
    proof_path=OUT/'proof.json';proof_path.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_assigned_checks_passed':True,'source_groups':total,'output_counts':dict(output_totals),
        'target_index':duplicate_counts,'temporary_DB_removed':not working.exists(),
        'nine_all_in_exact_next4_ready':True,'proof_sha256':sha(proof_path.read_bytes())},ensure_ascii=False),flush=True)


if __name__=='__main__':
    main()
