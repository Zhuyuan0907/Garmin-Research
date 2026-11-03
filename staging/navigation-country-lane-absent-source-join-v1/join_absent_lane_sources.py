#!/usr/bin/env python3
"""One prepared-group pass for missing exact lane-house planning targets only.

Coordinates and full node IDs come exclusively from pinned prepared groups.
No map/CPU/PBF/ready-source/database/writer/device/canonical/ZIP operations.
"""
import ast
from collections import Counter,defaultdict
from datetime import datetime,timezone
from decimal import Decimal,ROUND_HALF_UP,InvalidOperation
from fractions import Fraction
import gzip
import hashlib
import heapq
import importlib.util
import json
from pathlib import Path
import re
import resource
import sys
import time
import unicodedata

sys.dont_write_bytecode=True
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
LANE=ROOT/'staging/navigation-country-lane-path-match-v1'
GROUPS=ROOT/'staging/navigation-taiwan-address-ingestion-v1/address-planning-groups.jsonl.gz'
COUNTRY=ROOT/'staging/navigation-country-address-ready-join-v1/proof.json'
GEO=ROOT/'staging/navigation-country-city-geometry-v1'
DISTRICT=ROOT/'staging/navigation-kaohsiung-district-geometry-v1'
LABELS=ROOT/'staging/navigation-native-house-label-index-v1'
INTEGER=re.compile(r'[1-9][0-9]*號\Z')
HOUSE=re.compile(r'[1-9][0-9]*(?:之[1-9][0-9]*)?號\Z')
GROUP_ID=re.compile(rb'\{"group_id":([1-9][0-9]*),')
MAX_RSS_KIB=500*1024
PINS={
 LANE/'proof.json':'174739c4a3866d98ac2ff1d79af9c981f311525f2029e951dccffa5752112ee1',
 LANE/'match_country_lane_paths.py':'ec910fb881cff3ff37f19cf99da352b67d38264dabe604dcaeeb66005ee0c49f',
 COUNTRY:'b61cd949152fece0548265ccf438c14d3bbeeddfc5e3ae05140df20d3aa0a175',
 GEO/'proof.json':'de9a7dc37f8506fe137480b1d79dd4235e4ac721356586c5e3db17a5a20033f3',
 GEO/'city-geometries.json':'cd44ea3aba74357480487ab83cf228232bdf0fc99821d7bf39fd58bbcd50cfc5',
 DISTRICT/'district_membership.py':'c99ba1ad496356ca389f0bd8a8f1c7b00929a216066b7ed05a6c100359d0e998',
 DISTRICT/'district-geometries.json':'64c5219bc8ee1f8f5b779b34bc65f41e1797d1d684f9ed8ad0960894425b64b8',
 DISTRICT/'proof.json':'1c119734f9c1c4c524b23f8c4233fe8b413e43212721f7ceb8edb00693eb1f50',
 DISTRICT/'source-membership.json':'6f818e684fe5cdc248b5b9657a2526b3bb69ec5c511d3be86d91658a32403836',
 LABELS/'proof.json':'793ad2853b07ee3940d0e4f44b39809c612b4ed2de5632387b3a7c36123ed3b4',
 ROOT/'scripts/native_address_records.py':'8dfec0a03795e29fc223fbd06f0418536b6f3969024083b5023e25620319eb33',
 ROOT/'scripts/prepare_taichung_city_geometry_v1.py':'2fff38c613a41017553f8a59978b85811fce6b118b6db87cfc07fe1e17d74101',
 ROOT/'staging/navigation-kaohsiung-native-house-merge-v1/merge_policy.py':'166cd5318782c96cebe23b08149c691192387774d2302115d5faa781b67e4877'}

def need(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def stat(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def norm(text):return unicodedata.normalize('NFKC',text or '').strip().replace('臺','台')
def load(path,inputs):
    before=stat(path);need(before[2]<5_000_000,'Small sealed input ceiling')
    raw=path.read_bytes();need(sha(raw)==PINS[path] and stat(path)==before,'Sealed helper/proof/geometry binding')
    inputs.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),stat_before=before,stat_after=stat(path)))
    return raw
def selected_defs(raw,path,names,namespace):
    nodes=[n for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
    need(len(nodes)==len(names),'Exact reusable source definitions')
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),namespace)
    return namespace
def verified_module(path,raw,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;spec.loader.exec_module(m);need(sha(path.read_bytes())==sha(raw),'Module immutable during import');return m

def gzip_lines(path,expected,receipts,plain_prior=True):
    before=stat(path);need(before[2]==expected['bytes'],'Pinned compressed length')
    rows=0;plain=hashlib.sha256();plainbytes=0
    with path.open('rb') as source:
        reader=IO['HashReader'](source)
        with gzip.GzipFile(fileobj=reader,mode='rb') as stream:
            for line in stream:
                rows+=1;plain.update(line);plainbytes+=len(line);yield line
        need(reader.count==before[2] and reader.hash.hexdigest()==expected['sha256'],'Compressed pin and full input EOF')
    need(rows==expected['rows'] and stat(path)==before,'Pinned rows and immutable input')
    if plain_prior:need(plain.hexdigest()==expected['uncompressed_sha256'],'Inherited plain pin')
    receipts.append(dict(path=str(path.relative_to(ROOT)),rows=rows,bytes=reader.count,sha256=reader.hash.hexdigest(),
        uncompressed_sha256=plain.hexdigest(),uncompressed_bytes=plainbytes,plain_digest_status=
            'verified_against_inherited_pin' if plain_prior else 'newly_established_no_prior_plain_pin_available',
        gzip_EOF_validated=True,full_content_passes=1,stat_before=before,stat_after=stat(path),stat_unchanged=True))

def coordinate_status(group):
    ready=group['coordinate_selection_ready'];different=group['different_coordinate_nodes']
    need(type(ready) is bool and type(different) is int and different>=0 and ready==(different==0),'Coordinate readiness metadata consistency')
    if not ready:return 'source_coordinate_conflict',None
    value=group['first_coordinate']
    try:
        lat,lon=map(Decimal,value)
        need(lat.is_finite() and lon.is_finite() and -90<=lat<=90 and -180<=lon<180,'Finite global source point')
    except (InvalidOperation,TypeError,ValueError):return 'invalid_or_missing',None
    return 'coordinate_ready_global_bounds',(lat,lon)

def target_parent(row):
    return dict(record=row['actual_parent_record'],level=row['actual_parent_level'],ID=row['actual_parent_ID'],
        label=row['actual_parent_label'],raw_flags=row['actual_parent_raw_flags'],high_flags=row['actual_parent_high_flags'],
        next_leaf_level=row['next_leaf_level'],old_first_child=row['old_first_child'],old_child_count=row['old_child_count'],
        root_street_record=row['native_root_street_record'],path_record_ids=row['actual_path_record_ids'],
        path_tokens=row['exact_path_tokens'],city=row['normalized_planning_key'][0],district=row['normalized_planning_key'][1],
        source_full_street=row['normalized_planning_key'][2])

def exact_raw24_city(geometry,raw24):
    lat,lon=[POLICY['signed24'](v) for v in raw24]
    y=Fraction(lat*360*10000000,1<<24);x=Fraction(lon*360*10000000,1<<24)
    for rings in geometry.polygons:
        outer=rings[0].test(x,y)
        if outer==2:return True
        if outer==0:continue
        holes=[ring.test(x,y) for ring in rings[1:]]
        if 2 in holes or 1 not in holes:return True
    return False

def assess_geometry(parent,point,raw24,cities,districts,citymeta):
    city,district=parent['city'],parent['district']
    if city=='高雄市':
        source=districts.assess(city,district,*point)
        native=POLICY['quantized_assess'](districts,city,district,raw24)
        return source,native,None if source['eligible'] and native['eligible'] else 'source_or_raw24_not_inside_same_complete_district'
    if city not in cities:return None,None,'city_boundary_unavailable'
    try:
        source_inside=cities[city].covers(*point)
    except (ValueError,InvalidOperation,OverflowError):return None,None,'source_precision_exceeds_geometry_policy'
    native_inside=exact_raw24_city(cities[city],raw24)
    witness=dict(city=city,geometry_scope='complete_city_only_not_district',**citymeta[city])
    source=dict(**witness,eligible=source_inside,status='inside_verified_city' if source_inside else 'outside_verified_city')
    native=dict(**witness,eligible=native_inside,status='inside_verified_city' if native_inside else 'outside_verified_city',
        quantized_exact_rational_degrees=[str(Fraction(POLICY['signed24'](v)*360,1<<24)) for v in raw24])
    return source,native,None if source_inside and native_inside else 'source_or_raw24_not_inside_same_complete_city'

def eligibility(members,house):
    reasons=[]
    if not INTEGER.fullmatch(house):reasons.append('noninteger_or_subnumber_house')
    if any(m['coordinate_status']!='coordinate_ready_global_bounds' for m in members):reasons.append('source_coordinate_conflict_or_unavailable')
    refs={m['primary_ref'] for m in members}
    if None in refs or any(type(ref) is not int or not 0<=ref<524287 for ref in refs):reasons.append('missing_or_invalid_existing_numeric_label_ref')
    if len(refs)!=1:reasons.append('same_parent_house_reference_collision')
    points={tuple(map(Decimal,m['coordinate_strings'])) for m in members if m['coordinate_strings'] is not None}
    if len(points)>1:reasons.append('same_parent_house_exact_Decimal_point_collision')
    if any(m['native_parent']!=members[0]['native_parent'] for m in members):reasons.append('native_parent_path_or_old_range_collision')
    return reasons,points

def target_sort_key(row):
    house=row['house_label']
    return (row['key_parent'],0 if INTEGER.fullmatch(house) else 1,
            int(house[:-1]) if INTEGER.fullmatch(house) else 0,house)

def combine_target_rows(a,b):a['members'].extend(b['members'])

def main():
    need(not (OUT/'proof.json').exists(),'New isolated scope only')
    started=datetime.now(timezone.utc).isoformat();t0=time.monotonic();inputs=[];streams=[]
    global IO,POLICY
    io_path=LANE/'match_country_lane_paths.py'
    IO=selected_defs(load(io_path,inputs),io_path,{'encoded','HashReader','HashWriter','Ledger','run_rows','merged_runs'},
        dict(need=need,sha=sha,stat=stat,ROOT=ROOT,json=json,gzip=gzip,hashlib=hashlib,heapq=heapq))
    laneproof=json.loads(load(LANE/'proof.json',inputs));country=json.loads(load(COUNTRY,inputs))
    sourcepin=next(r for r in country['inputs'] if r['path']==str(GROUPS.relative_to(ROOT)))
    sourcepin=dict(sourcepin,rows=sourcepin['json_rows'])
    need(sourcepin['rows']==4630959 and sourcepin['bytes']==137633122 and
         sourcepin['sha256']=='0cf58f5536812c1dbb2246559f9ef021e59fa0cc1967bb0a924456aa5ff1587b','Prepared source pin')
    labelproof=json.loads(load(LABELS/'proof.json',inputs));labeldict={}
    labelpin=dict(bytes=labelproof['ledger_bytes'],sha256=labelproof['ledger_sha256'],rows=50567)
    for line in gzip_lines(LABELS/'house-labels.jsonl.gz',labelpin,streams,False):
        r=json.loads(line);need(r['label'] not in labeldict and HOUSE.fullmatch(r['label']),'Conservative unique numeric label index')
        labeldict[r['label']]=r['primary_ref']
    selected={};previous=0;seen=0
    for line in gzip_lines(LANE/'matched-native-lane-groupkeys.jsonl.gz',laneproof['artifacts']['matched_groupkeys'],streams):
        match=GROUP_ID.match(line);need(match is not None,'Actual matched output group-ID field order')
        ID=int(match.group(1));need(ID>previous,'Source group order in matched keys');previous=ID
        if b'"source_house_exact_membership":"absent"' not in line:continue
        r=json.loads(line);need(r['source_house_exact_membership']=='absent' and ID not in selected,'Unique actual absent key')
        house=r['house_label'];ref=labeldict.get(house) if HOUSE.fullmatch(house) else None
        status='existing_numeric_label_ref' if ref is not None else 'numeric_label_ref_absent' if HOUSE.fullmatch(house) else 'nonconservative_house_label'
        need(r['primary_ref']==ref and r['label_status']==status,'Exact current inherited stock numeric text ref')
        need(r['native_match']=='missing_native_street' and r['matching_planning_only'] is True and
             r['actual_parent_raw_flags']&7==r['next_leaf_level'],'Exact upstream lane/parent source scope')
        # Raw immutable JSON bytes, not retained parsed key object graphs.
        selected[ID]=line;seen+=1
    need(seen==76849==laneproof['matched_group_counts']['house_absent'],'All and only absent source keys')
    del labeldict
    rows=0;joined_count=0;conflict_keys=0;runbuffer=[];runmetas=[];run_readbacks=[]
    (OUT/'sorted-joined-runs').mkdir()
    joined_output=IO['Ledger'](OUT/'joined-absent-source-groups.jsonl.gz')
    def flush_run():
        if not runbuffer:return
        ledger=IO['Ledger'](OUT/'sorted-joined-runs'/('run-%05d.jsonl.gz'%len(runmetas)))
        for r in sorted(runbuffer,key=target_sort_key):ledger.write(r)
        runmetas.append(ledger.close());runbuffer.clear()
    progress=IO['Ledger'](OUT/'progress-receipts.jsonl.gz')
    for line in gzip_lines(GROUPS,sourcepin,streams,False):
        rows+=1;match=GROUP_ID.match(line);need(match is not None and int(match.group(1))==rows,'Exact sequential prepared group order')
        keyraw=selected.pop(rows,None)
        if keyraw is not None:
            key=json.loads(keyraw)
            group=json.loads(line);joined_count+=1
            need(group['group_id']==key['group_id'] and group['raw_address']==key['raw_address'] and
                 group['normalized_planning_key']==key['normalized_planning_key'] and group['source_node_count']==key['source_node_count']
                 and group['native_match']==key['native_match'] and group['native_street_records']==key['candidate_native_street_records'],
                 'Actual prepared group matches key provenance/raw/normalized/native source values')
            IDs=group['source_ids'];need(len(IDs)==group['source_node_count'] and len(set(IDs))==len(IDs)
                and all(type(ID) is int and ID>0 for ID in IDs),'Complete unique positive node-ID provenance')
            status,point=coordinate_status(group);need(status==key['coordinate_status'],'Actual coordinate status equals keys metadata')
            if point is None:conflict_keys+=1
            parent=target_parent(key)
            member=dict(group_id=rows,source_ids=IDs,source_node_count=len(IDs),raw_address=key['raw_address'],
                normalized_planning_key=key['normalized_planning_key'],primary_ref=key['primary_ref'],label_status=key['label_status'],
                coordinate_status=status,coordinate_strings=group['first_coordinate'] if point is not None else None,
                unselected_first_coordinate_strings=group['first_coordinate'] if point is None else None,
                different_coordinate_nodes=group['different_coordinate_nodes'],coordinate_selection_ready=group['coordinate_selection_ready'],
                separate_floor_unit_nodes=group['separate_floor_unit_nodes'],embedded_floor_unit=group['embedded_floor_unit'],
                native_parent=parent,original_group_native_match=group['native_match'],
                actual_absent_house_matching_plan=key)
            wrapper=dict(key_parent=parent['record'],house_label=key['house_label'],members=[member])
            joined_output.write(wrapper);runbuffer.append(wrapper)
            if len(runbuffer)==5000:flush_run()
        if rows%200000==0:
            rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss;need(rss<=MAX_RSS_KIB,'Actual RSS ceiling500MiB')
            r=dict(source_rows=rows,actual_absent_groups_joined=joined_count,remaining_absent_keys=len(selected),max_RSS_KiB=rss,
                   elapsed_seconds=time.monotonic()-t0,utc=datetime.now(timezone.utc).isoformat())
            progress.write(r);print(json.dumps(r),flush=True)
    need(not selected and joined_count==76849,'Every actual absent key joined exactly once')
    flush_run();joined_artifact=joined_output.close()
    del selected,key,keyraw,group,member,wrapper
    engine_path=ROOT/'scripts/prepare_taichung_city_geometry_v1.py'
    geom=selected_defs(load(engine_path,inputs),engine_path,{'integer_coordinate','Ring','CityGeometry'},dict(Decimal=Decimal))
    geoproof=json.loads(load(GEO/'proof.json',inputs));need(geoproof['complete_city_geometries']==21,'Exact21 complete city dataset')
    geodata=json.loads(load(GEO/'city-geometries.json',inputs));cities={};citymeta={}
    for name,item in geodata.items():
        city=norm(name);cities[city]=geom['CityGeometry'](item['geometry'])
        citymeta[city]={'source_relation_id':item['source_relation_id'],'city_geometry_dataset_sha256':PINS[GEO/'city-geometries.json']}
    need(len(cities)==21 and '高雄市' not in cities,'No inferred Kaohsiung city union')
    del geodata
    for path in [DISTRICT/'district-geometries.json',DISTRICT/'proof.json',DISTRICT/'source-membership.json']:load(path,inputs)
    dpath=DISTRICT/'district_membership.py';districts=verified_module(dpath,load(dpath,inputs),'lane_join_exact_district_module').DistrictMembership()
    ppath=ROOT/'staging/navigation-kaohsiung-native-house-merge-v1/merge_policy.py'
    POLICY=selected_defs(load(ppath,inputs),ppath,{'signed24','quantized_assess'},dict(Fraction=Fraction))
    apath=ROOT/'scripts/native_address_records.py'
    quant=selected_defs(load(apath,inputs),apath,{'quantize_point24'},dict(Decimal=Decimal,ROUND_HALF_UP=ROUND_HALF_UP))['quantize_point24']
    ready=IO['Ledger'](OUT/'ready-lane-house-targets.jsonl.gz');held=IO['Ledger'](OUT/'held-lane-house-targets.jsonl.gz')
    parent_summary={};counts=Counter();reasons_count=Counter();by_city=defaultdict(Counter)
    for merged in IO['merged_runs'](runmetas,target_sort_key,combine_target_rows,run_readbacks):
        parentID,house=merged['key_parent'],merged['house_label'];members=merged['members'];parent=members[0]['native_parent']
        reasons,points=eligibility(members,house)
        if parent['city']=='高雄市' and any(m['raw_address'][:2]!=['高雄市',parent['district']] for m in members):
            reasons.append('Kaohsiung_raw_source_administration_not_exact_native_district')
        source_decision=native_decision=None;raw24=None;point_strings=None
        if not reasons:
            point=next(iter(points));point_strings=[str(x.normalize()) for x in point]
            q=quant(*point);raw24=[q['latitude']['wire_u24'],q['longitude']['wire_u24']]
            source_decision,native_decision,reason=assess_geometry(parent,point,raw24,cities,districts,citymeta)
            if reason:reasons.append(reason)
        IDs=sorted({ID for m in members for ID in m['source_ids']})
        result=dict(actual_parent=parent,house_label=house,numeric_house=int(house[:-1]) if INTEGER.fullmatch(house) else None,
            primary_ref=members[0]['primary_ref'],
            source_group_ids=[m['group_id'] for m in members],source_ids=IDs,source_node_count=len(IDs),source_members=members,
            selected_coordinate_strings=point_strings,planned_raw24=raw24,
            quantization_policy='Prototype nearest signed24 circle /Decimal ROUND_HALF_UP; stock rounding unproved.',
            source_geometry_decision=source_decision,exact_raw24_geometry_decision=native_decision,
            reasons=reasons,source_house_exact_membership='absent',source_and_native_points_checked=not reasons,
            planning_eligibility='source_join_geometry_ready' if not reasons else 'held',native_write_ready=False,
            required_next_scope='True native parent tree overlay/group preservation/capacity and original consumer validation before writer use.')
        counts['source_groups_joined']+=len(members);counts['targets']+=1
        if reasons:
            held.write(result);counts['held_targets']+=1;counts['held_source_groups']+=len(members)
            for reason in reasons:reasons_count[reason]+=1
            by_city[parent['city']]['held_targets']+=1
        else:
            ready.write(result);counts['ready_targets']+=1;counts['ready_source_groups']+=len(members)
            counts['ready_leaf_level'+str(parent['next_leaf_level'])]+=1;by_city[parent['city']]['ready_targets']+=1
            if len(members)>1:counts['coalesced_same_Decimal_targets']+=1;counts['coalesced_extra_source_groups']+=len(members)-1
            ps=parent_summary.setdefault(parentID,dict(actual_parent=parent,ready_house_targets=0,source_groups=0))
            need(ps['actual_parent']==parent,'One immutable true parent plan');ps['ready_house_targets']+=1;ps['source_groups']+=len(members)
        if counts['targets']%5000==0:
            rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss;need(rss<=MAX_RSS_KIB,'Actual RSS ceiling500MiB')
            print(json.dumps(dict(targets=counts['targets'],ready=counts['ready_targets'],held=counts['held_targets'],max_RSS_KiB=rss)),flush=True)
    need(counts['source_groups_joined']==76849 and counts['ready_targets']+counts['held_targets']==counts['targets'],'All absent join targets accounted')
    summaries=IO['Ledger'](OUT/'ready-parent-summary.jsonl.gz')
    for ID,summary in sorted(parent_summary.items()):summaries.write(summary)
    artifacts=dict(ready=ready.close(),held=held.close(),ready_parent_summary=summaries.close(),progress=progress.close(),
        joined_source_groups=joined_artifact,sorted_joined_runs=runmetas)
    rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss;need(rss<=MAX_RSS_KIB,'Actual RSS ceiling500MiB')
    proof=dict(schema='country-lane-absent-prepared-source-join/v1',started_utc=started,finished_utc=datetime.now(timezone.utc).isoformat(),
        all_assigned_checks_passed=True,script_sha256=sha(Path(__file__).read_bytes()),inputs=inputs,stream_inputs=streams,
        sorted_joined_run_readbacks=run_readbacks,join_run_buffer_limit_rows=5000,
        prior_failed_partial_source_scan=dict(rows_at_guard=2600000,full_EOF_verified=False,receipt='failed-initial-tool-receipt.json'),
        complete_corrected_prepared_source_passes=1,overall_prepared_source_read_attempts=2,
        counts=dict(counts),held_reason_target_counts=dict(reasons_count),city_target_counts={c:dict(v) for c,v in by_city.items()},
        ready_actual_parent_count=len(parent_summary),source_coordinate_conflict_or_unavailable_keys=conflict_keys,
        artifacts=artifacts,max_RSS_KiB=rss,max_RSS_limit_KiB=MAX_RSS_KIB,elapsed_seconds=time.monotonic()-t0,
        source_order_proof='Matched groupIDs strictly increasing; prepared group_id exactly equals1-based line number. All76849absent keys matched once.',
        provenance_policy='Exact raw/normalized addresses/native source classification/groupIDs/node counts/ref pins. Complete node IDs recovered from prepared group members only.',
        coordinate_policy='No selection for conflict. Same exact Decimal point only per actual native parent+integer house; differing points/refs/parent plans held.',
        geometry_policy='21complete city boundaries source and exact raw24 both cover same city. Kaohsiung37exact districts use pinned membership engine for both points; no city union or district assignment.',
        prepared_group_plain_digest_status='Newly established during this single pass; no inherited plaintext digest exists. Compressed pin, EOF, row count and stat verified.',
        stock_parent_and_flags_modified=False,new_native_records_encoded=False,native_write_ready=False,
        original_map_accessed=False,native_CPU_executed=False,closed_suites_replayed=False,PBF_accessed=False,
        exact_ready_source_ledgers_accessed=False,MDR_JAI_IMG_DB_USB_ZIP_canonical_or_services_modified=False,
        full_Taiwan_native_update_complete=False,
        limits=['Ready target count is source-joined geometry-qualified planning only; no new leaves written or installed.',
            'Actual tree overlay must preserve every old parent/group/path/flag before writing. No JAI family append or consumer assumptions.',
            'City geometry outside Kaohsiung does not verify geospatial district, road entrance or routing.',
            'Conflicted groups have completeIDs but only an unselected historical first-point witness, not all node-specific coordinates.',
            'Native search/order/UI/route/device acceptance, unknown flags, new streets/admins and pending boundaries remain unproved.'])
    (OUT/'proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    receipt=dict(exit_status=0,source_rows=rows,joined_absent_groups=joined_count,counts=dict(counts),max_RSS_KiB=rss,
        source_sha256=proof['script_sha256'],proof_sha256=sha((OUT/'proof.json').read_bytes()),elapsed_seconds=proof['elapsed_seconds'])
    (OUT/'execution-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt),flush=True)

if __name__=='__main__':
    try:main()
    except Exception as exc:
        (OUT/'unfinalized-failure.json').write_text(json.dumps(dict(exception=repr(exc),source_sha256=sha(Path(__file__).read_bytes())),indent=2)+'\n')
        raise
