#!/usr/bin/env python3
"""One relation from existing small Taiwan admin extract, not full Taiwan PBF."""
import ast
from collections import defaultdict
from datetime import datetime,timezone
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
SOURCE=ROOT/'staging/navigation-repair-v1/taiwan-admin-selected-from-source.osm.pbf'
INPUTS=[];COMMANDS=[]
DISTRICT_ID=2959946;CITY_ID=2921154


def need(ok,text):
    if not ok:raise ValueError(text)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def signature(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read(path,maximum,expected=None):
    before=signature(path);need(before[2]<=maximum,'Bounded assigned input')
    raw=path.read_bytes();after=signature(path);need(before==after,'Input immutable stat')
    if expected:need(sha(raw)==expected,'Pinned assigned input '+str(path))
    INPUTS.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),
        stat_before=before,stat_after=after,stat_unchanged=True))
    return raw


def load(path,maximum,expected=None):return json.loads(read(path,maximum,expected))


def save(name,value):
    raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    with (HERE/name).open('xb') as handle:handle.write(raw);handle.flush();os.fsync(handle.fileno())
    return dict(path=str((HERE/name).relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))


def command(args,label):
    process=subprocess.run(args,capture_output=True,check=False)
    (HERE/(label+'.stdout')).write_bytes(process.stdout)
    (HERE/(label+'.stderr')).write_bytes(process.stderr)
    row=dict(command=args,actual_exit_code=process.returncode,stdout_bytes=len(process.stdout),
             stdout_sha256=sha(process.stdout),stderr_bytes=len(process.stderr),stderr_sha256=sha(process.stderr))
    COMMANDS.append(row);need(process.returncode==0,'Actual external command '+label)
    return process.stdout


def main():
    started=datetime.now(timezone.utc).isoformat()
    candidate=load(ROOT/'staging/navigation-native-new-street-source-example-v1/candidate.json',11000,
        'd26c874e67b87232836f0810acaaa5a779251481d853e5c31efc20ccfb4c817c')
    closure=load(ROOT/'staging/navigation-repair-v1/package/verification/admin-boundary-closure.json',150000)
    witness=next(r for r in closure['roots'] if r['id']==DISTRICT_ID)
    need(witness['name']=='北屯區' and witness['complete_reference_closed_geometry'] and
         not witness['missing_way_ids'] and not witness['missing_node_ids'], 'Exact older individually closed Beitun witness')
    roots=load(ROOT/'staging/navigation-road-coverage-v1/native-taiwan-admin-roots.json',80000)
    city=next(r for r in roots['municipality_city_roots'] if r['id']==CITY_ID)
    need(city['name']=='臺中市' and city['ISO3166-2']=='TW-TXG','Exact source Taichung city root')
    source_before=signature(SOURCE)
    read(SOURCE,4400000,'5b8cd8d1de51a55446abc2d42164244c909e1bc70cadc55fe20fd9808e949c7d')
    metadata_path=HERE/'source-city-parent-only.osm'
    command(['osmium','getid','--no-progress','-f','osm','-o',str(metadata_path),str(SOURCE),'r'+str(CITY_ID)],'get-city-parent')
    metadata_xml=read(metadata_path,20000)
    parent_relations=ET.fromstring(metadata_xml).findall('relation')
    need(len(parent_relations)==1 and int(parent_relations[0].get('id'))==CITY_ID,'Exact source parent metadata only')
    parent=parent_relations[0]
    parent_tags={t.get('k'):t.get('v') for t in parent.findall('tag')}
    need(parent_tags.get('name')=='臺中市' and parent_tags.get('ISO3166-2')=='TW-TXG','Literal source city parent name/ISO')
    members=[dict(type=m.get('type'),ref=int(m.get('ref')),role=m.get('role')) for m in parent.findall('member')]
    selected_members=[m for m in members if m['type']=='relation' and m['ref']==DISTRICT_ID]
    need(selected_members==[dict(type='relation',ref=DISTRICT_ID,role='subarea')],'Actual source city→district subarea relationship')
    extracted_path=HERE/'Beitun-complete-relation.osm'
    command(['osmium','getid','--no-progress','-r','-f','osm','-o',str(extracted_path),str(SOURCE),'r'+str(DISTRICT_ID)],'get-Beitun-references')
    extract_xml=read(extracted_path,2000000)
    xml=ET.fromstring(extract_xml)
    relations=xml.findall('relation')
    need(len(relations)==1 and int(relations[0].get('id'))==DISTRICT_ID,'Exactly one relation plus references, no city/district expansion')
    relation=relations[0]
    tags={t.get('k'):t.get('v') for t in relation.findall('tag')}
    need(tags.get('name')=='北屯區' and tags.get('boundary')=='administrative' and tags.get('admin_level')=='7',
         'Literal target source administrative name and level')
    nodes={int(n.get('id')):(n.get('lat'),n.get('lon')) for n in xml.findall('node')}
    ways={int(w.get('id')):[int(n.get('ref')) for n in w.findall('nd')] for w in xml.findall('way')}
    relation_members=[dict(type=m.get('type'),ref=int(m.get('ref')),role=m.get('role')) for m in relation.findall('member')]
    boundary_members=[m for m in relation_members if m['type']=='way' and m['role'] in ('outer','inner')]
    need(boundary_members and all(m['ref'] in ways for m in boundary_members),'All actual boundary member ways present')
    need(all(n in nodes for refs in ways.values() for n in refs),'All actual way node references present')
    need(not any(m['type']=='relation' for m in relation_members),'No undeclared nested administrative relations in this narrow export')
    command(['osmium','check-refs','--no-progress','-r',str(extracted_path)],'check-extracted-references')
    exported=command(['osmium','export','--geometry-types=polygon','-u','type_id','-f','geojsonseq',str(extracted_path)],'export-Beitun-geometry')
    need(len(exported)<1000000,'Single district exported geometry cap')
    features=[json.loads(line.lstrip('\x1e')) for line in exported.decode().splitlines() if line.strip('\x1e\n ')]
    selected=[f for f in features if f.get('properties',{}).get('name')=='北屯區' and
              str(f.get('properties',{}).get('admin_level'))=='7']
    need(len(selected)==1,'Exactly one literal Beitun feature')
    feature=selected[0];geometry=feature['geometry']
    if geometry['type']=='Polygon':geometry=dict(type='MultiPolygon',coordinates=[geometry['coordinates']])
    need(geometry['type']=='MultiPolygon' and len(geometry['coordinates'])==1,'One accepted complete district outer polygon')
    need(len(geometry['coordinates'][0])==1 and all(r[0]==r[-1] and len(r)>=4 for r in geometry['coordinates'][0]),
         'Closed exported outer and no guessed inner topology')
    source_after=signature(SOURCE);need(source_before==source_after,'Existing small admin PBF remains immutable')
    geometry_artifact=save('geometry.json',geometry)
    engine_path=ROOT/'staging/navigation-country-merge-independent-review-v1/review_country_merge.py'
    engine_raw=read(engine_path,36000,'7490c4015dc16f4fa8e69d8bb45cdf3f0c6c2ad93afcf1093c44d0cb3d9852ec')
    tree=ast.parse(engine_raw);names={'WindingRing','WindingCity'}
    selected_AST=ast.Module(body=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name in names],type_ignores=[])
    need({n.name for n in selected_AST.body}==names,'Existing pure exact rational containment API only')
    namespace=dict(Decimal=Decimal,defaultdict=defaultdict,need=need)
    exec(compile(selected_AST,str(engine_path),'exec'),namespace)
    engine=namespace['WindingCity'](geometry)
    point=candidate['sourcepoint'];scaled=[Decimal(x)*10_000_000 for x in point]
    need(all(x==x.to_integral_value() for x in scaled),'Original OSM point precision')
    signed=[u-(1<<24) if u&(1<<23) else u for u in candidate['raw24']]
    source_inside=engine.covers(int(scaled[1]),int(scaled[0]))
    quantized_inside=engine.covers(signed[1]*3515625,signed[0]*3515625,16384)
    need(source_inside and quantized_inside,'Sole actual source and exact raw24 point inside same literal source district')
    membership=save('source-membership.json',dict(schema='explicit-source-Beitun-district-membership/v1',
        city='台中市',source_city='臺中市',district='北屯區',source_city_relation_id=CITY_ID,
        source_district_relation_id=DISTRICT_ID,source_parent_tags=parent_tags,
        actual_source_parent_subarea_member=selected_members[0],source_district_tags=tags,
        native_city=candidate['native_city'],native_district=candidate['native_district'],
        source_native_name_policy='Exact district text; explicit 臺中市 source→台中市 original native city spelling only.',
        complete_reference_closed_geometry=True,geometry=geometry_artifact,
        source_group_ids=candidate['source_group_ids'],source_ids=candidate['source_ids'],
        sourcepoint=point,raw24=candidate['raw24'],sourcepoint_inside_explicit_source_district=source_inside,
        exact_quantized_raw24_inside_same_source_district=quantized_inside,
        native_district_territory_or_device_acceptance_proved=False,official_street_alias_authenticity_proved=False))
    proof=save('proof.json',dict(schema='single-existing-admin-Beitun-district-geometry/v1',
        started_utc=started,finished_utc=datetime.now(timezone.utc).isoformat(),all_assigned_geometry_preparation_checks_passed=True,
        source_inputs=INPUTS,actual_external_commands=COMMANDS,script_sha256=sha(Path(__file__).read_bytes()),
        original_admin_source_stat_unchanged=True,original_admin_bytes=source_before[2],
        old_closure_selected_relations=closure['selected_admin_relation_count'],
        old_closure_complete_relations=sum(bool(r.get('complete_reference_closed_geometry')) for r in closure['roots']),
        old_all_selected_closed=closure['all_selected_admin_geometry_closed'],individual_old_Beitun_closed_witness=witness,
        actual_source_parent_subarea_membership_verified=True,source_city_relation_id=CITY_ID,source_district_relation_id=DISTRICT_ID,
        actual_recursive_extract=dict(nodes=len(nodes),ways=len(ways),relations=len(relations),boundary_way_members=len(boundary_members),
            all_member_way_and_node_refs_present=True,osmium_check_refs_exit_code=0),
        actual_export=dict(total_features=len(features),literal_selected_features=1,feature_id=feature.get('id'),properties=feature['properties'],
            polygons=len(geometry['coordinates']),rings=sum(len(p) for p in geometry['coordinates']),vertices=sum(len(r) for p in geometry['coordinates'] for r in p)),
        geometry=geometry_artifact,source_membership=membership,
        source_and_exact_quantized_point_inside_same_source_district=True,
        winding_pure_API_sha256=sha(engine_raw),winding_pure_AST_sha256=sha(ast.dump(selected_AST,include_attributes=False).encode()),
        historical_main_or_cases_executed=False,full_Taiwan_PBF_opened_or_extracted=False,web_browsed=False,
        alias_or_official_street_validated=False,native_prefix_query_UI_device_acceptance_proved=False,
        other_sealed_scope_mutated=False,device_IO=False,install_candidate=False,
        limits=['One primary OSM administrative source district polygon and actual source parent subarea relationship; not an official street-name verification.',
                'Source/raw24 points have now passed this district gate in this separate scope; prior fullDB geometry-gap proof remains unchanged.',
                'Reference closure and exported rings verified; no additional polygon self-intersection/physical territory/route/device validation claimed.']))
    print(json.dumps(dict(all_assigned_geometry_preparation_checks_passed=True,
        source_relation=DISTRICT_ID,source_parent=CITY_ID,source_and_raw24_district_gate=True,
        nodes=len(nodes),ways=len(ways),geometry=geometry_artifact,membership=membership,proof=proof),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
