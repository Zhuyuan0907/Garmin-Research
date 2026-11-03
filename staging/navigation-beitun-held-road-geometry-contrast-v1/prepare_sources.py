#!/usr/bin/env python3
"""Two full groups from the18KB frozen capture; four new membership calls only."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from decimal import Decimal, ROUND_HALF_UP
import gzip,hashlib,json,importlib.util,difflib,re

ROOT=Path('/root/garmin'); HERE=Path(__file__).resolve().parent
CAP=ROOT/'staging/navigation-beitun-source-capture-corrected-v1'
GEO=ROOT/'staging/navigation-beitun-district-geometry-v1'
OLD=ROOT/'staging/navigation-Dunfu6-compiled-road-linkage-v1'
READS=[]; CACHE={}

def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
    s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p):
    p=Path(p);before=stat(p);b=p.read_bytes();assert stat(p)==before
    READS.append(dict(path=str(p.relative_to(ROOT)),byte_range=[0,len(b)],bytes=len(b),sha256=sha(b),stat=before))
    CACHE[str(p)]=b;return b
def save(n,d):
    assert not(HERE/n).exists(),n
    (HERE/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def checksealed(directory,seal,name):
    b=read(directory/name);row=seal['files'][name]
    assert len(b)==row['bytes'] and sha(b)==row.get('sha256',row.get('SHA256'))
    return b

def main():
    assert not(HERE/'prepared-inputs.json').exists()
    cs=json.loads(read(CAP/'SEAL.json'));cp=json.loads(checksealed(CAP,cs,'proof.json'))
    zipped=checksealed(CAP,cs,'missing-source-groups.jsonl.gz')
    pin=cp['complete_groups_gzip']
    assert len(zipped)==18867==pin['compressed_bytes'] and sha(zipped)==pin['SHA256']=='937cfd4cd38ee374e99bdbb08d0a2546b6d9a40e6ea71bdd47408d309dfdc221'
    plain=gzip.decompress(zipped)
    assert len(plain)==pin['decompressed_bytes']==383921 and sha(plain)==pin['decompressed_SHA256']=='784bca17b70321b36a084b7a987849207a66fe34733b7b9ae28fcfb9ad24d031'
    lines=plain.splitlines(keepends=True);assert len(lines)==102==pin['complete_rows'] and plain.endswith(b'\n')
    desired=['景賢六街','榮興街'];found={}
    for i,line in enumerate(lines,1):
        d=json.loads(line);name=d['original_prepared_group']['raw_address'][2]
        if name in desired:found.setdefault(name,[]).append((i,line,d))
    assert all(len(found[n])==1 for n in desired)
    holdmap=json.loads(checksealed(CAP,cs,'hold-mapping.json'))
    holdmap={v['candidate_literal']:v for v in holdmap['roster']}
    gs=json.loads(read(GEO/'sealed-files.json'))
    geometry_membership_api=read(GEO/'beitun_membership.py')
    apirow=next(r for r in gs['files'] if r['path']==str((GEO/'beitun_membership.py').relative_to(ROOT)))
    assert len(geometry_membership_api)==apirow['bytes'] and sha(geometry_membership_api)==apirow['sha256']
    spec=importlib.util.spec_from_file_location('frozen_beitun_new_points',GEO/'beitun_membership.py')
    mod=importlib.util.module_from_spec(spec)
    # Execute only the already pinned API definitions, without importing through a second source read.
    exec(compile(geometry_membership_api,str(GEO/'beitun_membership.py'),'exec'),mod.__dict__)
    def tracked_pinned(p,pin):
        b=read(p);assert (len(b),sha(b))==pin;return b
    mod.pinned=tracked_pinned  # filesystem read accounting only; membership math is unchanged.
    membership=mod.BeitunMembership(directory=GEO)
    groups=[];selected=[];names=[];Q=Decimal(360)/Decimal(1<<24)
    for name in desired:
        capture_line,line,d=found[name][0];selected.append(line)
        g=d['original_prepared_group'];c=d['classification'];raw=g['raw_address'];key=g['normalized_planning_key']
        assert raw[:3]==['臺中市','北屯區',name] and key[:3]==['台中市','北屯區',name]
        assert g['group_id'] in holdmap[name]['group_ids'] and holdmap[name]['source_group_capture_lines']==[capture_line]
        assert g['source_node_count']==len(g['source_ids']) and g['source_ids'][0]==d['original_first_node_ID']
        p=c['point'];assert g['first_coordinate']==p['original_first_coordinate']
        raw24=[int((Decimal(v)/Q).to_integral_value(rounding=ROUND_HALF_UP))for v in g['first_coordinate']]
        assert raw24==p['native24']
        conflict=g['different_coordinate_nodes']!=0 or g['needs_coordinate_review'] or not g['coordinate_selection_ready']
        src=membership.assess_source_point(key[0],key[1],*g['first_coordinate'])
        nr=membership.assess_raw24(key[0],key[1],*raw24)
        eligible=not conflict and src['eligible'] and nr['eligible'] and not c['hard_data_holds']
        row=dict(literal=name,capture_line=capture_line,source_group_full=d,complete_hold_mapping=holdmap[name],
          actual_source_membership=src,actual_raw24_membership=nr,coordinate_conflict=conflict,
          eligible_for_readonly_road_contrast=eligible,existing_holds_preserved=True,
          all_holds=list(c['all_hold_reasons'])+([]if eligible else['new_geometry_or_coordinate_data_hold']),
          official_alias_address_route_or_write_ready=False)
        groups.append(row)
        if eligible:
            names += [name]+[v['stock_label']for v in c['near_stock_witnesses']]+[v['stock_label']for v in c['prefix_stock_witnesses']]
    (HERE/'selected-capture-lines.jsonl').write_bytes(b''.join(selected))
    save('candidate-groups.json',dict(schema='two-held-source-groups-and-new-Beitun-point-cases/v1',groups=groups,
       complete_capture_input=dict(compressed_bytes=len(zipped),compressed_sha256=sha(zipped),plain_bytes=len(plain),plain_sha256=sha(plain),rows=102,EOF_and_gzip_crc_passed=True),
       exact_original_lines_preserved=True,actual_new_membership_calls=dict(sourcepoint=2,raw24=2),
       old368_or_Chongde_controls_executed=False,full_source_or_PBF_opened=False))
    areas=ROOT/'staging/maps/Taiwan_OSM_20261001_UTF8/tiles/areas.list'
    args=ROOT/'staging/navigation-repair-v2/tiles.args'
    ab=read(areas);tb=read(args)
    tileargs={}
    for block in tb.decode().strip().split('\n\n'):
        f=dict(l.split(': ',1)for l in block.splitlines());tileargs[Path(f['input-file']).stem.split('.')[0]]=f['mapname']
    bounds=[]
    for m in re.finditer(r'^(\d+): (-?\d+),(-?\d+) to (-?\d+),(-?\d+)$',ab.decode(),re.M):
        t,*v=m.groups();v=list(map(int,v));bounds.append((t,v))
    selection=[]
    for row in groups:
        if not row['eligible_for_readonly_road_contrast']:continue
        p=row['source_group_full']['classification']['point'];raw24=p['native24'];src=list(map(Decimal,p['original_first_coordinate']))
        hit=[]
        for t,v in bounds:
            contains=v[0]<=raw24[0]<=v[2] and v[1]<=raw24[1]<=v[3]
            source_contains=Decimal(v[0])*Q<=src[0]<=Decimal(v[2])*Q and Decimal(v[1])*Q<=src[1]<=Decimal(v[3])*Q
            if contains and source_contains:hit.append(dict(split_tile=t,Search_v2_tile=tileargs[t],bbox_native24=[v[:2],v[2:]],both_points_in_bounds=True))
        selection.append(dict(literal=row['literal'],sourcepoint=p['original_first_coordinate'],raw24=raw24,containing_tiles=hit))
    unique=sorted({h['Search_v2_tile']for r in selection for h in r['containing_tiles']})
    valid=bool(selection) and all(len(r['containing_tiles'])==1 for r in selection) and len(unique)==1
    save('tile-selection.json',dict(schema='maximum-one-tile-two-point-selection/v1',selection=selection,
       maximum_tiles=1,selected_tiles=unique if valid else[],one_tile_contains_all_eligible_points=valid,
       stop_if_no_common_single_tile=True,no_tile_opened_during_selection=True))
    oldseal=json.loads(read(OLD/'SEAL.json'));java=checksealed(OLD,oldseal,'ReadRoadGeometryV2.java').decode()
    assert java.count('l.getText().equals("敦富六街")')==1
    names=sorted(set(names));replacement='Arrays.asList('+','.join(json.dumps(s,ensure_ascii=False)for s in names)+').contains(l.getText())'
    copy=java.replace('l.getText().equals("敦富六街")',replacement)
    (HERE/'ReadRoadGeometryV2.java').write_text(copy)
    (HERE/'reader-source.diff').write_text('\n'.join(difflib.unified_diff(java.splitlines(),copy.splitlines(),fromfile=str((OLD/'ReadRoadGeometryV2.java').relative_to(ROOT)),tofile=str((HERE/'ReadRoadGeometryV2.java').relative_to(ROOT)),lineterm=''))+'\n')
    # Old tile/JAR pins are inherited here; actual selected tile is opened only in the next ordinary parser step.
    inherited=json.loads(checksealed(OLD,oldseal,'inputs-at-run.json'))
    build=read(ROOT/'staging/navigation-repair-v2/build-manifest.json')
    package=read(ROOT/'staging/navigation-repair-v2/package/manifest.json')
    bm=json.loads(build);pm=json.loads(package)
    assert bm['exit_code']==0 and bm['family_id']==7053 and pm['new_map']['sha256']==bm['image_sha256']
    assert pm['compiled_image_reference']==bm['image']
    for row in READS:
        assert stat(ROOT/row['path'])==row['stat']
    save('prepared-inputs.json',dict(schema='held-road-readonly-preparation/v1',input_read_receipts=READS,
      unique_target_labels=names,ordinary_parser_allowed=valid,
      selected_tile=str((ROOT/'staging/navigation-repair-v2/compiled'/f'{unique[0]}.img').relative_to(ROOT))if valid else None,
      inherited_selected_tile_and_java_dependencies_sha256=inherited,
      inherited_Search_v2_image_sha256_not_rehashed=bm['image_sha256'],maximum_tiles=1,
      tracked_API_FS_reader_only=True,geometry_function_or_result_hooks=False,
      no_old_point_controls_no_native_CPU_no_device=True,handles_closed=True))
    print(json.dumps(dict(result='PREPARED two exact held groups; new district point cases',
      groups=[dict(literal=r['literal'],group_id=r['source_group_full']['original_prepared_group']['group_id'],
       source_ids=r['source_group_full']['original_prepared_group']['source_ids'],
       source_inside=r['actual_source_membership']['eligible'],raw24_inside=r['actual_raw24_membership']['eligible'],
       road_contrast_eligible=r['eligible_for_readonly_road_contrast'])for r in groups],
      selected_tiles=unique if valid else[],target_labels=names,holds_preserved=True,IMG_bytes=0,CPU_cases=0),ensure_ascii=False))

if __name__=='__main__':main()
