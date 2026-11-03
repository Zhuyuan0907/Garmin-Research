#!/usr/bin/env python3
"""Finite house184 inspection: frozen source point/geometry + bounded new NET reads."""
import ast
import base64
import hashlib
import json
import math
import mmap
import struct
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
BASE=Path(__file__).resolve().parent
MDR_READER=ROOT/'staging/navigation-mdr-query-v2/query_candidate_mdr_v3.py'
GEOMETRY=ROOT/'staging/navigation-road-regression-v2/new-road-geometry-v2.json'
SOURCE=ROOT/'staging/navigation-house184-v1/source-address184-proof.json'
MANIFEST=ROOT/'staging/navigation-repair-v2/build-manifest.json'


def need(value,message):
    if not value:raise ValueError(message)


def sha(path):
    need(path.stat().st_size<2*1024*1024,'Small dependency digest only')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def distance(point,a,b):
    scale=111320;cos=math.cos(math.radians(point[0]))
    ax=(a[1]-point[1])*scale*cos;ay=(a[0]-point[0])*scale
    bx=(b[1]-point[1])*scale*cos;by=(b[0]-point[0])*scale
    dx=bx-ax;dy=by-ay
    t=max(0,min(1,-(ax*dx+ay*dy)/(dx*dx+dy*dy))) if dx*dx+dy*dy else 0
    return math.hypot(ax+t*dx,ay+t*dy)


def image_class():
    # Reuse only immutable file-allocation helper definitions by static AST;
    # no imports/main/Sort/MDR checks from the completed reader are executed.
    need(sha(MDR_READER)=='c5b4a317cef765e88da2e29f9e4bda80b8bbc9f1221fe1531b31c29e189b665c','Frozen Image helper source')
    tree=ast.parse(MDR_READER.read_text())
    nodes=[n for n in tree.body if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name in ['Image','need','uint']]
    scope=dict(mmap=mmap,struct=struct,Counter=Counter)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(MDR_READER),'exec'),scope)
    return scope['Image']


def parse_net(image,tile,offset,known_distance):
    key=tile+'.NET';header=image.read(key,0,55)
    need(header[2:12]==b'GARMIN NET','NET identity')
    start,size=struct.unpack_from('<II',header,21)
    need(header[29]==0 and start+size<=image.components[key]['bytes'],'NET1 extent/shift')
    need(0<=offset<size,'Selected NET1 offset')
    data=image.read(key,start+offset,min(4096,size-offset));pos=0
    def take(n):
        nonlocal pos
        need(pos+n<=len(data),'Bounded selected NET record')
        result=int.from_bytes(data[pos:pos+n],'little');pos+=n;return result
    labels=[]
    for _ in range(4):
        v=take(3);labels.append(v&0x7fffff)
        if v&0x800000:break
    else:raise ValueError('NET label termination')
    flags=take(1);length=take(3);counts=[]
    for _ in range(24):
        count=take(1);counts.append(count&0x7f)
        if count&0x80:break
    else:raise ValueError('NET level counts termination')
    for count in counts:take(count*3)
    row=dict(tile=tile,net1_offset=offset,nearest_source_geometry_distance_m=known_distance,
        actual_NET_flags=hex(flags),label_offsets=labels,raw_road_length=length,level_polyline_counts=counts,
        number_block_present=False,number_stream_bytes=0)
    if flags&0x10:
        flags2=take(2);nodes=flags2&0x3ff
        labelheader=image.read(tile+'.LBL',0,196)
        citybytes=int.from_bytes(labelheader[63:67],'little');cityitem=int.from_bytes(labelheader[67:69],'little')
        zipbytes=int.from_bytes(labelheader[118:122],'little');zipitem=int.from_bytes(labelheader[122:124],'little')
        need(cityitem==5 and citybytes%5==0 and zipitem==3 and zipbytes%3==0,'LBL city/zip layout')
        citysize=max(1,((citybytes//cityitem).bit_length()+7)//8)
        zipsize=max(1,((zipbytes//zipitem).bit_length()+7)//8)
        fields={};rawfields={}
        for kind,shift,width in [('zip',10,zipsize),('city',12,citysize)]:
            flag=(flags2>>shift)&3
            if flag in (0,1):
                n=take(flag+1);need(pos+n<=len(data),'NET '+kind+' block bounds')
                rawfields[kind]=data[pos:pos+n].hex();pos+=n
                fields[kind]=dict(flag=flag,block_bytes=n)
            elif flag==2:fields[kind]=dict(flag=flag,single_local_index=take(width))
            else:fields[kind]=dict(flag=flag,absent=True)
        numberflag=(flags2>>14)&3
        row.update(address_flags2=hex(flags2),number_nodes=nodes,number_flag=numberflag,
            swapped_default_styles=bool(flags&0x20),address_fields=fields,address_field_raw_hex=rawfields)
        if numberflag in (0,1):
            n=take(numberflag+1);need(pos+n<=len(data),'NET number block bounds')
            numberdata=data[pos:pos+n];pos+=n
            row.update(number_block_present=n>0,number_stream_bytes=n,number_stream_hex=numberdata.hex())
        elif numberflag!=3:row['unsupported_number_flag']=numberflag
    row['selected_NET_record_bytes_parsed']=pos
    return row


def main():
    out=BASE/'house184-compiled-NET-inspection-v1.json'
    need(not out.exists(),'Do not rerun terminal finite inspection')
    source=json.loads(SOURCE.read_text());matches=[r for r in source['house184_prefix_matches'] if r['id']=='8528998711']
    need(len(matches)==1,'Exact source point');house=matches[0];point=house['coordinate']
    geometry=json.loads(GEOMETRY.read_text());near=[]
    for road in geometry:
        if '民權路' not in road['labels']:continue
        candidates=[distance(point,a,b) for line in road['segments'] for a,b in zip(line,line[1:])]
        if candidates and min(candidates)<=150:
            near.append(dict(tile=Path(road['file']).stem,netOffset=road['netOffset'],distance_m=min(candidates),
                             inherited_compiled_cities=road['cities']))
    need(near,'No selected compiled road within official150m threshold')
    near.sort(key=lambda r:r['distance_m'])
    manifest=json.loads(MANIFEST.read_text());need(manifest['state']=='compiled_candidate_not_device_verified' and manifest['exit_code']==0,'Frozen terminal build')
    image_path=ROOT/manifest['image'];before=image_path.stat();need(before.st_size==manifest['image_bytes'],'ROOT image size')
    image=image_class()(image_path)
    rows=[parse_net(image,r['tile'],r['netOffset'],r['distance_m']) for r in near]
    selected=[r for r in rows if r['number_block_present']]
    inputs=''.join(f"{r['tile']}\t{r['net1_offset']}\t{r['number_nodes']}\t{int(r['swapped_default_styles'])}\t{r['number_stream_hex']}\n" for r in selected)
    with (BASE/'selected-NET-number-streams-v1.tsv').open('x') as stream:stream.write(inputs)
    command=['java','-cp',str(BASE/'classes')+':'+str(ROOT/'sources/maps/mkgmap-r4924/mkgmap.jar'),'ReadHouseStreams']
    result=subprocess.run(command,input=inputs,text=True,capture_output=True)
    with (BASE/'official-number-reader-output-v1.txt').open('x') as stream:stream.write(result.stdout)
    with (BASE/'official-number-reader-stderr-v1.txt').open('x') as stream:stream.write(result.stderr)
    need(result.returncode==0,'Official bounded NumberReader helper failed')
    need(result.stdout.splitlines()[0]=='CONTROL\t0,E,24,8,O,23,13\tpassed','Official known stream control')
    decoded={}
    for line in result.stdout.splitlines()[1:]:
        f=line.split('\t');need(len(f)==8 and f[0]=='STREAM','Official reader result shape')
        specs=[];hits=[]
        for spec in f[7].split(';'):
            if not spec:continue
            pieces=spec.split(',');need(len(pieces)==7,'Number range shape');specs.append(spec)
            for side,base in [('left',1),('right',4)]:
                style=pieces[base];start,end=int(pieces[base+1]),int(pieces[base+2])
                contains=style!='N' and min(start,end)<=184<=max(start,end) and (style=='B' or style=='E')
                if contains:hits.append(dict(node_index=int(pieces[0]),side=side,style=style,start=start,end=end,includes184=True))
        decoded[(f[1],int(f[2]))]=dict(decoded_range_specs=specs,decoded_ranges_including184=hits,
            official_reader_node_counter=int(f[4]),official_reader_bit_position=int(f[5]),
            official_reader_diagnostics=base64.b64decode(f[6]).decode(),full_semantic_range_completion_claim=False)
    for row in rows:
        if row['number_block_present']:row.update(decoded[row['tile'],row['net1_offset']])
        parent=next(r for r in near if r['tile']==row['tile'] and r['netOffset']==row['net1_offset'])
        row['inherited_compiled_cities']=parent['inherited_compiled_cities']
    after=image_path.stat();need((before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
        (after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Candidate changed')
    hitrows=[r for r in rows if r.get('decoded_ranges_including184')]
    output=dict(checked_utc=datetime.now(timezone.utc).isoformat(),scope='Exact source184 plus nearest frozen compiled geometry and bounded targeted actual NET number streams only',
        all_setup_and_pointer_checks_passed=True,source_house=house,selected_roads_within150m=len(rows),
        selected_tiles=sorted(set(r['tile'] for r in rows)),actual_number_blocks=len(selected),
        compiled_number_range_including184_observed=bool(hitrows),compiled184_range_road_count=len(hitrows),selected_NET_rows=rows,
        official_number_test_reader='staging/navigation-house184-query-v1/reference/NumberReader.java',known_stream_control_passed=True,
        source_parse184_from_existing_frozen_parser=184,ROOT_candidate=dict(path=manifest['image'],bytes=manifest['image_bytes'],
            declared_sha256=manifest['image_sha256'],whole_IMG_digest_repeated=False,metadata_unchanged=True),
        logical_IMG_read_bytes_by_extension=dict(image.read_bytes),old_MDR20_checks_rerun=False,full36tiles_scanned=False,
        NET_RGN_geometry_regression_rerun=False,source_node_to_specific_compiler_road_assignment_proved=False,
        Garmin_UI_house_lookup_verified=False,original_NT_AP_carrier_update_verified=False,candidate_canonical_or_device_modified=False,
        limitations=['Existing frozen NET/RGN geometry is used to select roads, not replayed or claimed as exact compiler nearest association.',
            'Official r4924 NumberReader is a test decoder and can stop with captured stream-end diagnostics; positive184 ranges are observed, complete native query acceptance is not inferred.',
            'Range contains184 does not uniquely identify the original OSM node or prove on-device numeric query, street-city filtering or native NT/AP-format compatibility.',
            'Source city/rawstreet style path is separately reviewed; this bounded reader does not reconstruct full style/bounds compiler state.',
            'No USB, candidate mutation, wholeIMG/backup digest, original native probe, nationwide build or canonical changes.'])
    with out.open('x') as stream:stream.write(json.dumps(output,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(proof=str(out),selected_roads=len(rows),number_blocks=len(selected),range184_roads=len(hitrows),
        hit_road_keys=[(r['tile'],r['net1_offset']) for r in hitrows]),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
