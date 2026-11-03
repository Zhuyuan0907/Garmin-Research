#!/usr/bin/env python3
"""Exact district containment, ordinary compiled-road distances, no alias decision."""
import sys
sys.dont_write_bytecode=True
import ast,hashlib,json,math,re
from pathlib import Path
from fractions import Fraction
from decimal import Decimal,ROUND_HALF_UP
from collections import defaultdict
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
READS=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p,pin=None):
 before=stat(p);b=p.read_bytes();assert stat(p)==before
 if pin:assert (len(b),sha(b))==pin
 READS.append(dict(path=str(p.relative_to(ROOT)),byte_range=[0,len(b)],bytes=len(b),sha256=sha(b),stat=before))
 return b
def save(n,d):
 assert not (HERE/n).exists()
 (HERE/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def need(ok,message):
 if not ok:raise ValueError(message)
def cross(a,b):return a[0]*b[1]-a[1]*b[0]
def edges_of(g):
 edges=[]
 assert g['type']=='MultiPolygon'
 for poly in g['coordinates']:
  for ring in poly:
   points=[]
   for lon,lat in ring:
    vs=[Decimal(str(v))*10_000_000 for v in (lon,lat)]
    assert all(v==v.to_integral_value() for v in vs)
    points.append(tuple(int(v) for v in vs))
   assert points[0]==points[-1]
   edges.extend(zip(points,points[1:]))
 return edges
def complete_segment_inside(engine,edges,a,b,den):
 """Partition at every exact polygon intersection; test every open interval.

 a/b are integer x/y numerators with common positive denominator den in OSM1e7 units.
 No endpoints-only inference: holes and boundary-crossing segments are rejected.
 """
 assert den>0
 if not engine.covers(*a,den) or not engine.covers(*b,den):return False
 r=(b[0]-a[0],b[1]-a[1]);rr=r[0]*r[0]+r[1]*r[1]
 if not rr:return True
 cuts={Fraction(0),Fraction(1)}
 bbox=(min(a[0],b[0]),min(a[1],b[1]),max(a[0],b[0]),max(a[1],b[1]))
 for c,d in edges:
  c=(c[0]*den,c[1]*den);d=(d[0]*den,d[1]*den)
  if max(c[0],d[0])<bbox[0] or min(c[0],d[0])>bbox[2] or max(c[1],d[1])<bbox[1] or min(c[1],d[1])>bbox[3]:continue
  s=(d[0]-c[0],d[1]-c[1]);q=(c[0]-a[0],c[1]-a[1]);div=cross(r,s)
  if div:
   t=Fraction(cross(q,s),div);u=Fraction(cross(q,r),div)
   if 0<=t<=1 and 0<=u<=1:cuts.add(t)
  elif cross(q,r)==0:
   for p in (c,d):
    t=Fraction((p[0]-a[0])*r[0]+(p[1]-a[1])*r[1],rr)
    if 0<=t<=1:cuts.add(t)
 ts=sorted(cuts)
 for t0,t1 in zip(ts,ts[1:]):
  t=(t0+t1)/2
  if not engine.covers(a[0]*t.denominator+r[0]*t.numerator,
                       a[1]*t.denominator+r[1]*t.numerator,den*t.denominator):return False
 return True
def distance(point,a,b):
 """Local equirectangular meter approximation, not route distance."""
 lat,lon=map(float,point);sx=111320*math.cos(math.radians(lat));sy=110574
 ax=(float(a[1])-lon)*sx;ay=(float(a[0])-lat)*sy
 bx=(float(b[1])-lon)*sx;by=(float(b[0])-lat)*sy
 dx=bx-ax;dy=by-ay;t=0 if dx*dx+dy*dy==0 else max(0,min(1,-(ax*dx+ay*dy)/(dx*dx+dy*dy)))
 return dict(distance_m=math.hypot(ax+t*dx,ay+t*dy),projection_t=t,
  projected_lat_lon=[float(a[0])+t*(float(b[0])-float(a[0])),float(a[1])+t*(float(b[1])-float(a[1]))])
def trace_receipt(text,tile,tilebytes):
 positions={};ranges=[];mappings=[];opens=closes=signal_lines=0
 target=str(tile)
 for line in text.splitlines():
  if '--- SIG' in line:signal_lines+=1;continue
  if target not in line:continue
  if 'openat(' in line:
   m=re.search(r'= (\d+)<',line);assert m,line
   positions[int(m[1])]=0;opens+=1
  elif 'lseek(' in line:
   m=re.search(r'lseek\((\d+)<[^>]+>, (-?\d+), (SEEK_\w+)\) = (-?\d+)',line);assert m,line
   assert int(m[4])>=0;positions[int(m[1])]=int(m[4])
  elif 'pread64(' in line:
   m=re.search(r'pread64\((\d+)<[^>]+>, .*?, (\d+), (\d+)\) = (\d+)',line);assert m,line
   count=int(m[4]);at=int(m[3]);ranges.append(dict(offset=at,bytes=count,syscall='pread64'))
  elif re.search(r'\bread\(',line):
   m=re.search(r'read\((\d+)<[^>]+>, .*?, (\d+)\) = (\d+)',line);assert m,line
   fd=int(m[1]);count=int(m[3]);assert fd in positions
   ranges.append(dict(offset=positions[fd],bytes=count,syscall='read'));positions[fd]+=count
  elif 'mmap(' in line:mappings.append(line)
  elif 'close(' in line:
   m=re.search(r'close\((\d+)<[^>]+>\) = 0',line);assert m,line
   del positions[int(m[1])];closes+=1
  else:raise ValueError('Unaccounted selected-tile syscall '+line)
 assert opens==closes==1 and not positions and not mappings
 assert ranges and all(0<=r['offset']<=r['offset']+r['bytes']<=tilebytes for r in ranges)
 union=[]
 for a,b in sorted((r['offset'],r['offset']+r['bytes']) for r in ranges if r['bytes']):
  if union and a<=union[-1][1]:union[-1][1]=max(union[-1][1],b)
  else:union.append([a,b])
 return dict(schema='selected-tile-actual-Java-syscall-byte-ranges/v1',tile=str(tile.relative_to(ROOT)),
  successful_open_count=opens,successful_close_count=closes,reads=ranges,
  actual_read_syscall_count=len(ranges),actual_syscall_bytes_read=sum(r['bytes'] for r in ranges),
  unique_byte_ranges=union,unique_bytes_read=sum(b-a for a,b in union),mmap_count=0,
  JVM_signal_trace_lines=signal_lines,process_exit_code=0,
  signal_lines_are_not_an_original_ARM_guest_or_hardware_result=True,
  storage_medium_page_IO_not_measured=True)
def main():
 prep=json.loads(read(HERE/'prepared-inputs.json'));groups=json.loads(read(HERE/'candidate-groups.json'))['groups']
 process=json.loads(read(HERE/'reader-process.json'));rows=json.loads(read(HERE/'road-geometry.json'))
 assert process['exit_code']==0 and process['actual_invocations']==1
 assert [r['literal'] for r in groups if r['eligible_for_readonly_road_contrast']]==['景賢六街']
 tile=ROOT/prep['selected_tile'];tilepin=next(r for r in process['input_hash_read_receipts'] if r['path']==prep['selected_tile'])
 assert stat(tile)==tilepin['stat']
 trace=read(HERE/'java-tile-IO.trace').decode();io=trace_receipt(trace,tile,tilepin['bytes'])
 save('java-tile-read-receipt.json',io)
 enginepath=ROOT/'staging/navigation-country-merge-independent-review-v1/review_country_merge.py'
 enginebytes=read(enginepath,(35417,'7490c4015dc16f4fa8e69d8bb45cdf3f0c6c2ad93afcf1093c44d0cb3d9852ec'))
 tree=ast.parse(enginebytes);module=ast.Module(body=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name in {'WindingRing','WindingCity'}],type_ignores=[])
 ns=dict(Decimal=Decimal,defaultdict=defaultdict,need=need);exec(compile(module,str(enginepath),'exec'),ns)
 gpath=ROOT/'staging/navigation-beitun-district-geometry-v1/geometry.json'
 geo=json.loads(read(gpath,(144506,'c4b4c2a842af2042ca4fff893fb9e5ccd33940ffe27e445aa3222121269d49b3')))
 engine=ns['WindingCity'](geo);edges=edges_of(geo)
 # New pure segment algorithm controls, not the old source368/Chongde point suite.
 square=dict(type='MultiPolygon',coordinates=[[[[0,0],[10,0],[10,10],[0,10],[0,0]],[[4,4],[6,4],[6,6],[4,6],[4,4]]]])
 se=ns['WindingCity'](square);ee=edges_of(square);controls=[]
 for name,a,b,expected in [('inside',(1,1),(3,1),True),('hole-crossing-with-inside-endpoints',(1,5),(9,5),False),
  ('outside-endpoint',(1,1),(11,1),False),('outer-boundary',(0,0),(10,0),True),
  ('hole-diagonal',(1,1),(9,9),False),('repeated-inside-point',(1,1),(1,1),True)]:
  scaled=lambda p:tuple(v*10_000_000 for v in p)
  actual=complete_segment_inside(se,ee,scaled(a),scaled(b),1);assert actual==expected
  controls.append(dict(name=name,actual=actual,expected=expected))
 save('new-segment-controls.json',dict(synthetic_pure_geometry=True,old_point_controls_run=False,cases=controls,all_passed=True))
 source=groups[0]['source_group_full'];point=source['classification']['point'];Q=Decimal(360)/Decimal(1<<24)
 sourcepoint=point['original_first_coordinate'];rawpoint=point['native24_degrees']
 allowed=set(prep['unique_target_labels']);comparisons=[];decodedcounts={l:0 for l in allowed};pairs=vertices=0
 for road in rows:
  assert road['geometryResolution']==24 and road['geometryZoomLevel']==0
  assert road['cities'] and all(c['name']=='臺中市' and c['region']=='臺中市' for c in road['cities'])
  names=set(road['labels'])&allowed;assert names
  for name in names:decodedcounts[name]+=1
  segment_proofs=[];best_source=None;best_raw=None
  for si,segment in enumerate(road['segments']):
   assert len(segment)>=2
   raw=[]
   for lat,lon in segment:
    values=[Decimal(str(v)) for v in (lat,lon)]
    native=[int((v/Q).to_integral_value(rounding=ROUND_HALF_UP)) for v in values]
    assert all(abs(v-Decimal(n)*Q)<=Decimal('0.00000000000005') for v,n in zip(values,native))
    raw.append(native);vertices+=1
   for ei,(a,b) in enumerate(zip(raw,raw[1:])):
    pa=(a[1]*3515625,a[0]*3515625);pb=(b[1]*3515625,b[0]*3515625)
    inside=complete_segment_inside(engine,edges,pa,pb,16384);pairs+=1
    segment_proofs.append(dict(RGN_polyline=si,edge_index=ei,raw24_lat_lon=[a,b],complete_segment_inside_Beitun=inside))
    if not inside:continue
    aa=[str(Decimal(v)*Q) for v in a];bb=[str(Decimal(v)*Q) for v in b]
    for p,key in ((sourcepoint,'source'),(rawpoint,'raw')):
     d=dict(distance(p,aa,bb),RGN_polyline=si,edge_index=ei)
     if key=='source' and (best_source is None or d['distance_m']<best_source['distance_m']):best_source=d
     if key=='raw' and (best_raw is None or d['distance_m']<best_raw['distance_m']):best_raw=d
  comparisons.append(dict(road_NET_row=road,complete_segment_district_checks=segment_proofs,
   all_decoded_pairs_inside_Beitun=all(p['complete_segment_inside_Beitun'] for p in segment_proofs),
   sourcepoint_minimum_on_proved_inside_segments=best_source,raw24point_minimum_on_proved_inside_segments=best_raw,
   data_geography_only=True,alias_renaming_formal_address_route_match=False))
 assert not any(l in allowed for l in ['榮興街','北興街','平興街','江興街'])
 result=dict(schema='two-held-road-data-geometry-contrast/v1',source_group_id=36096,source_ids=[7867809101],
  preserved_literal='景賢六街',sourcepoint=sourcepoint,raw24point=point['native24'],
  one_tile=prep['selected_tile'],exact_label_decoded_NET_rows=decodedcounts,
  exact_candidate_found_in_this_tile=decodedcounts['景賢六街']>0,
  not_found_is_not_proof_of_nonexistence=True,comparisons=sorted(comparisons,key=lambda r:r['road_NET_row']['netOffset']),
  geometry_method='All original source polygon boundary intersections as exact rational t; every partition midpoint and endpoints covered. Raw24 coordinates exact rational OSM1e7 denominator16384.',
  distance_method='Local equirectangular: longitude scale111320*cos(each assessed point latitude), latitude scale110574 meter/degree; clipped segment projection; no geodesic/route distance claim.',
  coordinate_double_text_grid_tolerance_degrees='0.00000000000005',
  RGN_vertices_checked=vertices,complete_segment_pairs_checked=pairs,
  held_and_not_road_decoded=[dict(literal=g['literal'],source_group_id=g['source_group_full']['original_prepared_group']['group_id'],
    source_ids=g['source_group_full']['original_prepared_group']['source_ids'],all_holds=g['all_holds'],
    source_inside=g['actual_source_membership']['eligible'],raw_inside=g['actual_raw24_membership']['eligible'])
    for g in groups if not g['eligible_for_readonly_road_contrast']],
  all_original_relationship_holds_retained=True,official_alias_address_route_write_install_ready=False,
  nearest_auto_rename_or_cross_district_match=False,native_CPU_cases=0,device_IO=False)
 save('contrast-results.json',result)
 for r in READS:assert stat(ROOT/r['path'])==r['stat']
 save('analysis-input-read-receipts.json',dict(reads=READS,handles_closed=True,IMG_data_read_in_this_analysis=0))
 print(json.dumps(dict(exact_candidate_NET_rows=decodedcounts['景賢六街'],near_name_roads=[dict(labels=r['road_NET_row']['labels'],
   whole_polyline_inside=r['all_decoded_pairs_inside_Beitun'],source_distance_m=r['sourcepoint_minimum_on_proved_inside_segments']['distance_m'] if r['sourcepoint_minimum_on_proved_inside_segments'] else None) for r in comparisons],
  Rongxing_stopped_outside_district=True,Java_actual_reads=io['actual_read_syscall_count'],Java_bytes=io['actual_syscall_bytes_read'],
  all_holds_preserved=True,no_alias_decision=True),ensure_ascii=False))
if __name__=='__main__':main()
