#!/usr/bin/env python3
"""One compiled road/tile normal Java MapReader file parse; no native CPU.
No PBF/source ledger/global map scan/hash or old Minquan suite is executed.
"""
import sys
sys.dont_write_bytecode=True
import json,hashlib,re,subprocess,math,difflib,time
from pathlib import Path
from decimal import Decimal,ROUND_HALF_UP
from datetime import datetime,timezone
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
ORIGINAL=ROOT/'staging/navigation-road-regression-v1/ReadRoadGeometryV2.java'
COMPARE=ROOT/'staging/navigation-road-regression-v1/compare_road_cities_v2.py'
AREAS=ROOT/'staging/maps/Taiwan_OSM_20261001_UTF8/tiles/areas.list'
MANIFEST=ROOT/'staging/navigation-repair-v2/build-manifest.json'
PACKAGE=ROOT/'staging/navigation-repair-v2/package/manifest.json'
ARGS=ROOT/'staging/navigation-repair-v2/tiles.args'
CANDIDATE=ROOT/'staging/navigation-native-new-street-source-example-v1/candidate.json'
JAR=ROOT/'sources/maps/mkgmap-r4924/mkgmap.jar'
UNITS=Decimal(1<<24);QUANTUM=Decimal(360)/UNITS
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def save(p,v):
 with p.open('x')as f:json.dump(v,f,ensure_ascii=False,indent=2);f.write('\n')
def distance_to_segment(point,a,b):
 lat,lon=point;sx=111320*math.cos(math.radians(lat));sy=110574
 ax=(a[1]-lon)*sx;ay=(a[0]-lat)*sy;dx=(b[1]-a[1])*sx;dy=(b[0]-a[0])*sy
 t=max(0,min(1,-(ax*dx+ay*dy)/(dx*dx+dy*dy))) if dx*dx+dy*dy else 0
 return math.hypot(ax+t*dx,ay+t*dy),t
def main():
 assert not(BASE/'proof.json').exists()
 manifest=json.loads(MANIFEST.read_text());package=json.loads(PACKAGE.read_text());candidate=json.loads(CANDIDATE.read_text())
 assert manifest['exit_code']==0 and manifest['family_id']==7053 and manifest['tile_count']==36
 assert package['new_map']['sha256']==manifest['image_sha256']and package['compiled_image_reference']==manifest['image']
 assert candidate['raw_street']=='敦富六街'and candidate['raw_house']=='368'
 source=[Decimal(x)for x in candidate['sourcepoint']];native=[int((x/QUANTUM).to_integral_value(rounding=ROUND_HALF_UP))for x in source]
 assert native==candidate['raw24']==[1127253,5625400]
 quantized=[Decimal(n)*QUANTUM for n in native]
 tile_args={}
 for block in ARGS.read_text().strip().split('\n\n'):
  f=dict(line.split(': ',1)for line in block.splitlines());tile_args[Path(f['input-file']).stem.split('.')[0]]=f['mapname']
 bounds=[]
 for m in re.finditer(r'^(\d+): (-?\d+),(-?\d+) to (-?\d+),(-?\d+)$',AREAS.read_text(),re.M):
  tile,la,lo,lb,lp=m.groups();ints=[int(x)for x in(la,lo,lb,lp)]
  contains=ints[0]<=native[0]<=ints[2]and ints[1]<=native[1]<=ints[3]
  if contains:
   assert tile in tile_args
   bounds.append(dict(split_tile=tile,Search_v2_tile=tile_args[tile],bbox_native24=[ints[:2],ints[2:]],
    bbox_degrees=[[str(Decimal(v)*QUANTUM)for v in ints[:2]],[str(Decimal(v)*QUANTUM)for v in ints[2:]]],contains_quantized_point=True))
 assert 1<=len(bounds)<=3,('unbounded/empty tile selection',bounds)
 tiles=[ROOT/'staging/navigation-repair-v2/compiled'/f"{x['Search_v2_tile']}.img"for x in bounds]
 save(BASE/'tile-selection.json',dict(source=rel(AREAS),selection='exact native24 containing bounds, then frozen tiles.args mapping',selected=bounds,
  point_raw24=native,sourcepoint=list(map(str,source)),maximum_tiles=3,selected_tiles=len(tiles),whole_Taiwan_tiles_not_parsed=True,
  no_PBF_or_source_node_ledger_opened=True))
 original=ORIGINAL.read_text();needle='(l.getText().contains("民權路")||l.getText().contains("民和路"))';assert original.count(needle)==1
 new=original.replace(needle,'l.getText().equals("敦富六街")')
 reader=BASE/'ReadRoadGeometryV2.java';assert not reader.exists();reader.write_text(new)
 diff='\n'.join(difflib.unified_diff(original.splitlines(),new.splitlines(),fromfile=rel(ORIGINAL),tofile=rel(reader),lineterm=''))+'\n'
 (BASE/'reader-source.diff').write_text(diff)
 libs=sorted((JAR.parent/'lib').glob('*.jar'))
 inputs=[Path(__file__),ORIGINAL,COMPARE,reader,AREAS,MANIFEST,PACKAGE,ARGS,CANDIDATE,JAR,ROOT/'sources/maps/format-reference/Utils.java',*libs,*tiles]
 hashes={rel(p):sha(p)for p in inputs};save(BASE/'inputs-at-run.json',hashes)
 argv=['java','-Xmx384m','--class-path',str(JAR)+':'+str(JAR.parent/'lib/*'),str(reader),*map(str,tiles)]
 started=datetime.now(timezone.utc).isoformat();t=time.monotonic();run=subprocess.run(argv,text=True,capture_output=True,check=False,timeout=60)
 (BASE/'road-geometry.json').write_text(run.stdout);(BASE/'reader-stderr.txt').write_text(run.stderr)
 save(BASE/'reader-process.json',dict(argv=argv,returncode=run.returncode,started_utc=started,elapsed_seconds=time.monotonic()-t,
  normal_Java_IMG_file_parsing=True,native_CPU_or_firmware_build=False,device_IO=False))
 if run.returncode:
  save(BASE/'proof.json',dict(analysis_complete=False,reader_returncode=run.returncode,actual_stdout_and_stderr_preserved=True,source_SHA256=hashes,
   App_audio_install_flags=False,device_IO=False,native_CPU_execution=False))
  print(json.dumps(dict(reader_failed=True,exit_code=run.returncode,stderr=run.stderr[-1800:]),ensure_ascii=False),flush=True);raise SystemExit(1)
 rows=json.loads(run.stdout);assert isinstance(rows,list)
 exact=[r for r in rows if '敦富六街'in r['labels']];geographic=[];all_vertices=[]
 for r in exact:
  for si,seg in enumerate(r['segments']):
   for v in seg:
    scaled=[float(x)/float(QUANTUM)for x in v];units=[round(x)for x in scaled];assert max(abs(x-n)for x,n in zip(scaled,units))<1e-6
    assert [float(Decimal(n)*QUANTUM)for n in units]==v
    all_vertices.append(dict(tile=Path(r['file']).stem,NET_offset=r['netOffset'],segment_index=si,coordinate_native24=units,degrees=v))
   for ai,(a,b)in enumerate(zip(seg,seg[1:])):
    d,t=distance_to_segment(tuple(map(float,source)),a,b);qd,qt=distance_to_segment(tuple(map(float,quantized)),a,b)
    geographic.append(dict(tile=Path(r['file']).stem,NET_offset=r['netOffset'],reader_ID_not_OSM_ID=r['readerIdNotOsmWayId'],segment_index=si,
     vertex_pair_index=ai,labels=r['labels'],cities=r['cities'],A_degrees=a,B_degrees=b,
     A_native24=[round(float(x)/float(QUANTUM))for x in a],B_native24=[round(float(x)/float(QUANTUM))for x in b],
     sourcepoint_distance_m_approx=d,quantized_native24_housepoint_distance_m_approx=qd,projection_fraction=t,
     quantized_projection_fraction=qt,projected_closest_degrees=[a[0]+t*(b[0]-a[0]),a[1]+t*(b[1]-a[1])]))
 geographic.sort(key=lambda r:r['quantized_native24_housepoint_distance_m_approx']);nearest=geographic[0]if geographic else None
 save(BASE/'native24-road-vertices.json',all_vertices)
 cities=sorted({c['name']for r in exact for c in r['cities']});regions=sorted({c['region']for r in exact for c in r['cities']})
 consistent=bool(exact)and all(r['cities']and all(c['name']==candidate['raw_city']and c['region']==candidate['raw_city']for c in r['cities'])for r in exact)
 assert all(sha(ROOT/p)==h for p,h in hashes.items()),'read inputs changed'
 proof=dict(schema='Garmin Searchv2 compiled Dunfu6 road linkage/v1',analysis_complete=True,ordinary_reader_returncode=0,
  compiled_road_present=bool(exact),matching_NET_entries=len(exact),matching_RGN_polylines=sum(len(r['segments'])for r in exact),
  matching_line_vertex_pairs=len(geographic),decoded_geometry_levels=[dict(tile=Path(r['file']).stem,NET_offset=r['netOffset'],zoom=r['geometryZoomLevel'],resolution=r['geometryResolution'])for r in exact],
  source_address=dict(street=candidate['raw_street'],house=candidate['raw_house'],city=candidate['raw_city'],district=candidate['raw_district'],
   sourcepoint=list(map(str,source)),native24_housepoint=native,quantized_degrees=list(map(str,quantized)),
   candidate=rel(CANDIDATE),candidate_SHA256=sha(CANDIDATE),source_ids=candidate['source_ids']),
  tile_selection=bounds,reader_join='same selected Searchv2 tile: finest-level RGN road raw NET offset -> NET RoadDef -> LBL labels and LBL/RGN point-reference city metadata',
  road_labels=sorted({l for r in exact for l in r['labels']}),road_city_names=cities,road_region_names=regions,
  compiled_city_region_match_same_source_city_literal=consistent,source_district_polygon_or_compiled_district_membership_proven=False,
  nearest_same_exact_street_label=nearest,nearest_three_same_label_line_pairs=geographic[:3],
  geometric_correspondence_within_30m=bool(nearest)and nearest['quantized_native24_housepoint_distance_m_approx']<=30,
  native24_coordinate_policy=dict(quantum_degrees=str(QUANTUM),house_policy=candidate['coordinate_quantization']['policy'],
   decoded_road_vertices_degrees_are_exact_native24_grid=True,road_vertex_count=len(all_vertices),native24_is_file_coordinate_grid_not_cpu_execution=True),
  distance_method='local equirectangular projection centered on evaluated point: x=longitude_delta*111320*cos(latitude), y=latitude_delta*110574; clipped segment projection; metres approximate',
  package_compiled_identity=dict(family_id=7053,selected_tile_ids=[x['Search_v2_tile']for x in bounds],parent_manifest_image_sha256_not_rehashed=manifest['image_sha256'],
   package_sha256_matches_build_manifest=True,installed_Searchv2_relationship='parent reported installed; this scope parses corresponding compiled tiles, with no fresh device or whole-image readback'),
  source_diff_only_exact_street_filter=True,source_SHA256=hashes,
  limitations=['Nearest matching named road establishes spatial correspondence only; no official house368 verification or routable address attachment.',
   'No NET house-number-range, address interpolation or route solver is run.',
   'NET reader ID is not an OSM way ID. Source node ledger and full PBF were not opened.',
   'City/region fields are from the same NET/LBL/RGN tile; source district is literal metadata, not independently tested polygon membership.',
   'One selected compiled tile, not whole Taiwan, physical rendering, device search or route acceptance.',
   'Native24 means coordinate quantization; no ARM/Thumb CPU, firmware build, call-site or device modification.'],
  house368_formally_verified=False,physical_device_search_or_route_verified=False,whole_Taiwan_coverage=False,
  original_MINQUAN_suite_rerun=False,App_audio_direct_phone_speaker_install_flags=False,device_IO=False,native_CPU_execution=False)
 save(BASE/'proof.json',proof)
 print(json.dumps(dict(analysis_complete=True,compiled_road_present=bool(exact),selected_tiles=len(tiles),NET_entries=len(exact),
  RGN_polylines=proof['matching_RGN_polylines'],cities=cities,regions=regions,city_region_match_source_literal=consistent,
  sourcepoint_distance_m_approx=None if not nearest else round(nearest['sourcepoint_distance_m_approx'],3),
  native24_housepoint_distance_m_approx=None if not nearest else round(nearest['quantized_native24_housepoint_distance_m_approx'],3),
  native24=native,formal_house_or_route_acceptance=False,device_IO=False),ensure_ascii=False),flush=True)
if __name__=='__main__':main()
