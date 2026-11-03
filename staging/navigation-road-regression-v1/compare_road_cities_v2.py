#!/usr/bin/env python3
"""One-shot old/new compiled Taichung road-city comparison after map build ends."""
import argparse
from collections import Counter
import datetime as dt
import hashlib
import json
import math
from pathlib import Path
import subprocess

P=Path(__file__).resolve().parent
ROOT=P.parents[1]
JAR=ROOT/'sources/maps/mkgmap-r4924/mkgmap.jar'
CP=str(JAR)+':'+str(JAR.parent/'lib/*')
OLD=ROOT/'staging/maps/Taiwan_OSM_20261001_UTF8/compiled'
NEW=ROOT/'staging/navigation-repair-v1/compiled'
SOURCE_PROOF=ROOT/'staging/navigation-road-coverage-v1/road-anchor-proof.json'
GROUPS={
 'central_minquan':{'names':['民權路'],'bbox':[120.66,24.13,120.69,24.17]},
 'coastal_minhe':{'names':['民和路一段','民和路二段'],'bbox':[120.54,24.24,120.56,24.27]},
}
def point_in_box(p,box):
 lat,lon=p;return box[0]<=lon<=box[2] and box[1]<=lat<=box[3]
def located(row,group):
 return bool(set(row['labels'])&set(group['names'])) and any(point_in_box(p,group['bbox']) for seg in row['segments'] for p in seg)
def distance_to_segment(point,a,b):
 lat,lon=point;sx=111320*math.cos(math.radians(lat));sy=110574
 ax=(a[1]-lon)*sx;ay=(a[0]-lat)*sy;dx=(b[1]-a[1])*sx;dy=(b[0]-a[0])*sy
 t=max(0,min(1,-(ax*dx+ay*dy)/(dx*dx+dy*dy))) if dx*dx+dy*dy else 0
 return math.hypot(ax+t*dx,ay+t*dy)
def group_summary(rows,group):
 selected=[r for r in rows if located(r,group)]
 city_names=Counter(c['name'] for r in selected for c in r['cities'])
 return {'selected_net_road_entries':len(selected),'street_names':sorted({s for r in selected for s in r['labels'] if s in group['names']}),'city_counts':dict(city_names),'region_counts':dict(Counter(c['region'] for r in selected for c in r['cities'])),'country_counts':dict(Counter(c['country'] for r in selected for c in r['cities'])),'all_rows_have_only_Taichung_city':bool(selected) and all({c['name'] for c in r['cities']}=={'臺中市'} for r in selected),'all_rows_have_Taichung_region':bool(selected) and all(r['cities'] and all(c['region']=='臺中市' for c in r['cities']) for r in selected),'row_keys':[{'tile':Path(r['file']).stem,'netOffset':r['netOffset']} for r in selected]}
def nearest_label_witness(rows,anchor):
 label='民權路' if '民權路' in anchor['name'] else ('民和路一段' if '一段' in anchor['name'] else '民和路二段')
 candidates=[]
 for r in rows:
  if label not in r['labels']:continue
  for seg in r['segments']:
   for a,b in zip(seg,seg[1:]):candidates.append((distance_to_segment((anchor['lat'],anchor['lon']),a,b),r))
 if not candidates:return {'label':label,'matching_geometry_present':False}
 dist,row=min(candidates,key=lambda x:x[0])
 return {'label':label,'matching_geometry_present':True,'nearest_m_approx':round(dist,3),'within_30m':dist<=30,'tile':Path(row['file']).stem,'netOffset':row['netOffset'],'city_names':sorted({c['name'] for c in row['cities']})}
def parse_reader_output(text):
 rows=json.loads(text)
 if not isinstance(rows,list):raise ValueError('Reader output must be array')
 for r in rows:
  if not isinstance(r.get('segments'),list) or not isinstance(r.get('cities'),list):raise ValueError('Malformed reader row')
  for seg in r['segments']:
   for pt in seg:
    if len(pt)!=2 or any(not isinstance(x,(int,float)) for x in pt):raise ValueError('Malformed geometry coordinate')
 return rows
def reader(paths,out):
 for path in paths:
  if not path.is_file() or path.stat().st_size<1024:raise FileNotFoundError(path)
 run=subprocess.run(['java','-Xmx384m','--class-path',CP,str(P/'ReadRoadGeometryV2.java'),*map(str,paths)],text=True,capture_output=True,check=False)
 out.write_text(run.stdout);out.with_suffix('.stderr.txt').write_text(run.stderr)
 out.with_suffix('.process.json').write_text(json.dumps({'returncode':run.returncode,'argv':run.args},indent=2)+'\n')
 if run.returncode:raise RuntimeError('Reader child failed; preserved stdout/stderr; '+run.stderr[-1800:])
 return parse_reader_output(run.stdout)
def self_test():
 # Real old NET/LBL names used as immutable fixtures; synthetic coordinates
 # solely exercise geographic exclusions, so they do not assert IMG decoding.
 real=json.loads((ROOT/'staging/navigation-road-coverage-v1/compiled-roads-v2.json').read_text())
 row=next(x for x in real if '民權路' in x['labels'] and any(c['name']=='臺中市' for c in x['cities']))
 fixture={**row,'segments':[[[24.145,120.671],[24.146,120.671]]],'cities':[{'name':'臺中市','region':'臺中市','country':'Taiwan'}]}
 assert located(fixture,GROUPS['central_minquan'])
 assert not located({**fixture,'segments':[[[24.42,120.86],[24.43,120.86]]]},GROUPS['central_minquan'])
 assert group_summary([fixture],GROUPS['central_minquan'])['all_rows_have_only_Taichung_city']
 bad={**fixture,'cities':fixture['cities']+[{'name':'後壠子','region':'Taiwan','country':'Taiwan'}]}
 assert not group_summary([bad],GROUPS['central_minquan'])['all_rows_have_only_Taichung_city']
 alias={**fixture,'cities':[{'name':'台中市','region':'臺中市','country':'Taiwan'}]}
 assert not group_summary([alias],GROUPS['central_minquan'])['all_rows_have_only_Taichung_city']
 anchor={'name':'臺中市民權路中段測試點','lat':24.1455,'lon':120.671}
 assert nearest_label_witness([fixture],anchor)['within_30m']
 assert not nearest_label_witness([],anchor)['matching_geometry_present']
 for obj in ({},[{'segments':[],'cities':None}]):
  try:parse_reader_output(json.dumps(obj))
  except (ValueError,TypeError,AttributeError):continue
  raise AssertionError('Malformed reader output accepted')
 return {'all_passed':True,'fixture':'actual old NET/LBL metadata + explicit synthetic selector-only coordinates','tests':9,'new_map_read':False,'old_map_decoding_rerun':False}
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--self-test',action='store_true');ap.add_argument('--new-dir',type=Path,default=NEW);args=ap.parse_args()
 if args.self_test:
  result=self_test();(P/'selector-self-test.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result));return
 # Parent must explicitly launch this after the exact fullmap build is terminal.
 oldpaths=[OLD/f'705100{n:02}.img' for n in (19,20,21)];newpaths=[args.new_dir/f'705200{n:02}.img' for n in (19,20,21)]
 old=reader(oldpaths,P/'old-road-geometry-v2.json');new=reader(newpaths,P/'new-road-geometry-v2.json')
 anchors=json.loads(SOURCE_PROOF.read_text())['points'];groups={name:{'old':group_summary(old,g),'new':group_summary(new,g)} for name,g in GROUPS.items()}
 witnesses=[{'source_anchor':a,'old':nearest_label_witness(old,a),'new':nearest_label_witness(new,a)} for a in anchors]
 checks={name+'_labels_retained':set(r['new']['street_names'])==set(GROUPS[name]['names']) for name,r in groups.items()}
 checks.update({name+'_only_Taichung_city':r['new']['all_rows_have_only_Taichung_city'] for name,r in groups.items()})
 checks.update({name+'_Taichung_region':r['new']['all_rows_have_Taichung_region'] for name,r in groups.items()})
 checks['all_source_anchor_labels_within_30m']=all(w['new'].get('within_30m',False) for w in witnesses)
 files=[JAR,P/'ReadRoadGeometryV2.java',Path(__file__).resolve(),SOURCE_PROOF,*oldpaths,*newpaths]
 report={'checked_utc':dt.datetime.now(dt.timezone.utc).isoformat(),'all_passed':all(checks.values()),'checks':checks,'groups':groups,'anchor_witnesses':witnesses,'inputs':[{'path':str(f),'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()} for f in files],'reader_join':'Detailed-level RGN polyline raw NET offset joined to NETFileReader road metadata; LBL point-reference cities resolved from actual RGN points','scope':'Old/new compiled tiles 19/20/21 NET/LBL/RGN road label/city/region fields and spatial correspondence near five source nodes. Not global MDR binary search, number-range decode, routing solver or physical device search.','source_27_ways_and_2635_addresses_not_equated_to_compiled_entry_count':True,'physical_device_search_tested':False,'routing_correctness_tested':False,'full_taiwan_map_coverage_tested':False}
 (P/'road-city-regression-proof-v2.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'all_passed':report['all_passed'],'checks':checks,'groups':{n:{v:{k:x[k] for k in ('selected_net_road_entries','street_names','city_counts','region_counts')} for v,x in r.items()} for n,r in groups.items()}},ensure_ascii=False));raise SystemExit(0 if report['all_passed'] else 1)
if __name__=='__main__':main()
