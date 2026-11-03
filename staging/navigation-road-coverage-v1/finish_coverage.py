#!/usr/bin/env python3
"""Create bounded road/administrative/address evidence from extracted local data."""
import collections
import datetime as dt
import gzip
import hashlib
import json
import math
from pathlib import Path
import subprocess
import xml.etree.ElementTree as E

P = Path(__file__).resolve().parent
R = P.parents[1]
d=json.loads((P/'coverage-raw.json').read_text())
nodes={}; ways={}; relations={}
for path in (P/'admin-with-refs.osm',P/'coastal-admin-with-refs.osm'):
 for e in E.parse(path).getroot():
  if e.tag=='node': nodes[int(e.attrib['id'])]=(float(e.attrib['lat']),float(e.attrib['lon']))
  elif e.tag=='way': ways[int(e.attrib['id'])]=[int(n.attrib['ref']) for n in e.findall('nd')]
  elif e.tag=='relation': relations[int(e.attrib['id'])]=e

def rings(sequences):
 result=[];remain=[list(x) for x in sequences]
 while remain:
  seq=remain.pop(0)
  while seq[-1]!=seq[0]:
   found=False
   for i,other in enumerate(remain):
    if other[0]==seq[-1]: seq+=other[1:]
    elif other[-1]==seq[-1]:seq+=other[-2::-1]
    elif other[-1]==seq[0]:seq=other[:-1]+seq
    elif other[0]==seq[0]:seq=other[:0:-1]+seq
    else:continue
    remain.pop(i);found=True;break
   if not found:raise ValueError('Open administrative ring')
  if any(n not in nodes for n in seq):raise ValueError('Missing administrative ring node')
  result.append([nodes[n] for n in seq])
 return result

admin=[]
for id,e in relations.items():
 tags={n.attrib['k']:n.attrib['v'] for n in e.findall('tag')}
 if tags.get('boundary')!='administrative':continue
 roles={r:[] for r in ('outer','inner')}
 for m in e.findall('member'):
  if m.attrib['type']=='way' and m.attrib['role'] in roles:roles[m.attrib['role']].append(ways[int(m.attrib['ref'])])
 admin.append({'id':id,'tags':tags,'rings':{k:rings(v) for k,v in roles.items()}})

def ring_contains(lat,lon,ring):
 hit=False
 for (a,b),(c,e) in zip(ring,ring[1:]):
  cross=(lat-a)*(e-b)-(lon-b)*(c-a)
  if abs(cross)<1e-12 and min(a,c)-1e-10<=lat<=max(a,c)+1e-10 and min(b,e)-1e-10<=lon<=max(b,e)+1e-10:return 'boundary'
  if (a>lat)!=(c>lat) and lon<(e-b)*(lat-a)/(c-a)+b:hit=not hit
 return 'inside' if hit else 'outside'

def contains(a,lat,lon):
 outer=[ring_contains(lat,lon,r) for r in a['rings']['outer']]
 inner=[ring_contains(lat,lon,r) for r in a['rings']['inner']]
 if 'boundary' in outer+inner:return 'boundary'
 return 'inside' if 'inside' in outer and 'inside' not in inner else 'outside'

def administrative_membership(coord):
 return [{'relation_id':a['id'],'name':a['tags'].get('name'),'admin_level':a['tags']['admin_level'],'status':v} for a in admin if (v:=contains(a,coord['lat'],coord['lon']))!='outside']

central=lambda x:24.13<x['coordinate']['lat']<24.17 and 120.66<x['coordinate']['lon']<120.69
roads=[x for x in d['local_roads'] if central(x) and x['tags'].get('name')=='民權路']
coastal=[x for x in d['local_roads'] if x['tags'].get('name') in ('民和路一段','民和路二段')]
addresses=[x for x in d['local_addresses'] if central(x) and x['tags'].get('addr:street')=='民權路']
for x in roads+coastal:x['admin_membership_at_centroid']=administrative_membership(x['coordinate'])

def distance_to_segment(c,a,b):
 # Local equirectangular metric for a 3km urban road, not global routing.
 y=c['lat'];sx=111320*math.cos(math.radians(y));sy=110574
 ax=(a[1]-c['lon'])*sx;ay=(a[0]-y)*sy;bx=(b[1]-c['lon'])*sx;by=(b[0]-y)*sy
 dx=bx-ax;dy=by-ay;t=max(0,min(1,-(ax*dx+ay*dy)/(dx*dx+dy*dy))) if dx*dx+dy*dy else 0
 return math.hypot(ax+t*dx,ay+t*dy)
address_distances=[]
for x in addresses:
 nearest=min((min(distance_to_segment(x['coordinate'],a,b) for a,b in zip(w['node_coordinates'],w['node_coordinates'][1:])),w['id']) for w in roads)
 address_distances.append({'type':x['type'],'id':x['id'],'nearest_road_way_id':nearest[1],'nearest_distance_m_approx':round(nearest[0],3),'city':x['tags'].get('addr:city'),'district':x['tags'].get('addr:district'),'housenumber':x['tags'].get('addr:housenumber')})
unique=sorted({x['tags']['addr:housenumber'] for x in addresses})
cmd=['java','--class-path',str(R/'sources/maps/mkgmap-r4924/mkgmap.jar')+':'+str(R/'sources/maps/mkgmap-r4924/lib/*'),str(P/'CheckHouseNumberParser.java')]
run=subprocess.run(cmd,input='\n'.join(unique)+'\n',text=True,capture_output=True,check=True)
(P/'housenumber-parser.txt').write_text(run.stdout)
parse={line.rsplit('\t',1)[0]:(int(line.rsplit('\t',1)[1]) if line.rsplit('\t',1)[1]!='null' else None) for line in run.stdout.splitlines()}
compiled=json.loads((P/'compiled-roads-v2.json').read_text())
stats=collections.Counter()
for x in compiled:
 for name in x['labels']:
  if name=='民權路' or name.startswith('民和路'):
   for c in x['cities']:stats[(Path(x['file']).stem,name,c['name'])]+=1

report={'checked_utc':dt.datetime.now(dt.timezone.utc).isoformat(),'source_timestamp':d['source_header']['header']['option']['timestamp'],'source_pbf_declared_sha256':'f57631c6c5cdcee9b2e38c460494bf224c80d03301e6a45fd3bfaec0b52e5912','source_pbf_rehashed_this_scope':False,'scope':'Existing Geofabrik OSM source and old UTF-8 tile NET/LBL reading; no device or navigation search run','central_minquan':{'way_count':len(roads),'way_ids':[x['id'] for x in roads],'road_names_correct':all(x['tags'].get('name')==x['tags'].get('name:zh')=='民權路' for x in roads),'road_name_zh_hant_present':sum('name:zh-Hant' in x['tags'] for x in roads),'road_address_city_tags':collections.Counter(x['tags'].get('addr:city','<absent>') for x in roads),'road_is_in_tags':collections.Counter(x['tags'].get('is_in','<absent>') for x in roads),'roads':roads,'address_count':len(addresses),'city_counts':collections.Counter(x['tags'].get('addr:city','<absent>') for x in addresses),'district_counts':collections.Counter(x['tags'].get('addr:district','<absent>') for x in addresses),'unique_raw_house_number_strings':len(unique),'numeric_parse_valid_count':sum(parse[x['tags']['addr:housenumber']] is not None for x in addresses),'numeric_parse_failure_count':sum(parse[x['tags']['addr:housenumber']] is None for x in addresses),'unique_numeric_house_numbers':len({v for v in parse.values() if v is not None}),'within_150m_of_same_name_road_count':sum(x['nearest_distance_m_approx']<=150 for x in address_distances),'addresses_farther_than_150m':[x for x in address_distances if x['nearest_distance_m_approx']>150],'address_samples':addresses[:6]},'coastal_minhe':{'way_count':len(coastal),'roads':coastal},'admin_geometry_checks':[{'relation_id':a['id'],'name':a['tags'].get('name'),'admin_level':a['tags']['admin_level'],'outer_rings':len(a['rings']['outer']),'inner_rings':len(a['rings']['inner']),'all_ring_refs_present':True,'all_rings_closed':True} for a in admin],'compiled_tile_road_entries':len(compiled),'compiled_name_city_counts':[{'tile':k[0],'road':k[1],'city':k[2],'count':v} for k,v in sorted(stats.items(),key=lambda p:repr(p[0]))],'interpretation':['Source correctly distinguishes central Taichung 民權路 and coastal 民和路一段/二段; changing the name is unwarranted.','Old UTF-8 tiles contain target roads and 臺中市 associations. Missing source road is not supported as explanation for this named example.','Original compile lacks preprocessed administrative bounds and Taiwan-specific region/city assignment; nearest assignment is documented as best guess. This is a robustness deficiency, not proven cause of two-hour device hang.','Garmin address data has more structure than street labels; compiled global MDR/SRT sorting, map mixing and hardware search remain independent checks.','Most central addresses contain suffix 號 or repeated units, but actual r4924 parser accepts their first integer; do not falsely claim suffix alone loses every address.','NETFileReader does not reconstruct house number lists; returned RoadDef.hasHouseNumbers false is not evidence of absent actual NET house-number data.'],'minimum_candidate_changes':['Generate administrative bounds from this same source, use --bounds and explicit TWN rules that map admin_level4 to municipal region and admin_level7 to district/city, then verify both 臺中市 and 臺中市西區 lookup requirements rather than choosing one silently.','Normalize 台中市 alias locally to 臺中市 for canonical location keys while retaining a search alias or city POI; never rename roads 民權→民和.','Create a small reversible GPX route-anchor POI set from real street coordinates and full names such as 臺中市西區民權路; use this to separate All POI lookup from address MDR lookup. It is an interim route-anchor fallback, not complete street/address repair.'],'unproven':['Two-hour firmware search cause','Real device revised index acceptance/search/routing','Exact global street/house-number coverage beyond these roads','Full OSM completeness for every Taiwanese road or current official City Navigator replacement']}
(P/'road-coverage-proof.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
(P/'central-address-distance-checks.json').write_text(json.dumps(address_distances,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'central_ways':len(roads),'minhe_ways':len(coastal),'address_count':len(addresses),'numeric_parse_valid_count':report['central_minquan']['numeric_parse_valid_count'],'unique_numeric_house_numbers':report['central_minquan']['unique_numeric_house_numbers'],'within_150m':report['central_minquan']['within_150m_of_same_name_road_count'],'compiled_city_counts':report['compiled_name_city_counts']},ensure_ascii=False))
