#!/usr/bin/env python3
"""Read-only local OSM road/name/address investigation; no network or IMG writes."""
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
SOURCE = ROOT / 'sources/maps/taiwan-latest.osm.pbf'
names = ('民權路', '民和路')
filters = ['n/place', 'r/boundary=administrative']
for key in ('name', 'name:zh-Hant', 'name:zh', 'addr:street'):
    filters += [f'nwr/{key}=*{name}*' for name in names]
tagfile = OUT / 'target-tags.osm'
if not tagfile.exists():
    subprocess.run(['osmium', 'tags-filter', '-R', '--no-progress', '-o', str(tagfile), str(SOURCE), *filters], check=True)

items = []
for element in ET.parse(tagfile).getroot():
    if element.tag not in ('node', 'way', 'relation'):
        continue
    tags = {x.attrib['k']: x.attrib['v'] for x in element.findall('tag')}
    matches = {key: value for key, value in tags.items() if any(name in value for name in names)}
    if matches:
        item = {'type': element.tag, 'id': int(element.attrib['id']), 'tags': tags, 'matched_values': matches}
        if element.tag == 'node':
            item['coordinate'] = {'lat': float(element.attrib['lat']), 'lon': float(element.attrib['lon'])}
        if element.tag == 'way':
            item['refs'] = [int(x.attrib['ref']) for x in element.findall('nd')]
        items.append(item)
target_ids = OUT / 'target-ids.txt'
target_ids.write_text(''.join(f"{x['type'][0]}{x['id']}\n" for x in items))
referencefile = OUT / 'targets-with-refs.osm'
if not referencefile.exists():
    subprocess.run(['osmium', 'getid', '--no-progress', '-r', '-i', str(target_ids), '-o', str(referencefile), str(SOURCE)], check=True)
nodes = {int(x.attrib['id']): (float(x.attrib['lat']), float(x.attrib['lon'])) for x in ET.parse(referencefile).getroot().findall('node')}
for item in items:
    if item['type'] == 'way':
        coordinates = [nodes[n] for n in item['refs'] if n in nodes]
        item['node_coordinates'] = coordinates
        item['missing_refs'] = [n for n in item['refs'] if n not in nodes]
        if coordinates:
            item['coordinate'] = {'lat': sum(x[0] for x in coordinates)/len(coordinates), 'lon': sum(x[1] for x in coordinates)/len(coordinates)}
            item['bbox'] = [min(x[1] for x in coordinates), min(x[0] for x in coordinates), max(x[1] for x in coordinates), max(x[0] for x in coordinates)]

taichung_bbox = [120.4, 24.0, 121.05, 24.55]
def local(item):
    c = item.get('coordinate')
    return c and taichung_bbox[0] <= c['lon'] <= taichung_bbox[2] and taichung_bbox[1] <= c['lat'] <= taichung_bbox[3]
localitems = [x for x in items if local(x)]
roads = [x for x in localitems if x['type']=='way' and 'highway' in x['tags']]
addresses = [x for x in localitems if 'addr:street' in x['tags']]
place_nodes = []
admin_relations = []
for element in ET.parse(tagfile).getroot():
    tags = {x.attrib['k']: x.attrib['v'] for x in element.findall('tag')}
    if element.tag == 'node' and 'place' in tags:
        x = {'type':'node','id':int(element.attrib['id']),'tags':tags,'coordinate':{'lat':float(element.attrib['lat']),'lon':float(element.attrib['lon'])}}
        if local(x): place_nodes.append(x)
    if element.tag == 'relation' and tags.get('boundary')=='administrative':
        if any(n in str(tags) for n in ('臺中', '台中', '中區', '西區', '北區', '北屯區', '南區', '東區', '南屯區', '西屯區', '太平區', '大里區')):
            admin_relations.append({'type':'relation','id':int(element.attrib['id']),'tags':tags,'members':[x.attrib for x in element.findall('member')]})

summary = {'source':str(SOURCE),'source_header':json.loads(subprocess.check_output(['osmium','fileinfo','-j',str(SOURCE)])),'taichung_bbox_is_selection_not_boundary':taichung_bbox,'national_matched_count':len(items),'local_matched_count':len(localitems),'local_road_count':len(roads),'local_address_count':len(addresses),'local_roads':roads,'local_addresses':addresses,'nearby_place_nodes':place_nodes,'candidate_admin_relations':admin_relations,'limitations':['bbox only selects coordinates; full Taichung administrative inclusion follows separately','tags do not prove compiled IMG index content or real Garmin search behavior','OSM source is dated 2026-10-01; no fresh download performed']}
(OUT/'coverage-raw.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
(OUT/'national-matches.json').write_text(json.dumps(items,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({k:summary[k] for k in ('national_matched_count','local_matched_count','local_road_count','local_address_count')},ensure_ascii=False))
print(json.dumps([{'id':x['id'],'name':x['tags'].get('name'),'highway':x['tags'].get('highway'),'coordinate':x['coordinate'],'address_tags':{k:v for k,v in x['tags'].items() if k.startswith(('addr:','is_in'))}} for x in roads],ensure_ascii=False,indent=2))
