#!/usr/bin/env python3
"""Check 22 root ring reference closure from root agent's read-only bounds PBF."""
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as E

P=Path(__file__).resolve().parent
INPUT=P.parents[0]/'navigation-repair-v1/taiwan-admin.osm.pbf'
selected=json.loads((P/'native-taiwan-admin-roots.json').read_text())
ids={x['id'] for k in ('municipality_city_roots','county_roots') for x in selected[k]}
nodes=set();ways={};relations={}
proc=subprocess.Popen(['osmium','cat','--no-progress','-f','osm',str(INPUT)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
for _,e in E.iterparse(proc.stdout,events=('end',)):
 if e.tag=='node':nodes.add(int(e.attrib['id']));e.clear()
 elif e.tag=='way':ways[int(e.attrib['id'])]=[int(x.attrib['ref']) for x in e.findall('nd')];e.clear()
 elif e.tag=='relation':
  if int(e.attrib['id']) in ids:relations[int(e.attrib['id'])]=([m.attrib.copy() for m in e.findall('member')],{x.attrib['k']:x.attrib['v'] for x in e.findall('tag')})
  e.clear()
err=proc.stderr.read().decode();assert proc.wait()==0,err
def join(seqs):
 closed=0;opened=[];remain=[list(x) for x in seqs]
 while remain:
  seq=remain.pop(0)
  while seq[-1]!=seq[0]:
   found=False
   for i,o in enumerate(remain):
    if o[0]==seq[-1]:seq+=o[1:]
    elif o[-1]==seq[-1]:seq+=o[-2::-1]
    elif o[-1]==seq[0]:seq=o[:-1]+seq
    elif o[0]==seq[0]:seq=o[:0:-1]+seq
    else:continue
    remain.pop(i);found=True;break
   if not found:break
  if seq[-1]==seq[0]:closed+=1
  else:opened.append({'first_node':seq[0],'last_node':seq[-1],'nodes':len(seq)})
 return {'closed_rings':closed,'open_chains':opened}
rows=[]
for id in sorted(ids):
 if id not in relations:rows.append({'id':id,'relation_missing':True});continue
 members,tags=relations[id]; roles={k:[] for k in ('outer','inner')};missingways=[];missingnodes=[]
 for m in members:
  if m['type']!='way' or m['role'] not in roles:continue
  wid=int(m['ref'])
  if wid not in ways:missingways.append(wid);continue
  roles[m['role']].append(ways[wid]);missingnodes.extend(n for n in ways[wid] if n not in nodes)
 geom={k:join(v) for k,v in roles.items()}
 rows.append({'id':id,'name':tags.get('name'),'missing_way_ids':missingways,'missing_node_ids':sorted(set(missingnodes)),'roles':geom,'complete_reference_closed_geometry':not(missingways or missingnodes or any(v['open_chains'] for v in geom.values()))})
out={'source':str(INPUT),'root_count':len(ids),'all_22_roots_geometry_closed':all(x.get('complete_reference_closed_geometry') for x in rows),'roots':rows,'scope':'Reference presence and edge-chain ring closure only, not polygon validity/self-intersection or final BoundaryPreprocessor assignment'}
(P/'native-root-closure-proof.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n');print(json.dumps(out,ensure_ascii=False))
