#!/usr/bin/env python3
"""Finite ordinary FILE review and one-leaf COW plan. No guest or writer."""
from pathlib import Path
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from collections import Counter
import ast
import hashlib
import json
import os
import re
import resource
import struct
import time

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
LIMIT = 1 << 20
PROFILES = [([16,9,24,19,1,10,0,0],[1,1],122),
            ([16,9,24,19,1,10,0,0],[1,1],122),
            ([23,9,24,19,1,12,0,0],[1,0],112),
            ([22,9,24,19,1,10,0,0],[1,1],128),
            ([21,9,24,19,1,9,0,0],[1,1],126),
            ([0,0,24,19,1,0,0,0],[1,0],68)]
NAMES = ('00004171.MD2','00004171.MDR','00004171.SRT',
         'I053061A.GMP','I053061A.SRT','MAPSOURC.MPS')
IMAGES = {
 'v2': dict(path='staging/navigation-country-native-candidate-v2/gmapprom1.img',
    sha256='925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb',
    bytes=128356352,block_bytes=4096,counts=[22,343,47870,3781594,2667573,1984066],
    seal='staging/navigation-country-native-candidate-v2/sealed-files.json',
    seal_sha256='659ae2d149b45098542fd90cd0a3000e74e3c9e2d76077f4d1ecdbbeec022766'),
 'v3': dict(path='staging/navigation-country-native-lane-candidate-v3/gmapprom1.img',
    sha256='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360',
    bytes=153346048,block_bytes=8192,counts=[22,343,47870,4896236,3077845,2062771],
    seal='staging/navigation-country-native-lane-candidate-v3/sealed-files.json',
    seal_sha256='dfc47744887137f944d710dffeb5ea6f6821c24eb8abbeb522cb406576754335')}
READER_PATH = 'staging/navigation-country-native-lane-independent-review-v3/review_actual_v3.py'
READER_SHA = 'e4b5cebe1f805e4569929fa43111efd92aed8af560993b619a89c17c8a8acb56'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stat(path):
    s = path.stat()
    return dict(dev=s.st_dev,ino=s.st_ino,bytes=s.st_size,mtime_ns=s.st_mtime_ns,
                ctime_ns=s.st_ctime_ns,nlink=s.st_nlink,mode=oct(s.st_mode & 0o777))


def saved(name, obj):
    path = HERE/name
    raw = json.dumps(obj,ensure_ascii=False,indent=2).encode()+b'\n'
    with path.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    return dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))


def saved_bytes(name, raw):
    path=HERE/name
    with path.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    return dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))


def bounded_file(path, pin, inputs, maximum=200000):
    p = ROOT/path; before = stat(p)
    need(before['bytes'] <= maximum, 'Small sealed input budget')
    with p.open('rb') as f:
        raw = f.read(maximum+1)
        need(f.read(1)==b'', 'Small input EOF')
    need(sha(raw)==pin and stat(p)==before,'Small input SHA/stat pin')
    inputs.append(dict(path=path,bytes=len(raw),sha256=pin,stat_before=before,
                       stat_after=stat(p),EOF_verified=True))
    return raw


def load(path,pin,inputs,maximum=200000):
    return json.loads(bounded_file(path,pin,inputs,maximum))


class Budget:
    def __init__(self): self.bytes=0; self.rows=[]
    def read(self, image, at, size, purpose):
        need(type(at) is int and type(size) is int and 0<=at<=at+size<=image.size,
             'Explicit physical IMG bounds')
        need(self.bytes+size<=LIMIT,'Global 1MiB IMG read cap')
        image.f.seek(at); data=image.f.read(size)
        need(len(data)==size,'Complete actual physical read')
        self.bytes+=size
        self.rows.append(dict(image=image.name,physical_offset=at,bytes=size,
                              sha256=sha(data),purpose=purpose))
        return data


class Image:
    """Strict six-component mapper for the TWO sealed profiles only."""
    def __init__(self,name,f,pin,budget):
        self.name,self.f,self.pin,self.budget=name,f,pin,budget
        f.seek(0,2); self.size=f.tell(); self.block_bytes=pin['block_bytes']
        need(self.size==pin['bytes'] and self.size%self.block_bytes==0,'Exact candidate byte count')
        h=self.physical(0,512,'actual header'); self.header=h
        need(h[0]==0 and h[16:23]==b'DSKIMG\0' and h[65:72]==b'GARMIN\0'
             and h[510:512]==b'\x55\xaa','Actual AP header markers')
        profile=(9,3) if self.block_bytes==4096 else (9,4)
        sectors=262144 if self.block_bytes==4096 else 524288
        need(tuple(h[97:99])==profile and struct.unpack_from('<H',h,99)[0]==32768
             and struct.unpack_from('<I',h,458)[0]==sectors,'Strict actual 4K/8K capacity profile')
        self.capacity=32768*self.block_bytes
        need(self.capacity==sectors*512 and self.size<=self.capacity,'Actual capacity coherence')
        start=h[64]*512; root=self.physical(start,512,'actual root FAT row')
        need(root[0]==1 and root[1:12]==b' '*11 and root[16]==3
             and struct.unpack_from('<H',root,17)[0]==0,'Canonical root FAT')
        end=struct.unpack_from('<I',root,12)[0]
        need(start>=512 and start+512<=end<=self.size and end<=200000
             and end%self.block_bytes==0,'Bounded metadata extent')
        need(self.blocks(root)==list(range(end//self.block_bytes)),'Exact metadata allocation')
        owners={i:'<metadata>' for i in range(end//self.block_bytes)}
        directory=root+self.physical(start+512,end-start-512,'actual remaining FAT rows')
        self.components={}; order=[]; last=None; used=0; free=0
        for at in range(512,len(directory),512):
            row=directory[at:at+512]
            if row[0]==0:
                need(row==bytes(512),'Unused FAT row zero'); free+=1; continue
            need(row[0]==1 and row[16]!=3,'Canonical component FAT row')
            name=row[1:9].decode('ascii').rstrip(' ')+'.'+row[9:12].decode('ascii').rstrip(' ')
            part=struct.unpack_from('<H',row,17)[0]; size=struct.unpack_from('<I',row,12)[0]
            if part==0:
                need(name in NAMES and name not in self.components and size>0,'Exact component identity')
                self.components[name]=dict(size=size,blocks=[],parts=0); order.append(name); last=name
            need(name==last and part==self.components[name]['parts'],'Ordered FAT continuation')
            need(part==0 or size==0,'Continuation zero logical size')
            ids=self.blocks(row); need(ids,'Positive allocated block count')
            for block in ids:
                need(block not in owners,'No allocation overlap'); owners[block]=name
            self.components[name]['blocks'].extend(ids); self.components[name]['parts']+=1; used+=1
        need(tuple(order)==NAMES,'Original six components exactly')
        for c in self.components.values():
            need(len(c['blocks'])==(c['size']+self.block_bytes-1)//self.block_bytes
                 and c['parts']==(len(c['blocks'])+239)//240,'Exact allocation ceil/continuation count')
        need(set(owners)==set(range(self.size//self.block_bytes)),'No orphan allocation')
        self.directory_start,self.directory_end,self.used_rows,self.free_rows=start,end,used,free
    def blocks(self,row):
        out=[]; ended=False
        for v in struct.unpack_from('<240H',row,32):
            if v==65535: ended=True
            else:
                need(not ended and v<self.size//self.block_bytes,'Allocation block/padding bounds'); out.append(v)
        return out
    def physical(self,at,size,purpose): return self.budget.read(self,at,size,purpose)
    def logical(self,name,at,size,purpose):
        need(name in self.components and 0<=at<=at+size<=self.components[name]['size'],'Logical component bounds')
        c=self.components[name]; end=at+size; out=bytearray()
        while at<end:
            ordinal,within=divmod(at,self.block_bytes); n=min(end-at,self.block_bytes-within)
            out.extend(self.physical(c['blocks'][ordinal]*self.block_bytes+within,n,
                                     purpose+'; '+name+' logical '+str(at))); at+=n
        return bytes(out)


class Records:
    def __init__(self,image,extract,decode):
        self.image,self.extract,self.decode=image,extract,decode
        self.tables={}; self.labels={}; self.group_windows={}
        header=image.logical('00004171.MDR',0,772,'MDR header')
        need(struct.unpack_from('<H',header)[0]==772 and header[2:12]==b'GARMIN MDR','Actual MDR marker')
        start,size,item,tag=struct.unpack_from('<4I',header,600)
        need((size,item,tag)==(120,20,1) and start+120==image.components['00004171.MDR']['size'],'Actual six DIR at EOF')
        directory=image.logical('00004171.MDR',start,120,'actual six table descriptors')
        for level in range(1,7):
            a,b,stride,w,x=struct.unpack_from('<5I',directory,(level-1)*20)
            widths=[w>>18&63,w>>24&63,w>>12&63,w>>6&63,w&63,x&63,x>>11&63,x>>17&63]
            refs=[w>>30&1,w>>31&1]; count=b*8//stride
            need((widths,refs,stride)==PROFILES[level-1] and count==image.pin['counts'][level-1]
                 and b==(count*stride+7)//8,'Exact sealed actual profile/count')
            self.tables[level]=dict(level=level,start=a,bytes=b,stride=stride,count=count,widths=widths,
                                    refs=refs,directory_hex=directory[(level-1)*20:level*20].hex())
        cursor=self.tables[6]['start']
        for level in [6,5,4,3,2,1]:
            need(self.tables[level]['start']==cursor,'Tight native table suffix'); cursor+=self.tables[level]['bytes']
        need(cursor==start,'Actual table suffix closes at DIR'); self.directory_start=start
        gmp=image.logical('I053061A.GMP',0,57,'GMP header')
        need(struct.unpack_from('<H',gmp)[0]==57 and gmp[2:12]==b'GARMIN GMP','Actual GMP marker')
        lbl_at=struct.unpack_from('<7I',gmp,25)[2]
        lbl=image.logical('I053061A.GMP',lbl_at,661,'LBL header')
        need(struct.unpack_from('<H',lbl)[0]==661 and lbl[2:12]==b'GARMIN LBL','Actual LBL marker')
        self.pool_start,self.pool_size=struct.unpack_from('<II',lbl,21); self.shift=lbl[29]
        need((self.pool_start,self.pool_size,self.shift,lbl[30],struct.unpack_from('<H',lbl,170)[0])
             ==(6566,3805432,3,10,950),'Original existing CP950 label pool')
        need(self.pool_start+self.pool_size<=image.components['I053061A.GMP']['size'],'Pool bounds')
    def label(self,ref):
        if ref is None: return None
        if ref not in self.labels:
            need(type(ref) is int and 0<=ref<524287 and (ref<<self.shift)<self.pool_size,'Label ref bounds')
            offset=ref<<self.shift
            raw=self.image.logical('I053061A.GMP',self.pool_start+offset,min(64,self.pool_size-offset),'CP950 label ref '+str(ref))
            end=raw.find(b'\0'); need(end>=0,'Bounded actual text NUL')
            self.labels[ref]=raw[:end].decode('cp950',errors='strict')
        return self.labels[ref]
    def unpack(self,level,ID,value,shift):
        t=self.tables[level]; r=self.decode(value,t)
        need(r['mapordinal']==1,'AP mapordinal1')
        r.update(record=level<<28|ID,level=level,ID=ID,payload=value.to_bytes((t['stride']+7)//8,'little').hex(),
                 initial_bit_shift=shift,label=self.label(r['primary_ref']))
        return r
    def record(self,level,ID):
        t=self.tables[level]; need(1<=ID<=t['count'],'Record ID bounds')
        byte,shift=divmod((ID-1)*t['stride'],8)
        raw=self.image.logical('00004171.MDR',t['start']+byte,(shift+t['stride']+7)//8,'L%d ID%d'%(level,ID))
        r=self.unpack(level,ID,self.extract(raw,shift,t['stride']),shift)
        r.update(table_relative_bit_offset=(ID-1)*t['stride'],table_relative_byte_offset=byte,
                 logical_MDR_byte_offset=t['start']+byte)
        return r
    def group(self,parent):
        level,first,count=parent['next_level'],parent['first_child'],parent['child_count']
        need(level in self.tables and 1<=count<=1023,'Chosen parent <=1023 children')
        t=self.tables[level]; need(1<=first and first+count-1<=t['count'],'Group bounds')
        byte,shift=divmod((first-1)*t['stride'],8)
        raw=self.image.logical('00004171.MDR',t['start']+byte,(shift+count*t['stride']+7)//8,
                               'Exact children of '+str(parent['record']))
        self.group_windows[parent['record']]=dict(raw=raw,level=level,first=first,count=count,
             initial_bit_shift=shift,significant_bits=count*t['stride'],
             table_relative_bit_offset=(first-1)*t['stride'],table_relative_byte_offset=byte,
             logical_MDR_byte_offset=t['start']+byte)
        result=[]
        for ordinal in range(count):
            r=self.unpack(level,first+ordinal,self.extract(raw,shift+ordinal*t['stride'],t['stride']),
                          (shift+ordinal*t['stride'])%8)
            r['ordinal']=ordinal; result.append(r)
            r.update(table_relative_bit_offset=(first+ordinal-1)*t['stride'],
                     table_relative_byte_offset=((first+ordinal-1)*t['stride'])//8,
                     logical_MDR_byte_offset=t['start']+((first+ordinal-1)*t['stride'])//8)
        return result


def main():
    need(not (HERE/'proof.json').exists(),'New finite scope')
    began=datetime.now(timezone.utc).isoformat(); t0=time.monotonic(); inputs=[]; budget=Budget()
    raw=bounded_file(READER_PATH,READER_SHA,inputs)
    tree=ast.parse(raw.decode()); selected=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('extract','decode')]
    need([n.name for n in selected]==['extract','decode'],'Only existing ordinary pure bit helper definitions')
    helpers={'need':need}; exec(compile(ast.Module(body=selected,type_ignores=[]),READER_PATH,'exec'),helpers)
    helper_bindings={n.name:sha(ast.dump(n,include_attributes=False).encode()) for n in selected}
    cpu_seal=load('staging/navigation-country-native-lane-cpu-v3/sealed-files.json',
                  '4dca5ab38bbf621d42d03b9b5f3fd319054cbef3c12ef43ab7ef198ac0bdfcdb',inputs)
    selection_pin=next(r for r in cpu_seal['files'] if Path(r['path']).name=='finite-selection.json')
    need(selection_pin['sha256']=='7315e1f0ec601a971765f4b3ec8f96656ac3ed291da6a23bf4a8f4a97aeb6ffb','Known sealed small sample')
    need(cpu_seal['all_assigned_actual_CPU_checks_passed'],'Inherited finite CPU scope passed')
    selection=load(selection_pin['path'],selection_pin['sha256'],inputs)
    review_seal=load('staging/navigation-country-native-lane-independent-review-v3/sealed-files.json',
                     'c091c972bb50a7d0e38c469f21aa02aab21c6394156bcbca0ec4ebeaae2aab99',inputs)
    need(review_seal['all_assigned_checks_passed'],'Inherited complete v3 native readback review')
    witness=load('staging/navigation-country-native-lane-independent-review-v3/actual-native-CPU-witnesses.json',
                 '7431c5821d1f322d6c7a74c473b3df450fd62dcc785fc3a06e1d7e841d28b59a',inputs)
    review=load('staging/navigation-country-native-lane-independent-review-v3/proof.json',
                '9b2ba5d69d26939911fdfe2c311736d22244e80afc6850668716075ee8e5e01d',inputs)
    need(review['all_assigned_checks_passed'] and witness['source_full_EOF_verified'],'Full producer provenance/readback scope inherited only')
    screens=[]; candidate=None
    for sampled in selection['new_leaf_samples'][:3]:
        row=sampled['sample']; target=row['source_ready_target']; members=row['source_members']
        reasons=[]
        if any(m['separate_floor_unit_nodes'] for m in members): reasons.append('floor_unit_door_level_metadata_present')
        if any(m['embedded_floor_unit'] for m in members): reasons.append('embedded_floor_unit')
        if target['reasons']: reasons+=target['reasons']
        if not all(m['coordinate_selection_ready'] and m['different_coordinate_nodes']==0 for m in members): reasons.append('coordinate_conflict')
        screens.append(dict(new_lowID=row['new_lowID'],house_label=row['house_label'],raw_address=members[0]['raw_address'],
                            source_ids=row['source_ids'],reasons=reasons,eligible_for_this_control=not reasons))
        if not reasons:
            candidate=row; break
    need(candidate is not None and len(screens)<=3,'Finite <=3 candidate choice with source holds')
    need(candidate['source_ids']==[12084620255] and candidate['source_group_ids']==[3508619]
         and candidate['new_lowID']==2668082 and candidate['house_label']=='2號','Exactly scoped selected control')
    ready=candidate['source_ready_target']; parent=ready['actual_parent']
    need(parent['city']=='新北市' and parent['district']=='板橋區' and parent['path_tokens']==['4巷']
         and parent['root_street_record']==805307521,'Literal native lane path')
    need(candidate['source_members']==ready['source_members'] and candidate['source_ids']==ready['source_ids']
         and candidate['raw24']==ready['planned_raw24'] and candidate['coordinate_strings']==ready['selected_coordinate_strings'],
         'Complete embedded source identity')
    need(sorted({v for m in candidate['source_members'] for v in m['source_ids']})==candidate['source_ids']
         and all(type(v) is int and v>0 for v in candidate['source_ids'])
         and candidate['source_node_count']==sum(m['source_node_count'] for m in candidate['source_members']),
         'Complete positive source IDs/member node count')
    quantized=[int((Decimal(v)*Decimal(1<<24)/Decimal(360)).quantize(Decimal(1),rounding=ROUND_HALF_UP))
               for v in candidate['coordinate_strings']]
    need(quantized==candidate['raw24'],'Source Decimal nearest24 matches recorded prototype quantization')
    need(all(ready[k]['eligible'] and ready[k]['geometry_scope']=='complete_city_only_not_district'
             for k in ('source_geometry_decision','exact_raw24_geometry_decision')),'Honest inherited city-only geometry scope')
    matches=[r for r in witness['new_leaf_samples'] if r['sample']['new_lowID']==candidate['new_lowID']]
    need(len(matches)==1 and matches[0]['sample']==candidate,'Small source sample exactly equals full-review witness')
    paths=[r for r in selection['complete_path_samples'] if r['stock_parent_record']==candidate['stock_parent_record']]
    need(len(paths)==1,'Unique embedded full ancestor path'); path=paths[0]
    boundimages={}; actual={}; captured_groups={}
    for name,pin in IMAGES.items():
        seal=load(pin['seal'],pin['seal_sha256'],inputs)
        need(seal['all_assigned_checks_passed'],'Actual IMG producer seal passed')
        imgrow=next(r for r in seal['files'] if r['path']==pin['path'])
        need((imgrow['bytes'],imgrow['sha256'])==(pin['bytes'],pin['sha256']),'Inherited IMG whole SHA identity')
        p=ROOT/pin['path']; before=stat(p); old=imgrow['stat_at_seal']
        need([before[k] for k in ('dev','ino','bytes','mtime_ns')]==old[:4]
             and before['mode']=='0o444','Same immutable content inode/size/mtime; post-release link ctime captured fresh')
        with p.open('rb') as f:
            image=Image(name,f,pin,budget); records=Records(image,helpers['extract'],helpers['decode'])
            root=records.record(3,1153)
            need(root['label']=='四川路二段' and root['raw_flags']==4 and root['next_level']==4,'Actual exact root')
            rootgroup=records.group(root); lanes=[r for r in rootgroup if r['label']=='4巷']
            need(len(lanes)==1 and lanes[0]['next_level']==5 and lanes[0]['raw_flags']==5,'Unique actual exact 4巷→L5 path')
            lane=lanes[0]
            expected_parent=path['current_v2_parent_record'] if name=='v2' else path['new_COW_parent_record']
            need(lane['record']==expected_parent,'Same selected current/final ancestor binding')
            houses=records.group(lane); found=[r for r in houses if r['label']==candidate['house_label']]
            need(len(found)==(0 if name=='v2' else 1),'Selected true v3 new leaf absent v2/exact unique v3')
            if name=='v3':
                leaf=found[0]
                need(leaf['ID']==candidate['new_lowID'] and leaf['payload']==candidate['payload']
                     and leaf['primary_ref']==candidate['primary_ref']
                     and [leaf['raw_location_a'],leaf['raw_location_b']]==candidate['raw24'],
                     'Actual V3 payload/ref/raw24 matches complete embedded source')
            need(records.label(candidate['primary_ref'])==candidate['house_label'],'Existing actual v2/v3 house text, no new GMP label')
            captured_groups[name]={'root':records.group_windows[root['record']],
                                   'lane':records.group_windows[lane['record']]}
            actual[name]=dict(root=root,lane=lane,houses=houses,root_children=rootgroup,
                              leaf_matches=found,tables=records.tables,
                              actual_container=dict(block_bytes=image.block_bytes,capacity=image.capacity,
                                metadata_start=image.directory_start,metadata_end=image.directory_end,
                                component_sizes={k:v['size'] for k,v in image.components.items()},
                                component_block_counts={k:len(v['blocks']) for k,v in image.components.items()},
                                component_part_counts={k:v['parts'] for k,v in image.components.items()},
                                free_FAT_rows=image.free_rows,used_FAT_rows=image.used_rows,
                                header_sha256=sha(image.header),header_hex=image.header.hex()))
            need(stat(p)==before,'Actual candidate stat/nlink stable while rb handle open')
        need(stat(p)==before,'Actual candidate stat stable after closed handle')
        boundimages[name]=dict(path=pin['path'],bytes=pin['bytes'],inherited_whole_SHA256=pin['sha256'],
                              hash_recomputed=False,stat_before=before,stat_after=stat(p),handle_closed=True)
    v2,v3=actual['v2'],actual['v3']
    need(v2['lane']['child_count']==4 and v3['lane']['child_count']==6,'Exact four-to-six selected terminal group')
    old=v2['houses']; full=v3['houses']; old_by_payload=Counter(r['payload'] for r in old)
    kept=[r for r in full if old_by_payload[r['payload']]>0]
    need([r['payload'] for r in kept]==[r['payload'] for r in old],'All actual prior L5 significant bits/order preserved in v3 group')
    need(all(r['next_level']==r['child_count']==r['first_child']==r['raw_flags']==0 for r in old+full),
         'Selected L5 terminal subtree has no nested child pointers/unknown flags')
    def numeric_key(label):
        match=re.fullmatch(r'([1-9][0-9]*)(?:之([1-9][0-9]*))?號',label)
        return (int(match[1]),int(match[2] or 0)) if match else None
    numeric=[numeric_key(r['label']) for r in old]
    need(all(n is not None for n in numeric) and numeric==sorted(numeric)
         and len(numeric)==len(set(numeric)) and (2,0) not in numeric,
         'Exact existing positive integer/之subnumber ordering; no ambiguous house parsing')
    leaf=v3['leaf_matches'][0]
    single=sorted(old+[leaf],key=lambda r:numeric_key(r['label']))
    new_first4=v2['tables'][4]['count']+1; new_first5=v2['tables'][5]['count']+1
    root_count=v2['root']['child_count']; house_count=len(single)
    need(root_count<=1023 and new_first4+root_count-1<(1<<23) and new_first5<(1<<22)
         and house_count<(1<<10),'Actual same-profile first/count capacity')
    new_counts=[v2['tables'][i]['count'] for i in range(1,7)]
    new_counts[3]+=root_count; new_counts[4]+=house_count
    old5bytes=v2['tables'][5]['bytes']; new5bytes=(new_counts[4]*126+7)//8
    delta4=root_count*16; delta5=new5bytes-old5bytes; delta=delta4+delta5
    container=v2['actual_container']; old_mdr=container['component_sizes']['00004171.MDR']; new_mdr=old_mdr+delta
    blocks_before=container['component_block_counts']['00004171.MDR']; blocks_after=(new_mdr+4095)//4096
    parts_before=container['component_part_counts']['00004171.MDR']; parts_after=(blocks_after+239)//240
    needed_FAT_rows=parts_after-parts_before
    need(needed_FAT_rows<=container['free_FAT_rows'],'Existing actual 4K metadata row capacity')
    projected_image_bytes=IMAGES['v2']['bytes']+(blocks_after-blocks_before)*4096
    need(projected_image_bytes<=container['capacity'],'Actual v2 4K capacity fits finite control arithmetic')
    # Name/ref/order equality proves how to pair copied root rows. No broad v3 subtree copy.
    need(len(v2['root_children'])==len(v3['root_children']),'Bounded selected root group same count')
    same_keys=lambda r:(r['label'],r['primary_ref'],r['secondary_ref'],r['raw_flags'])
    need([same_keys(r) for r in v2['root_children']]==[same_keys(r) for r in v3['root_children']],
         'Root group ordinal/name/ref/flags pairing')
    changed_pointers=[dict(ordinal=a['ordinal'],label=a['label'],v2_record=a['record'],v3_record=b['record'],
                          v2_next=a['next_level'],v3_next=b['next_level'],
                          v2_first=a['first_child'],v3_first=b['first_child'],
                          v2_count=a['child_count'],v3_count=b['child_count'])
        for a,b in zip(v2['root_children'],v3['root_children'])
        if (a['first_child'],a['child_count'])!=(b['first_child'],b['child_count'])]
    plan=dict(schema='garmin-minimal-one-lane-render-control-plan/v1',actual_IMG_created=False,
        chosen_source=candidate,source_geometry_reexecuted=False,
        geometry_scope='inherited complete city only; native exact city/district names, no source district polygon assertion',
        baseline='actual country v2 4K/23-bit L3 first/112-bit stride',
        updated_records=[dict(level=3,ID=1153,first_child=new_first4,child_count=root_count,
                              preserve_other_fields_and_raw_flags=True),
            dict(level=4,source_v2_lane_ID=v2['lane']['ID'],new_lane_ID=new_first4+v2['lane']['ordinal'],
                 first_child=new_first5,child_count=house_count,raw_flags=5)],
        actual_v2_root_group_to_clone=dict(level=4,first=v2['root']['first_child'],count=root_count,
                                          significant_bits=root_count*128),
        appended_L5=dict(first=new_first5,count=house_count,significant_bits=house_count*126,
                        relative_order_labels=[r['label'] for r in single],new_leaf_ordinal=single.index(leaf),
                        selected_new_leaf_payload=leaf['payload'],selected_new_leaf_ref=leaf['primary_ref'],
                        prior_significant_bits_retained=True,other_v3_new_house_excluded=['3號']),
        exact_v3_terminal_subtree=dict(level=5,first=v3['lane']['first_child'],count=len(full),
            has_nested_child_pointers=False,can_clone_without_lower_pointer_remap=True,
            direct_clone_would_add_two_houses=[r['label'] for r in full if r['payload'] not in old_by_payload],
            directly_clone_only_selected_payload_for_this_one_leaf_control=True,
            complete_group_clone_not_approved_by_this_single_source_scope=True),
        unsafe_v3_root_group_copy=dict(changed_childptr_count=len(changed_pointers),changed_childptrs=changed_pointers,
            explanation='Other v3 lane/alley child pointers target v3 COW groups. Clone actual v2 root group instead; only chosen lane pointer changes.',
            remap_other_childptr_needed_if_copy_v3_group=True,
            chosen_lane_old_childptr_maps_back_to_v2_first=v2['lane']['first_child']),
        table_counts_before=IMAGES['v2']['counts'],table_counts_projected=new_counts,
        lower_widths_and_strides_unchanged={str(i):dict(widths=v2['tables'][i]['widths'],stride=v2['tables'][i]['stride']) for i in (3,4,5,6)},
        L5_tight_bit_splice=dict(old_significant_bits=v2['tables'][5]['count']*126,
            old_unused_pad_bits=(-v2['tables'][5]['count']*126)%8,
            appended_significant_bits=house_count*126,new_unused_pad_bits=(-new_counts[4]*126)%8,
            byte_prefix_append_valid=False),
        arithmetic=dict(L4_logical_growth_bytes=delta4,L5_logical_growth_bytes=delta5,MDR_logical_growth_bytes=delta,
            MDR_bytes_before=old_mdr,MDR_bytes_projected=new_mdr,
            MDR_4K_blocks_before=blocks_before,MDR_4K_blocks_projected=blocks_after,
            MDR_FAT_parts_before=parts_before,MDR_FAT_parts_projected=parts_after,
            additional_FAT_rows=needed_FAT_rows,current_metadata_bytes=container['metadata_end'],
            IMG_bytes_before=IMAGES['v2']['bytes'],IMG_bytes_projected=projected_image_bytes,
            declared_4K_capacity=container['capacity'],within_original_v2_4K_capacity=True),
        original_v2_header_can_be_preserved_in_future_layout=True,
        original_v2_header_preservation_qualification='Arithmetic and existing FAT row capacity only. Future writer must preserve exact header/nonallocation metadata and validate actual output.',
        future_changes_required=['L5 significant-bit splice at actual v2 end, retaining old significant bits',
            'L4 append original v2 chosen root group with only chosen lane first/count patch',
            'L3 root1153 first/count bit patch at actual112-bit profile',
            'Shift existing L4/L3/L2/L1 starts and DIR offset by lower logical growth as required; patch exact six DIR entries and MDRheader600',
            'Update MDR FAT logical size/4K allocation, preserve other five component bytes and allocation metadata'],
        GMP_new_text_needed=False,existing_actual_label_ref=19,existing_actual_label_text='2號',
        LBL_JAI_SQLite_change_needed=False,device_acceptance=False,renderer_result_verified=False,
        official_postal_house_verified=False,source_OSM_semantics_only=True,full_Taiwan_complete=False)
    artifacts={}
    rawcaptures={}
    for key,window in [('v2-root-L4',captured_groups['v2']['root']),('v2-lane-L5',captured_groups['v2']['lane'])]:
        rawcaptures[key]=dict(**{k:v for k,v in window.items() if k!='raw'},
                             artifact=saved_bytes(key+'-raw-window.bin',window['raw']))
    # Extract from the actual cached V3 group; no second IMG read, pointer patch, or writer output.
    window=captured_groups['v3']['lane']; ordinal=leaf['ordinal']; width=v3['tables'][5]['stride']
    actual_value=helpers['extract'](window['raw'],window['initial_bit_shift']+ordinal*width,width)
    actual_leaf_bytes=actual_value.to_bytes((width+7)//8,'little')
    need(actual_leaf_bytes.hex()==candidate['payload'],'Cached true actual V3 leaf significant bits')
    rawcaptures['v3-selected-house-L5']=dict(record=leaf['record'],ID=leaf['ID'],significant_bits=width,
        original_table_bit_offset=leaf['table_relative_bit_offset'],original_table_byte_offset=leaf['table_relative_byte_offset'],
        original_initial_bit_shift=leaf['initial_bit_shift'],original_logical_MDR_byte_offset=leaf['logical_MDR_byte_offset'],
        primary_ref=leaf['primary_ref'],raw24=[leaf['raw_location_a'],leaf['raw_location_b']],
        artifact=saved_bytes('v3-selected-2-house-L5-significant-bits.bin',actual_leaf_bytes),
        extracted_from_cached_actual_group=True,high_unused_bits_zero=(-width)%8)
    artifacts['raw_capture_metadata']=saved('actual-raw-capture-metadata.json',dict(
        schema='garmin-minimal-control-original-window-captures/v1',captures=rawcaptures,
        parent_actual_bit_offsets={name:dict(root=actual[name]['root'],lane=actual[name]['lane']) for name in IMAGES},
        complete_source_members=candidate['source_members'],actual_IMG_reread_for_capture=False,
        pointer_patch_or_append_payload_produced=False))
    artifacts['candidate']=saved('selected-control.json',dict(schema='garmin-source-backed-minimal-lane-control/v1',
        candidate=candidate,complete_ancestor_path=path,screened_candidates=screens,
        inherited_full_new_leaf_ledger_pin=witness['source_new_leaf_ledger_pin'],
        full_ledger_read_this_scope=False,source_geometry_scope='city only, not district polygon',
        official_postal_house_verified=False,alias_transform_used=False))
    artifacts['actual']=saved('actual-v2-v3-records.json',actual)
    artifacts['plan']=saved('minimal-cow-plan.json',plan)
    artifacts['reads']=saved('actual-IMG-read-receipts.json',dict(schema='garmin-bounded-ordinary-file-read-ledger/v1',
                    total_bytes=budget.bytes,operation_count=len(budget.rows),global_cap_bytes=LIMIT,reads=budget.rows))
    proof=dict(schema='garmin-minimal-lane-render-isolation-proof/v1',started_utc=began,
        finished_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        source_files=inputs,ordinary_helper_AST_bindings=helper_bindings,actual_candidates=boundimages,
        actual_candidate_IMG_bytes_read=budget.bytes,actual_candidate_IMG_read_operations=len(budget.rows),
        per_image_bytes_read=dict(Counter({name:sum(r['bytes'] for r in budget.rows if r['image']==name) for name in IMAGES})),
        candidate_count_screened=len(screens),selected_candidate_count=1,
        source_node_ids=candidate['source_ids'],source_group_ids=candidate['source_group_ids'],
        v2_house_exact_membership='absent',v3_house_exact_membership='unique',
        actual_v3_payload_matches_sealed_source=True,full_source_provenance_in_small_sealed_sample=True,
        full_source_ledger_EOF_and_SHA_inherited_only=True,source_big_ledger_read=False,
        all_original_v2_selected_L5_records_preserved_in_v3_significant_bits_and_order=True,
        actual_root_children=len(v2['root_children']),actual_selected_house_children={'v2':len(old),'v3':len(full)},
        no_floor_unit_door_level_annotation=True,no_embedded_floor_unit=True,no_source_coordinate_conflict=True,
        no_street_alias_or_name_guess_applied=True,source_geometry_city_only_not_district=True,
        actual_v2_L3_first_width=23,actual_v2_L3_stride=112,actual_v3_L3_first_width=23,actual_v3_L3_stride=112,
        stock22_111_not_used_as_v2_profile=True,not_the_source172188_existing_address=True,
        artifacts=artifacts,MAIN_bytes_read=0,CPU_executed=False,audio_or_native_guest_executed=False,
        physical_device_IO=False,IMG_or_DIR_or_GMP_written=False,whole_IMG_hash_recomputed=False,
        new_IMG_created=False,source_metadata_or_sealed_files_modified=False,
        official_postal_house_or_current_UI_or_renderer_acceptance_verified=False,
        full_Taiwan_or_App_goal_complete=False,max_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        elapsed_seconds_receipt_only=time.monotonic()-t0)
    p=saved('proof.json',proof)
    print(json.dumps(dict(all_assigned_checks_passed=True,proof=p,actual_IMG_read_bytes=budget.bytes,
        v2_new_house_absent=True,v3_new_house_unique=True,projected_new_leaf_count=1,
        projected_MDR_growth=delta,projected_IMG_bytes=projected_image_bytes,
        actual_v3_changed_childptr_count=len(changed_pointers),handles_closed=True),ensure_ascii=False))


if __name__=='__main__':
    try:
        main()
    except Exception as exc:
        if not (HERE/'failure.json').exists():
            saved('failure.json',dict(schema='garmin-finite-control-failure/v1',exception_type=type(exc).__name__,
                error=str(exc),retry_or_guard_relaxation=False,new_IMG_created=False,device_IO=False))
        raise
