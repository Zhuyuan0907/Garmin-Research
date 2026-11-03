#!/usr/bin/env python3
"""Independent strict AP8K mapper and actual tree/house review.

Does not import any writer/repacker/parser helper or execute native CPU code.
"""
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter,defaultdict
from bisect import bisect_right
import gzip
import hashlib
import json
import os
import re
import struct
import resource
import time

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
BASE=ROOT/'staging/navigation-country-native-lane-candidate-v3'
DATA=ROOT/'staging/navigation-native-lane-tree-cow-append-v1'
BASE_SEAL='dfc47744887137f944d710dffeb5ea6f6821c24eb8abbeb522cb406576754335'
BASE_PROOF='b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0'
BASE_SHA='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
BASE_STAT=[45826,538039,153346048,1791317242895661512,1791317284446198518]
DATA_SEAL='1c25b3963a3f9eb3b218a3747287e8154e253745698f5087064df1135445b077'
DATA_PROOF='1cde367d1d3aba44290b7f44be40c9cb5d04bf911a3e8bd3898e071a1329b4e9'
NAMES=('00004171.MD2','00004171.MDR','00004171.SRT','I053061A.GMP','I053061A.SRT','MAPSOURC.MPS')
PATH=re.compile(r'[A-Z0-9_]{1,8}\.[A-Z0-9_]{3}\Z')
PROFILES=[([16,9,24,19,1,10,0,0],[1,1],122),([16,9,24,19,1,10,0,0],[1,1],122),
          ([23,9,24,19,1,12,0,0],[1,0],112),([22,9,24,19,1,10,0,0],[1,1],128),
          ([21,9,24,19,1,9,0,0],[1,1],126),([0,0,24,19,1,0,0,0],[1,0],68)]
COUNTS=[22,343,47870,4896236,3077845,2062771]
MAX_RSS_KIB=512000


def need(x,message):
    if not x:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def stat(path):
    s=path.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def load(path,pin,inputs,maximum=1000000):
    before=stat(path);need(before[2]<=maximum,'Bounded immutable metadata');raw=path.read_bytes()
    need(sha(raw)==pin and stat(path)==before,'Metadata seal/pin/stat')
    inputs.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=pin,stat_before=before,stat_after=stat(path)))
    return json.loads(raw)


class HashReader:
    def __init__(self,f):self.f=f;self.h=hashlib.sha256();self.count=0
    def read(self,n=-1):
        raw=self.f.read(n);self.h.update(raw);self.count+=len(raw);return raw


def input_rows(path,pin,inputs):
    before=stat(path);rows=amount=0;h=hashlib.sha256()
    with path.open('rb')as f:
        r=HashReader(f)
        with gzip.GzipFile(fileobj=r,mode='rb')as z:
            for line in z:h.update(line);rows+=1;amount+=len(line);yield json.loads(line)
    need((r.count,r.h.hexdigest(),rows,amount,h.hexdigest())==(pin['bytes'],pin['sha256'],pin['rows'],pin['uncompressed_bytes'],pin['uncompressed_sha256']),
         'Complete sealed data compressed/plain/EOF/row pins')
    need(stat(path)==before,'Data immutable during stream')
    inputs.append(dict(path=str(path.relative_to(ROOT)),rows=rows,bytes=r.count,sha256=r.h.hexdigest(),uncompressed_bytes=amount,
                       uncompressed_sha256=h.hexdigest(),gzip_EOF_verified=True,stat_before=before,stat_after=stat(path)))


class Ledger:
    def __init__(self,name):
        self.path=HERE/name;self.f=self.path.open('xb');self.z=gzip.GzipFile(filename='',fileobj=self.f,mode='wb',mtime=0)
        self.h=hashlib.sha256();self.rows=self.amount=0
    def add(self,row):
        raw=json.dumps(row,ensure_ascii=False,separators=(',',':')).encode()+b'\n';self.z.write(raw);self.h.update(raw);self.amount+=len(raw);self.rows+=1
    def close(self):
        self.z.close();self.f.flush();os.fsync(self.f.fileno());self.f.close()
        return dict(path=str(self.path.relative_to(ROOT)),rows=self.rows,bytes=self.path.stat().st_size,sha256=sha(self.path.read_bytes()),
            uncompressed_bytes=self.amount,uncompressed_sha256=self.h.hexdigest())


def saved(name,row):
    p=HERE/name
    with p.open('x')as f:json.dump(row,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    return dict(path=str(p.relative_to(ROOT)),bytes=p.stat().st_size,sha256=sha(p.read_bytes()))


class Image8K:
    """Independent allocation parser; record offsets are never writer offsets."""
    def __init__(self,handle,log=None):
        self.handle,self.log=handle,log;self.readbytes=self.readops=0;handle.seek(0,2);self.size=handle.tell()
        need(self.size>0 and self.size%8192==0,'Whole8K input blocks')
        h=self.physical(0,512,'header');self.header=h
        need(h[0]==0 and h[16:23]==b'DSKIMG\0'and h[65:72]==b'GARMIN\0'and h[510:512]==b'\x55\xaa','AP XOR0 DSKIMG/GARMIN/end marker')
        need((h[97],h[98])==(9,4),'Exact explicit8K exponent profile')
        blocks=struct.unpack_from('<H',h,99)[0];sectors=struct.unpack_from('<I',h,458)[0]
        need((blocks,sectors)==(32768,524288),'Explicit8K capacity fields')
        self.capacity=blocks*8192;need(self.size<=self.capacity and self.capacity==sectors*512,'Declared capacity coherent')
        start=h[64]*512;need(512<=start<self.size,'Root directory start')
        root=self.physical(start,512,'root row');need(root[0]==1 and root[1:12]==b' '*11 and root[16]==3 and struct.unpack_from('<H',root,17)[0]==0,'Single canonical root DIR')
        end=struct.unpack_from('<I',root,12)[0];need(start+512<=end<=self.size and end%8192==0 and end<=1_000_000,'Bounded aligned root directory extent')
        metadata=tuple(range(end//8192));need(self.blocks(root)==metadata,'Root allocation covers metadata exactly')
        owners={i:'<metadata>'for i in metadata};directory=root+self.physical(start+512,end-start-512,'all allocation rows')
        components={};order=[];last=None
        for at in range(512,len(directory),512):
            row=directory[at:at+512]
            if row[0]==0:need(row==bytes(512),'Unused rows must be zero');continue
            need(row[0]==1 and row[16]!=3,'Canonical allocated component row')
            name=row[1:9].decode('ascii').rstrip(' ')+'.'+row[9:12].decode('ascii').rstrip(' ');need(PATH.fullmatch(name)is not None,'Canonical component path')
            part=struct.unpack_from('<H',row,17)[0];size=struct.unpack_from('<I',row,12)[0]
            if part==0:
                need(name not in components and size>0,'Unique positive-size component start');components[name]=dict(size=size,blocks=[],rows=[]);order.append(name);last=name
            need(name==last and part==len(components[name]['rows']),'Ordered unique FAT continuations')
            need(part==0 or size==0,'Continuation logical size zero');ids=self.blocks(row);need(ids,'Nonempty allocated part')
            for block in ids:need(block not in owners,'No repeated/overlapping physical blocks');owners[block]=name
            components[name]['blocks'].extend(ids);components[name]['rows'].append(row)
        need(tuple(order)==NAMES,'Exact six-component order/paths')
        for name,c in components.items():
            need(len(c['blocks'])==(c['size']+8191)//8192 and len(c['rows'])==(len(c['blocks'])+239)//240,'Exact component logical size/allocation/part count')
        need(set(owners)==set(range(self.size//8192)),'Complete allocation without orphan physical blocks')
        self.components=components;self.directory_start=start;self.directory_end=end
    def blocks(self,row):
        result=[];padding=False
        for value in struct.unpack_from('<240H',row,32):
            if value==65535:padding=True
            else:need(not padding and value<self.size//8192,'Block outside input/after padding sentinel');result.append(value)
        return tuple(result)
    def physical(self,at,size,purpose):
        need(type(at)is int and type(size)is int and 0<=at<=at+size<=self.size and size<=1_000_000,'Bounded physical read')
        self.handle.seek(at);raw=self.handle.read(size);need(len(raw)==size,'Complete physical read')
        self.readbytes+=size;self.readops+=1
        if self.log:self.log.add(dict(physical_offset=at,bytes=size,sha256=sha(raw),purpose=purpose))
        return raw
    def logical(self,name,at,size,purpose):
        need(name in self.components,'Known component');c=self.components[name]
        need(type(at)is int and type(size)is int and 0<=at<=at+size<=c['size']and size<=1_000_000,'Bounded logical component range')
        result=bytearray();cursor=at
        while cursor<at+size:
            ordinal,within=divmod(cursor,8192);n=min(at+size-cursor,8192-within)
            result.extend(self.physical(c['blocks'][ordinal]*8192+within,n,purpose+'; '+name+' logical '+str(cursor)));cursor+=n
        return bytes(result)


def extract(raw,bit,width):
    need(type(bit)is int and bit>=0 and type(width)is int and width>=0,'Explicit bit window')
    at,shift=divmod(bit,8);n=(shift+width+7)//8;need(at+n<=len(raw),'Bit read within declared span')
    return(int.from_bytes(raw[at:at+n],'little')>>shift)&((1<<width)-1)


def decode(value,table):
    widths=table['widths'];refs=table['refs'];cursor=0;result={}
    for name,width,on,isref in [('mapordinal',widths[4],True,False),('secondary_ref',widths[3],bool(refs[1]),True),
        ('primary_ref',widths[3],bool(refs[0]),True),('first_child',widths[0],bool(widths[0]),False),
        ('child_count',widths[5],bool(widths[5]),False),('raw_flags',widths[1],bool(widths[1]),False),
        ('raw_location_a',widths[2],bool(widths[2]),False),('raw_location_b',widths[2],bool(widths[2]),False)]:
        v=(value>>cursor)&((1<<width)-1)if on else None if isref else 0
        result[name]=None if on and isref and v==(1<<width)-1 else v;cursor+=width if on else 0
    need(cursor==table['stride'],'Complete descriptor-derived stride');result['next_level']=result['raw_flags']&7;return result


class Records:
    def __init__(self,image):
        self.image=image;self.cache={};self.labels={};self.tables={};self.unique_records=0
        header=image.logical('00004171.MDR',0,772,'MDR header');need(header[2:12]==b'GARMIN MDR'and struct.unpack_from('<H',header)[0]==772,'MDR header exact')
        start,size,item,tag=struct.unpack_from('<4I',header,600);need((size,item,tag)==(120,20,1)and start+size==image.components['00004171.MDR']['size'],'Actual6DIR/EOF')
        raw=image.logical('00004171.MDR',start,size,'Actual6DIR')
        for level in range(1,7):
            a,b,stride,w,x=struct.unpack_from('<5I',raw,(level-1)*20)
            widths=[w>>18&63,w>>24&63,w>>12&63,w>>6&63,w&63,x&63,x>>11&63,x>>17&63];refs=[w>>30&1,w>>31&1];count=b*8//stride
            need((widths,refs,stride)==PROFILES[level-1]and count==COUNTS[level-1]and b==(count*stride+7)//8,'Actual current profile/span/count')
            self.tables[level]=dict(level=level,start=a,bytes=b,stride=stride,count=count,widths=widths,refs=refs,directory_hex=raw[(level-1)*20:level*20].hex())
        cursor=self.tables[6]['start']
        for level in [6,5,4,3,2,1]:need(self.tables[level]['start']==cursor,'Physical suffix sequence');cursor+=self.tables[level]['bytes']
        need(cursor==start,'Tables→DIR exact closure');self.directory_start=start
        gmp=image.logical('I053061A.GMP',0,57,'Actual GMP header');need(gmp[2:12]==b'GARMIN GMP'and struct.unpack_from('<H',gmp)[0]==57,'GMP header')
        offset=struct.unpack_from('<7I',gmp,25)[2];lbl=image.logical('I053061A.GMP',offset,661,'Actual LBL header')
        need(lbl[2:12]==b'GARMIN LBL'and struct.unpack_from('<H',lbl)[0]==661,'LBL header')
        self.pool_start,self.pool_size=struct.unpack_from('<II',lbl,21);self.shift=lbl[29]
        need((self.pool_start,self.pool_size,self.shift,lbl[30],struct.unpack_from('<H',lbl,170)[0])==(6566,3805432,3,10,950),'Actual CP950 pool descriptor')
        need(self.pool_start+self.pool_size<=image.components['I053061A.GMP']['size'],'Actual LBL bounds')
    def label(self,ref):
        if ref is None:return None
        if ref not in self.labels:
            need(type(ref)is int and 0<=ref<524287,'Existing non-sentinel label reference');offset=ref<<self.shift;need(offset<self.pool_size,'Text ref bounds')
            raw=self.image.logical('I053061A.GMP',self.pool_start+offset,min(64,self.pool_size-offset),'CP950 ref '+str(ref));end=raw.find(b'\0');need(end>=0,'Bounded text NUL')
            self.labels[ref]=raw[:end].decode('cp950',errors='strict')
        return self.labels[ref]
    def record(self,encoded,cache=False):
        if encoded in self.cache:return self.cache[encoded]
        level,ID=encoded>>28,encoded&0xfffffff;need(level in self.tables,'Known record level');t=self.tables[level];need(1<=ID<=t['count'],'Actual one-based ID bounds')
        bit=(ID-1)*t['stride'];byte,shift=divmod(bit,8);raw=self.image.logical('00004171.MDR',t['start']+byte,(shift+t['stride']+7)//8,'L%d ID%d'%(level,ID))
        value=extract(raw,shift,t['stride']);r=decode(value,t);need(r['mapordinal']==1,'Actual AP mapordinal1')
        r.update(record=encoded,level=level,ID=ID,value=value,payload=value.to_bytes((t['stride']+7)//8,'little').hex(),initial_bit_shift=shift,
                 logical_offset=t['start']+byte,label=self.label(r['primary_ref']))
        if cache:self.cache[encoded]=r
        self.unique_records+=1;return r
    def group(self,level,first,count):
        t=self.tables[level];need(1<=first and count>0 and first+count-1<=t['count'],'Actual group bounds');bit=(first-1)*t['stride'];byte,shift=divmod(bit,8)
        raw=self.image.logical('00004171.MDR',t['start']+byte,(shift+count*t['stride']+7)//8,'Bounded root rawflag sample')
        return raw,shift,t


def main():
    need(not(HERE/'proof.json').exists(),'New independent scope only');started=datetime.now(timezone.utc).isoformat();t0=time.monotonic();inputs=[]
    bs=load(BASE/'sealed-files.json',BASE_SEAL,inputs);bp=load(BASE/'proof.json',BASE_PROOF,inputs)
    need(bs['all_assigned_checks_passed']and bp['all_assigned_checks_passed']and bp['candidate_sha256']==BASE_SHA,'Completed frozen v3 binding')
    ds=load(DATA/'sealed-files.json',DATA_SEAL,inputs);dp=load(DATA/'proof.json',DATA_PROOF,inputs);dpins={Path(r['path']).name:r for r in ds['files']}
    pathproof=load(DATA/'new-tree-path-proof.json',dpins['new-tree-path-proof.json']['sha256'],inputs)
    need(all(r['all_significant_bits_identical']for r in bp['lower_prefix_significant_bit_checks'])and
         all(r['matches_sealed_producer_stream']for r in bp['actual_append_extraction_checks']),'Inherited root full-prefix and shifted-append gates')
    candidate=BASE/'gmapprom1.img';before=stat(candidate);need(before==BASE_STAT and candidate.stat().st_mode&0o777==0o444,'Exact root terminal frozen stat')
    readlog=Ledger('actual-8K-read-receipts.jsonl.gz');pathsout=Ledger('actual-tree-path-review.jsonl.gz');leavesout=Ledger('actual-new-house-review.jsonl.gz');priorout=Ledger('actual-prior-copied-house-review.jsonl.gz')
    counts=Counter();globalshifts=defaultdict(Counter);finalparents={};rootgroups={};samples={};path_samples={};raw13=None;unknown_sample_rows=unknown_sample_groups=0
    with candidate.open('rb')as f:
        image=Image8K(f,readlog);records=Records(image)
        for row in input_rows(DATA/'new-tree-parent-paths.jsonl.gz',pathproof['artifact'],inputs):
            steps=row['complete_path'];links=row['ancestor_links'];actual=records.record(steps[0]['new_COW_record'],True);actualpath=[actual['record']]
            need(actual['label']==steps[0]['label']and actual['raw_flags']==steps[0]['raw_flags'],'Actual root CP950 label/rawflags')
            rootgroups[actual['record']]=(actual['next_level'],actual['first_child'],actual['child_count'])
            for link,step in zip(links,steps[1:]):
                need(actual['record']==link['parent_new_record']and(actual['next_level'],actual['first_child'],actual['child_count'],actual['raw_flags'])==
                    (link['next_level'],link['first_child'],link['count'],link['raw_flags']),'True current parent pointer/count/full flags')
                ordinal=link['child_ordinal'];need(0<=ordinal<actual['child_count'],'Child ordinal within actual parent')
                encoded=actual['next_level']<<28|(actual['first_child']+ordinal)
                need(encoded==link['child_new_record']==step['new_COW_record'],'Actual traversed child ID equals bound new path node')
                actual=records.record(encoded,True);need(actual['label']==step['label']and actual['raw_flags']==step['raw_flags'],'Actual child exact CP950 label/full rawflags')
                actualpath.append(encoded);counts['actual_ancestor_links']+=1
            need(actual['record']==row['new_COW_parent_record']and(actual['first_child'],actual['child_count'],actual['next_level'],actual['raw_flags'])==
                (row['new_house_group_first'],row['new_house_group_count'],row['next_leaf_level'],row['full_flags']),'Actual terminal house-containing parent')
            need(actual['record']not in finalparents,'Unique actual new parent path');finalparents[actual['record']]=actual
            path_samples[actual['record']]=row
            pathsout.add(dict(stock_parent_record=row['stock_parent_record'],actual_path=actualpath,parent_fields={k:v for k,v in actual.items()if k not in['value']},all_links_followed_from_actual_fields=True))
            counts['actual_complete_house_parent_paths']+=1
        need(counts['actual_complete_house_parent_paths']==20613 and counts['actual_ancestor_links']==24442 and len(rootgroups)==7650,'Every actual path/root/link')
        counts['actual_roots_high_first23']=sum(first>4194303 for level,first,count in rootgroups.values())
        for row in input_rows(DATA/'new-lane-house-records.jsonl.gz',dp['artifacts']['new_records'],inputs):
            parent=finalparents[row['new_parent_record']];need(parent['next_level']==row['level'],'Actual leaf next table from traversed parent')
            ID=parent['first_child']+row['group_ordinal'];need(0<=row['group_ordinal']<parent['child_count']and ID==row['new_lowID'],'Actual house ordinal reached through true terminal parent')
            actual=records.record(parent['next_level']<<28|ID)
            need(actual['value']==int.from_bytes(bytes.fromhex(row['payload']),'little')and actual['primary_ref']==row['primary_ref']and
                 [actual['raw_location_a'],actual['raw_location_b']]==row['raw24']and actual['label']==row['house_label'],'Every actual leaf payload/ref/raw24/CP950 text')
            need(actual['first_child']==actual['child_count']==actual['raw_flags']==0,'Actual new leaf zero branch fields')
            source=row['source_ready_target'];need(source['source_ids']==row['source_ids']and source['source_group_ids']==row['source_group_ids']and
                source['source_members']==row['source_members']and source['planned_raw24']==row['raw24']and not source['reasons'],'Full sealed source provenance inherited unchanged')
            need(sorted({ID for m in row['source_members']for ID in m['source_ids']})==row['source_ids'],'Actual complete source union')
            shift=actual['initial_bit_shift'];globalshifts[actual['level']][shift]+=1;samplekey='L%d_shift%d'%(actual['level'],shift)
            if samplekey not in samples:samples[samplekey]=dict(source_record=row,actual_record=actual,actual_parent=parent,actual_path=path_samples[parent['record']])
            if len(path_samples[parent['record']]['complete_path'])>=3 and'multi_ancestor_leaf'not in samples:
                samples['multi_ancestor_leaf']=dict(source_record=row,actual_record=actual,actual_parent=parent,actual_path=path_samples[parent['record']])
            leavesout.add(dict(level=actual['level'],lowID=ID,parent_record=parent['record'],actual_ref=actual['primary_ref'],actual_raw24=[actual['raw_location_a'],actual['raw_location_b']],
                actual_label=actual['label'],global_initial_bit_shift=shift,payload=actual['payload'],source_group_ids=row['source_group_ids'],source_ids=row['source_ids'],full_source_node_count=row['source_node_count']))
            counts['actual_new_house_leaves']+=1;counts['full_new_source_node_memberships']+=row['source_node_count']
            if counts['actual_new_house_leaves']%10000==0:
                need(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss<=MAX_RSS_KIB,'Actual independent memory guard')
                print(json.dumps(dict(new_houses=counts['actual_new_house_leaves'],readbytes=image.readbytes,max_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)),flush=True)
        need(counts['actual_new_house_leaves']==58233 and counts['full_new_source_node_memberships']==111147,'All actual source-bound new houses')
        # All copied prior leaves belong to a true selected root child group.
        groupedroots={level:sorted((first,count,root)for root,(nextlevel,first,count)in rootgroups.items()if nextlevel==level)for level in [4,5,6]}
        rootstarts={level:[r[0]for r in rows]for level,rows in groupedroots.items()}
        for row in input_rows(DATA/'prior-v2-new-leaf-identity-status.jsonl.gz',dp['artifacts']['prior_new_identities'],inputs):
            if row['status']!='actual_cloned_append_payload_identical':counts['outside_COW_prior_prefix_gate_inherited']+=1;continue
            level,ID=row['level'],row['cloned_lowID'];i=bisect_right(rootstarts[level],ID)-1;need(i>=0,'Copied prior leaf owned by selected actual root');first,count,root=groupedroots[level][i]
            need(first<=ID<first+count,'Copied prior leaf within actual root child range');parent=records.record(root,True);ordinal=ID-parent['first_child']
            actual=records.record(parent['next_level']<<28|(parent['first_child']+ordinal));need(actual['value']==int.from_bytes(bytes.fromhex(row['unchanged_payload']),'little'),
                'Every copied prior house identical in actual selected path')
            need(actual['child_count']==actual['first_child']==0 and actual['label']is not None,'Prior copied house leaf fields/label actual')
            priorout.add(dict(current_v2_lowID=row['current_lowID'],actual_new_lowID=ID,level=level,actual_root_record=root,actual_root_first=first,
                actual_root_count=count,actual_child_ordinal=ordinal,actual_payload=actual['payload'],actual_label=actual['label'],source_identity_sha256=row['source_content_identity_sha256']))
            counts['actual_prior_copied_houses']+=1
        need(counts['actual_prior_copied_houses']==51332 and counts['outside_COW_prior_prefix_gate_inherited']==79305,'All prior identities actual-copied versus inherited-prefix distinction')
        # Small fixed host budget: find one true copied raw13 without a broad CPU scan.
        groupmeta={};sample_roots=sorted(rootgroups);indices=sorted({i*(len(sample_roots)-1)//99 for i in range(100)})
        for row in input_rows(DATA/'emitted-cow-groups.jsonl.gz',dp['artifacts']['groups'],inputs):
            for owner in row['current_parent_owners']:
                if owner>>28==3:groupmeta[owner]=row
        for index in indices:
            root=sample_roots[index];level,first,count=rootgroups[root]
            if unknown_sample_rows+count>30000:continue
            raw,shift,table=records.group(level,first,count);unknown_sample_rows+=count;unknown_sample_groups+=1;group=groupmeta[root]
            for ordinal in range(count):
                value=extract(raw,shift+ordinal*table['stride'],table['stride']);r=decode(value,table)
                if r['raw_flags']!=13:continue
                inserted=set(group['inserted_new_ordinals']);need(ordinal not in inserted,'Raw13 is an old copied row')
                oldordinal=ordinal-sum(p<ordinal for p in inserted);currentID=group['current_group']['first']+oldordinal
                old=records.record(level<<28|currentID);need(old['value']==value,'True oldraw13 copied significant bits identical in actual base prefix')
                raw13=dict(level=level,new_lowID=first+ordinal,payload=value.to_bytes((table['stride']+7)//8,'little').hex(),current_lowID=currentID,
                    group_key=[level,group['current_group']['first'],group['current_group']['count']],actual_root_record=root,actual_root_first=first,actual_root_count=count,
                    actual_group_ordinal=ordinal,current_old_ordinal=oldordinal,unchanged_first_child=r['first_child'],unchanged_child_count=r['child_count'],raw_flags=13,
                    actual_root_fields=records.record(root,True),actual_old_prefix_record=old,unknown_branch_not_followed_or_converted=True);break
            if raw13:break
        needed={'L5_shift0','L5_shift2','L5_shift4','L5_shift6','L6_shift0','L6_shift4','multi_ancestor_leaf'}
        need(needed<=samples.keys(),'Actual finite CPU witness coverage selected during required source EOF pass')
        counts['raw13_sample_groups']=unknown_sample_groups;counts['raw13_sample_rows']=unknown_sample_rows
        counts['raw13_true_clone_found']=int(raw13 is not None)
        need(stat(candidate)==before,'Actual v3 frozen stat unchanged');rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss;need(rss<=MAX_RSS_KIB,'Independent process memory guard')
        sample_artifact=saved('actual-native-CPU-witnesses.json',dict(schema='actual-v3-bounded-native-CPU-witnesses/v1',candidate_sha256=BASE_SHA,
            source_new_leaf_ledger_pin=dp['artifacts']['new_records'],source_parent_paths_pin=pathproof['artifact'],actual_directory=records.tables,
            new_leaf_samples=[dict(selection_name=k,sample=v['source_record'],actual_record=v['actual_record'],actual_parent=v['actual_parent'])for k,v in samples.items()],
            parent_path_samples=list({v['actual_path']['stock_parent_record']:v['actual_path']for v in samples.values()}.values()),raw13_clone=raw13,
            raw13_sample_budget_groups=100,raw13_sample_budget_rows=30000,raw13_actual_groups=unknown_sample_groups,raw13_actual_rows=unknown_sample_rows,
            source_full_EOF_verified=True,native_CPU_not_executed_here=True))
        artifacts=dict(paths=pathsout.close(),new_houses=leavesout.close(),prior_copied_houses=priorout.close(),actual_reads=readlog.close(),CPU_witnesses=sample_artifact)
        proof=dict(schema='independent-actual-v3-8K-tree-and-house-review/v1',started_utc=started,finished_utc=datetime.now(timezone.utc).isoformat(),
            script_sha256=sha(Path(__file__).read_bytes()),all_assigned_checks_passed=True,candidate_sha256=BASE_SHA,candidate_stat_before=before,candidate_stat_after=stat(candidate),
            candidate_complete_SHA_inherited_not_recomputed=True,independent_reader_does_not_import_writer_or_shared_decoder=True,
            inputs=inputs,actual_tables=records.tables,actual_directory_start=records.directory_start,actual_component_metadata={n:dict(size=c['size'],block_count=len(c['blocks']),part_count=len(c['rows']))for n,c in image.components.items()},
            counts=dict(counts),actual_new_leaf_global_shifts={str(k):dict(v)for k,v in globalshifts.items()},actual_unique_cached_path_records=len(records.cache),actual_label_references=len(records.labels),
            actual_readbytes=image.readbytes,actual_read_operations=image.readops,max_RSS_KiB=rss,unchanged_RSS_guard_KiB=MAX_RSS_KIB,artifacts=artifacts,
            all_old_unknown_flag_preservation_inherited_from_root_complete_significant_prefix_and_append_hashes=True,
            one_raw13_true_clone_actual_read_and_prefix_identity_verified=raw13 is not None,native_CPU_query_UI_geometry_or_device_not_executed=True,
            PBF_prepared_source_ready_source_or_append_bin_not_read=True,whole_IMG_ZIP_USB_canonical_or_prior_files_not_modified=True,
            native_write_ready=False,full_Taiwan_native_update_complete=False,elapsed_seconds_receipt_only=time.monotonic()-t0,
            limits=['Independent host field/path/label review; original CPU and full comparator/query/UI/device acceptance remain separate.',
                'All58233newhouses and20613paths are actual reads; copied51332prior leaves actualselectedrootpaths read;79305outside-prefix gate inherited from root fullbit checks.',
                'Unknownflags preserve whole significantbits via root full-prefix/append gates; one bounded raw13 sample iffound adds no branch interpretation.',
                'Source geometry/fullprovenance inherited from sealed appendproducer; no reextraction, rounding or geometry claim added.'])
        saved('proof.json',proof);receipt=dict(exit_status=0,counts=dict(counts),actual_readbytes=image.readbytes,actual_read_operations=image.readops,max_RSS_KiB=rss,
            source_sha256=proof['script_sha256'],proof_sha256=sha((HERE/'proof.json').read_bytes()),CPU_witnesses=sample_artifact,image_handle_closed=True)
        saved('execution-receipt.json',receipt);print(json.dumps(receipt),flush=True)


if __name__=='__main__':main()
