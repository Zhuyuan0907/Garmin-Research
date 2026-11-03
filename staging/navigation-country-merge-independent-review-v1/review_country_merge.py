#!/usr/bin/env python3
"""Independent all-new-row review using actual candidate bits and bounded stock.

Does not import producer packing/point/geometry functions, rerun CPU/suites,
read full source-ready/group/PBF/node ledgers, or write a native file.
"""
from collections import Counter,defaultdict
from datetime import datetime,timezone
from decimal import Decimal
from fractions import Fraction
import gzip
import hashlib
import json
from pathlib import Path
import re
import resource
import struct
import unicodedata

ROOT=Path('/root/garmin')
OUT=Path(__file__).resolve().parent
BASE=ROOT/'staging/navigation-country-native-house-merge-v1'
CANDIDATE=ROOT/'staging/navigation-country-native-candidate-v1/gmapprom1.img'
STOCK=ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img'
ROSTER=ROOT/'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz'
GEOMETRY=ROOT/'staging/navigation-country-city-geometry-v1/city-geometries.json'
GEOPROOF=GEOMETRY.parent/'proof.json'
JOIN=ROOT/'staging/navigation-country-address-ready-join-v1/proof.json'
HOUSE=re.compile(r'^[1-9][0-9]*號$')
EXPECTED_COUNTS={4:2133948,5:2341096,6:1973316}
EXPECTED_BITS={4:128,5:126,6:68}


def need(ok,text):
    if not ok:raise AssertionError(text)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def signature(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def norm(value):return unicodedata.normalize('NFKC',value or '').strip().replace('臺','台')


def read_file(path,maximum,inputs,expected=None):
    before=signature(path);need(before[2]<=maximum,'Bounded assigned input '+str(path))
    raw=path.read_bytes();after=signature(path)
    need(before==after,'Immutable assigned input '+str(path))
    if expected:need(len(raw)==expected['bytes'] and sha(raw)==expected['sha256'],'Sealed bytes/hash '+str(path))
    inputs.append({'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':sha(raw),
        'stat_before':before,'stat_after':after,'stat_unchanged':True})
    return raw


class HashReader:
    def __init__(self,handle):self.handle=handle;self.hash=hashlib.sha256();self.count=0
    def read(self,amount=-1):
        raw=self.handle.read(amount);self.hash.update(raw);self.count+=len(raw);return raw


class Image:
    """Independent logical FAT mapper with coalesced physical reads."""
    def __init__(self,path):
        self.path=path;self.before=signature(path);self.handle=path.open('rb');self.log=[]
        header=self.physical(0,512,'public IMG header')
        need(header[16:23]==b'DSKIMG\0','DSKIMG signature')
        self.block_bytes=1<<(header[97]+header[98]);need(self.block_bytes==4096,'Original 4K container')
        fatstart=header[64]*512;first=self.physical(fatstart,512,'FAT first entry')
        fatend=struct.unpack_from('<I',first,12)[0]
        need(0<fatstart<fatend<1_000_000 and (fatend-fatstart)%512==0,'Bounded original FAT directory')
        fat=self.physical(fatstart,fatend-fatstart,'FAT complete metadata only')
        parts=defaultdict(list)
        for off in range(0,len(fat),512):
            row=fat[off:off+512]
            if row[0]!=1 or row[16]==3:continue
            name=row[1:9].decode('ascii').rstrip()+'.'+row[9:12].decode('ascii').rstrip()
            if name not in ('00004171.MDR','I053061A.GMP'):continue
            parts[name].append((struct.unpack_from('<H',row,17)[0],struct.unpack_from('<I',row,12)[0],
                struct.unpack_from('<240H',row,32)))
        self.components={}
        for name,rows in parts.items():
            rows.sort();need([r[0] for r in rows]==list(range(len(rows))),'Component part continuity')
            blocks=[x for r in rows for x in r[2] if x!=65535]
            need(len(blocks)*self.block_bytes>=rows[0][1] and all((x+1)*self.block_bytes<=self.before[2] for x in blocks),'FAT blocks inside actual file')
            self.components[name]={'bytes':rows[0][1],'blocks':blocks}
        need(set(self.components)=={'00004171.MDR','I053061A.GMP'},'Required native components')

    def physical(self,offset,count,reason):
        need(0<=offset and offset+count<=self.before[2] and count<=32_000_000,'Bounded physical image read')
        self.handle.seek(offset);raw=self.handle.read(count);need(len(raw)==count,'Actual image read complete')
        self.log.append({'physical_offset':offset,'bytes':count,'sha256':sha(raw),'reason':reason})
        return raw

    def get(self,name,offset,count,reason):
        component=self.components[name]
        need(0<=offset and offset+count<=component['bytes'],'Bounded logical component read')
        spans=[];cursor=offset;end=offset+count
        while cursor<end:
            index,inside=divmod(cursor,self.block_bytes)
            amount=min(end-cursor,self.block_bytes-inside)
            physical=component['blocks'][index]*self.block_bytes+inside
            if spans and spans[-1][0]+spans[-1][1]==physical:
                spans[-1][1]+=amount
            else:spans.append([physical,amount])
            cursor+=amount
        return b''.join(self.physical(off,size,reason+'; '+name+' logical-range '+str(offset)) for off,size in spans)

    def close(self):
        self.handle.close();after=signature(self.path);need(after==self.before,'Image immutable stat')
        return {'path':str(self.path.relative_to(ROOT)),'stat_before':self.before,'stat_after':after,
            'stat_unchanged':True,'actual_bytes_read':sum(x['bytes'] for x in self.log),'operations':len(self.log),
            'full_image_read_or_hash':False,'bounded_reads':self.log}


def tables(image):
    public=image.get('00004171.MDR',0,32,'public MDR header')
    need(public[2:12]==b'GARMIN MDR','MDR signature')
    desc=image.get('00004171.MDR',600,16,'actual directory descriptor')
    start,size,item,tag=struct.unpack('<4I',desc);need((size,item,tag)==(120,20,1),'Six original-style table descriptors')
    directory=image.get('00004171.MDR',start,size,'actual six table descriptors')
    result={}
    for level in range(1,7):
        off,count,stride,a,b=struct.unpack_from('<5I',directory,(level-1)*20)
        w=[(a>>18)&63,(a>>24)&63,(a>>12)&63,(a>>6)&63,a&63,b&63,(b>>11)&63,(b>>17)&63]
        flags=[(a>>30)&1,(a>>31)&1]
        result[level]={'start':off,'bytes':count,'stride':stride,'count':count*8//stride,
            'widths':w,'flags':flags,'unused_tail_bits':count*8%stride}
        need(w[4]+sum(flags)*w[3]+w[0]+w[5]+w[1]+w[2]*2==stride and not w[6] and not w[7],'Descriptor-driven field length')
    return result,{'logical_offset':600,'u32_LE':[start,size,item,tag],'raw_hex':desc.hex()}


def bits(raw,at,count):
    byte,shift=divmod(at,8);size=(shift+count+7)//8
    need(at>=0 and byte+size<=len(raw),'True packed bit span in actual bytes')
    return (int.from_bytes(raw[byte:byte+size],'little')>>shift)&((1<<count)-1)


def decode(number,table):
    w=table['widths'];flags=table['flags'];pos=0;row={}
    specs=[('mapordinal',w[4],True,False),('secondary_ref',w[3],bool(flags[1]),True),
        ('primary_ref',w[3],bool(flags[0]),True),('first_child',w[0],bool(w[0]),False),
        ('child_count',w[5],bool(w[5]),False),('full_flags',w[1],bool(w[1]),False),
        ('raw_lat',w[2],bool(w[2]),False),('raw_lon',w[2],bool(w[2]),False)]
    for name,width,present,reference in specs:
        val=(number>>pos)&((1<<width)-1) if present else None if reference else 0
        row[name]=None if reference and present and val==(1<<width)-1 else val
        if present:pos+=width
    need(pos==table['stride'],'Independent field decode consumed actual stride')
    return row


def point24(text):
    # Exact rational rounding, separate from producer Decimal.quantize policy.
    value=Fraction(text)*16777216/360
    sign=-1 if value<0 else 1;positive=abs(value)
    whole,remainder=divmod(positive.numerator,positive.denominator)
    if 2*remainder>=positive.denominator:whole+=1
    signed=sign*whole;need(-(1<<23)<=signed<(1<<23),'Signed raw24 bounds')
    return signed&0xffffff


def source_point(texts):
    need(isinstance(texts,list) and len(texts)==2 and all(isinstance(x,str) and x for x in texts),'Two original coordinate strings')
    vals=[Decimal(x) for x in texts]
    need(all(x.is_finite() for x in vals) and -90<=vals[0]<=90 and -180<=vals[1]<180,'Finite global coordinates')
    scaled=[x*10_000_000 for x in vals]
    need(all(x==x.to_integral_value() for x in scaled),'OSM seven-decimal precision without guessing')
    return vals,[int(x) for x in scaled]


class WindingRing:
    BAND=50000
    def __init__(self,coords):
        points=[]
        for lon,lat,*ignored in coords:
            pair=[Decimal(str(x))*10_000_000 for x in (lon,lat)]
            need(all(x==x.to_integral_value() for x in pair),'Exact city-vertex source precision')
            points.append(tuple(int(x) for x in pair))
        need(len(points)>=4 and points[0]==points[-1],'Closed complete ring')
        self.bounds=(min(x for x,y in points),min(y for x,y in points),max(x for x,y in points),max(y for x,y in points))
        self.bands=defaultdict(list)
        for a,b in zip(points,points[1:]):
            for k in range(min(a[1],b[1])//self.BAND,max(a[1],b[1])//self.BAND+1):self.bands[k].append((a,b))
    def locate(self,x,y,den=1):
        minx,miny,maxx,maxy=self.bounds
        if not(minx*den<=x<=maxx*den and miny*den<=y<=maxy*den):return 0
        winding=0
        for (ax,ay),(bx,by) in self.bands.get(y//(den*self.BAND),[]):
            cross=(bx-ax)*(y-ay*den)-(by-ay)*(x-ax*den)
            if cross==0 and min(ax,bx)*den<=x<=max(ax,bx)*den and min(ay,by)*den<=y<=max(ay,by)*den:return 2
            if ay*den<=y<by*den and cross>0:winding+=1
            if by*den<=y<ay*den and cross<0:winding-=1
        return int(winding!=0)


class WindingCity:
    def __init__(self,geometry):
        need(geometry['type']=='MultiPolygon','Complete city multipolygon')
        self.polygons=[[WindingRing(r) for r in p] for p in geometry['coordinates']]
    def covers(self,x,y,den=1):
        for rings in self.polygons:
            outer=rings[0].locate(x,y,den)
            if outer==2:return True
            if not outer:continue
            hole_inside=False
            for ring in rings[1:]:
                hit=ring.locate(x,y,den)
                if hit==2:return True
                if hit:hole_inside=True;break
            if not hole_inside:return True
        return False


def canonical(values,width):
    h=hashlib.sha256()
    for v in values:h.update(v.to_bytes((width+7)//8,'little'))
    return h.hexdigest()


def choose_samples(ranges):
    chosen={}
    for level in (4,5,6):
        eligible=[r for r in ranges if r['next_level']==level]
        selected={}
        def add(r):
            if len(selected)<10:selected[r['nativeStreetID']]=r
        for r in eligible:
            if r['nativeStreetID']==16707:add(r)
        for r in [eligible[0],eligible[-1],max(eligible,key=lambda x:x['original_count']),
                  max(eligible,key=lambda x:x['new_integer_house_count'])]:add(r)
        # Cover old/output shifts, then named 巷/弄 and spaced positions.
        shifts=set()
        for r in eligible:
            key=(r['original_source_initial_bit_shift'],r['appended_bit_offset']%8)
            if key not in shifts:add(r);shifts.add(key)
        for r in eligible:
            if '巷' in r['street'] or '弄' in r['street']:add(r);break
        for i in range(0,len(eligible),max(1,len(eligible)//10)):add(eligible[i])
        for r in eligible:add(r)
        need(len(selected)==10,'Exactly ten bounded groups per level')
        for ID,r in selected.items():chosen[(level,ID)]=r
    return chosen


def main():
    target=OUT/'proof.json';need(not target.exists(),'New review scope only')
    started=datetime.now(timezone.utc).isoformat();inputs=[]
    seal=json.loads(read_file(BASE/'sealed-files.json',10000,inputs))
    need(seal['all_assigned_checks_passed'],'Producer seal succeeded')
    sealed={r['path']:r for r in seal['files']}
    producer=json.loads(read_file(BASE/'proof.json',100000,inputs,sealed['proof.json']))
    need(producer['all_assigned_checks_passed'] and producer['counts']['new_integer_house_records']==111608,'Pinned producer count')
    jraw=read_file(JOIN,500000,inputs,next(r for r in producer['inputs'] if r['path']==str(JOIN.relative_to(ROOT))))
    join=json.loads(jraw)
    geo_proof=json.loads(read_file(GEOPROOF,10000,inputs,next(r for r in producer['inputs'] if r['path']==str(GEOPROOF.relative_to(ROOT)))))
    geometries=json.loads(read_file(GEOMETRY,4_000_000,inputs,next(r for r in producer['inputs'] if r['path']==str(GEOMETRY.relative_to(ROOT)))))
    need(geo_proof['all_assigned_checks_passed'] and len(geometries)==21 and '高雄市' not in geometries,'21 complete city geometries; Kaohsiung held')
    city_geometry={norm(name):WindingCity(item['geometry']) for name,item in geometries.items()}
    roster_raw=read_file(ROSTER,2_000_000,inputs,next(r for r in join['inputs'] if r['path']==str(ROSTER.relative_to(ROOT))))
    roster={r['low28_id']:r for r in (json.loads(x) for x in gzip.decompress(roster_raw).splitlines()) if r['level']==3}
    ranges=json.loads(read_file(BASE/'selected-street-ranges.json',16_000_000,inputs,sealed['selected-street-ranges.json']))
    need(len(ranges)==15679,'Complete selected-range metadata count')
    selected={};ordinals=Counter();range_levels=Counter();range_cities=Counter()
    for r in ranges:
        ID=r['nativeStreetID'];level=r['next_level'];native=roster[ID]
        need(ID not in selected and r['native_street_record']==native['record']==0x30000000|ID,'Native L3 ID/record identity')
        need([r['city'],r['district'],r['street']]==[native['city'],native['district'],native['street']] and native['district'] is not None,'Exact native named city/district/street; no direct-city inputs')
        need([r['original_first'],r['original_count'],r['original_flags'],level]==
             [native['first_child'],native['child_count'],native['child_level_and_flags'],native['next_level']], 'Range matches original immutable roster')
        need(r['record_bits']==EXPECTED_BITS[level] and r['new_count']==r['original_count']+r['new_integer_house_count'],'Range old/new integer count arithmetic')
        need(r['appended_record_ordinal']==ordinals[level] and r['appended_bit_offset']==ordinals[level]*EXPECTED_BITS[level]
             and r['new_first']==EXPECTED_COUNTS[level]+ordinals[level]+1,'Continuous append bit positions; no per-group padding')
        selected[ID]=r;ordinals[level]+=r['new_count'];range_levels[level]+=1;range_cities[r['city']]+=1
    sample=choose_samples(ranges);sample_insertions={key:set() for key in sample}
    candidate_meta=json.loads(read_file(CANDIDATE.parent/'proof.json',10000,inputs))
    need(candidate_meta['all_assigned_checks_passed'] and candidate_meta['candidate_bytes']==121823232
         and candidate_meta['candidate_sha256']=='a2e3d43ae33307e6e81bd6f724314a5e03af82082cf453d0aa20cdc4c81b12fa','Inherited actual candidate complete SHA/size proof')
    candidate=Image(CANDIDATE);old=Image(STOCK)
    need(candidate.before[2]==121823232,'Actual candidate size')
    actual_tables,actual_desc=tables(candidate);old_tables,old_desc=tables(old)
    need(actual_tables[3]['stride']==112 and actual_tables[3]['widths'][0]==23,'Actual wider L3 directory profile')
    appends={};append_checks=[]
    for level in (4,5,6):
        t=actual_tables[level];ot=old_tables[level]
        need(ot['count']==EXPECTED_COUNTS[level] and t['stride']==ot['stride']==EXPECTED_BITS[level]
             and t['widths']==ot['widths'] and t['flags']==ot['flags'],'Original child table profiles preserved')
        need(t['count']==producer['proposed_counts'][str(level)]==EXPECTED_COUNTS[level]+ordinals[level],'Actual table count/end matches appended ranges')
        name=f'appended-level{level}.bin'
        artifact=read_file(BASE/name,22_000_000,inputs,sealed[name])
        actual=candidate.get('00004171.MDR',t['start']+ot['bytes'],len(artifact),'actual L'+str(level)+' append tail')
        need(actual==artifact and t['bytes']==ot['bytes']+len(actual),'Actual candidate tail equals sealed packed file')
        validbits=ordinals[level]*t['stride'];padding=len(actual)*8-validbits
        need(0<=padding<8 and (not padding or actual[-1]>>(8-padding)==0),'Only final unused high bits are zero')
        appends[level]=actual
        append_checks.append({'level':level,'actual_candidate_MDR_append_offset':t['start']+ot['bytes'],
            'bytes':len(actual),'records':ordinals[level],'valid_bits':validbits,'final_unused_high_bits':padding,
            'actual_tail_sha256':sha(actual),'matches_sealed_append':True})
    lbl=old.get('I053061A.GMP',874,176,'original public LBL fields')
    need(lbl[2:12]==b'GARMIN LBL','Actual original LBL header')
    pool_start,pool_bytes=struct.unpack_from('<II',lbl,21);shift=lbl[29];encoding=lbl[30];cp=struct.unpack_from('<H',lbl,170)[0]
    need((pool_start,pool_bytes,shift,encoding,cp)==(6566,3805432,3,10,950),'Original CP950 shifted reference pool')
    pool=old.get('I053061A.GMP',pool_start,pool_bytes,'bounded original label pool only')
    label_cache={}
    def label(ref):
        if ref is None:return None
        if ref not in label_cache:
            off=ref<<shift;need(0<=off<pool_bytes,'Actual primary/secondary ref inside original pool')
            end=pool.find(b'\0',off,min(off+512,pool_bytes));need(end>=off,'Bounded original label NUL')
            label_cache[ref]=pool[off:end].decode('cp950',errors='strict')
        return label_cache[ref]
    per_level=Counter();per_city=Counter();member_count=source_count=0
    all_source_ids=set();all_group_ids=set();all_new_ids=set();all_targets=set()
    quantized_city_outliers=[];member_raw_house_with_unit=0;new_position_shifts=Counter()
    rows_digest=hashlib.sha256();rows_path=BASE/'new-house-records.jsonl.gz';rows_before=signature(rows_path)
    need(rows_before[2]==sealed[rows_path.name]['bytes'],'New-row ledger sealed byte size')
    scanned=0;decoded_identity_hash=hashlib.sha256();source_identity_hash=hashlib.sha256()
    with rows_path.open('rb') as handle:
        hashed=HashReader(handle)
        with gzip.GzipFile(fileobj=hashed,mode='rb') as stream:
            for rawline in stream:
                rows_digest.update(rawline);r=json.loads(rawline);scanned+=1
                ID=r['nativeStreetID'];level=r['next_level'];range_row=selected[ID];native=roster[ID];table=actual_tables[level]
                need(level==range_row['next_level'] and r['record_bits']==table['stride'],'Row native path selects actual profile')
                need([r['city'],r['district'],r['street']]==[native['city'],native['district'],native['street']]
                     and [r['old_child_first'],r['old_child_count'],r['old_parent_flags']]==
                     [native['first_child'],native['child_count'],native['child_level_and_flags']], 'Every row exact original hierarchy')
                labeltext=r['house_label'];need(HOUSE.fullmatch(labeltext),'Positive ASCII integer house label only')
                target_key=(ID,labeltext);newkey=(level,r['new_lowID'])
                need(target_key not in all_targets and newkey not in all_new_ids,'New target/record ID unique')
                all_targets.add(target_key);all_new_ids.add(newkey)
                position=r['appended_bit_offset'];width=table['stride']
                need(position==(r['new_lowID']-EXPECTED_COUNTS[level]-1)*width
                     and range_row['appended_bit_offset']<=position<range_row['appended_bit_offset']+range_row['new_count']*width
                     and (position-range_row['appended_bit_offset'])%width==0,'Every true packed position/lowID/street range')
                value=bits(appends[level],position,width);fields=decode(value,table)
                payload=bytes.fromhex(r['payload'])
                need(len(payload)==(width+7)//8 and int.from_bytes(payload,'little')==value,'Actual candidate significant payload equals row receipt')
                need(fields['mapordinal']==1 and fields['primary_ref']==r['primary_ref'] and fields['secondary_ref'] is None
                     and fields['first_child']==fields['child_count']==fields['full_flags']==0,'Every leaf references/hierarchy independent decode')
                need(label(fields['primary_ref'])==labeltext,'Every new house ref resolves to exact original GMP text')
                vals,scaled=source_point(r['coordinate_strings'])
                raw24=[fields['raw_lat'],fields['raw_lon']]
                need(raw24==r['raw24']==[point24(x) for x in r['coordinate_strings']],'Actual point fields independently rounded from source strings')
                city=norm(native['city']);need(city in city_geometry and city!='高雄市','Complete expected source-city geometry exists')
                need(city_geometry[city].covers(scaled[1],scaled[0]),'Every source point inside its exact complete city geometry')
                signed=[x if x<0x800000 else x-0x1000000 for x in raw24]
                if not city_geometry[city].covers(signed[1]*3515625,signed[0]*3515625,16384):
                    quantized_city_outliers.append({'nativeStreetID':ID,'level':level,'new_lowID':r['new_lowID'],
                        'city':native['city'],'house_label':labeltext,'source_coordinate_strings':r['coordinate_strings'],'raw24':raw24})
                need(isinstance(r['source_members'],list) and r['source_members'],'Embedded full source members')
                flat_ids=[];flat_groups=[]
                for member in r['source_members']:
                    member_count+=1;group_id=member['group_id'];ids=member['source_ids']
                    need(type(group_id)is int and group_id>0 and group_id not in all_group_ids,'Positive globally unique embedded source group ID')
                    need(isinstance(ids,list) and len(ids)==member['source_node_count'] and ids
                         and all(type(x)is int and x>0 for x in ids) and len(set(ids))==len(ids),'Positive unique original OSM IDs and member count')
                    need(not(all_source_ids.intersection(ids)),'No OSM source node reused across new houses')
                    all_source_ids.update(ids);all_group_ids.add(group_id)
                    mcoords,_=source_point(member['coordinate_strings']);need(mcoords==vals,'Every coalesced member has identical Decimal source coordinates')
                    need(len(member['raw_address'])==4 and tuple(map(norm,member['raw_address'][:3]))==
                         tuple(map(norm,(native['city'],native['district'],native['street']))),'Every member literal source city/district/street matches exact hierarchy under explicit host normalization')
                    rawhouse=unicodedata.normalize('NFKC',member['raw_address'][3]).strip()
                    simple=re.fullmatch(r'([1-9][0-9]*)號?',rawhouse)
                    if simple:need(simple.group(1)+'號'==labeltext,'Source raw integer house identity')
                    else:
                        unit=re.fullmatch(r'([1-9][0-9]*號)(.+(?:樓|室|F|f).*)',rawhouse)
                        need(unit is not None and unit.group(1)==labeltext and member['embedded_floor_unit_first_source_flag'] is True,
                             'Explicit embedded floor/unit raw house provenance, without guessing a new house number')
                        member_raw_house_with_unit+=1
                    need(type(member['separate_floor_unit_source_nodes'])is int and 0<=member['separate_floor_unit_source_nodes']<=len(ids)
                         and type(member['embedded_floor_unit_first_source_flag'])is bool,'Floor/unit source metadata bound and type')
                    flat_ids.extend(ids);flat_groups.append(group_id);source_count+=len(ids)
                    source_identity_hash.update(json.dumps([group_id,ids,member['raw_address'],member['coordinate_strings']],ensure_ascii=False,separators=(',',':')).encode()+b'\n')
                need(r['source_ids']==flat_ids and r['source_group_ids']==flat_groups,'Row source arrays exactly equal embedded members')
                per_level[level]+=1;per_city[native['city']]+=1;new_position_shifts[(level,position%8)]+=1
                decoded_identity_hash.update(struct.pack('<IIIIII',level,r['new_lowID'],ID,fields['primary_ref'],*raw24))
                key=(level,ID)
                if key in sample:sample_insertions[key].add((position-range_row['appended_bit_offset'])//width)
                if scanned%25000==0:print(json.dumps({'new_rows_verified':scanned,'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}),flush=True)
        need(hashed.count==rows_before[2] and hashed.hash.hexdigest()==sealed[rows_path.name]['sha256'],'New-row complete compressed stream hash/EOF')
    need(signature(rows_path)==rows_before and scanned==111608,'New-row immutable EOF/count')
    need(rows_digest.hexdigest()==producer['artifacts']['new_records']['uncompressed_sha256'],'Producer plain ledger binding')
    inputs.append({'path':str(rows_path.relative_to(ROOT)),'bytes':hashed.count,'sha256':hashed.hash.hexdigest(),
        'uncompressed_sha256':rows_digest.hexdigest(),'json_rows':scanned,'gzip_EOF_validated':True,
        'stat_before':rows_before,'stat_after':signature(rows_path),'stat_unchanged':True,'compressed_content_passes':1})
    need(dict(per_level)=={4:74455,5:35183,6:1970},'Independent per-level new counts')
    need(dict(per_city)=={c:v['new_integer_house_records'] for c,v in producer['counts_by_city'].items() if v.get('new_integer_house_records')},'Independent actual-used city counts')
    bounded=[];old_record_count=0;nonnumeric=flags8=flags13=old_nested=0
    for key,r in sorted(sample.items()):
        level,ID=key;table=old_tables[level];width=table['stride']
        source_start,source_shift=divmod((r['original_first']-1)*width,8)
        window=old.get('00004171.MDR',table['start']+source_start,(source_shift+r['original_count']*width+7)//8,
            'bounded original street '+str(ID)+' L'+str(level))
        need(sha(window)==r['original_source_window_sha256'] and source_shift==r['original_source_initial_bit_shift'],'Actual original group source window offset/shift/hash')
        old_values=[bits(window,source_shift+i*width,width) for i in range(r['original_count'])]
        new_values=[bits(appends[level],r['appended_bit_offset']+i*width,width) for i in range(r['new_count'])]
        inserted=sample_insertions[key];need(len(inserted)==r['new_integer_house_count'],'Representative new-position accounting')
        retained=[v for i,v in enumerate(new_values) if i not in inserted]
        need(retained==old_values and canonical(old_values,width)==r['original_significant_records_sha256']
             and canonical(new_values,width)==r['new_significant_records_sha256'],'Old significant bits and complete relative order preserved in actual candidate')
        details=[];group_nonnum=group_nested=group_flag8=group_flag13=0
        for i,v in enumerate(old_values):
            d=decode(v,table);name=label(d['primary_ref'])
            if not name or not re.fullmatch(r'[1-9][0-9]*(?:之[1-9][0-9]*)?號',name):group_nonnum+=1
            if d['child_count']:group_nested+=1
            group_flag8+=d['full_flags']==8;group_flag13+=d['full_flags']==13
            if len(details)<6 and (d['child_count'] or d['full_flags'] in (8,13) or not name or '巷' in name or '弄' in name):
                details.append({'old_lowID':r['original_first']+i,'primary_label':name,'decoded_fields':d})
        # Every selected parent is checked directly against original and candidate bits.
        original_parent_start,original_parent_shift=divmod((ID-1)*old_tables[3]['stride'],8)
        new_parent_start,new_parent_shift=divmod((ID-1)*actual_tables[3]['stride'],8)
        op=old.get('00004171.MDR',old_tables[3]['start']+original_parent_start,(original_parent_shift+old_tables[3]['stride']+7)//8,'sample original L3 parent '+str(ID))
        np=candidate.get('00004171.MDR',actual_tables[3]['start']+new_parent_start,(new_parent_shift+actual_tables[3]['stride']+7)//8,'sample actual L3 parent '+str(ID))
        od=decode(bits(op,original_parent_shift,old_tables[3]['stride']),old_tables[3]);nd=decode(bits(np,new_parent_shift,actual_tables[3]['stride']),actual_tables[3])
        need((od['first_child'],od['child_count'],od['full_flags'])==(r['original_first'],r['original_count'],r['original_flags']),'Original selected parent actual fields')
        need((nd['first_child'],nd['child_count'],nd['full_flags'])==(r['new_first'],r['new_count'],r['original_flags'])
             and all(nd[k]==od[k] for k in od if k not in ('first_child','child_count')),'Candidate selected parent only child first/count updated')
        old_record_count+=len(old_values);nonnumeric+=group_nonnum;old_nested+=group_nested;flags8+=group_flag8;flags13+=group_flag13
        bounded.append({'level':level,'nativeStreetID':ID,'city':r['city'],'district':r['district'],'street':r['street'],
            'original_count':len(old_values),'new_count':len(new_values),'original_bit_shift':source_shift,
            'candidate_output_bit_shift':r['appended_bit_offset']%8,'old_nonnumeric_label_records':group_nonnum,
            'old_nested_records':group_nested,'old_raw_flag8_records':group_flag8,'old_raw_flag13_records':group_flag13,
            'old_significant_bits_and_relative_order_equal':True,'parent_fields_checked_from_actual_original_and_candidate':True,
            'representative_original_branch_records':details})
    need(len(bounded)==30 and nonnumeric>0 and old_nested>0 and flags8>0,'Meaningful old mixed hierarchy/flags sample, not numeric leaves alone')
    old_receipt=old.close();candidate_receipt=candidate.close()
    need(old_receipt['actual_bytes_read']<5_000_000 and candidate_receipt['actual_bytes_read']<27_000_000,'Bounded original/candidate read budgets')
    ready_inherited=[r for r in producer['inputs'] if 'exact-next' in r['path']]
    need(len(ready_inherited)==3 and all(r['gzip_EOF_validated'] and r['stat_unchanged'] for r in ready_inherited),'Producer source-ready complete EOF/hash evidence explicit inheritance')
    result={'schema':'country-merge-independent-readonly-review/v1','started_utc':started,
        'finished_utc':datetime.now(timezone.utc).isoformat(),'all_assigned_checks_passed':True,
        'script_sha256':sha(Path(__file__).read_bytes()),'fresh_inputs':inputs,
        'actual_candidate_complete_file_sha256_inherited':candidate_meta['candidate_sha256'],
        'actual_candidate_complete_hash_freshly_recomputed':False,'actual_candidate_directory':actual_desc,
        'actual_original_directory':old_desc,'actual_candidate_tables':actual_tables,'actual_original_tables':old_tables,
        'actual_candidate_append_checks':append_checks,
        'new_rows_all_independently_decoded':scanned,'new_rows_by_level':dict(per_level),'new_rows_by_city':dict(per_city),
        'new_coordinate_fields_independent_exact_rational_rounding':True,
        'all_new_house_refs_checked_against_actual_original_CP950_label_pool':True,
        'original_label_pool_bytes_read':pool_bytes,'distinct_actual_stock_labels_decoded':len(label_cache),
        'all_new_rows_source_member_counts':member_count,'positive_unique_OSM_source_ids':source_count,
        'positive_unique_source_group_ids':len(all_group_ids),'source_members_Decimal_coordinates_equal':True,
        'source_member_exact_native_city_district_street_strings_under_host_policy':True,
        'embedded_raw_house_floor_unit_members_explicitly_verified':member_raw_house_with_unit,
        'host_name_policy':'NFKC/outer whitespace/臺→台 only, inherited explicit country join policy; no other Chinese/admin/street aliases or district assignments.',
        'source_ready_ledger_provenance_inherited_not_reread':ready_inherited,
        'independently_reopened_source_ready_total_ledgers':0,
        'complete_source_city_geometries':21,'actual_new_record_cities_used':len(per_city),
        'Kaohsiung_new_records':per_city.get('高雄市',0),
        'all_source_points_inside_expected_complete_city_signed_winding_check':True,
        'independent_geometry_method':'Exact integer signed winding number with0.005-degree latitude bands, boundary included, holes excluded; does not import producer parity-ray implementation.',
        'district_geographic_membership_proved':False,
        'quantized_point_city_membership_outliers':quantized_city_outliers,
        'quantized_point_city_check_note':'Additional check of native grid point, separate from producer source-point city policy; quantization can move a source point across a boundary.',
        'all_new_actual_position_shifts':[{ 'level':k[0],'shift':k[1],'records':v} for k,v in sorted(new_position_shifts.items())],
        'decoded_new_identity_sha256':decoded_identity_hash.hexdigest(),'source_members_identity_sha256':source_identity_hash.hexdigest(),
        'original_group_bounded_review':{'groups':len(bounded),'old_records_directly_compared':old_record_count,
            'nonnumeric_label_records':nonnumeric,'nested_branch_records':old_nested,'raw_flag8_records':flags8,'raw_flag13_records':flags13,
            'groups_by_level':dict(Counter(r['level'] for r in bounded)),
            'source_and_candidate_shifts':sorted({(r['level'],r['original_bit_shift'],r['candidate_output_bit_shift']) for r in bounded}),
            'representatives':bounded},
        'bounded_original_image_receipt':old_receipt,'bounded_candidate_image_receipt':candidate_receipt,
        'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'flag8_13_semantics_proved_here':False,'full_original_groups_or_tables_reviewed_here':False,
        'no_new_IMG_or_native_source_modified':True,'device_IO':False,'native_CPU_executed':False,
        'full_PBF_or_source_groups_or_node_ledger_read':False,'closed_suites_rerun':False,
        'full_Taiwan_native_update_complete':False,
        'limits':['Independent new-row structural/provenance/city review and30 bounded old groups only.',
            'Ready-source complete stream provenance uses sealed producer EOF/SHA evidence, not a new read of all source-ready/group ledgers.',
            'Actual candidate full image hash and complete original-table/selected-group preservation are inherited root readback; only bounded tails/representative windows read here.',
            'No original native comparator/CPU/UI/navigation/entrance acceptance; source city containment does not prove source district geography or house authenticity.',
            'Flags8/13 raw values preserved in sampled old significant records; semantic rewrite rules are not inferred.']}
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_assigned_checks_passed':True,'new_rows':scanned,'source_members':member_count,
        'OSM_ids':source_count,'used_cities':len(per_city),'old_sample_groups':len(bounded),'old_sample_records':old_record_count,
        'original_bytes_read':old_receipt['actual_bytes_read'],'candidate_bytes_read':candidate_receipt['actual_bytes_read'],
        'quantized_city_outliers':len(quantized_city_outliers),'proof_sha256':sha(target.read_bytes())},ensure_ascii=False),flush=True)


if __name__=='__main__':main()
