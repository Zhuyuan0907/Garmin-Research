#!/usr/bin/env python3
"""Read a finite stock AP sample; plan next5/6 coverage without writing a map.

The full-source metrics are inherited from the completed join, not rescanned.
Record and label samples are derived from the original MDR header/FAT only.
This is host decoding, not a native-CPU or device execution claim.
"""
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
AP = ROOT / 'backups/20261002T154458Z/files/.System/gmapprom1.img'
ROSTER = ROOT / 'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz'
JOIN = ROOT / 'staging/navigation-address-house-join-v1/proof.json'
LBL_PROOF = ROOT / 'staging/navigation-native-house-label-index-v1/proof.json'
EXPECTED_PROFILES = [
    ([16,9,24,19,1,10,0,0],[1,1],122),
    ([16,9,24,19,1,10,0,0],[1,1],122),
    ([22,9,24,19,1,12,0,0],[1,0],111),
    ([22,9,24,19,1,10,0,0],[1,1],128),
    ([21,9,24,19,1,9,0,0],[1,1],126),
    ([0,0,24,19,1,0,0,0],[1,0],68),
]
SEEDS = [1,2,5,180,278,12992,12998,13001,14369,14482,14483,16707]


def need(ok, message):
    if not ok:
        raise AssertionError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stat(path):
    s = path.stat()
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def load_small(path, maximum):
    before = stat(path)
    need(before[2] <= maximum, 'Input exceeds assigned small/roster scope')
    raw = path.read_bytes()
    need(stat(path) == before, 'Input changed while read: '+str(path))
    return raw, {'path':str(path.relative_to(ROOT)), 'bytes':len(raw),
                 'sha256':sha(raw),'stat_before':before,'stat_after':stat(path)}


class StockImage:
    def __init__(self, handle):
        self.handle = handle
        self.log = []
        header = self.physical(0,512,'IMG header')
        need(header[16:23] == b'DSKIMG\0','Stock DSKIMG signature')
        self.block_size = 1 << (header[97]+header[98])
        need(self.block_size == 4096,'Expected stock block size')
        fat_start = header[64]*512
        first = self.physical(fat_start,512,'FAT first row')
        fat_end = struct.unpack_from('<I',first,12)[0]
        need(0 < fat_start < fat_end < 2_000_000 and (fat_end-fat_start)%512 == 0,'Bounded FAT')
        fat = self.physical(fat_start,fat_end-fat_start,'FAT directory')
        self.parts = {}
        for i in range(0,len(fat),512):
            row = fat[i:i+512]
            if row[0] != 1 or row[16] == 3:
                continue
            name = row[1:9].decode('ascii').rstrip()+'.'+row[9:12].decode('ascii').rstrip()
            if name not in ('00004171.MDR','I053061A.GMP'):
                continue
            part = struct.unpack_from('<H',row,17)[0]
            size = struct.unpack_from('<I',row,12)[0]
            blockids = list(struct.unpack_from('<240H',row,32))
            self.parts.setdefault(name,[]).append((part,size,blockids))
        self.components = {}
        for name,parts in self.parts.items():
            parts.sort()
            need([p[0] for p in parts] == list(range(len(parts))),'Contiguous FAT parts')
            blocks = [b for p in parts for b in p[2] if b != 65535]
            self.components[name] = {'bytes':parts[0][1],'blocks':blocks}
            need(len(blocks)*self.block_size >= parts[0][1],'Component block capacity')
        need(set(self.components) == {'00004171.MDR','I053061A.GMP'},'Both required components')

    def physical(self, offset, length, reason):
        need(length <= 2_000_000,'Individual read ceiling')
        self.handle.seek(offset)
        raw = self.handle.read(length)
        need(len(raw) == length,'Complete bounded physical read')
        self.log.append({'physical_offset':offset,'bytes':length,'sha256':sha(raw),'reason':reason})
        return raw

    def component(self, name, offset, length, reason):
        component = self.components[name]
        need(offset >= 0 and offset+length <= component['bytes'],'Logical component bounds')
        chunks = []
        cursor = offset
        while cursor < offset+length:
            index,within = divmod(cursor,self.block_size)
            amount = min(offset+length-cursor,self.block_size-within)
            chunks.append(self.physical(component['blocks'][index]*self.block_size+within,amount,
                reason+'; '+name+' logical '+str(cursor)))
            cursor += amount
        return b''.join(chunks)


def derive_tables(image):
    header = image.component('00004171.MDR',0,32,'public MDR header')
    need(header[2:12] == b'GARMIN MDR' and struct.unpack_from('<H',header)[0] == 772,'Original MDR header')
    descriptor = image.component('00004171.MDR',600,16,'real original directory descriptor')
    start,size,stride,tag = struct.unpack('<4I',descriptor)
    need((size,stride,tag) == (120,20,1),'Six-entry descriptor')
    directory = image.component('00004171.MDR',start,size,'original directory')
    tables = []
    for i in range(6):
        a,b,c,w,x = struct.unpack_from('<5I',directory,i*20)
        widths = [(w>>18)&63,(w>>24)&63,(w>>12)&63,(w>>6)&63,w&63,x&63,(x>>11)&63,(x>>17)&63]
        flags = [(w>>30)&1,(w>>31)&1]
        need((widths,flags,c) == EXPECTED_PROFILES[i],'Directory-derived original profile differs')
        count,unused = divmod(b*8,c)
        tables.append({'level':i+1,'start':a,'bytes':b,'record_bits':c,'count':count,
            'widths':widths,'reference_flags':flags,'unused_tail_bits':unused,
            'directory_raw_hex':directory[i*20:i*20+20].hex()})
    need(tables[2]['start'] == 91983716 and tables[4]['count'] == 2341096
         and tables[5]['count'] == 1973316,'Original directory source anchors')
    return tables,{'logical_offset':600,'raw_hex':descriptor.hex(),'u32_LE':[start,size,stride,tag]}


def read_record(image, tables, level, ID):
    table = tables[level-1]
    need(type(ID) is int and 1 <= ID <= table['count'],'Valid one-based record ID')
    bit = (ID-1)*table['record_bits']
    byte,offset = divmod(bit,8)
    length = (offset+table['record_bits']+7)//8
    raw = image.component('00004171.MDR',table['start']+byte,length,'L'+str(level)+' ID'+str(ID))
    value = int.from_bytes(raw,'little')>>offset
    w = table['widths']; flags = table['reference_flags']
    decoded = {'level':level,'one_based_ID':ID,'logical_offset':table['start']+byte,
               'initial_bit_offset':offset,'span_hex':raw.hex()}
    cursor = 0
    for name,width,enabled,isref in [
        ('mapordinal',w[4],True,False),('secondary_ref',w[3],bool(flags[1]),True),
        ('primary_ref',w[3],bool(flags[0]),True),('first_child',w[0],bool(w[0]),False),
        ('child_count',w[5],bool(w[5]),False),('child_level_and_flags',w[1],bool(w[1]),False),
        ('raw_location_a',w[2],bool(w[2]),False),('raw_location_b',w[2],bool(w[2]),False)]:
        x = (value>>cursor)&((1<<width)-1) if enabled else None if isref else 0
        decoded[name] = None if enabled and isref and x == (1<<width)-1 else x
        cursor += width if enabled else 0
    need(cursor == table['record_bits'] and decoded['mapordinal'] == 1,'Complete original record fields')
    decoded['next_level'] = decoded['child_level_and_flags']&7
    if decoded['child_count']:
        nextlevel = decoded['next_level']
        need(level < nextlevel <= 6 and 1 <= decoded['first_child']
             and decoded['first_child']+decoded['child_count']-1 <= tables[nextlevel-1]['count'],
             'Child range within original next-level table')
    return decoded


class Labels:
    def __init__(self,image,proof):
        self.image = image
        self.start = proof['logical_GMP_pool_start']
        self.size = proof['pool_bytes']
        self.shift = proof['label_shift']
        self.codepage = proof['codepage']
        need((self.start,self.size,self.shift,self.codepage) == (6566,3805432,3,950),'Inherited original pool contract')
        self.cache = {}

    def get(self,ref):
        if ref is None:
            return None
        if ref not in self.cache:
            off = ref<<self.shift
            need(0 <= off < self.size,'Label ref inside original pool')
            raw = self.image.component('I053061A.GMP',self.start+off,min(256,self.size-off),'text reference '+str(ref))
            end = raw.find(b'\0')
            need(end >= 0,'Bounded NUL-terminated stock label')
            text = raw[:end].decode('cp950',errors='strict')
            self.cache[ref] = {'reference':ref,'label':text,'GMP_logical_offset':self.start+off,
                'bytes_through_NUL_hex':raw[:end+1].hex(),'label_class':label_class(text)}
        return self.cache[ref]


def label_class(text):
    if re.fullmatch(r'[1-9][0-9]*號',text):
        return 'numeric_integer_house'
    if re.fullmatch(r'[1-9][0-9]*之[1-9][0-9]*號',text):
        return 'numeric_subnumber_house'
    if not text:
        return 'empty'
    if re.search(r'巷|弄',text):
        return 'contains_lane_alley_text_marker_only'
    if re.search(r'路|街|道',text):
        return 'contains_road_street_text_marker_only'
    return 'other_text'


def selected_ids(first,count):
    # Finite complete groups <=84; otherwise six evenly spaced records.
    if count <= 84:
        return list(range(first,first+count))
    return sorted({first,first+1,first+count//3,first+2*count//3,first+count-2,first+count-1})


def main():
    proof_path = OUT/'deeper-address-plan.json'
    need(not proof_path.exists(),'Refusing proof overwrite')
    started = datetime.now(timezone.utc).isoformat()
    roster_raw,roster_meta = load_small(ROSTER,2_000_000)
    roster = [json.loads(x) for x in gzip.decompress(roster_raw).splitlines()]
    named = {r['low28_id']:r for r in roster if r['level']==3}
    need(len(named) == 47853 and all(x in named for x in SEEDS),'Existing roster identity and seeds')
    join_raw,join_meta = load_small(JOIN,200_000)
    joined = json.loads(join_raw)
    need(joined['all_assigned_checks_passed'] and joined['source_group_total'] == 4630959,'Complete source join metrics')
    lbl_raw,lbl_meta = load_small(LBL_PROOF,100_000)
    lbl_proof = json.loads(lbl_raw)
    need(lbl_proof['all_assigned_checks_passed'] and lbl_proof['source_stat_unchanged'],'Original label-pool evidence')
    before = stat(AP)
    samples = []
    records = {}
    with AP.open('rb') as handle:
        image = StockImage(handle)
        tables,descriptor = derive_tables(image)
        labels = Labels(image,lbl_proof)
        def decorated(level,ID):
            key = (level,ID)
            if key not in records:
                r = read_record(image,tables,level,ID)
                r['primary_label'] = labels.get(r['primary_ref'])
                r['secondary_label'] = labels.get(r['secondary_ref'])
                records[key] = r
            return records[key]
        for ID in SEEDS:
            roster_row = named[ID]
            street = decorated(3,ID)
            need((street['first_child'],street['child_count'],street['child_level_and_flags']) ==
                 (roster_row['first_child'],roster_row['child_count'],roster_row['child_level_and_flags']),
                 'Fresh original source and existing roster branch agree')
            ids = selected_ids(street['first_child'],street['child_count'])
            children = []
            for childID in ids:
                child = decorated(street['next_level'],childID)
                follow = []
                if child['child_count']:
                    deeperIDs = selected_ids(child['first_child'],child['child_count'])
                    if len(deeperIDs)>8:
                        deeperIDs = [deeperIDs[0],deeperIDs[1],deeperIDs[len(deeperIDs)//2],deeperIDs[-1]]
                    for dID in deeperIDs:
                        follow.append(decorated(child['next_level'],dID))
                children.append({'record':child,'deeper_sample':follow,
                    'deeper_complete':len(follow)==child['child_count']})
            samples.append({'native_street':roster_row,'street_record':street,
                'direct_child_complete':len(children)==street['child_count'],
                'direct_child_rows_examined':len(children),'children':children})
        reads = image.log
        pool_labels = list(labels.cache.values())
    after = stat(AP)
    need(before == after,'Original AP immutable stat')
    need(sum(r['bytes'] for r in reads)<500_000,'Assigned bounded read total ceiling')
    source_metrics = {}
    for city,metrics in joined['whole_country_city_group_and_street_metrics'].items():
        source_metrics[city] = {f'next{level}':metrics.get(f'matched_unique_next{level}',
            {'groups':0,'unique_source_city_district_street_keys':0,'unique_matched_native_street_records':0})
            for level in (5,6)}
    totals = {f'next{level}':{field:sum(x[f'next{level}'][field] for x in source_metrics.values())
        for field in ('groups','unique_source_city_district_street_keys','unique_matched_native_street_records')}
        for level in (5,6)}
    need(totals['next5']['groups']==541855 and totals['next6']['groups']==16735,'Inherited next5/6 source totals')
    stock_counts = Counter(r['next_level'] for r in named.values())
    proof = {'schema':'native-deeper-address-plan/v1','started_utc':started,
        'finished_utc':datetime.now(timezone.utc).isoformat(),'all_assigned_checks_passed':True,
        'script_sha256':sha(Path(__file__).read_bytes()),'inputs':[roster_meta,join_meta,lbl_meta],
        'source_AP':str(AP.relative_to(ROOT)),
        'source_AP_full_sha256_inherited_backup':'864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2',
        'fresh_full_image_hash':False,'source_AP_stat_before':before,'source_AP_stat_after':after,
        'source_AP_stat_immutable':before==after,'directory_derived_from_real_header':descriptor,
        'original_tables':tables,'original_named_street_counts_by_next_level':dict(stock_counts),
        'source_matching_counts_by_city':source_metrics,'source_matching_totals':totals,
        'source_metrics_inherited_complete_join':str(JOIN.relative_to(ROOT)),
        'source_metrics_units':'groups / unique source city,district,street keys / unique matched native L3 records, each per city',
        'source_metrics_limits':'Exact host name matching, including four direct-city layouts with district unverified. These are matched planning groups, not proven novel stock addresses.',
        'bounded_original_read_count':len(reads),'bounded_original_read_bytes':sum(r['bytes'] for r in reads),
        'bounded_original_reads':reads,'distinct_packed_records_examined':len(records),
        'distinct_labels_examined':len(pool_labels),'stock_label_samples':pool_labels,
        'representative_street_branches':samples,
        'device_IO':False,'native_CPU_executed':False,'PBF_accessed':False,'source_groups_rescanned':False,
        'full_image_copied_or_rewritten':False,'existing_map_or_database_modified':False,
        'full_Taiwan_native_update_complete':False,
        'limits':['Finite representative stock branches, not all L5/L6 semantics or native consumers.',
                  'No original house overlap decision, new record encoder, writer or device installation.',
                  'Flags preserve full raw value; textual markers do not establish street aliases or administrative equivalence.',
                  'Current-original-profile width capacities are not a GarminOS platform hard limit.']}
    proof_path.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'status':'complete','proof':str(proof_path),'read_bytes':proof['bounded_original_read_bytes'],
        'records':len(records),'labels':len(pool_labels),'source_matching_totals':totals},ensure_ascii=False))


if __name__ == '__main__':
    main()
