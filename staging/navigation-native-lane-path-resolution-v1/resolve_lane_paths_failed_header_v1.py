#!/usr/bin/env python3
"""Finite source-example → actual stock MDR lane/alley parent resolver.

Host decoding only. No source ledger/PBF, CPU, device, database or map writes.
The stock image reader/profile derivation is reused from a sealed scope; its
main, historical samples and CPU cases are never executed.
"""
import ast
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import time
import unicodedata

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
AP = ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img'
ROSTER = ROOT/'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz'
JOIN = ROOT/'staging/navigation-country-address-ready-join-v1/proof.json'
READER = ROOT/'staging/navigation-native-deeper-address-plan-v1/inspect_deeper_address_paths.py'
REFERENCE = READER.parent/'semantic-path-plan.json'
SCHEMA = ROOT/'staging/navigation-stock-address-schema-v1/stock-address-schema-evidence.json'
EXPECTED_SHA = {
    ROSTER:'45333390cec4996db40b4a4a987eb421641fec352203bb318aedfd6a6fce2776',
    JOIN:'b61cd949152fece0548265ccf438c14d3bbeeddfc5e3ae05140df20d3aa0a175',
    READER:'1348bcb2f0191bd1fa5b32ca446ee15b084e76dd7ed3ea33c31b5351b2d021ec',
    REFERENCE:'9c9e944388fb649a73623d8eb8683fdfd0d02eaa96b2ca175ad06a5f8177deda',
    SCHEMA:'8111d750106255d91becf7254e8a8ead8c4ad1c2562cf83df3ddd64cafeef21d',
}
EXAMPLES = [12378,15329,758,759,1324,457,461,11767,101,487,15385,388,
            4201529,1183,9247,5006,3822,1809,23,822807]
DIRECT_CITIES = {'基隆市','台北市','新竹市','嘉義市'}
TOKEN = re.compile(r'[1-9][0-9]*[巷弄]')
HOUSE = re.compile(r'[1-9][0-9]*(?:之[1-9][0-9]*)?號')
MAX_IMAGE_BYTES = 1_500_000
MAX_CHILD_ROWS = 18_000


def need(ok, message):
    if not ok:
        raise AssertionError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stat(path):
    s = path.stat()
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def load(path, inputs, ceiling=2_000_000):
    before = stat(path)
    need(before[2] <= ceiling,'Small input ceiling')
    raw = path.read_bytes()
    need(stat(path) == before,'Input immutable while read')
    need(sha(raw) == EXPECTED_SHA[path],'Sealed input content binding: '+str(path))
    inputs.append({'path':str(path.relative_to(ROOT)), 'bytes':len(raw),'sha256':sha(raw),
                   'stat_before':before,'stat_after':stat(path),'stat_unchanged':True})
    return raw


def norm(text):
    return unicodedata.normalize('NFKC',text).strip().replace('臺','台') if text is not None else None


def suffix_tokens(suffix):
    tokens = TOKEN.findall(suffix)
    return tokens if tokens and ''.join(tokens) == suffix else None


def exact_prefix(fullstreet, rows):
    candidates = [r for r in rows if fullstreet.startswith(norm(r['street']))]
    if not candidates:
        return None,'no_exact_native_street_prefix'
    longest = max(len(norm(r['street'])) for r in candidates)
    best = [r for r in candidates if len(norm(r['street'])) == longest]
    if len(best) != 1:
        return None,'duplicate_longest_native_street_prefix'
    return best[0],None


def exact_token_child(children, token):
    matches = [r for r in children if r['primary_label'] == token]
    if not matches:
        return None,'exact_path_token_not_found'
    if len(matches) > 1:
        return None,'duplicate_exact_path_token'
    return matches[0],None


def reused_reader(raw):
    tree = ast.parse(raw)
    names = {'need','sha','StockImage','derive_tables','read_record'}
    nodes = [n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
    profiles = [n for n in tree.body if isinstance(n,ast.Assign)
                and any(isinstance(t,ast.Name) and t.id=='EXPECTED_PROFILES' for t in n.targets)]
    need(len(nodes) == len(names) and len(profiles) == 1,'Exact sealed reader definitions')
    namespace = {'struct':struct,'hashlib':hashlib}
    exec(compile(ast.Module(body=profiles+nodes,type_ignores=[]),str(READER),'exec'),namespace)
    return namespace


class ActualLabels:
    def __init__(self,image):
        self.image = image
        raw = image.component('I053061A.GMP',0,57,'actual GMP header and LBL pointer')
        need(struct.unpack_from('<H',raw)[0] == 57 and raw[2:12] == b'GARMIN GMP','Original GMP public header')
        offsets = struct.unpack_from('<7I',raw,25)
        self.lbl_header_offset = offsets[2]
        need(0 < self.lbl_header_offset < image.components['I053061A.GMP']['bytes']-661,'Actual LBL pointer bounds')
        lbl = image.component('I053061A.GMP',self.lbl_header_offset,661,'actual LBL header and text pool descriptor')
        need(struct.unpack_from('<H',lbl)[0] == 661 and lbl[2:12] == b'GARMIN LBL','Original LBL public header')
        relative_start,self.size = struct.unpack_from('<II',lbl,21)
        self.start = self.lbl_header_offset+relative_start
        self.shift,self.encoding = lbl[29],lbl[30]
        self.codepage = struct.unpack_from('<H',lbl,170)[0]
        need((self.start,self.size,self.shift,self.encoding,self.codepage) == (6566,3805432,3,10,950),
             'Derived stock CP950 pool contract')
        need(self.start+self.size <= image.components['I053061A.GMP']['bytes'],'Pool bounds')
        self.descriptor = {'GMP_header_hex':raw.hex(),'GMP_subfile_offsets':list(offsets),
            'LBL_GMP_offset':self.lbl_header_offset,'LBL_header_sha256':sha(lbl),
            'LBL_pool_relative_start':relative_start,'GMP_pool_start':self.start,
            'pool_bytes':self.size,'label_shift':self.shift,'encoding':self.encoding,'codepage':self.codepage}
        self.cache = {}

    def get(self, ref):
        if ref is None:
            return None
        if ref not in self.cache:
            off = ref<<self.shift
            need(0 <= off < self.size,'Actual label ref pool bounds')
            raw = self.image.component('I053061A.GMP',self.start+off,min(64,self.size-off),'exact stock label ref '+str(ref))
            end = raw.find(b'\0')
            need(end >= 0,'Bounded 64-byte actual label has NUL; no unbounded fallback')
            label = raw[:end].decode('cp950',errors='strict')
            self.cache[ref] = {'reference':ref,'label':label,'GMP_logical_offset':self.start+off,
                               'bytes_through_NUL_hex':raw[:end+1].hex()}
        return self.cache[ref]['label']


class ActualTree:
    def __init__(self,image,tables,labels,reader):
        self.image,self.tables,self.labels,self.reader = image,tables,labels,reader
        self.records,self.groups = {},{}
        self.child_rows = 0

    def decorate(self, r):
        r['native_record'] = (r['level']<<28)|r['one_based_ID']
        r['native_record_hex'] = hex(r['native_record'])
        r['primary_label'] = self.labels.get(r['primary_ref'])
        self.records[(r['level'],r['one_based_ID'])] = r
        return r

    def record(self, level, ID):
        key = (level,ID)
        if key not in self.records:
            self.decorate(self.reader['read_record'](self.image,self.tables,level,ID))
        return self.records[key]

    def children(self,parent):
        level,first,count = parent['next_level'],parent['first_child'],parent['child_count']
        if not count:
            return []
        need(parent['level'] < level <= 6 and 1 <= first and
             first+count-1 <= self.tables[level-1]['count'],'Actual parent child bounds')
        key = (level,first,count)
        if key in self.groups:
            return self.groups[key]['children']
        self.child_rows += count
        need(count <= 4095 and self.child_rows <= MAX_CHILD_ROWS,'Finite direct-child scan budget')
        table = self.tables[level-1]
        bit = (first-1)*table['record_bits']
        byte,initial = divmod(bit,8)
        length = (initial+count*table['record_bits']+7)//8
        need(length <= 65536,'Finite group packed-byte budget')
        raw = self.image.component('00004171.MDR',table['start']+byte,length,
                                    'complete exact direct group L%d %d+%d'%(level,first,count))
        children = []
        for i in range(count):
            local_bit = initial+i*table['record_bits']
            local_byte,offset = divmod(local_bit,8)
            span = raw[local_byte:local_byte+(offset+table['record_bits']+7)//8]
            value = int.from_bytes(span,'little')>>offset
            w,flags = table['widths'],table['reference_flags']
            r = {'level':level,'one_based_ID':first+i,'logical_offset':table['start']+byte+local_byte,
                 'initial_bit_offset':offset,'span_hex':span.hex()}
            cursor = 0
            for name,width,enabled,isref in [
                ('mapordinal',w[4],True,False),('secondary_ref',w[3],bool(flags[1]),True),
                ('primary_ref',w[3],bool(flags[0]),True),('first_child',w[0],bool(w[0]),False),
                ('child_count',w[5],bool(w[5]),False),('child_level_and_flags',w[1],bool(w[1]),False),
                ('raw_location_a',w[2],bool(w[2]),False),('raw_location_b',w[2],bool(w[2]),False)]:
                v = (value>>cursor)&((1<<width)-1) if enabled else None if isref else 0
                r[name] = None if enabled and isref and v == (1<<width)-1 else v
                cursor += width if enabled else 0
            need(cursor == table['record_bits'] and r['mapordinal'] == 1,'Complete original packed record fields')
            r['next_level'] = r['child_level_and_flags']&7
            if r['child_count']:
                need(level < r['next_level'] <= 6 and r['first_child'] >= 1 and
                     r['first_child']+r['child_count']-1 <= self.tables[r['next_level']-1]['count'],
                     'Child record deeper range bounds')
            children.append(self.decorate(r))
        self.groups[key] = {'level':level,'first':first,'count':count,
             'logical_offset':table['start']+byte,'initial_bit_offset':initial,
             'packed_span_bytes':len(raw),'packed_span_sha256':sha(raw),'packed_span_hex':raw.hex(),
             'children':children}
        return children


def resolve(example,bucket,by_district,tree):
    city,district,fullstreet,house = example['normalized_planning_key']
    result = {'source_example':example,'source_proof_bucket':bucket,'path_tokens':[],
              'matched_path_records':[],'status':'held','reason':None,
              'source_coordinates_retrieved':False,'native_rewrite_ready':False}
    if city in DIRECT_CITIES or 'direct_city' in example['native_match']:
        result['reason'] = 'direct_city_source_district_unverified'
        return result
    rows = by_district.get((city,district),[])
    root,reason = exact_prefix(fullstreet,rows)
    if reason:
        result['reason'] = reason
        return result
    suffix = fullstreet[len(norm(root['street'])):]
    tokens = suffix_tokens(suffix)
    result['native_root_roster'] = root
    result['exact_suffix'] = suffix
    if tokens is None:
        result['reason'] = 'longest_exact_prefix_suffix_not_supported_numeric_lane_alley_tokens'
        return result
    result['path_tokens'] = tokens
    parent = tree.record(3,root['low28_id'])
    need((parent['first_child'],parent['child_count'],parent['child_level_and_flags'],parent['next_level']) ==
         (root['first_child'],root['child_count'],root['child_level_and_flags'],root['next_level']),
         'Actual original L3 matches sealed existing roster')
    need(norm(parent['primary_label']) == norm(root['street']),'Actual stock L3 primary text matches native roster')
    result['matched_path_records'].append(parent)
    for token in tokens:
        children = tree.children(parent)
        child,reason = exact_token_child(children,token)
        result.setdefault('path_steps',[]).append({'parent_record':parent['native_record'],
            'parent_raw_flags':parent['child_level_and_flags'],'next_level':parent['next_level'],
            'first':parent['first_child'],'count':parent['child_count'],'token':token,
            'complete_direct_group_examined':True,'matching_record_ids':
                 [r['native_record'] for r in children if r['primary_label'] == token]})
        if reason:
            result['reason'] = reason if children else 'parent_has_no_children_for_remaining_path_token'
            return result
        parent = child
        result['matched_path_records'].append(parent)
    if parent['level'] not in (3,4,5) or not parent['child_count'] or parent['next_level'] not in (4,5,6):
        result['reason'] = 'resolved_token_record_has_no_supported_direct_leaf_group'
        return result
    children = tree.children(parent)
    houses = [r for r in children if r['child_count'] == 0 and r['primary_label'] is not None
              and HOUSE.fullmatch(r['primary_label'])]
    if not houses:
        result['reason'] = 'resolved_parent_has_no_observed_numeric_house_leaves'
        return result
    matches = [r for r in houses if r['primary_label'] == house]
    result.update({'status':'resolved_house_parent','reason':None,
        'resolved_parent':{'record':parent['native_record'],'record_hex':parent['native_record_hex'],
            'level':parent['level'],'ID':parent['one_based_ID'],'actual_label':parent['primary_label'],
            'next_leaf_level':parent['next_level'],'first_child':parent['first_child'],
            'child_count':parent['child_count'],'raw_child_level_and_flags':parent['child_level_and_flags'],
            'raw_high_flags':parent['child_level_and_flags']&~7},
        'complete_final_direct_group_examined':True,'observed_numeric_house_leaf_count':len(houses),
        'other_direct_child_count':len(children)-len(houses),
        'source_house_exact_membership':{'label':house,'matches':matches,
           'status':'absent' if not matches else 'present_unique' if len(matches)==1 else 'duplicate_exact_leaf_labels',
           'source_global_numeric_ref_is_not_membership_proof':True},
        'parent_group_review_ready':example['coordinate_status']=='coordinate_ready_global_bounds' and len(matches)<=1,
        'merge_constraints':['Preserve this actual parent level, next leaf level, full raw flags and all old child records.',
                            'Source coordinates and source IDs must be bound from the original group ledger in a later scope.',
                            'No JAI family creation; parent_record uniqueness requires grouping by this actual parent.']})
    return result


def synthetic_controls():
    rows = [{'street':'文化街'},{'street':'文化街68巷'}]
    need(suffix_tokens('36巷9弄') == ['36巷','9弄'],'Exact two-token parse')
    for bad in ('','036巷','36巷附','三十六巷','36巷 9弄','36弄/9巷','36巷9號'):
        need(suffix_tokens(bad) is None,'Reject unsupported suffix '+bad)
    need(exact_prefix('文化街68巷9弄',rows)[0]['street']=='文化街68巷','Longest exact prefix')
    need(exact_prefix('文化街68巷9弄',rows+[{'street':'文化街68巷'}])[1]=='duplicate_longest_native_street_prefix','Duplicate longest held')
    need(exact_prefix('埔里文化街68巷',rows)[1]=='no_exact_native_street_prefix','No stripped district alias')
    need(exact_token_child([{'primary_label':'36巷'}],'36巷')[0] is not None,'Exact direct token')
    need(exact_token_child([{'primary_label':'36巷'},{'primary_label':'36巷'}],'36巷')[1]=='duplicate_exact_path_token','Duplicate token held')
    need(exact_token_child([{'primary_label':'36弄'}],'36巷')[1]=='exact_path_token_not_found','No lane/alley alias')
    need(norm('臺北市')=='台北市' and norm('台北巿') != '台北市','Inherited normalization has no 巿 alias')
    return {'count':15,'scope':'Pure in-memory token/prefix/uniqueness controls only; no fake stock results.',
            'all_passed':True}


def main():
    need(not (OUT/'proof.json').exists(),'New proof only; refuse overwrite')
    started = datetime.now(timezone.utc).isoformat(); t0=time.monotonic()
    inputs = []
    reader = reused_reader(load(READER,inputs))
    joined = json.loads(load(JOIN,inputs)); need(joined['all_assigned_checks_passed'],'Sealed join passed')
    selected = {}
    for bucket in joined['pending_name_examples']:
        for example in bucket['bounded_examples']:
            if example['group_id'] in EXAMPLES:
                need(example['group_id'] not in selected,'Unique true proof example')
                selected[example['group_id']] = (example,{'city':bucket['city'],'classification':bucket['classification']})
    need(set(selected)==set(EXAMPLES) and len(EXAMPLES)==20,'Exactly 20 selected real examples')
    for example,_ in selected.values():
        need(re.search(r'[1-9][0-9]*[巷弄]$',example['normalized_planning_key'][2]),'True numeric-suffix example')
    districts = {(e['normalized_planning_key'][0],e['normalized_planning_key'][1]) for e,_ in selected.values()}
    by_district = defaultdict(list); categories = Counter(); levels = Counter()
    roster_raw = load(ROSTER,inputs)
    for line in gzip.decompress(roster_raw).splitlines():
        row = json.loads(line); levels[row['level']]+=1
        if row['level'] == 3:
            categories[row['next_level']]+=1
            key = (norm(row['city']),norm(row['district']))
            if key in districts and key[1] is not None:
                by_district[key].append(row)
    need(levels == {1:22,2:343,3:47853} and categories=={4:20107,5:19036,6:8710},'Corrected sealed original named roster')
    reference = json.loads(load(REFERENCE,inputs))
    schema = json.loads(load(SCHEMA,inputs))
    schema_strings = []
    def collect(o):
        if isinstance(o,dict):
            for v in o.values():collect(v)
        elif isinstance(o,list):
            for v in o:collect(v)
        elif isinstance(o,str) and 'CREATE TABLE japan_addr_family' in o:
            schema_strings.append(o)
    collect(schema)
    need(schema_strings == ['CREATE TABLE japan_addr_family (parent_record INTEGER UNIQUE, the_first_record INTEGER PRIMARY KEY)'],
         'Actual stock JAI parent uniqueness evidence')
    controls=synthetic_controls()
    before=stat(AP)
    class BoundedImage(reader['StockImage']):
        def physical(self,offset,length,reason):
            need(sum(r['bytes'] for r in self.log)+length <= MAX_IMAGE_BYTES,'Actual image read budget')
            return super().physical(offset,length,reason)
    with AP.open('rb') as handle:
        image=BoundedImage(handle)
        tables,descriptor=reader['derive_tables'](image)
        physical_order = list(reversed(tables))
        need(all(a['start']+a['bytes']==b['start'] for a,b in zip(physical_order,physical_order[1:])),
             'Actual six tables touch in physical 6→5→4→3→2→1 order')
        need(tables[0]['start']+tables[0]['bytes']==descriptor['u32_LE'][0] and
             descriptor['u32_LE'][0]+descriptor['u32_LE'][1]==image.components['00004171.MDR']['bytes'],
             'Actual directory follows L1 and ends at component end')
        labels=ActualLabels(image); tree=ActualTree(image,tables,labels,reader)
        results=[resolve(*selected[ID],by_district,tree) for ID in EXAMPLES]
        reads=image.log
    after=stat(AP); need(before==after,'Original AP stat unchanged')
    outcome=Counter(r['status'] for r in results)
    reasons=Counter(r['reason'] for r in results if r['status']=='held')
    proof={'schema':'native-lane-path-resolution/v1','started_utc':started,
        'finished_utc':datetime.now(timezone.utc).isoformat(),'all_assigned_checks_passed':True,
        'script_sha256':sha(Path(__file__).read_bytes()),'inputs':inputs,
        'source_AP':str(AP.relative_to(ROOT)),'source_AP_stat_before':before,'source_AP_stat_after':after,
        'source_AP_stat_unchanged':True,'fresh_full_AP_hash':False,
        'source_AP_full_sha256_inherited_backup':'864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2',
        'selection_group_ids':EXAMPLES,'selection_policy':'20 deterministic finite pending-name proof examples; no source ledger or PBF read.',
        'normalization':'Inherited NFKC/outer-whitespace/臺→台 only; exact city/district and longest native street prefix. Child labels compared exactly.',
        'roster_named_counts_by_level':dict(levels),'roster_named_L3_counts_by_next_level':dict(categories),
        'derived_directory_descriptor':descriptor,'actual_original_tables':tables,
        'actual_GMP_LBL_descriptor':labels.descriptor,'source_examples':results,
        'outcomes':dict(outcome),'held_reasons':dict(reasons),
        'ready_parent_group_review_examples':sum(r.get('parent_group_review_ready',False) for r in results),
        'synthetic_controls':controls,'complete_distinct_direct_groups_examined':len(tree.groups),
        'complete_distinct_direct_child_rows_examined':tree.child_rows,
        'distinct_records_decoded':len(tree.records),'distinct_actual_primary_labels':len(labels.cache),
        'actual_read_count':len(reads),'actual_read_bytes':sum(r['bytes'] for r in reads),
        'actual_bounded_reads':reads,'actual_primary_label_evidence':list(labels.cache.values()),
        'actual_complete_child_group_evidence':list(tree.groups.values()),
        'JAI_parent_record_constraint':schema_strings[0],
        'old_MinQuan_186lane_3alley_reference':{'path':str(REFERENCE.relative_to(ROOT)),
            'sha256':EXPECTED_SHA[REFERENCE],'reuse':'Semantic tree-shape reference only; historical map/CPU case not rerun.'},
        'raw_flags_policy':'Full original flags retained. Raw13 is next5 plus unknown high bit8; never converted to5. No new record flags inferred.',
        'source_group_ledger_accessed':False,'PBF_accessed':False,'source_coordinate_values_read':False,
        'new_native_records':False,'existing_IMG_or_DB_modified':False,'full_image_copy':False,
        'native_CPU_executed':False,'device_IO':False,'new_streets_coverage_claimed':False,
        'full_Taiwan_native_update_complete':False,
        'limits':['Finite 20 proof examples; counts do not estimate countrywide unresolved paths.',
                  'Host packed-record and text decoding only; no native query/search/route/device validation.',
                  'Resolved parent plans need later exact source IDs/coordinates, overlap policy and unchanged-branch writer binding.',
                  'Direct-city source district unverified; duplicates, missing exact tokens and no supported numeric leaves held.',
                  'Unknown flags8/13 semantics, mixed subbranches and JAI family update consumers remain unproved.'],
        'elapsed_seconds':time.monotonic()-t0}
    (OUT/'proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    (OUT/'execution-receipt.json').write_text(json.dumps({'exit_status':0,'started_utc':started,
        'finished_utc':proof['finished_utc'],'elapsed_seconds':proof['elapsed_seconds'],
        'actual_read_bytes':proof['actual_read_bytes'],'source_stat_unchanged':True,
        'new_scope_only':True,'source_sha256':proof['script_sha256'],'proof_sha256':sha((OUT/'proof.json').read_bytes()),
        'outcomes':proof['outcomes'],'held_reasons':proof['held_reasons']},ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'outcomes':dict(outcome),'held_reasons':dict(reasons),
        'read_bytes':proof['actual_read_bytes'],'groups':len(tree.groups),'child_rows':tree.child_rows,
        'review_ready':proof['ready_parent_group_review_examples'],'elapsed_seconds':proof['elapsed_seconds'],
        'proof_sha256':sha((OUT/'proof.json').read_bytes())},ensure_ascii=False))


if __name__=='__main__':
    main()
