#!/usr/bin/env python3
"""Complete inherited country classifications plus bounded name-only samples.

Does not read PBF, source groups/nodes, native image/DB or CPU. No aliases are
applied. Literal lexical review suggestions are not geographic matches.
"""
from collections import Counter,defaultdict
import csv
from datetime import datetime,timezone
import gzip
import hashlib
import json
from pathlib import Path
import re

ROOT=Path('/root/garmin')
OUT=Path(__file__).resolve().parent
COUNTRY=ROOT/'staging/navigation-country-address-ready-join-v1/proof.json'
KEYS=COUNTRY.parent/'unresolved-native-name-group-keys.jsonl.gz'
ROSTER=ROOT/'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz'
CATEGORIES=['missing_native_city','missing_native_district','missing_native_street',
    'missing_native_street_in_direct_city_district_unverified','ambiguous_native_street_exact',
    'ambiguous_direct_city_street','missing_source_street','missing_source_district']
PREFIX_ROW_LIMIT=20000
PREFIX_BYTE_LIMIT=1_000_000


def need(ok,message):
    if not ok:raise AssertionError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def stat(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def small(path,ceiling):
    before=stat(path);need(before[2]<ceiling,'Bounded small input')
    raw=path.read_bytes();need(stat(path)==before,'Immutable input')
    return raw,{'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':sha(raw),
        'stat_before':before,'stat_after':stat(path),'stat_unchanged':True}


class SampleLimit(Exception):pass


class PrefixReader:
    def __init__(self,stream):self.stream=stream;self.count=0;self.hash=hashlib.sha256()
    def read(self,amount=-1):
        left=PREFIX_BYTE_LIMIT-self.count
        if left<=0:raise SampleLimit()
        amount=min(left,amount if amount>=0 else left)
        raw=self.stream.read(amount);self.count+=len(raw);self.hash.update(raw);return raw


def one_edit(a,b):
    if a==b or abs(len(a)-len(b))>1:return False
    if len(a)==len(b):return sum(x!=y for x,y in zip(a,b))==1
    short,long=(a,b) if len(a)<len(b) else (b,a)
    i=j=differences=0
    while i<len(short) and j<len(long):
        if short[i]==long[j]:i+=1;j+=1
        else:j+=1;differences+=1
        if differences>1:return False
    return differences+(len(long)-j)==1


def glyph_difference(a,b):
    if len(a)!=len(b):return []
    return [{'position':i,'source':x,'source_codepoint':f'U+{ord(x):04X}',
             'native':y,'native_codepoint':f'U+{ord(y):04X}'}
            for i,(x,y) in enumerate(zip(a,b)) if x!=y]


def main():
    target=OUT/'unresolved-name-plan.json';need(not target.exists(),'New output scope')
    craw,cmeta=small(COUNTRY,500_000);country=json.loads(craw)
    need(country['all_assigned_checks_passed'] and country['source_group_total']==4630959,'Complete inherited country source evidence')
    totals={x:country['whole_country_group_metrics'].get(x,0) for x in CATEGORIES}
    need(sum(totals.values())==2278269==country['artifacts']['unresolved_native_names']['rows'],'Whole unresolved counts reconcile')
    city_counts=[]
    for city,metrics in country['whole_country_city_group_and_street_metrics'].items():
        values={x:metrics.get(x,{'groups':0,'unique_source_city_district_street_keys':0,
            'unique_matched_native_street_records':0}) for x in CATEGORIES}
        unresolved=sum(v['groups'] for v in values.values())
        if unresolved:
            city_counts.append({'city':city,'unresolved_groups':unresolved,
                'classification_metrics':values,
                'all_prepared_city_groups':metrics['all_groups']['groups'],
                'unresolved_fraction_of_city_prepared_groups':unresolved/metrics['all_groups']['groups']})
    city_counts.sort(key=lambda x:(-x['unresolved_groups'],x['city']))
    need(sum(x['unresolved_groups'] for x in city_counts)==sum(totals.values()),'City unresolved totals reconcile')
    rraw,rmeta=small(ROSTER,2_000_000)
    expected=next(x for x in country['inputs'] if x['path']==str(ROSTER.relative_to(ROOT)))
    need(rmeta['sha256']==expected['sha256'],'Existing native-name roster pinned to country join')
    roster=[json.loads(x) for x in gzip.decompress(rraw).splitlines()]
    cities={r['city']:r for r in roster if r['level']==1}
    district_names=defaultdict(dict);district_city=defaultdict(list)
    street_names=defaultdict(dict);direct_cities=set()
    for r in roster:
        if r['level']==2:
            district_names[r['city']][r['district']]=r
            district_city[r['district']].append({'city':r['city'],'district':r['district'],
                'native_district_record':r['record']})
        elif r['level']==3:
            street_names[(r['city'],r['district'] or '')][r['street']]=r
            if r['district'] is None:direct_cities.add(r['city'])
    need(direct_cities=={'基隆市','台北市','新竹市','嘉義市'},'Direct-city roster layout')
    # First include the complete country pass's <=8 examples per city/category.
    sample_groups={r['group_id']:r for bundle in country['pending_name_examples'] for r in bundle['bounded_examples']}
    inherited_sample_rows=len(sample_groups)
    before=stat(KEYS);artifact=country['artifacts']['unresolved_native_names']
    need(before[2]==artifact['bytes'],'Unresolved key-file inherited size')
    sampled_prefix=[];stopped='row_limit'
    with KEYS.open('rb') as handle:
        reader=PrefixReader(handle)
        try:
            with gzip.GzipFile(fileobj=reader,mode='rb') as stream:
                for line in stream:
                    row=json.loads(line);sampled_prefix.append(row);sample_groups[row['group_id']]=row
                    if len(sampled_prefix)>=PREFIX_ROW_LIMIT:break
                else:stopped='unexpected_complete_EOF'
        except SampleLimit:stopped='compressed_byte_limit'
        prefix_bytes=reader.count;prefix_hash=reader.hash.hexdigest()
    after=stat(KEYS);need(before==after,'Bounded sampled key file unchanged')
    need(stopped!='unexpected_complete_EOF' and 0<len(sampled_prefix)<=PREFIX_ROW_LIMIT
         and prefix_bytes<=PREFIX_BYTE_LIMIT,'Bounded incomplete prefix sample only')
    by_key={}
    for row in sample_groups.values():
        city,district,street,house=row['normalized_planning_key']
        key=(city,district,street,row['native_match'])
        if key not in by_key:
            by_key[key]={'source_city':city,'source_district':district,'source_street':street,
                'native_match':row['native_match'],'observed_sample_group_count':0,
                'observed_house_labels':[],'observed_source_group_examples':[],
                'review_tags':[],'literal_native_city_candidates':[],
                'literal_native_district_candidates':[],'literal_native_street_candidates':[],
                'possible_existing_numeric_lane_alley_prefixes':[]}
        entry=by_key[key];entry['observed_sample_group_count']+=1
        if len(entry['observed_house_labels'])<8 and house not in entry['observed_house_labels']:
            entry['observed_house_labels'].append(house)
        if len(entry['observed_source_group_examples'])<4:
            entry['observed_source_group_examples'].append({'group_id':row['group_id'],'raw_address':row['raw_address'],
                'coordinate_status':row['coordinate_status'],'source_node_count':row['source_node_count'],
                'source_group_ledger_reference':row['source_group_ledger_reference']})
    for (city,district,street,classification),entry in by_key.items():
        tags=entry['review_tags']
        if classification=='missing_native_city':
            tags.append('source_city_string_unmatched')
            for name,row in cities.items():
                if one_edit(city,name):
                    entry['literal_native_city_candidates'].append({'native_city':name,'native_city_record':row['record'],
                        'literal_character_differences':glyph_difference(city,name),'applied':False})
            if city in district_city:
                tags.append('source_city_literal_equals_native_district_name_role_review')
                entry['native_district_name_role_candidates']=district_city[city]
        elif classification=='missing_native_district':
            tags.append('source_district_string_unmatched')
            for name,row in district_names[city].items():
                if one_edit(district,name) or district.startswith(name):
                    same_stem=bool(district and name and district[:-1]==name[:-1])
                    entry['literal_native_district_candidates'].append({'native_district':name,'native_district_record':row['record'],
                        'literal_character_differences':glyph_difference(district,name),
                        'same_literal_stem_different_final_admin_character':same_stem,
                        'source_contains_native_name_prefix':district.startswith(name),'applied':False})
            if re.search(r'郷|巿|恒|廘',district):tags.append('source_unicode_glyph_variant_review')
            if any(x['same_literal_stem_different_final_admin_character'] for x in entry['literal_native_district_candidates']):
                tags.append('admin_suffix_or_historical_name_review_not_verified')
            if re.search(r'村|里|鄰|工業|加工|路|街',district):tags.append('source_admin_field_contains_extra_place_or_street_text_review')
        else:
            direct=classification=='missing_native_street_in_direct_city_district_unverified'
            if direct:tags.append('direct_city_source_district_unverified')
            context=street_names[(city,'' if direct else district)]
            for name,row in context.items():
                if street.startswith(name) and len(street)>len(name):
                    suffix=street[len(name):]
                    if re.fullmatch(r'(?:[0-9一二三四五六七八九十百千零○壹貳參肆伍陸柒捌玖]+[巷弄]){1,3}',suffix):
                        entry['possible_existing_numeric_lane_alley_prefixes'].append({'native_street':name,
                            'nativeStreetID':row['low28_id'],'native_street_record':row['record'],
                            'source_literal_suffix':suffix,'original_next_level':row['next_level'],
                            'original_first_child':row['first_child'],'original_child_count':row['child_count'],
                            'original_full_flags':row['child_level_and_flags'],'branch_exists_or_matches_proved':False})
                if one_edit(street,name) and len(entry['literal_native_street_candidates'])<6:
                    entry['literal_native_street_candidates'].append({'native_street':name,'nativeStreetID':row['low28_id'],
                        'native_street_record':row['record'],'literal_character_differences':glyph_difference(street,name),'applied':False})
            entry['possible_existing_numeric_lane_alley_prefixes'].sort(key=lambda x:-len(x['native_street']))
            if entry['possible_existing_numeric_lane_alley_prefixes']:tags.append('possible_existing_nested_lane_alley_requires_child_label_read')
            if entry['literal_native_street_candidates']:tags.append('same_context_literal_one_edit_street_review_not_alias')
            if re.search(r'\(|\)|（|）',street):tags.append('source_street_annotation_review')
            if district and street.startswith(district):tags.append('source_street_repeats_source_district_prefix_review')
            if re.search(r'村|里|鄰',street) or not re.search(r'路|街|大道|巷|弄',street):
                tags.append('village_place_or_non_road_style_address_name_review')
            if re.search(r'郷|巿|恒|廘',street):tags.append('source_unicode_glyph_variant_review')
            if not entry['possible_existing_numeric_lane_alley_prefixes'] and not entry['literal_native_street_candidates']:
                tags.append('candidate_native_full_street_name_gap_requires_source_and_hierarchy_confirmation')
        entry['name_or_admin_alias_applied']=False
        entry['actual_new_native_street_or_JAI_entry_determined']=False
    sample_keys=list(by_key.values())
    sample_keys.sort(key=lambda x:(-x['observed_sample_group_count'],x['source_city'],x['source_district'],x['source_street']))
    basename_candidates=[x for x in sample_keys if x['native_match']=='missing_native_street'
        and 'candidate_native_full_street_name_gap_requires_source_and_hierarchy_confirmation' in x['review_tags']
        and re.search(r'路|街|大道',x['source_street'])
        and not re.search(r'巷|弄|村|里|鄰|\(|（',x['source_street'])
        and not x['source_street'].startswith(x['source_district'])][:40]
    possible_branches=[x for x in sample_keys if x['possible_existing_numeric_lane_alley_prefixes']][:40]
    admin_reviews=[x for x in sample_keys if x['native_match'] in ('missing_native_city','missing_native_district')]
    street_variants=[x for x in sample_keys if x['literal_native_street_candidates'] or any(t in x['review_tags']
        for t in ['source_street_annotation_review','source_street_repeats_source_district_prefix_review','source_unicode_glyph_variant_review'])][:40]
    sample_artifact=OUT/'bounded-name-samples.jsonl.gz'
    with sample_artifact.open('xb') as handle:
        with gzip.GzipFile(filename='',fileobj=handle,mode='wb',mtime=0) as stream:
            for row in sample_keys:stream.write((json.dumps(row,ensure_ascii=False,separators=(',',':'))+'\n').encode())
    sample_written=sample_artifact.read_bytes()
    csvpath=OUT/'unresolved-name-classification-by-city.csv'
    with csvpath.open('x',encoding='utf-8',newline='') as f:
        writer=csv.writer(f);writer.writerow(['city','unresolved_groups','all_prepared_groups']+[x+'_groups' for x in CATEGORIES])
        for row in city_counts:writer.writerow([row['city'],row['unresolved_groups'],row['all_prepared_city_groups']]+[row['classification_metrics'][x]['groups'] for x in CATEGORIES])
    plan={'schema':'native-unresolved-name-prioritization/v1','created_utc':datetime.now(timezone.utc).isoformat(),
        'all_assigned_checks_passed':True,'script_sha256':sha(Path(__file__).read_bytes()),'small_inputs':[cmeta,rmeta],
        'complete_country_prepared_group_scope':{'groups':country['source_group_total'],
            'source_nodes_represented':country['source_nodes_represented_by_groups'],
            'unresolved_groups':sum(totals.values()),'classification_groups':totals,
            'units':'All counts are prepared groups; street-key counts are unique normalized city,district,street keys, not physical roads or determined new JAI entries.'},
        'complete_city_classification_metrics':city_counts,
        'original_direct_city_correction':country['four_city_raw_missing_district_group_corrections'],
        'direct_city_handling':'277514 groups are missing city+street names with district unverified, not missing native districts; 171158 direct-city uniquely matched groups remain a separate prepared country subset.',
        'bounded_unresolved_key_prefix':{'path':str(KEYS.relative_to(ROOT)),
            'full_file_bytes':before[2],'full_SHA256_inherited_country_write_stream':artifact['sha256'],
            'fresh_full_file_hash_or_pass':False,'compressed_prefix_bytes_read':prefix_bytes,
            'compressed_prefix_sha256':prefix_hash,'prefix_row_count':len(sampled_prefix),
            'row_limit':PREFIX_ROW_LIMIT,'compressed_byte_limit':PREFIX_BYTE_LIMIT,'stop_reason':stopped,
            'full_gzip_EOF_validated_here':False,'stat_before':before,'stat_after':after,'stat_unchanged':True},
        'sample_scope':{'complete_pass_inherited_bounded_example_groups':inherited_sample_rows,
            'distinct_sample_groups_combining_inherited_and_prefix':len(sample_groups),'unique_sample_city_district_street_classification_keys':len(sample_keys),
            'sample_not_representative_or_complete_street_ranking':True,
            'all_sample_group_refs':'Original complete source group ledger retained; no source IDs/points invented from this lean key sample.'},
        'sample_artifact':{'path':str(sample_artifact.relative_to(ROOT)),'rows':len(sample_keys),
            'bytes':len(sample_written),'sha256':sha(sample_written),'bounded_derived_file_hash_only':True},
        'sample_review_tag_counts':dict(Counter(t for x in sample_keys for t in x['review_tags'])),
        'candidate_full_street_name_gap_examples':basename_candidates,
        'possible_existing_nested_branch_examples':possible_branches,
        'source_city_or_district_name_review_examples':admin_reviews,
        'literal_street_variant_or_extra_text_review_examples':street_variants,
        'priority_plan':[
            'Use complete per-city missing-street counts to prioritize coverage. They do not rank individual street names nationally.',
            'For sampled apparent full street-name gaps under an existing exact city/district, confirm source/admin geography and inspect native nearby/nested labels before planning new L3/JAI entries.',
            'For exact native street prefixes plus numeric 巷/弄 suffixes, inspect existing child labels; missing complete JAI street text may already exist as a deeper native address branch.',
            'Review raw Unicode glyphs, admin suffixes, role mixtures and street annotations against authoritative names/source objects. Literal one-edit alternatives are suggestions only; no name is changed.',
            'Keep direct-city street gaps separate until source district/geography is reviewed; do not invent a native district layer.',
            'Only after explicit identity decisions compute actual new native street/JAI growth while preserving original IDs, DB keys, full flags and old branch references.'
        ],
        'limits':['Complete counts inherited from one earlier country pass; only bounded prefix and inherited samples inspected here.',
            '0 ambiguous/no-source-street/no-source-district applies to the prepared full-tag/conservative-group ledger; it is not a claim about every OSM address node.',
            'Literal name candidates do not prove current official names, historical rename dates, geographic equality, stock nested branch existence or new physical roads.',
            'No automatic Chinese aliases, original database/native data edits, new JAI/record generation, CPU/device operations or completed country update.'],
        'name_or_admin_alias_applied':False,'native_DB_IMG_GMP_MDR_modified':False,
        'source_groups_or_PBF_or_node_ledger_read':False,'native_CPU_executed':False,'device_IO':False,
        'full_Taiwan_native_update_complete':False}
    target.write_text(json.dumps(plan,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'all_assigned_checks_passed':True,'classification_groups':totals,
        'bounded_prefix_rows':len(sampled_prefix),'bounded_prefix_compressed_bytes':prefix_bytes,
        'sample_keys':len(sample_keys),'apparent_full_street_gap_examples':len(basename_candidates),
        'admin_review_examples':len(admin_reviews),'plan_sha256':sha(target.read_bytes())},ensure_ascii=False))


if __name__=='__main__':main()
