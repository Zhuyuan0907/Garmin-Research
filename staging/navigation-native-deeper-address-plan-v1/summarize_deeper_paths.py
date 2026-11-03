#!/usr/bin/env python3
"""Summarize the finite stock evidence and read one already-identified alley.

No source-node/groups/PBF scan, native CPU run or image/database mutation.
"""
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import json
from pathlib import Path

from inspect_deeper_address_paths import (
    AP, OUT, ROOT, StockImage, Labels, derive_tables, read_record, load_small, need, sha, stat,
)


def main():
    target = OUT/'semantic-path-plan.json'
    need(not target.exists(),'Refusing summary overwrite')
    raw,source_meta = load_small(OUT/'deeper-address-plan.json',700_000)
    source = json.loads(raw)
    need(source['all_assigned_checks_passed'],'Finite initial evidence passed')
    parent = next(d for s in source['representative_street_branches']
        for c in s['children'] for d in c['deeper_sample']
        if d['level']==5 and d['one_based_ID']==1021924)
    need(parent['primary_label']['label']=='3弄' and parent['next_level']==6
         and parent['first_child']==828708 and parent['child_count']==4,'Identified original alley branch')
    lbl_proof_raw,lbl_meta = load_small(ROOT/'staging/navigation-native-house-label-index-v1/proof.json',100_000)
    lbl_proof = json.loads(lbl_proof_raw)
    before = stat(AP)
    with AP.open('rb') as handle:
        image = StockImage(handle)
        tables,descriptor = derive_tables(image)
        need(tables==source['original_tables'] and descriptor==source['directory_derived_from_real_header'],
             'Second bounded header source agrees with initial evidence')
        labels = Labels(image,lbl_proof)
        alley_children = []
        for ID in range(parent['first_child'],parent['first_child']+parent['child_count']):
            record = read_record(image,tables,6,ID)
            record['primary_label'] = labels.get(record['primary_ref'])
            record['secondary_label'] = labels.get(record['secondary_ref'])
            alley_children.append(record)
        reads = image.log
    need(stat(AP)==before,'Original AP unchanged by final four-record read')
    need(all(r['primary_label']['label_class']=='numeric_integer_house' for r in alley_children),
         'Complete selected alley group consists of integer houses')
    street_summaries = []
    for sample in source['representative_street_branches']:
        street = sample['native_street']
        classes = Counter()
        for child in sample['children']:
            label = child['record']['primary_label']
            classes['explicit_intersection_label' if label and label['label']=='+ 交叉路口 +'
                    else label['label_class'] if label else 'missing_primary_ref'] += 1
        street_summaries.append({'nativeStreetID':street['low28_id'],'city':street['city'],
            'district':street['district'],'street':street['street'],
            'direct_child_level':street['next_level'],'raw_street_flags':street['child_level_and_flags'],
            'old_first_child':street['first_child'],'old_child_count':street['child_count'],
            'sample_complete':sample['direct_child_complete'],'sampled_direct_child_label_classes':dict(classes)})
    csvpath = OUT/'next5-next6-source-coverage-by-city.csv'
    with csvpath.open('x',encoding='utf-8',newline='') as f:
        writer=csv.writer(f)
        writer.writerow(['city','next5_source_groups','next5_unique_source_street_keys','next5_native_street_records',
                         'next6_source_groups','next6_unique_source_street_keys','next6_native_street_records'])
        for city,metrics in source['source_matching_counts_by_city'].items():
            writer.writerow([city]+[metrics[f'next{level}'][key] for level in (5,6)
                for key in ('groups','unique_source_city_district_street_keys','unique_matched_native_street_records')])
    plan = {'schema':'native-deeper-address-semantic-plan/v1','created_utc':datetime.now(timezone.utc).isoformat(),
        'all_assigned_checks_passed':True,'script_sha256':sha(Path(__file__).read_bytes()),
        'inputs':[source_meta,lbl_meta],'source_AP_stat_before':before,'source_AP_stat_after':stat(AP),
        'source_AP_stat_immutable':stat(AP)==before,
        'source_AP_full_sha256_inherited_backup':source['source_AP_full_sha256_inherited_backup'],
        'additional_bounded_original_reads':reads,'additional_bounded_original_read_bytes':sum(r['bytes'] for r in reads),
        'total_bounded_original_read_bytes_this_task':source['bounded_original_read_bytes']+sum(r['bytes'] for r in reads),
        'source_matching_totals':source['source_matching_totals'],
        'source_matching_counts_by_city':source['source_matching_counts_by_city'],
        'source_count_units_and_matching_limits':source['source_metrics_units']+'; '+source['source_metrics_limits'],
        'representative_stock_branch_summaries':street_summaries,
        'complete_selected_lane_alley_path':{
            'path_labels':['民權路','186巷','3弄'],
            'path_packed_IDs':[{'level':3,'one_based_ID':16707},{'level':4,'one_based_ID':904781},
                               {'level':5,'one_based_ID':1021924}],
            'last_parent_record':parent,'complete_level6_children':alley_children},
        'observations':[
            'L3 next5 groups can directly contain positive integer and subnumber house labels, alongside an explicit + 交叉路口 + row which points to L6 road labels.',
            'L3 next6 groups can directly contain house labels. Original L6 stores a primary text reference plus coordinates; it is not an unlabelled coordinate-only table.',
            'The same record level has multiple uses: selected L6 rows hold either houses or intersection-road labels, depending on their parent.',
            'Minquan demonstrates L3 street -> L4 lane -> L5 alley -> L6 house. Named lane suffixes may also be complete JAI L3 streets; textual lane markers alone do not choose insertion level.',
            'Sampled L5 next5-street mixed groups have the literal intersection row first, then houses whose first raw flag is8; other sampled house rows are0. Minquan has further flag8 rows after nested branches.',
            'Both sampled raw street flag13 groups contain only one intersection branch. No rule for converting raw13 to5 is proved.'
        ],
        'flag_semantics_status':{
            'low_three_bits_as_next_level':'Inherited source/native directory-reader evidence; host decoded and sampled again here.',
            'bit8_and_raw13':'Static observed raw values only. First-result separator/adjacency meaning is an unproved interpretation in this scope.',
            'preservation_requirement':'Keep complete raw flags and existing child IDs. Do not clear/transfer bit8 or change13 to5 based on this sample.',
            'further_validation_needed':'Actual numeric merge rules and original query/comparator consumption at each affected level.'},
        'potential_insertion_paths':[
            {'condition':'An exact uniquely matched complete L3 street currently has next_level5.',
             'potential_house_record_level':5,'original_record_bits':126,
             'required_work':'Merge validated source house labels/points into this street group; preserve old L5 houses, intersection branches and their original L6 references. Prove level5 query/order and flag handling before writing.'},
            {'condition':'An exact uniquely matched complete L3 street currently has next_level6.',
             'potential_house_record_level':6,'original_record_bits':68,
             'required_work':'Merge into the existing direct L6 labelled-house group; L6 has no child fields or secondary reference. Prove native level6 search/query behavior and ordering before writing.'},
            {'condition':'A source complete street name exactly matches a named lane/alley JAI L3 street.',
             'potential_house_record_level':'Use that matched L3 street own existing next_level; do not infer from 巷/弄 text.',
             'required_work':'Maintain exact names. Do not silently split source street text or resolve an unmatched source street to a substring of another street.'},
            {'condition':'Source requires a nested lane/alley under an existing L3 street rather than an exact JAI L3 street.',
             'potential_house_record_level':'Only after exact labelled branch matching; Minquan proves one L3->L4->L5->L6 example.',
             'required_work':'Prepared groups alone do not establish Chinese branch aliases. Retain as unprepared/manual hierarchy classification until branch matching and original consumer behavior are demonstrated.'}],
        'current_original_profile_field_limits':{
            'not_a_GarminOS_platform_hard_limit':True,
            'L3_first_child_bits':22,'L3_first_child_max':4194303,'L3_child_count_bits':12,'L3_child_count_max':4095,
            'L5_first_child_bits':21,'L5_first_child_max':2097151,'L5_child_count_bits':9,'L5_child_count_max':511,
            'original_L5_count':2341096,'original_L6_count':1973316,
            'original_L5_to_new_L6_reference_headroom':123835,
            'scope_note':'L5 21-bit limit applies to L5 child pointers into L6; it does not cap all L6 IDs when referenced directly by a wider L3/L4 pointer. Table counts/source groups are not actual new-record growth or stock overlap proofs.',
            'future_profile_change':'A different declared width/stride may be possible with complete reencoding and original-reader validation; not attempted here.'},
        'next_preparation':[
            'Produce countrywide prepared subsets for levels4/5/6 from the existing planning-group ledger, without rescanning PBF.',
            'Keep exact city/district/street unique matches separate from four direct-city matches with district explicitly unverified; retain missing/ambiguous names and coordinate conflicts.',
            'Retain reusable numeric label refs, source IDs/raw house tags/floor-unit indicators, coordinates and original first/count/full flags, with actual stock overlap still unassessed.',
            'Then compute distinct truly new houses and bounded cluster growth only after old labelled group overlap and coordinate conflict review.'
        ],
        'limits':['Only finite original record/label reads and inherited complete source metrics.',
                  'No all-country house-row extraction was done in this scope.',
                  'No proof of flags8/13 meanings, native numeric comparator at levels5/6, new point getter, hierarchy writer or installation.',
                  'Direct-city source districts remain unverified; no automatic district assignment.'],
        'native_CPU_executed':False,'device_IO':False,'PBF_accessed':False,'source_groups_rescanned':False,
        'full_image_copied_or_rewritten':False,'existing_sources_modified':False,'full_Taiwan_native_update_complete':False}
    target.write_text(json.dumps(plan,ensure_ascii=False,indent=2)+'\n')
    note = '''原廠 next5 / next6 地址路徑準備（僅 bounded read，未更新地圖）

全台匹配来源：next5 541,855 個門牌群組 / 13,421 筆原廠街道；next6 16,735 個群組 / 706 筆街道。
這是 source planning groups，尚未判定與原廠重疊，不能稱新增地址數。

next5 本身可以直接存門牌。原廠湖海路二段、北投路二段、台中太平民權街為 L3→L5；同群第一筆『+ 交叉路口 +』再指向 L6 路名。
next6 也直接存門牌並有 primary text ref。基隆三合街 L6 的『2號』與台中仁美九巷 L6 的『78之1號』等已直接讀出。
民權路原廠另有 L3民權路(ID16707)→L4 186巷(ID904781)→L5 3弄(ID1021924)→L6 的完整4筆門牌子群。

後續可延伸各街原 next_level=5 或6來 merge，保留既有交叉路口與巷弄子群；不可把全部街道強制轉成L4。
巷／弄文字也可能是完整 JAI L3街名；不能只依文字決定層級，不能静默拆字或加中文街別名。

raw flags8／13 只記為靜態觀察值。first-separator／adjacency 是本 scope 未證明的解釋，不提供13→5改寫規則。實際寫入前仍要驗證對應層級的原 query／order／旗標處理。
現行原廠 profile：L3 firstchild22bits、count12bits；L5 childpointer21bits、count9bits。這不是整個GarminOS平台硬上限。L6有primaryref／座標，沒有child fields／secondaryref。

下一步是沿現有完整planning-group ledger輸出全台4／5／6候選。四個direct-city佈局須保留district-unverified類別；缺街名、ambiguous、coordinates conflict不得猜解或丟棄。
全台原生圖資更新仍未完成；此 scope 沒有 PBF掃描、native CPU、裝置I/O、映像改寫或安裝。
'''
    (OUT/'DEEPER-PATH-PLAN.txt').write_text(note)
    artifacts={}
    for p in [target,csvpath,OUT/'DEEPER-PATH-PLAN.txt',OUT/'deeper-address-plan.json',
              OUT/'inspect_deeper_address_paths.py',Path(__file__)]:
        b=p.read_bytes();artifacts[p.name]={'bytes':len(b),'sha256':sha(b)}
    receipt={'schema':'deeper-address-plan-execution-receipt/v1','created_utc':datetime.now(timezone.utc).isoformat(),
             'artifacts':artifacts,'all_assigned_checks_passed':True,
             'bounded_original_read_bytes':plan['total_bounded_original_read_bytes_this_task'],
             'source_AP_stat_unchanged':True,'no_PBF_or_source_group_ledger_read':True,
             'native_CPU_executed':False,'device_IO':False,'full_Taiwan_native_update_complete':False,
             'first_pass_actual_tool_receipt':{'tool':'exec_command','chunk_id':'4ebf7b','exit_code':0,
                 'command':'python3 staging/navigation-native-deeper-address-plan-v1/inspect_deeper_address_paths.py'},
             'final_pass_actual_tool_receipt':'Record the actual terminal chunk/exit in root parent evidence; this file is written before process exit.'}
    (OUT/'execution-receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'status':'complete','plan':str(target),'bounded_original_read_bytes':plan['total_bounded_original_read_bytes_this_task'],
        'four_alley_house_labels':[r['primary_label']['label'] for r in alley_children],
        'plan_sha256':artifacts[target.name]['sha256']},ensure_ascii=False))


if __name__=='__main__':
    main()
