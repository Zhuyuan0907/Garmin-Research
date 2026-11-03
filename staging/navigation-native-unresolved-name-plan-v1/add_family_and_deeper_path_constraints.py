#!/usr/bin/env python3
"""Append bounded lexical followup and frozen schema constraints, no map I/O."""
from collections import Counter
from datetime import datetime,timezone
import gzip
import hashlib
import json
from pathlib import Path
import re

ROOT=Path('/root/garmin')
OUT=Path(__file__).resolve().parent
SCHEMA=ROOT/'staging/navigation-stock-address-schema-v1/stock-address-schema-evidence.json'
DEEPER=ROOT/'staging/navigation-native-deeper-address-plan-v1/semantic-path-plan.json'
ROSTER=ROOT/'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz'


def need(ok,text):
    if not ok:raise AssertionError(text)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def load(path,maximum,inputs):
    before=path.stat();need(before.st_size<=maximum,'Small bounded input')
    raw=path.read_bytes();after=path.stat()
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Immutable input stat')
    inputs.append({'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':sha(raw),'stat_unchanged':True})
    return raw


def main():
    target=OUT/'family-and-deeper-path-constraints.json';need(not target.exists(),'New followup output')
    inputs=[]
    plan=json.loads(load(OUT/'unresolved-name-plan.json',700_000,inputs))
    schema=json.loads(load(SCHEMA,300_000,inputs))
    need(schema['all_readonly_structural_checks_passed'],'Frozen original schema structural checks')
    family=next(x for x in schema['databases']['jai']['schema'] if x.get('name')=='japan_addr_family' and x.get('type')=='table')
    need(family['sql']=='CREATE TABLE japan_addr_family (parent_record INTEGER UNIQUE, the_first_record INTEGER PRIMARY KEY)',
         'Original JAI family schema constraints')
    deeper=json.loads(load(DEEPER,100_000,inputs));need(deeper['all_assigned_checks_passed'],'Bounded original deeper path evidence')
    known=deeper['complete_selected_lane_alley_path']
    need(known['path_labels']==['民權路','186巷','3弄'] and
         [x['primary_label']['label'] for x in known['complete_level6_children']]==['2號','4號','6號','8號'],
         'Inherited exact original lane/alley example')
    rr=load(ROSTER,2_000_000,inputs)
    expected=next(x['sha256'] for x in plan['small_inputs'] if x['path']==str(ROSTER.relative_to(ROOT)))
    need(sha(rr)==expected,'Same existing native name roster')
    streets={}
    for r in (json.loads(x) for x in gzip.decompress(rr).splitlines()):
        if r['level']==3:streets.setdefault((r['city'],r['district'] or ''),{})[r['street']]=r
    sample_path=OUT/'bounded-name-samples.jsonl.gz'
    sr=load(sample_path,500_000,inputs);need(sha(sr)==plan['sample_artifact']['sha256'],'Bounded derived sample binding')
    samples=[json.loads(x) for x in gzip.decompress(sr).splitlines()]
    need(len(samples)==3784,'Derived bounded sample rows')
    named_suffix_examples=[]
    for row in samples:
        if row['native_match'] not in ('missing_native_street','missing_native_street_in_direct_city_district_unverified'):continue
        city,district,street=row['source_city'],row['source_district'],row['source_street']
        direct=row['native_match']=='missing_native_street_in_direct_city_district_unverified'
        existing=row['possible_existing_numeric_lane_alley_prefixes']
        for name,native in streets.get((city,'' if direct else district),{}).items():
            if not street.startswith(name) or len(street)==len(name):continue
            suffix=street[len(name):]
            if not re.fullmatch(r'(?:[^巷弄]{1,24}[巷弄]){1,3}',suffix):continue
            if any(x['native_street']==name for x in existing):continue
            named_suffix_examples.append({'source_city':city,'source_district':district,'source_street':street,
                'nativeStreetID':native['low28_id'],'native_street':name,'literal_source_suffix':suffix,
                'original_next_level':native['next_level'],'original_first_child':native['first_child'],
                'original_child_count':native['child_count'],'original_full_flags':native['child_level_and_flags'],
                'observed_sample_group_count':row['observed_sample_group_count'],
                'source_group_examples':row['observed_source_group_examples'],
                'source_district_verified':not direct,'actual_child_labels_compared':False,
                'branch_exists_or_matches_proved':False,'name_alias_applied':False})
    named_suffix_examples.sort(key=lambda x:(-x['observed_sample_group_count'],-len(x['native_street']),x['source_street']))
    numeric_keys=sum(bool(x['possible_existing_numeric_lane_alley_prefixes']) for x in samples)
    numeric_groups=sum(x['observed_sample_group_count'] for x in samples if x['possible_existing_numeric_lane_alley_prefixes'])
    result={'schema':'unresolved-name-family-and-deeper-path-constraints/v1',
        'created_utc':datetime.now(timezone.utc).isoformat(),'all_assigned_checks_passed':True,
        'script_sha256':sha(Path(__file__).read_bytes()),'small_inputs':inputs,
        'original_japan_addr_family_SQL':family['sql'],
        'family_constraint_implication':'parent_record UNIQUE prevents simply appending a second disjoint family row for the same parent. New full JAI street entries require a coherent parent/range/index design; any needed L3/MDR/JAI remapping is not implemented or proven here.',
        'full_street_name_not_match_is_not_a_new_road_count':True,
        'sample_numeric_prefix_counts':{'unique_city_district_street_classification_keys':numeric_keys,
            'observed_prepared_sample_groups':numeric_groups,
            'total_sample_keys':len(samples),'total_sample_groups':plan['sample_scope']['distinct_sample_groups_combining_inherited_and_prefix'],
            'bounded_sample_only_no_country_extrapolation':True},
        'additional_named_lane_alley_prefix_matches_in_sample':len(named_suffix_examples),
        'additional_named_suffix_examples':named_suffix_examples[:40],
        'inherited_actual_original_deeper_path_example':known,
        'inherited_deeper_evidence_scope':'Only this Minquan 186巷/3弄 path and finite houses were actually decoded from original stock bytes in the earlier bounded scope. Its existence does not prove any other sampled source suffix branch exists.',
        'required_deeper_path_resolution':[
            'Confirm source normalized city/district/full street identity and preserve original raw names.',
            'Select an exact old JAI street prefix within the already-matched city/district, or city-only scope with source district unverified.',
            'Read the actual old parent child group and match the next literal lane/alley component exactly; do not infer a branch from a prefix string.',
            'Continue through actual next_level/first_child/count for every component; preserve intersection branches, raw full flags and old record IDs.',
            'Only an exact complete path permits later labelled-house overlap/coordinate/merge analysis at its true child level.',
            'If an exact child label is absent, keep the path unresolved and design an explicit new branch/entry. Do not map to nearest branch, swap Chinese characters or fabricate a JAI range.'],
        'limits':['No automatic street/admin aliases or solved names; literal prefixes are candidate directions only.',
            'No all-country deeper-path scan, source group/node/PBF reread, original DB/image read or mutation in this scope.',
            'No full unresolved-key file hash/pass; original prefix was393226 compressed bytes /20000 rows.',
            'No claim all1996063+277514 missing street groups need new physical roads or JAI entries.'],
        'name_alias_applied':False,'actual_new_native_streets_determined':False,
        'native_CPU_executed':False,'device_IO':False,'full_Taiwan_native_update_complete':False}
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    top=plan['complete_city_classification_metrics'][:6]
    text='''待解決原生名稱：唯讀優先計畫，未解決／未新增任何街道

完整preparedgroup分類（不是所有OSM address nodes）：
  原city/district已匹配但完整JAI街名缺匹配：1,996,063群組。
  原direct-city佈局 city+street缺匹配、source district未驗：277,514群組。
  行政區字串缺匹配：4,688群組；城市字串缺匹配：4群組。
  ambiguous / missing source street / missing source district：本prepared scope皆0。
  合計2,278,269群組。不能把前兩類直接稱為新道路或必須新增JAI街道數。

完整城市優先量（unresolved groups，含各市全部分類）：
'''
    text+='\n'.join(f"  {r['city']}：{r['unresolved_groups']:,}" for r in top)
    text+='''

首先追existing deeper paths：樣本完整JAI名稱沒匹配，但原名冊可能有完整street prefix，
如『復興路二段71巷31弄』→原『復興路二段』、『內湖路一段91巷35弄』→原『內湖路一段』。
numeric巷/弄樣本有3196個street-classification keys，這是有界樣本結果，不能推成全台比例。
還有中文具名巷/弄suffix可作同方向檢查；所有prefix候選 branch_exists_or_matches_proved=false。
必須依真first_child/count/next_level逐層精確核對actual child label，不得猜或套name alias。

先前原檔實證只有民權路→186巷→3弄→L6 2/4/6/8號這個例子；不代表其他suffix已存在。
街名完整字串缺JAI仍可能已有L4/L5/L6路徑，因此深層核對可能比新增街道索引更優先。

需要核對的名稱例子：OSM『卑南郷』與原『卑南鄉』、OSM『台北巿』與原『台北市』、
OSM『恒春鎮』與原『恆春鎮』；『頭份鎮／頭份市』『員林鎮／員林市』『土城市／土城區』
僅列原source/native字串差異，不證明官方歷史或現在行政名稱，也不自動改source。
『屏東市』放在city欄但原名冊有『屏東縣→屏東市』是角色層級待核對，不能直接當市縣alias。

具體完整street-name缺口樣本包括新北市中和區『立業路』、台中市后里區『三豐路三段／四段』、
屏東縣枋山鄉『舊庄路』、桃園市蘆竹區『小古山路』。它們只是在本樣本沒有exact完整JAI名字，
新增native/JAI前仍需source/admin geography與既有分支／路段名稱核對，不宣稱是新的physical roads。

原japan_addr_family：parent_record UNIQUE；the_first_record PRIMARY KEY。
不能簡單替同parent新增第二段disjoint familyrow。新street/JAI需一致的family/range/index設計，
可能牽涉L3/MDR及JAI重編／remap；本scope沒有實作或宣稱可保持全部street IDs的插入方案。

原unresolved-key檔只讀prefix393226B／20000rows，另外沿用完整countrypass每市分類有界examples。
未重PBF、sourcegroups、nodeledger，沒有IMG/DB寫入、native CPU、USB或自動套別名。
全台地址更新仍未完成。
'''
    (OUT/'PRIORITY-PLAN.txt').write_text(text)
    print(json.dumps({'all_assigned_checks_passed':True,'numeric_prefix_sample_keys':numeric_keys,
        'numeric_prefix_sample_groups':numeric_groups,'additional_named_lane_alley_prefix_matches':len(named_suffix_examples),
        'constraints_sha256':sha(target.read_bytes())},ensure_ascii=False))


if __name__=='__main__':main()
