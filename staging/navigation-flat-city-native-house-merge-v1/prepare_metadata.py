#!/usr/bin/env python3
"""Bound small sealed metadata and original flat roster before address streaming."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
PINS = {
    'staging/navigation-country-native-house-merge-v1/proof.json':
        (17508, 'bfc55b01f1f567cbad495ba3e35301d358cf54d1fdddea9fe1b8a9e6c8412a41'),
    'staging/navigation-country-native-house-merge-v1/sealed-files.json':
        (2630, '92577ed46a3bc321a5580b06262f5a74d1d82be9af673186848905a9446afd10'),
    'staging/navigation-kaohsiung-native-house-merge-v1/proof.json':
        (19637, '5c8502e617ed4b178237dd9d9228a7d84a1c8a995cd3311658237a31896c9704'),
    'staging/navigation-kaohsiung-native-house-merge-v1/sealed-files.json':
        (2814, '9700bd027bdf9f6e4c181ce2207b28e371ba070b86707cce146943d606f02234'),
    'staging/navigation-country-address-ready-join-v1/proof.json':
        (357380, 'b61cd949152fece0548265ccf438c14d3bbeeddfc5e3ae05140df20d3aa0a175'),
    'staging/navigation-flat-city-district-geometry-v1/sealed-files.json':
        (2111, 'a022c04e9192c011cc2502068bc46d1d767e64f246e70ec32737432ede814948'),
    'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz':
        (1210093, '45333390cec4996db40b4a4a987eb421641fec352203bb318aedfd6a6fce2776'),
}
CITIES = {'台北市', '基隆市', '新竹市', '嘉義市'}
STRIDES = {4:128, 5:126, 6:68}
START = {4:3642683, 5:2659853, 6:1984052}


def sha(payload):return hashlib.sha256(payload).hexdigest()


def signature(path):
    x = path.stat()
    return [x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns]


def save(name, value):
    with (OUT / name).open('x') as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def main():
    assert not (OUT / 'preflight.json').exists()
    inputs, data = [], {}
    for relative, (size, digest) in PINS.items():
        path = ROOT / relative
        before = signature(path)
        payload = path.read_bytes()
        assert len(payload) == size and sha(payload) == digest and signature(path) == before, relative
        inputs.append({'path':relative, 'bytes':size, 'sha256':digest,
                       'stat_before':before, 'stat_after':before, 'stat_unchanged':True})
        data[relative] = payload
    country = json.loads(data['staging/navigation-country-native-house-merge-v1/proof.json'])
    kh = json.loads(data['staging/navigation-kaohsiung-native-house-merge-v1/proof.json'])
    join = json.loads(data['staging/navigation-country-address-ready-join-v1/proof.json'])
    assert country['all_assigned_checks_passed'] and kh['all_assigned_checks_passed'] and join['all_assigned_checks_passed']
    assert {int(k):v for k,v in kh['proposed_counts'].items()} == START
    assert kh['starting_country_v1_counts'] == country['proposed_counts']
    assert not CITIES.intersection(country['counts_by_city'])
    for relative, proof in [('staging/navigation-country-native-house-merge-v1/sealed-files.json', country),
                            ('staging/navigation-kaohsiung-native-house-merge-v1/sealed-files.json', kh)]:
        seal = json.loads(data[relative])
        item = next(r for r in seal['files'] if r['path']=='proof.json')
        assert (item['bytes'],item['sha256']) == PINS[relative.replace('sealed-files.json','proof.json')]
    bindings = country['source_code_bindings']
    for item in bindings:
        path = ROOT / item['path']
        before = signature(path)
        payload = path.read_bytes()
        assert len(payload)==item['bytes'] and sha(payload)==item['sha256'] and signature(path)==before
        inputs.append(dict(item,stat_before=before,stat_after=before,stat_unchanged=True))
    geometry_seal = json.loads(data['staging/navigation-flat-city-district-geometry-v1/sealed-files.json'])
    assert geometry_seal['all_assigned_preparation_and_new_wrapper_checks_passed']
    API_binding = next(r for r in geometry_seal['files'] if r['path']=='source_district_membership.py')
    API_path = ROOT / 'staging/navigation-flat-city-district-geometry-v1' / API_binding['path']
    before = signature(API_path)
    payload = API_path.read_bytes()
    assert len(payload)==API_binding['bytes'] and sha(payload)==API_binding['sha256'] and signature(API_path)==before
    inputs.append(dict(API_binding,path=str(API_path.relative_to(ROOT)),stat_before=before,stat_after=before,stat_unchanged=True))
    native = []
    level_counts = {c:Counter() for c in CITIES}
    hierarchy_rows = 0
    for line in gzip.decompress(data['staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz']).splitlines():
        r = json.loads(line); hierarchy_rows += 1
        if r.get('city') in CITIES:
            level_counts[r['city']][r['level']] += 1
            if r['level']==3:
                assert r['district'] is None and r['record']==(3<<28)|r['low28_id']
                native.append(r)
    assert len(native)==2098 and all(v[1]==1 and v[2]==0 for v in level_counts.values())
    original_by_level = Counter()
    streets_by_level = Counter()
    for r in native:
        original_by_level[r['next_level']] += r['child_count']
        streets_by_level[r['next_level']] += 1
    ready = {level:join['artifacts'][f'directcity_{level}_ready'] for level in STRIDES}
    assert {k:v['rows'] for k,v in ready.items()} == {4:144987,5:14537,6:70}
    upper = {level:{'all_flat_original_children':original_by_level[level],
                   'all_flat_native_streets':streets_by_level[level],
                   'ready_groups_upper_bound_on_new_integer_records':ready[level]['rows'],
                   'append_records_upper_bound':original_by_level[level]+ready[level]['rows'],
                   'append_bytes_upper_bound':((original_by_level[level]+ready[level]['rows'])*STRIDES[level]+7)//8,
                   'final_count_upper_bound':START[level]+original_by_level[level]+ready[level]['rows'],
                   'within_current_country_L3_23bit_firstchild_profile':START[level]+original_by_level[level]+ready[level]['rows']<=0x7fffff}
             for level in STRIDES}
    save('native-flat-roster.json',native)
    roster_raw = (OUT / 'native-flat-roster.json').read_bytes()
    save('preflight.json',{'schema':'flat-city-native-house-merge-metadata-preflight/v1',
        'created_utc':datetime.now(timezone.utc).isoformat(),'metadata_checks_passed':True,
        'input_receipts':inputs,'code_bindings':bindings,'geometry_API_binding':dict(API_binding,path=str(API_path.relative_to(ROOT))),
        'join_direct_ready_bindings':ready,'sealed_start_counts':START,
        'source_native_original_counts':{4:2133948,5:2341096,6:1973316},
        'current_base_country_v1_counts':country['proposed_counts'],
        'current_base_Kaohsiung_final_counts':kh['proposed_counts'],
        'base_exclusion_policy':'Root may explicitly rebase after excluding one v1 L4 record; local append bytes/ordinals stay immutable. No silent count mutation.',
        'base_selected_street_disjointness_evidence':'Sealed country v1 city scope excludes all four flat cities; sealed KH scope is Kaohsiung only. Prior selected full ledgers not reopened.',
        'native_hierarchy_complete_rows':hierarchy_rows,'native_hierarchy_gzip_EOF':True,
        'native_flat_city_level_counts':{c:dict(v) for c,v in level_counts.items()},
        'native_flat_roster_file':{'path':'native-flat-roster.json','bytes':len(roster_raw),'sha256':sha(roster_raw)},
        'strides':STRIDES,'conservative_capacity_upper_bounds':upper,
        'conservative_append_bytes_upper_bound_all_levels':sum(v['append_bytes_upper_bound'] for v in upper.values()),
        'no_address_ready_ledger_opened_in_preflight':True})
    print(json.dumps({'metadata_checks_passed':True,'starting_counts':START,
        'upper_bounds':upper,'append_bytes_upper_bound_all_levels':sum(v['append_bytes_upper_bound'] for v in upper.values()),
        'preflight_sha256':sha((OUT/'preflight.json').read_bytes())},ensure_ascii=False))


if __name__=='__main__':main()
