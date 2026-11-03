#!/usr/bin/env python3
"""New bounded producer-prefix metadata selection; no candidate IMG read."""
import datetime
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
ROOT = Path('/root/garmin');HERE = Path(__file__).resolve().parent
PRODUCER = ROOT/'staging/navigation-native-lane-tree-cow-append-v1'
PRODUCER_SEAL_SHA = '1c25b3963a3f9eb3b218a3747287e8154e253745698f5087064df1135445b077'
STRIDES = {4:128,5:126,6:68}


def need(ok,message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stat(path):
    s = path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--witness-path',required=True)
    parser.add_argument('--witness-sha256',required=True)
    args = parser.parse_args()
    output = HERE/'finite-selection.json';need(not output.exists(),'Refuse overwrite prepared selection')
    seal_raw = (PRODUCER/'sealed-files.json').read_bytes()
    need(sha(seal_raw) == PRODUCER_SEAL_SHA,'Exact producer final seal pin')
    seal = json.loads(seal_raw);pins = {r['path']:r for r in seal['files']};receipts = []
    def record(path,stats,rows,plainbytes,fully_read=False):
        relative = str(path.relative_to(ROOT));pin = pins.get(relative)
        need(stat(path) == stats,'Selection source changed:'+relative)
        if pin:
            need(path.stat().st_size == pin['bytes'],'Frozen prepared input size mismatch')
        receipts.append({'path':relative,'stat_before':stats,'stat_after':stat(path),'rows_selected_prefix_read':rows,
                         'plain_bytes_read':plainbytes,'full_EOF_read':fully_read,'sha256_inherited_from_closed_seal':pin['sha256'] if pin else None})
    def prefix_rows(name,limit=5000,bytes_limit=64*1024*1024):
        path = PRODUCER/name;before = stat(path);count = total = 0;complete = False
        try:
            with gzip.open(path,'rt',encoding='utf8') as stream:
                while count < limit:
                    line = stream.readline()
                    if not line:
                        complete = True;break
                    count += 1;total += len(line.encode('utf8'))
                    need(total <= bytes_limit,'Finite prepared-prefix byte cap:'+name)
                    yield json.loads(line)
        finally:
            record(path,before,count,total,complete)
    selected_path = PRODUCER/'selected-l3-range-changes.json';before = stat(selected_path)
    selected_raw = selected_path.read_bytes();pin = pins[str(selected_path.relative_to(ROOT))]
    need(sha(selected_raw) == pin['sha256'] and len(selected_raw) == pin['bytes'],'Selected range small metadata pin')
    selected = json.loads(selected_raw);need(len(selected) == 7650,'All affected root metadata count')
    record(selected_path,before,len(selected),len(selected_raw),True)
    selected_byID = {r['one_based_street_ID']:r for r in selected}
    witness_path = Path(args.witness_path).resolve();before = stat(witness_path)
    need(witness_path.stat().st_size <= 2*1024*1024 and not witness_path.stat().st_mode & 0o222,'Finite sealed actual-review witness file')
    witness_raw = witness_path.read_bytes()
    need(sha(witness_raw) == args.witness_sha256 and stat(witness_path) == before,'Explicit actual-review small witness pin')
    witness = json.loads(witness_raw)
    receipts.append({'path':str(witness_path.relative_to(ROOT)),'stat_before':before,'stat_after':stat(witness_path),
                     'plain_bytes_read':len(witness_raw),'rows_selected_prefix_read':None,'full_EOF_read':True,
                     'sha256_inherited_from_closed_seal':args.witness_sha256})
    leaves = {};required = {'L5_shift'+str(i) for i in (0,2,4,6)}|{'L6_shift'+str(i) for i in (0,4)}|{'multi_ancestor_leaf'}
    for pick in witness['new_leaf_samples']:
        row = pick['sample'];level = row['level'];shift = ((row['new_lowID']-1)*STRIDES[level])%8
        if level in (5,6):
            leaves.setdefault('L'+str(level)+'_shift'+str(shift),row)
        if len(row['source_ready_target']['actual_parent']['path_record_ids']) >= 3:
            leaves.setdefault('multi_ancestor_leaf',row)
    need(required <= leaves.keys(),'Finite producer prefix lacks required leaves/ancestry')
    unique = {}
    for name,row in leaves.items():
        key = (row['level'],row['new_lowID']);unique.setdefault(key,{'sample':row,'selection_names':[]})['selection_names'].append(name)
    wanted = {r['sample']['stock_parent_record'] for r in unique.values()}
    paths = {row['stock_parent_record']:row for row in witness['parent_path_samples'] if row['stock_parent_record'] in wanted}
    need(set(paths) == wanted,'Finite selected new leaves lack complete producer paths')
    parents = {}
    for path in paths.values():
        links = {r['parent_new_record']:r for r in path['ancestor_links']}
        for ordinal,node in enumerate(path['complete_path']):
            ID = node['new_COW_record'];level,lowID = ID>>28,ID&0xfffffff
            if ordinal == len(path['complete_path'])-1:
                first,count = path['new_house_group_first'],path['new_house_group_count']
            else:
                first,count = links[ID]['first_child'],links[ID]['count']
            parent = {'level':level,'lowID':lowID,'record':ID,'expected_first':first,'expected_count':count,
                      'expected_flags':node['raw_flags'],'expected_label':node['label'],'path_stock_parent':path['stock_parent_record']}
            if ID in parents:
                need(all(parents[ID][key] == parent[key] for key in ('level','lowID','expected_first','expected_count','expected_flags','expected_label')),
                     'Deduplicated selected path node disagrees')
            else:
                parents[ID] = parent
    roots = []
    high = next(r for r in selected if r['next_level'] == 4 and r['first_child'] > 4194304)
    roots.append({'selection_name':'affected_high_first23_root','sample':high,'expected_label':None})
    if not any(p['level'] == 3 and p['expected_flags']&7 == 5 for p in parents.values()):
        roots.append({'selection_name':'affected_root_branch5','sample':next(r for r in selected if r['next_level'] == 5),'expected_label':None})
    # Choose a separate current untouched branch6 from the compact frozen
    # MDR plan; no full provenance ledger or old CPU case is replayed.
    v2 = ROOT/'staging/navigation-country-native-candidate-v2';v2seal = json.loads((v2/'sealed-files.json').read_text())
    v2range_path = v2/'mdr-plan.json';before = stat(v2range_path)
    need(v2range_path.stat().st_size < 4*1024*1024,'Compact v2 metadata cap')
    v2raw = v2range_path.read_bytes()
    v2pin = next(r for r in v2seal['files'] if r['path'] == str(v2range_path.relative_to(ROOT)))
    need(sha(v2raw) == v2pin['sha256'] and stat(v2range_path) == before,'Compact frozen v2 plan pin')
    v2plan = json.loads(v2raw)
    v2row = next(row for row in v2plan['selected_ranges'] if row['next_level'] == 6 and
                 row['ID'] not in selected_byID and row['ID'] != 1226)
    receipts.append({'path':str(v2range_path.relative_to(ROOT)),'stat_before':before,'stat_after':stat(v2range_path),
                     'rows_selected_prefix_read':len(v2plan['selected_ranges']),'plain_bytes_read':len(v2raw),'full_EOF_read':True,
                     'sha256_inherited_from_closed_seal':v2pin['sha256']})
    roots.append({'selection_name':'untouched_prior_v2_branch6_root','sample':{'one_based_street_ID':v2row['ID'],
                  'first_child':v2row['first'],'count':v2row['count'],'next_level':6,'original_flags':v2row['original_flags']},
                  'expected_label':None,'untouched_by_current_COW':True})
    iterator = prefix_rows('prior-v2-new-leaf-identity-status.jsonl.gz',limit=20,bytes_limit=65536)
    try:
        retained = next(iterator)
    finally:
        iterator.close()
    need(retained['status'] == 'actual_cloned_append_payload_identical','Selected prior-v2 leaf has actual clone identity')
    prepared = {'schema':'finite-lane-COW-native-CPU-selection/v3','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'producer_seal_sha256':PRODUCER_SEAL_SHA,'prepared_input_receipts':receipts,
        'new_leaf_samples':list(unique.values()),'copied_path_parent_samples':list(parents.values()),
        'extra_root_samples':roots,'complete_path_samples':list(paths.values()),'retained_prior_v2_leaf_sample':retained,
        'raw13_clone_witness_pending_from_new_independent_producer_review':False,
        'raw13_clone_witness':witness['raw13_clone'],
        'new_independent_actual_review_witness_sha256':args.witness_sha256,
        'candidate_IMG_opened':False,'native_CPU_executed':False,'old_cases_or_suites_run':False}
    need(len(unique) <= 10 and len(parents)+len(roots) <= 20,'Finite CPU node caps')
    with output.open('x') as stream:
        json.dump(prepared,stream,ensure_ascii=False,indent=2);stream.write('\n')
    print(json.dumps({'prepared_sha256':sha(output.read_bytes()),'new_leaves':len(unique),'path_parents':len(parents),
                      'extra_roots':len(roots),'metadata_prefix_plain_bytes':sum(r['plain_bytes_read'] for r in receipts),
                      'candidate_opened':False},ensure_ascii=False))


if __name__ == '__main__':
    main()
