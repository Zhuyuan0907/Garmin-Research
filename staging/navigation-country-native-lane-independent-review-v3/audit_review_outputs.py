#!/usr/bin/env python3
"""Fresh output-only compressed/plain EOF audit; no IMG/input ledger opened."""
from pathlib import Path
import gzip
import hashlib
import json
import os
import re

HERE=Path(__file__).resolve().parent
ROOT=Path('/root/garmin')
proof=json.loads((HERE/'proof.json').read_bytes())
artifacts=proof['artifacts'];checks=[];parent_ids=set();root_ids=set();leaf_ids=set();prior_ids=set()


def digest(path):
    h=hashlib.sha256()
    with path.open('rb')as f:
        for raw in iter(lambda:f.read(65536),b''):h.update(raw)
    return h.hexdigest()


for key in ['paths','new_houses','prior_copied_houses','actual_reads']:
    pin=artifacts[key];path=ROOT/pin['path'];before=path.stat();h=hashlib.sha256();amount=rows=0
    assert before.st_size==pin['bytes']and digest(path)==pin['sha256']
    with gzip.open(path,'rb')as f:
        for raw in f:
            h.update(raw);amount+=len(raw);rows+=1;r=json.loads(raw)
            if key=='paths':
                ids=r['actual_path'];parent=r['parent_fields'];assert ids[-1]==parent['record']and parent['record']not in parent_ids
                assert len(ids)>=2 and ids[0]>>28==3 and all(ids[i]>>28<ids[i+1]>>28 for i in range(len(ids)-1))
                assert r['all_links_followed_from_actual_fields'];parent_ids.add(parent['record']);root_ids.add(ids[0])
            elif key=='new_houses':
                ID=(r['level'],r['lowID']);assert ID not in leaf_ids and r['parent_record']in parent_ids
                assert re.fullmatch(r'[1-9][0-9]*號',r['actual_label'])is not None and len(r['actual_raw24'])==2
                assert r['global_initial_bit_shift']==(r['lowID']-1)*proof['actual_tables'][str(r['level'])]['stride']%8
                assert len(set(r['source_ids']))==r['full_source_node_count'];leaf_ids.add(ID)
            elif key=='prior_copied_houses':
                ID=(r['level'],r['actual_new_lowID']);assert ID not in prior_ids and ID not in leaf_ids
                assert r['actual_root_record']in root_ids and r['actual_new_lowID']==r['actual_root_first']+r['actual_child_ordinal']
                assert 0<=r['actual_child_ordinal']<r['actual_root_count'];prior_ids.add(ID)
            else:
                assert 0<=r['physical_offset']<153346048 and 0<=r['bytes']<=1_000_000
                assert r['physical_offset']+r['bytes']<=153346048 and len(r['sha256'])==64
    assert (rows,amount,h.hexdigest())==(pin['rows'],pin['uncompressed_bytes'],pin['uncompressed_sha256'])
    after=path.stat();assert(before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    checks.append(dict(artifact=key,rows=rows,compressed_sha256=pin['sha256'],plain_sha256=h.hexdigest(),EOF_verified=True,immutable_stat_verified=True))

assert(len(parent_ids),len(root_ids),len(leaf_ids),len(prior_ids))==(20613,7650,58233,51332)
witness=ROOT/artifacts['CPU_witnesses']['path'];assert witness.stat().st_size==artifacts['CPU_witnesses']['bytes']and digest(witness)==artifacts['CPU_witnesses']['sha256']
w=json.loads(witness.read_bytes());assert w['source_full_EOF_verified']and len(w['parent_path_samples'])>=1
required={'L5_shift0','L5_shift2','L5_shift4','L5_shift6','L6_shift0','L6_shift4','multi_ancestor_leaf'}
assert required=={r['selection_name']for r in w['new_leaf_samples']}
assert all(r['sample']['new_parent_record']in parent_ids and(r['sample']['level'],r['sample']['new_lowID'])in leaf_ids for r in w['new_leaf_samples'])
assert all(len(r['ancestor_links'])==len(r['complete_path'])-1 and r['new_COW_parent_record']in parent_ids for r in w['parent_path_samples'])
assert w['raw13_clone']['raw_flags']==13 and w['raw13_clone']['payload']==w['raw13_clone']['actual_old_prefix_record']['payload']
result=dict(schema='independent-v3-output-only-audit/v1',all_assigned_checks_passed=True,
    source_sha256=digest(Path(__file__)),review_source_sha256=digest(HERE/'review_actual_v3.py'),
    checks=checks,unique_actual_parents=len(parent_ids),unique_actual_roots=len(root_ids),unique_actual_new_leaves=len(leaf_ids),unique_actual_prior_copied_leaves=len(prior_ids),
    witness_sha256=digest(witness),actual_IMG_or_external_source_inputs_not_opened=True,closed_suite_or_CPU_not_run=True)
with(HERE/'output-audit.json').open('x')as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
print(json.dumps(dict(all_assigned_checks_passed=True,unique_actual_parents=len(parent_ids),unique_actual_new_leaves=len(leaf_ids),unique_actual_prior_copied_leaves=len(prior_ids))),flush=True)
