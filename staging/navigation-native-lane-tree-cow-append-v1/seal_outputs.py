#!/usr/bin/env python3
"""Seal/freeze own outputs only; verify the new path ledger EOF once."""
from pathlib import Path
from datetime import datetime,timezone
import gzip
import hashlib
import json
import os

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]


def digest(path):
    before=path.stat();h=hashlib.sha256();amount=0
    with path.open('rb')as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b);amount+=len(b)
    after=path.stat();identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    if identity(before)!=identity(after)or amount!=before.st_size:raise ValueError('Own output changed during hash')
    return dict(path=str(path.relative_to(ROOT)),bytes=amount,sha256=h.hexdigest(),stat_after_freeze=list(identity(after)),mode=oct(after.st_mode&0o777))


def main():
    target=HERE/'sealed-files.json'
    if target.exists():raise ValueError('Fresh seal required')
    proof=json.loads((HERE/'proof.json').read_text());pathproof=json.loads((HERE/'new-tree-path-proof.json').read_text());pin=pathproof['artifact']
    p=ROOT/pin['path'];plain=hashlib.sha256();rows=amount=links=0;roots=set();parents=set()
    with gzip.open(p,'rb')as f:
        for line in f:
            rows+=1;amount+=len(line);plain.update(line);r=json.loads(line);steps=r['complete_path'];edges=r['ancestor_links']
            if len(edges)!=len(steps)-1 or steps[-1]['new_COW_record']!=r['new_COW_parent_record']:raise ValueError('New path output chain')
            for edge in edges:
                ID=edge['child_new_record']&0xfffffff
                if not edge['first_child']<=ID<edge['first_child']+edge['count']:raise ValueError('New path output child range')
            roots.add(steps[0]['new_COW_record']);parents.add(r['new_COW_parent_record']);links+=len(edges)
    if(rows,amount,plain.hexdigest())!=(pin['rows'],pin['uncompressed_bytes'],pin['uncompressed_sha256'])or(rows,len(roots),len(parents),links)!=(20613,7650,20613,24442):
        raise ValueError('New path output EOF/pin/counts')
    with(HERE/'new-tree-path-output-readback.json').open('x')as f:
        json.dump(dict(all_checks_passed=True,rows=rows,roots=len(roots),parents=len(parents),ancestor_links=links,
                       gzip_EOF_and_plain_hash_verified=True,current_candidate_not_reopened=True),f,indent=2);f.write('\n')
    pins={ROOT/v['path']:v for v in proof['artifacts'].values()};pins[p]=pin
    pins.update({HERE/v['path']:v for v in proof['append_artifacts'].values()})
    files=[]
    for path in sorted(HERE.rglob('*')):
        if not path.is_file()or'__pycache__'in path.parts:continue
        if path.is_symlink():raise ValueError('Unexpected output symlink')
        path.chmod(0o444);row=digest(path)
        if path in pins:
            expected=pins.pop(path)
            if row['sha256']!=expected['sha256']or row['bytes']!=expected['bytes']:raise ValueError('Output pin changed')
            for key in ['rows','uncompressed_sha256','uncompressed_bytes','record_count','record_bits','bit_length','unused_final_high_bits']:
                if key in expected:row[key]=expected[key]
        files.append(row)
    if pins:raise ValueError('Own output missing')
    seal=dict(schema='prepared-current-lane-tree-COW-appends-seal/v1',created_utc=datetime.now(timezone.utc).isoformat(),files=files,
        all_fresh_file_hashes_verified=True,all_scope_files_frozen444=True,runtime_bytecode_cache_excluded=True,
        original_inputs_or_candidate_or_geometry_or_CPU_not_reopened_during_seal=True,
        new_integer_house_records=58233,complete_new_source_node_memberships=111147,explicit_lower_parent_mappings=22216,
        complete_house_parent_paths=20613,current_L3_changes=7650,current_L3_classification={'already_selected_v2':6366,'previously_stock_range':1284},
        lower_final_counts={'4':4896236,'5':3077845,'6':2062771},prior_new_leaf_identity_counts={'copied_prior_new_leaves':51332,'untouched_current_prefix_prior_new_leaves':79305},
        current_v2_prefix_preservation_in_full_IMG_pending=True,native_write_ready=False,whole_IMG_written=False,
        device_USB_ZIP_canonical_or_prior_frozen_files_changed=False)
    with target.open('x')as f:json.dump(seal,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    target.chmod(0o444);print(json.dumps(dict(files=len(files),seal=digest(target))))


if __name__=='__main__':main()
