#!/usr/bin/env python3
"""Fresh own-file seal; no source/candidate/geometry inputs are reopened."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib
import json
import os

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]


def digest(path):
    before=path.stat();h=hashlib.sha256();amount=0
    with path.open('rb')as f:
        for raw in iter(lambda:f.read(1<<20),b''):h.update(raw);amount+=len(raw)
    after=path.stat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    if identity(before)!=identity(after)or amount!=before.st_size:raise ValueError('Own file changed')
    return dict(path=str(path.relative_to(ROOT)),bytes=amount,sha256=h.hexdigest(),stat_unchanged=True)


def main():
    target=HERE/'seal.json'
    if target.exists():raise ValueError('Fresh seal only')
    proof=json.loads((HERE/'proof.json').read_text());pins={ROOT/v['path']:v for v in proof['artifacts'].values()}
    entries=[]
    for path in sorted(HERE.rglob('*')):
        if not path.is_file()or'__pycache__'in path.parts:continue
        if path.is_symlink():raise ValueError('Unexpected symlink')
        row=digest(path)
        if path in pins:
            pin=pins.pop(path)
            if row['sha256']!=pin['sha256']or row['bytes']!=pin['bytes']:raise ValueError('Output pin mismatch')
            for key in ['rows','uncompressed_sha256','uncompressed_bytes']:
                if key in pin:row[key]=pin[key]
        entries.append(row)
    if pins:raise ValueError('Output artifact missing')
    seal=dict(schema='current-lane-tree-overlay-readonly-seal/v1',created_utc=datetime.now(timezone.utc).isoformat(),files=entries,
        all_fresh_file_hashes_verified=True,output_plain_EOF_and_tree_audit='output-readback-proof.json',
        runtime_bytecode_cache_excluded=True,no_candidate_source_geometry_or_CPU_inputs_reopened=True,
        qualified_missing_integer_targets=58233,current_parent_count=20613,copy_on_write_group_count=29866,
        exact_cloned_record_counts={'4':1114642,'5':365654,'6':65090},new_leaf_counts={'5':44618,'6':13615},
        final_table_counts={'4':4896236,'5':3077845,'6':2062771},first_descriptor_expansion_required=False,
        original4K_estimated_bytes=153337856,original4K_capacity=134217728,original4K_fits=False,
        explicit8K_estimated_bytes=153346048,explicit8K_on_device_proved=False,
        native_write_ready=False,new_binary_or_map_or_device_or_prior_frozen_scope_changed=False)
    with target.open('x')as f:json.dump(seal,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    print(json.dumps(dict(sealed_files=len(entries),seal=digest(target))))


if __name__=='__main__':main()
