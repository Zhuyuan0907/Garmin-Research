#!/usr/bin/env python3
"""Seal only this successful independent review's own regular files."""
from pathlib import Path
import hashlib
import json
import os

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent


def digest(path):
    h=hashlib.sha256()
    with path.open('rb')as f:
        for raw in iter(lambda:f.read(65536),b''):h.update(raw)
    return h.hexdigest()


assert not(HERE/'sealed-files.json').exists()
proof=json.loads((HERE/'proof.json').read_bytes());audit=json.loads((HERE/'output-audit.json').read_bytes());controls=json.loads((HERE/'new-reader-controls.json').read_bytes())
assert proof['all_assigned_checks_passed']and audit['all_assigned_checks_passed']and controls['all_assigned_checks_passed']
source=digest(HERE/'review_actual_v3.py');assert source==proof['script_sha256']==audit['review_source_sha256']==controls['source_sha256']
rows=[]
for path in sorted(HERE.iterdir()):
    if path.is_dir():continue
    assert path.is_file()and not path.is_symlink()
    before=path.stat();sha=digest(path);after=path.stat()
    assert(before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    if path.stat().st_mode&0o777!=0o444:path.chmod(0o444)
    st=path.stat();rows.append(dict(path=str(path.relative_to(ROOT)),bytes=st.st_size,sha256=sha,mode='444',stat=[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns]))
seal=dict(schema='sealed-independent-actual-v3-review/v1',all_assigned_checks_passed=True,
    files=rows,file_count=len(rows),all_fresh_file_hashes_verified=True,actual_review_terminal='0803a8',actual_review_exit_code=0,
    corrected_output_audit_terminal='8ee4d1',initial_output_audit_failure_preserved=True,
    original_CPU_or_device_tested=False,native_write_ready=False,full_Taiwan_native_update_complete=False)
p=HERE/'sealed-files.json'
with p.open('x')as f:json.dump(seal,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
p.chmod(0o444);print(json.dumps(dict(all_assigned_checks_passed=True,files=len(rows),seal_sha256=digest(p),image_handle_remains_closed=True)),flush=True)
