#!/usr/bin/env python3
"""Final source/output hash audit; does not reopen original DB/map or sandbox."""
from pathlib import Path
import hashlib
import json
import os

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent


def sha(path):
    h=hashlib.sha256()
    with path.open('rb')as f:
        for raw in iter(lambda:f.read(65536),b''):h.update(raw)
    return h.hexdigest()


def read(name):return json.loads((HERE/name).read_bytes())


assert not(HERE/'sealed-files.json').exists()
control=read('new-writer-controls.json');proof=read('sandbox-proof.json');snapshot=read('original-family-snapshot.json');binding=read('source-candidate-binding.json');receipts=read('original-read-receipt.json')
assert all(r['all_assigned_checks_passed']for r in [control,proof,snapshot,binding])and receipts['all_read_controls_passed']
assert sha(HERE/'jai_family_writer.py')==control['writer_sha256']==proof['writer_sha256']
assert sha(HERE/'original-family-snapshot.json')==proof['original_snapshot_sha256']==receipts['snapshot_SHA256']
assert sha(ROOT/proof['prototype']['path'])==proof['prototype']['sha256']
assert sha(ROOT/proof['plan']['path'])==proof['plan']['sha256']
assert sha(HERE/'original-DB-physical-reads.strace')==receipts['DB_strace_source_SHA256']
assert receipts['DB_actual_read_bytes']==sum(r['actual_bytes']for r in receipts['DB_reads'])and receipts['DB_actual_read_operations']==len(receipts['DB_reads'])
rows=[]
for p in sorted(HERE.iterdir()):
    if p.is_dir():continue
    assert p.is_file()and not p.is_symlink();before=p.stat();digest=sha(p);after=p.stat()
    assert(before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    if p.stat().st_mode&0o777!=0o444:p.chmod(0o444)
    st=p.stat();rows.append(dict(path=str(p.relative_to(ROOT)),bytes=st.st_size,sha256=digest,mode='444',stat=[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns]))
seal=dict(schema='sealed-finite-JAI-newstreet-sandbox-and-plan/v1',all_assigned_checks_passed=True,all_fresh_source_output_hashes_verified=True,files=rows,file_count=len(rows),
    controls_terminal='5dc6b2',original_read_terminal='a67d00',sandbox_terminal='524ac6',sourcebinding_terminal='9daa7f',
    full_original_DB_adapter_implemented=False,prefix_segment_writer_implemented=False,native_CPU_query_UI_or_device_tested=False,native_write_ready=False,
    original_DB_MAP_USB_ZIP_and_canonical_modified=False,full_Taiwan_native_update_complete=False)
p=HERE/'sealed-files.json'
with p.open('x')as f:json.dump(seal,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
p.chmod(0o444);print(json.dumps(dict(all_assigned_checks_passed=True,files=len(rows),seal_sha256=sha(p),original_handles_closed=True)),flush=True)
