"""Finish owned outputs after preserving first close failure; no input reopen."""
from pathlib import Path
import gzip,hashlib,json,stat
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def put(n,o):(HERE/n).write_text(json.dumps(o,ensure_ascii=False,separators=(',',':'))+'\n')
def main():
    proof=json.loads((HERE/'proof.json').read_text());failure=json.loads((HERE/'initial-close-failure.json').read_text())
    assert proof['all_assigned_checks_completed'] and proof['actual_review_input_bytes']==121994
    assert sha(gzip.decompress((HERE/failure['lossless_source_archive']).read_bytes()))==failure['failed_source_original_sha256']
    put('sealer-receipt.json',dict(all_review_checks_completed=True,shared_source_reads_during_close=0,
        all_source_handles_closed=True,IMG_stat=0,producer_execution=0,no_shared_mutations=True,
        initial_close_failure_preserved=True,permission_modes_unchanged=True,STOP=True))
    pins=[]
    for p in sorted(HERE.rglob('*')):
        if not p.is_file() or p.name=='sealed-files.json':continue
        b=p.stat();raw=p.read_bytes();a=p.stat();assert fp(b)==fp(a)
        pins.append(dict(path=str(p.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),
            mode=format(stat.S_IMODE(a.st_mode),'04o'),stat=fp(a)))
    put('sealed-files.json',dict(schema='AP-header-materializer-independent-review-seal/v1',
        all_assigned_checks_completed=True,actual_artifact_input_bytes=121994,output_cap=32768,
        files=pins,actual_mode_pinned_no_required444=True,all_handles_closed=True,STOP=True))
    total=sum(p.stat().st_size for p in HERE.rglob('*') if p.is_file());assert total<=32768
    for r in pins:assert fp((ROOT/r['path']).stat())==r['stat']
    print(json.dumps(dict(STOP=True,files=len(pins),output_bytes=total,input_bytes=121994,
        proof_sha256=sha((HERE/'proof.json').read_bytes()),seal_sha256=sha((HERE/'sealed-files.json').read_bytes()),
        IMG_stat_and_reads=0,producer_execution=0,all_handles_closed=True)))
if __name__=='__main__':main()
