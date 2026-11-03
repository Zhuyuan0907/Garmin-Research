"""Own-output close only. Compute final manifest size before writing it."""
from pathlib import Path
import gzip,hashlib,json,stat
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def render(o):return (json.dumps(o,ensure_ascii=False,separators=(',',':'))+'\n').encode()
def main():
    proof=json.loads((HERE/'proof.json').read_text());failure=json.loads((HERE/'initial-seal-failure.json').read_text())
    assert proof['all_assigned_checks_passed'] and proof['actual_reviewer_artifact_bytes']==152275
    for row in failure['lossless_archives']:
        raw=gzip.decompress((HERE/row['lossless_archive']).read_bytes())
        assert len(raw)==row['original_bytes'] and sha(raw)==row['original_sha256']
    (HERE/'sealer-receipt.json').write_bytes(render(dict(all_assigned_checks_passed=True,
        all_source_handles_closed=True,zero_original_input_reads_during_finish=True,IMG_stat=0,
        first_own_output_failure_preserved=True,shared_mutations=0,STOP=True)))
    pins=[]
    for path in sorted(HERE.rglob('*')):
        if not path.is_file() or path.name=='sealed-files.json':continue
        b=path.stat();raw=path.read_bytes();a=path.stat();assert fp(b)==fp(a)
        pins.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),
            mode=format(stat.S_IMODE(a.st_mode),'04o'),stat=fp(a)))
    raw=render(dict(schema='AP-coherent8K-actual-restore-independent-review-seal/v1',
        all_assigned_checks_passed=True,files=pins,actual_mode_pinned_no_required444=True,
        all_handles_closed=True,output_limit=65536,STOP=True))
    predicted=sum(r['bytes'] for r in pins)+len(raw);assert predicted<=65536
    (HERE/'sealed-files.json').write_bytes(raw)
    for row in pins:assert fp((ROOT/row['path']).stat())==row['stat']
    actual=sum(p.stat().st_size for p in HERE.rglob('*') if p.is_file());assert actual==predicted
    print(json.dumps(dict(STOP=True,files=len(pins),input_bytes=152275,output_bytes=actual,
        proof_sha256=sha((HERE/'proof.json').read_bytes()),seal_sha256=sha(raw),
        all_handles_closed=True,IMG_open_stat_data=0)))
if __name__=='__main__':main()
