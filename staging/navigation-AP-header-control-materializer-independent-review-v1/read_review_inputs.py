"""One bounded artifact-only capture for static review. Never import producer."""
from pathlib import Path
import ast,hashlib,json,stat
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent;CAP=131072
FILES=[
 'scripts/materialize_ap_header_control_v1.py',
 'staging/navigation-AP-header-control-materializer-v1/test_materializer.py',
 'staging/navigation-AP-header-control-materializer-v1/synthetic-test-proof.json',
 'staging/navigation-AP-header-control-materializer-v1/proof.json',
 'staging/navigation-AP-header-control-materializer-v1/sealed-files.json',
 'staging/navigation-AP-header-control-materializer-v1/actual-test-tool-receipt.json',
 'staging/navigation-AP-header-control-root-catalog-review-v1/actual-root-tool-receipt.json',
 'staging/navigation-AP-header-control-root-catalog-review-v1/actual-catalog.json',
 'staging/navigation-AP-header-control-root-catalog-review-v1/sealed-files.json']
PINS={FILES[0]:'dfbf182f4d1b40fc4315c5568a7e92c521c35d1c764bc1946e53269f7f958142',
 FILES[3]:'c9b7b59d962f262b3c89f089eab04aeed5cfbdcc29657705703515cc0d128d7e',
 FILES[4]:'442653f6ea55b5792f40048aa391c2c3a19b11cf0c7ed0af1a592d13df48197d',
 FILES[8]:'92406f56aff1a845cd18d41d869ed207a87b2693a200d5a0ccbab5f21a33dead'}
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def main():
    rows=[];raws={};total=0
    for name in FILES:
        p=ROOT/name;b=p.stat();assert stat.S_ISREG(b.st_mode) and total+b.st_size<=CAP
        with p.open('rb') as f:raw=f.read(b.st_size+1)
        a=p.stat();total+=len(raw);assert fp(b)==fp(a) and len(raw)==b.st_size
        digest=hashlib.sha256(raw).hexdigest()
        if name in PINS:assert digest==PINS[name]
        raws[name]=raw;rows.append(dict(path=name,bytes=len(raw),sha256=digest,
            mode=format(stat.S_IMODE(a.st_mode),'04o'),stat_before=fp(b),stat_after=fp(a),
            provided_root_digest_verified=name in PINS))
    for row in rows:assert fp((ROOT/row['path']).stat())==row['stat_after']
    # Record actual full artifacts once. No raw copies written under the32KiB output cap.
    (HERE/'input-read-receipts.json').write_text(json.dumps(dict(actual_small_artifact_bytes=total,
        cap=CAP,reads=rows,all_source_handles_closed=True,raw_input_copies_saved=False,
        IMG_open_or_stat=0,producer_import_or_execution=0,synthetic_reruns=0,
        MAIN_device_native_audio_canonical_operations=0),indent=2)+'\n')
    for name in FILES[:2]:
        source=raws[name].decode();tree=ast.parse(source)
        funcs=[dict(name=x.name,line=x.lineno,end=x.end_lineno) for x in ast.walk(tree)
               if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef))]
        print('SOURCE '+name+'\n'+source)
        print('FUNCTIONS '+json.dumps(funcs))
    for name in FILES[2:]:
        obj=json.loads(raws[name]);print('JSON '+name+'\n'+json.dumps(obj,ensure_ascii=False))
    print('ACTUAL_ARTIFACT_BYTES '+str(total))
if __name__=='__main__':main()
