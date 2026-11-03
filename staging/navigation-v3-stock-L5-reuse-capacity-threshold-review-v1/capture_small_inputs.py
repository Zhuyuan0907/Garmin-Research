"""One bounded capture of closed small numeric evidence, never images/scanners."""
from pathlib import Path
import hashlib,json,stat

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
OLD='staging/navigation-v3-compaction-capacity-independent-review-v1/'
NEW='staging/navigation-v3-exclusive-stock-L4-reuse-feasibility-v1/'
LIMIT=98304
def sha(raw):return hashlib.sha256(raw).hexdigest()
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def main():
    target=HERE/'captured-inputs';target.mkdir(exist_ok=False)
    rows=[];total=0
    def read(relative,label,pin=None,digest=None,size=None):
        nonlocal total
        assert relative.startswith((OLD,NEW))
        assert Path(relative).name in {'sealed-files.json','scope-summary.json','math.json','checklist.json','capacity-arithmetic.json'}
        p=ROOT/relative;b=p.stat();assert stat.S_ISREG(b.st_mode)
        assert total+b.st_size<=LIMIT
        if size is not None:assert b.st_size==size
        if pin:
            assert fp(b)==pin['stat_at_seal']
            assert stat.S_IMODE(b.st_mode)==int(pin['mode'],8)
            assert b.st_size==pin['bytes']
            assert digest is None or digest==pin['sha256']
            digest=pin['sha256']
        with p.open('rb') as f:raw=f.read(b.st_size+1)
        a=p.stat();total+=len(raw)
        assert fp(b)==fp(a) and len(raw)==b.st_size
        value=sha(raw)
        if digest:assert value==digest
        rows.append(dict(path=relative,bytes=len(raw),sha256=value,
            expected_sha256=digest,sha_newly_established_if_no_external_pin=digest is None,
            actual_mode=format(stat.S_IMODE(a.st_mode),'04o'),stat_before=fp(b),stat_after=fp(a)))
        (target/label).write_bytes(raw)
        return json.loads(raw)
    oldseal=read(OLD+'sealed-files.json','capacity-review-sealed-files.json',
        digest='76cfcdbb94e877633bcd615b940d6f6aef9c93714cc82395013573686267b047')
    newseal=read(NEW+'sealed-files.json','L4reuse-sealed-files.json')
    oldrows={r['path']:r for r in oldseal['files']};newrows={r['path']:r for r in newseal['files']}
    read(NEW+'scope-summary.json','L4reuse-scope-summary.json',newrows[NEW+'scope-summary.json'],
         digest='31ff1e560798e9c772cb5cdb01682aa049ba161b80c82d071e0715751e116ec9',size=2851)
    read(OLD+'math.json','prior-capacity-math.json',oldrows[OLD+'math.json'],
         digest='e2b44383925d87456c88de02d89bb98852f9eb054d6fe1aa43c06ad0492d1162',size=6759)
    read(OLD+'checklist.json','prior-capacity-checklist.json',oldrows[OLD+'checklist.json'],size=1437)
    read(NEW+'capacity-arithmetic.json','L4reuse-capacity-arithmetic.json',newrows[NEW+'capacity-arithmetic.json'],size=1177)
    for row in rows:assert fp((ROOT/row['path']).stat())==row['stat_after']
    receipt=dict(schema='garmin-L5-capacity-numeric-input-receipt/v1',
        external_artifact_bytes=total,external_limit_bytes=LIMIT,reads=rows,
        all_provided_and_closed_seal_file_pins_passed=True,all_handles_closed=True,
        scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0,
        source_or_mode_mutations=0)
    (HERE/'input-read-receipts.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(dict(files=len(rows),external_bytes=total,all_pins_passed=True,
                         all_handles_closed=True,scanner_IMG_MAIN_PBF_guest_device=0)))

if __name__=='__main__':main()
