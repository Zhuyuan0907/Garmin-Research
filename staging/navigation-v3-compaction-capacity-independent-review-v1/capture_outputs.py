"""Capture only finally sealed small numerical outputs, no scanner inputs."""
from pathlib import Path
import hashlib
import json
import stat
import sys

ROOT=Path('/root/garmin')
HERE=Path(__file__).resolve().parent
PREFIX='staging/navigation-v3-reachable-suffix-compaction-dependency-preflight-v5/'
LIMIT=98304
NAMES=['proof.json','feasibility-summary.json','actual-stream-read-receipts.json',
       'prepared-source.json','actual-root-tool-receipts.json']
PROOF_SHA='ca6e4225536d9240b58c7424934f49f1c86c58c23dd956b5c8f1c223500f4d82'

def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def sha(raw):return hashlib.sha256(raw).hexdigest()

def main():
    assert len(sys.argv)==2
    expected_seal=sys.argv[1]
    receipts=[];total=0
    out=HERE/'captured-inputs';out.mkdir(exist_ok=False)
    def read(relative,pin=None):
        nonlocal total
        assert relative.startswith(PREFIX)
        assert Path(relative).name in NAMES+['sealed-files.json']
        p=ROOT/relative;before=p.stat()
        assert stat.S_ISREG(before.st_mode) and total+before.st_size<=LIMIT
        if pin:
            assert before.st_size==pin['bytes']
            assert fp(before)==pin['stat_at_seal']
            assert stat.S_IMODE(before.st_mode)==int(pin['mode'],8)
        with p.open('rb') as handle:raw=handle.read(before.st_size+1)
        after=p.stat();total+=len(raw)
        assert len(raw)==before.st_size and fp(before)==fp(after)
        if pin:assert sha(raw)==pin['sha256']
        receipts.append(dict(path=relative,bytes=len(raw),sha256=sha(raw),
                             stat_before=fp(before),stat_after=fp(after),
                             actual_mode=format(stat.S_IMODE(after.st_mode),'04o')))
        (out/p.name).write_bytes(raw)
        return raw
    sealraw=read(PREFIX+'sealed-files.json');assert sha(sealraw)==expected_seal
    seal=json.loads(sealraw)
    rows={r['path']:r for r in seal['files']}
    for name in NAMES:
        relative=PREFIX+name
        raw=read(relative,rows[relative])
        if name=='proof.json':assert sha(raw)==PROOF_SHA
    for row in receipts:
        assert fp((ROOT/row['path']).stat())==row['stat_after']
    (HERE/'input-read-receipts.json').write_text(json.dumps(dict(
        schema='garmin-numeric-compaction-review-input-receipt/v1',
        external_artifact_bytes=total,external_artifact_limit_bytes=LIMIT,
        reads=receipts,all_hash_size_stat_and_actual_mode_pins_passed=True,
        no_scanner_IMG_MAIN_guest_execution=True,all_handles_closed=True),indent=2)+'\n')
    print(json.dumps(dict(files=len(receipts),external_artifact_bytes=total,
                         all_pins_passed=True,all_handles_closed=True,
                         scanner_IMG_MAIN_PBF_guest_audio_device=0)))

if __name__=='__main__':main()
