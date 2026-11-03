"""One pinned small actual-composition proof read; never open its IMG."""
from pathlib import Path
import hashlib,json,stat

ROOT=Path('/root/garmin')
HERE=Path(__file__).resolve().parent
REL='staging/navigation-country-native-lane-candidate-v3/proof.json'
PIN='b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0'
SIZE=9498
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def main():
    receipts=json.loads((HERE/'input-read-receipts.json').read_text())
    assert not(HERE/'captured-inputs/lane-v3-composition-proof.json').exists()
    assert receipts['external_artifact_bytes']+SIZE<=98304
    p=ROOT/REL;before=p.stat();assert before.st_size==SIZE
    with p.open('rb') as f:raw=f.read(SIZE+1)
    after=p.stat()
    assert fp(before)==fp(after) and len(raw)==SIZE
    digest=hashlib.sha256(raw).hexdigest();assert digest==PIN
    (HERE/'captured-inputs/lane-v3-composition-proof.json').write_bytes(raw)
    receipts['reads'].append(dict(path=REL,bytes=SIZE,sha256=digest,
        stat_before=fp(before),stat_after=fp(after),
        actual_mode=format(stat.S_IMODE(after.st_mode),'04o')))
    receipts['external_artifact_bytes']+=SIZE
    (HERE/'input-read-receipts.json').write_text(json.dumps(receipts,indent=2)+'\n')
    proof=json.loads(raw)
    print(json.dumps(dict(component_sizes={r['name']:r['bytes'] for r in proof['complete_actual_component_checks']},
        external_artifact_bytes=receipts['external_artifact_bytes'],all_handles_closed=True)))

if __name__=='__main__':main()
