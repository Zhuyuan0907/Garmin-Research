"""Bounded closed ordinary source/metadata capture; no IMG read."""
from pathlib import Path
import hashlib,json,stat

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
LIMIT=131072
FILES=[
 ('mapper-source.py.txt','staging/navigation-minimal-lane-render-isolation-plan-v1/prepare_control.py',35380,'a20877fce09cbfe36f1f5621144f2ade44a031c26e4c6d330d07b2a1b86c4095'),
 ('layout-facts.json','staging/navigation-native-L3-width-policy-static-v1/candidate-layout-and-CPU-facts.json',23299,'3305e1aa1019c1920fee5e8993936d21aa0fe0ebb79d745a624ae900978868e9'),
 ('v3-sealed-files.json','staging/navigation-country-native-lane-candidate-v3/sealed-files.json',4002,'dfc47744887137f944d710dffeb5ea6f6821c24eb8abbeb522cb406576754335'),
 ('v5-L6-receipt.json','staging/navigation-v3-reachable-suffix-compaction-dependency-preflight-v5/actual-stream-read-receipts.json',8480,'9ea624a4fa74107faa3b9ac2ff04ab94b1b6bcf8214301689f9213e35d913298'),
 ('L5-reuse-sealed-files.json','staging/navigation-v3-exclusive-stock-L5-reuse-feasibility-v1/sealed-files.json',5947,'3470bc9131486b71a3e661c95d9a85399c6e44c7aef72bc7f475d2b4a125ceba'),
 ('L5-reuse-summary.json','staging/navigation-v3-exclusive-stock-L5-reuse-feasibility-v1/scope-summary.json',2729,'3b68757d856d0efbd9cc1d3cd7ad33ba80c92a438cd2a969057690c466680d4a'),
]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def main():
    out=HERE/'captured-inputs';out.mkdir(exist_ok=False)
    total=0;rows=[]
    def read(label,path,size,digest,pin=None):
        nonlocal total
        assert path.startswith('staging/') and Path(path).suffix in {'.json','.py'}
        p=ROOT/path;b=p.stat();assert stat.S_ISREG(b.st_mode)
        assert b.st_size==size and total+size<=LIMIT
        if pin:
            assert fp(b)==pin['stat_at_seal']
            assert stat.S_IMODE(b.st_mode)==int(pin['mode'],8)
        with p.open('rb') as f:raw=f.read(size+1)
        a=p.stat();total+=len(raw)
        assert len(raw)==size and fp(a)==fp(b) and sha(raw)==digest
        (out/label).write_bytes(raw)
        rows.append(dict(path=path,bytes=size,sha256=digest,
            stat_before=fp(b),stat_after=fp(a),mode=format(stat.S_IMODE(a.st_mode),'04o')))
        return json.loads(raw) if path.endswith('.json') else raw
    for label,path,size,digest in FILES:read(label,path,size,digest)
    l5=json.loads((out/'L5-reuse-sealed-files.json').read_text())
    row=next(r for r in l5['files'] if r['path'].endswith('/capacity-arithmetic.json'))
    read('L5-reuse-capacity.json',row['path'],row['bytes'],row['sha256'],row)
    for r in rows:assert fp((ROOT/r['path']).stat())==r['stat_after']
    value=dict(external_artifact_bytes=total,limit=LIMIT,reads=rows,
        all_pins_passed=True,all_handles_closed=True,IMG_MAIN_PBF_CPU_guest_audio_device=0)
    (HERE/'input-read-receipts.json').write_text(json.dumps(value,indent=2)+'\n')
    facts=json.loads((out/'layout-facts.json').read_text())
    print(json.dumps(dict(files=len(rows),bytes=total,all_pins_passed=True,
                          profile_names=list(facts['profiles']),IMG_reads=0)))

if __name__=='__main__':main()
