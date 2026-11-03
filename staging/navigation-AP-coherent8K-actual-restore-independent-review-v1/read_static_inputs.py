"""Bounded artifact/static AST capture, never imports or stats any IMG."""
from pathlib import Path
import ast,gzip,hashlib,json,stat
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
A='staging/navigation-AP-coherent8k-actual-materialization-rollback-v1/'
B='staging/navigation-AP-coherent8k-actual-stock-verification-v2/'
FILES=['scripts/verify_actual_coherent8k_map_restore_v1.py','scripts/verify_actual_coherent8k_stock_restore_v2.py',
 'staging/navigation-AP-coherent-control-rollback-binding-preflight-v1/eightk_inverse_header_overlay.py',
 'staging/navigation-country-address-package-v3/native_8k_stock_restore.py',B+'proof.json',B+'sealed-files.json',
 B+'actual-root-tool-receipts.json',B+'execution-preflight.json',A+'actual-materialization-receipt.json',
 A+'actual-control-output-descriptor.json',A+'failure.json',A+'failure-closure.json',
 A+'actual-root-tool-receipts.json',A+'execution-preflight.json',A+'failed-root-driver-source.py.gz']
DIRECT={FILES[0]:'8ca8d42acacfb4e5680495949639c380ca7df9992bb0b0785c969478aa169f70',
 FILES[1]:'cbbf5515ee0f69f0326198fc40aed69e4ae7d68a34101fb0d05e36c387b1048e',
 FILES[2]:'284b164a568edaca06707b572f0dd1f4bd2d96b913546adb56e7a99979480dbc',
 FILES[3]:'43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f',
 FILES[4]:'e44ded4324705fc9482b60898edda790e6155a646a5d9e5d7b4a139e5f41aa8e',
 FILES[5]:'0c6589d72116afc30cb575cc99b6cd366cedde48ae2875f70cbc5bf447ad6410'}
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def sha(b):return hashlib.sha256(b).hexdigest()
def put(n,o):(HERE/n).write_text(json.dumps(o,ensure_ascii=False,separators=(',',':'))+'\n')
def main():
    data={};receipts=[];total=20391 # Initial source/proof/seal display, already read.
    for name in FILES:
        p=ROOT/name;b=p.stat();assert stat.S_ISREG(b.st_mode) and total+b.st_size<=163840
        with p.open('rb') as f:raw=f.read(b.st_size+1)
        a=p.stat();total+=len(raw);assert fp(b)==fp(a) and len(raw)==b.st_size
        digest=sha(raw)
        if name in DIRECT:assert digest==DIRECT[name]
        data[name]=raw;receipts.append(dict(path=name,bytes=len(raw),sha256=digest,
            stat_before=fp(b),stat_after=fp(a),mode=format(stat.S_IMODE(a.st_mode),'04o')))
    seal=json.loads(data[B+'sealed-files.json']);pins={r['path']:r for r in seal['files']}
    for row in receipts:
        pin=pins.get(row['path'])
        if pin:
            assert row['sha256']==pin['sha256'] and row['bytes']==pin['bytes']
            assert int(row['mode'],8)==int(pin['mode'],8)
    assert sha(gzip.decompress(data[A+'failed-root-driver-source.py.gz']))==sha(data[FILES[0]])
    for row in receipts:assert fp((ROOT/row['path']).stat())==row['stat_after']
    put('input-read-receipts.json',dict(actual_small_artifact_bytes=total,cap=163840,
        initial_display_bytes=20391,initial_display_terminals=['76b507 EXIT0','62e365 EXIT0'],
        reread_three_displayed_artifacts_accounted=True,reads=receipts,all_handles_closed=True,
        no_IMG_open_stat_data_or_producer_execution=True))
    summaries=[]
    for name in FILES[:4]:
        source=data[name].decode();tree=ast.parse(source);lines=source.splitlines()
        defs=[n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.ClassDef))]
        rows=[]
        for n in defs:
            rows.append(dict(name=n.name,line=n.lineno,end=n.end_lineno,
                calls=sorted({ast.unparse(x.func) for x in ast.walk(n) if isinstance(x,ast.Call)})))
        summaries.append(dict(path=name,sha256=sha(data[name]),assert_count=sum(isinstance(n,ast.Assert) for n in ast.walk(tree)),definitions=rows))
        print('SOURCE '+name)
        if name==FILES[1]:print('Already displayed; AST reparsed, no import.')
        elif name==FILES[3]:
            for n in tree.body:
                if isinstance(n,(ast.FunctionDef,ast.ClassDef)):print('\n'.join(lines[n.lineno-1:n.end_lineno]))
        else:print(source)
    put('AST-summary.json',summaries)
    for name in FILES[8:14]+[FILES[6],FILES[7]]:
        print('JSON '+name+'\n'+json.dumps(json.loads(data[name]),ensure_ascii=False))
    put('captured-small-evidence.json',{name:json.loads(data[name]) for name in FILES[4:14]})
    print('TOTAL_ORIGINAL_ARTIFACT_BYTES '+str(total))
if __name__=='__main__':main()
