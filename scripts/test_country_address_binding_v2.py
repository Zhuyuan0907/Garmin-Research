#!/usr/bin/env python3
"""New v2 identities and prior-country-state transaction controls only."""
import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'staging/navigation-country-address-package-v2'
sys.path.insert(0,str(BASE))
import install_native_house_supplement as install

def sha(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,message):
    if not ok:raise AssertionError(message)

def fixture():
    paths=[ROOT/'staging/navigation-taichung-address-package-v1/validation/test_new_transactions.py',
           ROOT/'scripts/test_country_address_binding_v1.py']
    namespace=dict(struct=struct,NAMES=['00004171.MD2','00004171.MDR','00004171.SRT',
      'I053061A.GMP','I053061A.SRT','MAPSOURC.MPS'],install=install,sha=sha,need=need)
    reused=[]
    for path,names in zip(paths,[{'fat','image'},{'fixture'}]):
        raw=path.read_bytes();tree=ast.parse(raw)
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
        need({n.name for n in nodes}==names,'Only selected shared fixture functions')
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),namespace)
        reused.append(dict(path=str(path.relative_to(ROOT)),sha256=sha(raw),
                           only_AST_fixture_functions=sorted(names),historical_main_or_cases_executed=False))
    f=namespace['fixture'](namespace['image'])
    prior=f['candidate']
    with io.BytesIO(prior) as stream:
        old_layout=install.restore.layout(stream,len(prior))
        mdr=install.restore.logical_read(stream,old_layout['components']['00004171.MDR'],0,
                  old_layout['components']['00004171.MDR']['size'])
    candidate,new_components,_,_=namespace['image'](mdr+b'V2-NEW-SIGNIFICANT-APPEND'*500)
    need(len(candidate)>len(prior),'V2 fixture genuinely larger than prior country fixture')
    f['previous_country_v1_candidate']=prior;f['candidate']=candidate
    f['manifest']['target']['bytes']=len(candidate)
    f['manifest']['target']['candidate_sha256']=sha(candidate)
    f['manifest']['target']['accepted_predecessors'].append(dict(state='previous_country_v1_candidate',
      bytes=len(prior),sha256=sha(prior)))
    f['old_recipe']=copy.deepcopy(f['recipe'])
    f['recipe']['candidate_bytes']=len(candidate);f['recipe']['candidate_sha256']=sha(candidate)
    f['recipe']['candidate_components']=new_components
    return f,reused

def main():
    output=BASE/'validation/country-v2-binding-results.json'
    need(not output.exists(),'One distinct terminal binding proof')
    m,source,recipe,manifest_sha=install.load_manifest(BASE)
    need(m['new_houses']==130637 and len(m['target']['accepted_predecessors'])==4,'Actual v2 scope/predecessors')
    need(len(recipe['MDR_ranges'])==8,'Actual new rollback separates L6/L5/L4')
    results=[]
    def record(name,**extra):results.append(dict(name=name,passed=True,**extra))
    record('production-v2-manifest-candidate-eight-range-restore-binding',manifest_sha256=manifest_sha,
      candidate_bytes=m['target']['bytes'],physical_device_IO=False)
    f,reused=fixture()
    with tempfile.TemporaryDirectory(prefix='country-v2-binding-',dir=BASE/'validation') as temp:
        root=Path(temp);(root/'.System').mkdir();(root/'Garmin').mkdir()
        target=root/install.TARGET;source=root/'new-v2-source.img'
        source.write_bytes(f['candidate']);target.write_bytes(f['previous_country_v1_candidate'])
        (root/'Garmin/GarminDevice.xml').write_bytes(f['xml'])
        (root/'.System/protected.bin').write_bytes(b'PROTECTED')
        inode=target.stat().st_ino;before=target.read_bytes()
        _,preflight=install.device_preflight(root,f['manifest'],'preflight')
        need(preflight['image_state']=='previous_country_v1_candidate' and target.read_bytes()==before
             and target.stat().st_ino==inode,'Prior country v1 correctly recognized without mutation')
        record('v2-readonly-prior-country-v1-state',synthetic_filesystem=True)
        os.utime(target,ns=(1650000000000000000,1650000000000000000));stamp=target.stat().st_mtime_ns
        result=install.transaction(root,f['manifest'],source,f['recipe'],'install')
        need(result['committed'] and result['readback_verified'] and
             result['previous_image_state']=='previous_country_v1_candidate','Actual prior-to-v2 upgrade')
        need(target.read_bytes()==f['candidate'] and target.stat().st_mtime_ns==stamp,'Exact v2 destination')
        record('prior-country-v1-to-v2-atomic-upgrade',synthetic_filesystem=True)
        inode=target.stat().st_ino
        result=install.transaction(root,f['manifest'],source,f['recipe'],'install')
        need(not result['committed'] and target.stat().st_ino==inode and target.read_bytes()==f['candidate'],
             'Already-v2 state avoids replacing destination')
        record('v2-binding-idempotent-already-current-state',synthetic_filesystem=True)
        result=install.transaction(root,f['manifest'],source,f['recipe'],'rollback')
        need(result['committed'] and result['readback_verified'] and target.read_bytes()==f['original'],
             'V2 rollback reconstructs exact stock')
        need(target.stat().st_size==len(f['original']) and target.stat().st_mtime_ns==stamp,'No v2 appended tail')
        record('v2-binding-exact-smaller-stock-rollback',synthetic_filesystem=True)
        target.write_bytes(f['previous_country_v1_candidate'][:-1]+b'!');before=target.read_bytes()
        try:install.transaction(root,f['manifest'],source,f['recipe'],'install')
        except install.Refusal:pass
        else:raise AssertionError('Altered previous country v1 was accepted')
        need(target.read_bytes()==before,'Unknown prior country content untouched')
        record('v2-refuses-same-size-unknown-prior-country-content',synthetic_filesystem=True)
        try:install.validate_recipe(f['old_recipe'],source,f['manifest']['target'])
        except install.Refusal:pass
        else:raise AssertionError('Prior country recipe accepted for v2 candidate')
        record('v2-refuses-prior-country-recipe-identity',synthetic_filesystem=True)
        need((root/'.System/protected.bin').read_bytes()==b'PROTECTED','Protected files unchanged')
        need(not (root/install.PARTIAL).exists(),'No owned transaction temporary remains')
    need(len(results)==7,'Seven new binding controls only')
    proof=dict(all_assigned_checks_passed=True,controls_passed=len(results),results=results,
      reused_fixture_helpers=reused,physical_device_IO=False,complete_unit_installation_test=False,
      old_35_transaction_suite_replayed=False,old_61_USB_suite_replayed=False,
      old_12_country_v1_binding_suite_replayed=False,
      inherited_transaction_algorithm_evidence='staging/navigation-taichung-address-package-v1/validation/new-transaction-results.json',
      binding_provenance='staging/navigation-country-address-package-v2/validation/binding-preparation-proof.json',
      limits=['Only changed v2 pins and exact prior-country predecessor/new-size identity were exercised.',
              'Fixture functions reused by AST; old main/control cases were not executed.',
              'Actual candidate manifest and rollback verified; transactions used small synthetic filesystem images.'])
    with output.open('x') as stream:
        json.dump(proof,stream,ensure_ascii=False,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    output.chmod(0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True,controls_passed=7,physical_device_IO=False)))

if __name__=='__main__':main()
