#!/usr/bin/env python3
"""New country bindings/intermediate state/multirange rollback checks only.

Previously closed 35 transaction and 61 USB controls are not replayed. Small
filesystem fixtures stay in a private temporary directory; there is no fake
device CLI and no physical disk access here.
"""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT/'staging/navigation-country-address-package-v1'
sys.path.insert(0, str(BASE))
import install_native_house_supplement as install


def sha(raw): return hashlib.sha256(raw).hexdigest()


def need(ok, message):
    if not ok: raise AssertionError(message)


def helpers():
    path = ROOT/'staging/navigation-taichung-address-package-v1/validation/test_new_transactions.py'
    tree = ast.parse(path.read_text())
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ('fat', 'image')]
    namespace = dict(struct=struct, NAMES=['00004171.MD2','00004171.MDR','00004171.SRT',
        'I053061A.GMP','I053061A.SRT','MAPSOURC.MPS'])
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace['image'], dict(path=str(path.relative_to(ROOT)), sha256=sha(path.read_bytes()),
        only_AST_selected_fixture_helpers_executed=['fat','image'], historical_main_or_case_executed=False)


def fixture(image):
    header = b'OLD-HEADER' * 20; prefix = b'UNKNOWN-PREFIX' * 50
    levels = {6:b'L6-ORIGINAL\x00'*700, 5:b'L5-ORIGINAL\x00'*950, 4:b'L4-ORIGINAL\x00'*1300}
    old3 = b'OLD-L3' * 99; new3 = b'NEW-L3-WIDTH23' * 57
    suffix = b'OLD-L2-L1' * 40; directory = b'OLD-DIR' * 20
    parts = [header,prefix,levels[6],levels[5],levels[4],old3,suffix,directory]
    original, old_components, tails, old_prefix = image(b''.join(parts))
    previous_nine = bytearray(original)
    at = old_components['00004171.MDR']['blocks'][0]*4096+500
    previous_nine[at:at+4] = b'NINE'
    intermediate, _, _, _ = image(b''.join(parts)+b'TAICHUNG-INTERMEDIATE' * 400)
    new_parts = [b'NEW-HEADER'*20,prefix,levels[6],b'NEW6'*800,levels[5],b'NEW5'*1100,
        levels[4],b'NEW4'*1900,new3,suffix,b'NEW-DIR'*20]
    candidate, new_components, _, _ = image(b''.join(new_parts))
    offset=0; positions=[]
    for part in new_parts: positions.append(offset);offset+=len(part)
    ranges=[dict(length=len(header),original_hex=header.hex()),dict(length=len(prefix),candidate_offset=positions[1]),
        dict(length=len(levels[6]),candidate_offset=positions[2]),dict(length=len(levels[5]),candidate_offset=positions[4]),
        dict(length=len(levels[4]),candidate_offset=positions[6]),dict(length=len(old3),original_hex=old3.hex()),
        dict(length=len(suffix),candidate_offset=positions[9]),dict(length=len(directory),original_hex=directory.hex())]
    recipe=dict(schema='garmin-native-layout-restore/v1',original_bytes=len(original),original_sha256=sha(original),
        candidate_bytes=len(candidate),candidate_sha256=sha(candidate),original_metadata_bytes=len(old_prefix),
        original_prefix_hex=old_prefix.hex(),original_components=old_components,candidate_components=new_components,
        MDR_ranges=ranges,original_tail_hex=tails,original_unused_blocks_hex={})
    xml=b'<Device xmlns="urn:garmin-private-country-test"><Model><PartNumber>006-B1352-00</PartNumber><SoftwareVersion>800</SoftwareVersion></Model><Id>country-private-fixture</Id></Device>'
    manifest=dict(device=dict(part_number='006-B1352-00',software_version='800',unit_id_sha256=install.support.private_hash('country-private-fixture')),
        target=dict(bytes=len(candidate),candidate_sha256=sha(candidate),original_bytes=len(original),original_sha256=sha(original),
            accepted_predecessors=[dict(state='original',bytes=len(original),sha256=sha(original)),
                dict(state='previous_verified_nine',bytes=len(previous_nine),sha256=sha(previous_nine)),
                dict(state='previous_Taichung_candidate',bytes=len(intermediate),sha256=sha(intermediate))]),
        preserved_stock_files=[dict(device_path='.System/protected.bin',bytes=9,sha256=sha(b'PROTECTED'))],
        required_files=[])
    need(len(original)<len(intermediate)<len(candidate),'Three genuinely different physical image sizes')
    return dict(original=original,previous_verified_nine=bytes(previous_nine),previous_Taichung_candidate=intermediate,
        candidate=candidate,recipe=recipe,manifest=manifest,xml=xml)


def main():
    output = BASE/'validation/country-binding-results.json'
    need(not output.exists(),'New binding scope results only')
    image, dependency = helpers(); f=fixture(image); results=[]
    def record(name, **extra): results.append(dict(name=name,passed=True,**extra))
    # Production manifest pins and the actual complete multilevel rollback are
    # checked once here; this is a new binding, not an old suite rerun.
    manifest, source, recipe, manifest_sha = install.load_manifest(BASE)
    need(manifest['new_houses']==111608 and len(manifest['target']['accepted_predecessors'])==3,'Actual country manifest scope')
    need(len(recipe['MDR_ranges'])==8,'Actual recipe has separate old table ranges')
    record('production-country-manifest-candidate-and-eight-range-restore-binding',physical_device_IO=False,
        manifest_sha256=manifest_sha,candidate_bytes=manifest['target']['bytes'])
    with tempfile.TemporaryDirectory(prefix='country-binding-',dir=BASE/'validation') as temp:
        root=Path(temp); (root/'.System').mkdir();(root/'Garmin').mkdir()
        target=root/install.TARGET; source=root/'country-fixture.img'
        source.write_bytes(f['candidate']); (root/'Garmin/GarminDevice.xml').write_bytes(f['xml'])
        (root/'.System/protected.bin').write_bytes(b'PROTECTED')
        install.validate_recipe(f['recipe'],source,f['manifest']['target'])
        record('new-three-table-separated-multirange-recipe-exact-original',actual_filesystem=True,synthetic_images=True)
        for state in ('original','previous_verified_nine','previous_Taichung_candidate','candidate'):
            target.write_bytes(f[state]); before=target.read_bytes(); inode=target.stat().st_ino
            _, result=install.device_preflight(root,f['manifest'],'preflight')
            need(result['image_state']==state and target.read_bytes()==before and target.stat().st_ino==inode,'Readonly state accurately recognized')
            record('new-four-state-preflight-'+state,actual_filesystem=True,synthetic_images=True)
        target.write_bytes(f['previous_Taichung_candidate'])
        os.utime(target,ns=(1650000000000000000,1650000000000000000));mtime=target.stat().st_mtime_ns
        result=install.transaction(root,f['manifest'],source,f['recipe'],'install')
        need(result['committed'] and result['readback_verified'] and result['previous_image_state']=='previous_Taichung_candidate','Intermediate state really upgraded')
        need(target.read_bytes()==f['candidate'] and target.stat().st_mtime_ns==mtime,'Country exact destination/timestamp')
        record('Taichung-intermediate-to-country-size-atomic-upgrade',actual_filesystem=True,synthetic_images=True)
        result=install.transaction(root,f['manifest'],source,f['recipe'],'rollback')
        need(result['committed'] and result['readback_verified'] and target.read_bytes()==f['original'],'Exact stock rollback across separate old tables')
        need(target.stat().st_size==len(f['original']) and target.stat().st_mtime_ns==mtime,'No country appended tail survives rollback')
        record('country-separated-three-table-rollback-no-surviving-tail',actual_filesystem=True,synthetic_images=True)
        for mode in ('install','rollback'):
            recovery=root/install.TAICHUNG_PARTIAL; recovery.write_bytes(b'PREEXISTING-RECOVERY')
            before=target.read_bytes(); inode=target.stat().st_ino
            try: install.transaction(root,f['manifest'],source,f['recipe'],mode)
            except install.Refusal: pass
            else: raise AssertionError('Old Taichung recovery was ignored')
            need(target.read_bytes()==before and target.stat().st_ino==inode and recovery.read_bytes()==b'PREEXISTING-RECOVERY','Early recovery refusal modifies neither file')
            recovery.unlink();record('country-refuses-old-Taichung-recovery-'+mode,actual_filesystem=True,synthetic_images=True)
        bad=copy.deepcopy(f['recipe']);bad['MDR_ranges'][3]['candidate_offset']=bad['MDR_ranges'][2]['candidate_offset']
        try:install.validate_recipe(bad,source,f['manifest']['target'])
        except install.Refusal:pass
        else:raise AssertionError('Wrong distinct table range accepted')
        record('country-refuses-wrong-distinct-table-reconstruction-source',actual_filesystem=True,synthetic_images=True)
        target.write_bytes(f['previous_Taichung_candidate'][:-1]+b'!')
        before=target.read_bytes()
        try:install.transaction(root,f['manifest'],source,f['recipe'],'install')
        except install.Refusal:pass
        else:raise AssertionError('Unknown intermediate content accepted')
        need(target.read_bytes()==before,'Unknown intermediate retained')
        record('country-refuses-same-size-unknown-intermediate-content',actual_filesystem=True,synthetic_images=True)
        need((root/'.System/protected.bin').read_bytes()==b'PROTECTED','Protected files unchanged')
        need(not (root/install.PARTIAL).exists() and not (root/install.OLD_PARTIAL).exists(),'No transaction leftovers')
    proof=dict(all_assigned_checks_passed=True,controls_passed=len(results),results=results,
        helper_source=dependency,old_35_transaction_suite_replayed=False,old_61_USB_suite_replayed=False,
        inherited_transaction_algorithm_evidence='staging/navigation-taichung-address-package-v1/validation/new-transaction-results.json',
        binding_provenance='staging/navigation-country-address-package-v1/validation/binding-preparation-proof.json',
        physical_device_IO=False,complete_unit_installation_test=False,
        limits=['New manifest/recipe/accepted-intermediate/recovery guards only; previously closed algorithm controls referenced.',
            'Filesystem transactions use explicitly small synthetic images; no virtual-device CLI or USB mutation.'])
    with output.open('x') as stream:
        json.dump(proof,stream,ensure_ascii=False,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    output.chmod(0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True,controls_passed=len(results),physical_device_IO=False)))


if __name__=='__main__':main()
