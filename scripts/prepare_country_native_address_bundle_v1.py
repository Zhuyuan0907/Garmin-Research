#!/usr/bin/env python3
"""Bind the country house candidate to a conservative portable transaction.

Local bundle preparation only; actual native/source/physical acceptance is
recorded separately. The package archive must wait for the new validations.
"""
import ast
import copy
import hashlib
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT/'staging/navigation-taichung-address-package-v1'
BASE = ROOT/'staging/navigation-country-address-package-v1'
CANDIDATE = ROOT/'staging/navigation-country-native-candidate-v1'
RESTORE = ROOT/'staging/navigation-country-layout-restore-v1'
OLD_INSTALL_SHA = '8f05a589310d277b60a2c0b1dddfacdc535cddc26894a6a45639b37cf3993121'


def write(path, data):
    if not isinstance(data, bytes): data = data.encode()
    with path.open('xb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    path.chmod(0o444)


def digest(path):
    with path.open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()


def function(source, name):
    return next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name==name)


def main():
    assert not BASE.exists()
    old_source = (OLD/'install_taichung_addresses.py').read_text()
    assert hashlib.sha256(old_source.encode()).hexdigest() == OLD_INSTALL_SHA
    proof = json.loads((CANDIDATE/'proof.json').read_text())
    rollback = json.loads((RESTORE/'proof.json').read_text())
    assert proof['all_assigned_checks_passed'] and rollback['all_assigned_checks_passed']
    assert proof['candidate_sha256'] == rollback['candidate_sha256']
    old = json.loads((OLD/'manifest.json').read_text())
    manifest = copy.deepcopy(old)
    manifest['schema'] = 'garmin-native-existing-street-house-supplement/v1'
    manifest['scope'] = '跨縣市15,679條既有街道新增111,608筆整數門牌；非全台完整更新'
    manifest['target']['bytes'] = proof['candidate_bytes']
    manifest['target']['candidate_sha256'] = proof['candidate_sha256']
    manifest['target']['accepted_predecessors'].append(dict(state='previous_Taichung_candidate',
        bytes=old['target']['bytes'], sha256=old['target']['candidate_sha256']))
    manifest['rollback']['bytes'] = rollback['recipe_bytes']
    manifest['rollback']['sha256'] = rollback['recipe_sha256']
    manifest['new_houses'] = 111608; manifest['updated_existing_streets'] = 15679
    manifest['new_houses_by_leaf_level'] = {'4':74455,'5':35183,'6':1970}
    manifest['candidate_native_and_source_validation_required_before_packaging'] = True
    manifest['limits'] = ['只新增既有精確匹配街道的整數門牌；新街道、完整巷弄、子號、行政區／座標矛盾未完成。',
        '高雄完整市界缺件，本批保留原資料；非所有2016地址已刷新至2026。',
        '此候選尚未實機安裝／驗收，原CPU有限讀取不等完整UI、搜尋或路線結果。',
        'Search v2道路圖需已在此機安裝；包中提供既有相同版本。']
    raw_manifest = (json.dumps(manifest, ensure_ascii=False, indent=2)+'\n').encode()
    values = dict(SCHEMA=repr(manifest['schema']), PARTIAL="TARGET + '.native-house-supplement.partial'",
        CANDIDATE_BYTES=str(proof['candidate_bytes']), CANDIDATE_SHA=repr(proof['candidate_sha256']),
        MANIFEST_BYTES=str(len(raw_manifest)), MANIFEST_SHA=repr(hashlib.sha256(raw_manifest).hexdigest()),
        RECIPE_BYTES=str(rollback['recipe_bytes']), RECIPE_SHA=repr(rollback['recipe_sha256']))
    source = old_source
    for name, value in values.items():
        source, count = re.subn(r'^'+name+r' = .*$', lambda _:name+' = '+value, source, count=1, flags=re.M)
        assert count==1
    old_predecessors = "    {'state': 'previous_verified_nine', 'bytes': ORIGINAL_BYTES, 'sha256': PREVIOUS_SHA},\n]"
    new_predecessors = old_predecessors[:-1] + "    {'state': 'previous_Taichung_candidate', 'bytes': 100945920, 'sha256': '3c03d0a09e24165f27b7ed275535552bfb3ea10defe0f492de6f51dfdaf9b00b'},\n]"
    assert source.count(old_predecessors)==1; source=source.replace(old_predecessors,new_predecessors)
    anchor = 'OLD_PARTIAL = support.PARTIAL\n'
    assert source.count(anchor)==1
    source=source.replace(anchor, anchor+"TAICHUNG_PARTIAL = TARGET + '.taichung-address.partial'\n")
    source=source.replace('seen = {TARGET.lower(), PARTIAL.lower(), OLD_PARTIAL.lower()}',
        'seen = {TARGET.lower(), PARTIAL.lower(), OLD_PARTIAL.lower(), TAICHUNG_PARTIAL.lower()}')
    source=source.replace('for partial in (PARTIAL, OLD_PARTIAL):', 'for partial in (PARTIAL, OLD_PARTIAL, TAICHUNG_PARTIAL):')
    source=source.replace('Taichung', 'country house supplement').replace('taichung', 'native house supplement')
    # The broad wording replacement must not affect paths/constants/identities.
    source=source.replace("TARGET + '.native house supplement-address.partial'", "TARGET + '.taichung-address.partial'")
    source=source.replace("'previous_country house supplement_candidate'", "'previous_Taichung_candidate'")
    source=source.replace('previous_country house supplement_candidate', 'previous_Taichung_candidate')
    source=source.replace('The larger country house supplement\ncandidate may upgrade stock or the previously verified nine-house candidate.',
        'The country house supplement\ncandidate may upgrade the exact stock, nine-house or Taichung candidate states.')
    # Compare the transaction's actual AST after normalizing error labels only.
    normalized=source.replace('country house supplement','Taichung')
    assert ast.dump(function(old_source,'transaction'),include_attributes=False)==ast.dump(function(normalized,'transaction'),include_attributes=False)
    assert ast.dump(function(old_source,'execute'),include_attributes=False)==ast.dump(function(normalized,'execute'),include_attributes=False)
    ast.parse(source)
    BASE.mkdir(); (BASE/'candidate').mkdir(); (BASE/'roadmap').mkdir(); (BASE/'validation').mkdir()
    write(BASE/'manifest.json', raw_manifest)
    write(BASE/'install_native_house_supplement.py', source)
    for name in ['device_support.py', 'native_address_layout_restore_v1.py']:
        write(BASE/name, (OLD/name).read_bytes())
    write(BASE/'restore-layout.json.gz', (RESTORE/'restore-layout.json.gz').read_bytes())
    os.link(CANDIDATE/'gmapprom1.img', BASE/'candidate/gmapprom1.img')
    os.link(OLD/'roadmap/Taiwan_OSM_SearchRepair_v2.img', BASE/'roadmap/Taiwan_OSM_SearchRepair_v2.img')
    write(BASE/'validation/binding-preparation-proof.json', (json.dumps(dict(all_assigned_checks_passed=True,
        manifest_bytes=len(raw_manifest), manifest_sha256=hashlib.sha256(raw_manifest).hexdigest(),
        candidate_bytes=proof['candidate_bytes'], candidate_sha256=proof['candidate_sha256'],
        old_installer_sha256=OLD_INSTALL_SHA, new_installer_sha256=hashlib.sha256(source.encode()).hexdigest(),
        support_helpers_byte_identical=True, layout_restore_helpers_byte_identical=True,
        transaction_and_USB_execute_AST_unchanged_except_error_wording=True,
        extra_accepted_state_exact_Taichung_image=True, old_Taichung_recovery_path_explicitly_refused=True,
        actual_new_binding_controls_pending=True, native_CPU_and_source_review_required_before_packaging=True,
        image_and_road_hardlinked=True, device_IO=False, zip_created=False), ensure_ascii=False, indent=2)+'\n').encode())
    print(json.dumps(dict(prepared=True, controls_pending=True, package_ready=False, device_IO=False)))


if __name__=='__main__': main()
