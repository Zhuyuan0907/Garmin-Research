#!/usr/bin/env python3
"""Bind the country+Kaohsiung candidate using the closed transaction algorithm."""
import ast
import copy
import hashlib
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT/'staging/navigation-country-address-package-v1'
BASE = ROOT/'staging/navigation-country-address-package-v2'
CANDIDATE = ROOT/'staging/navigation-country-native-candidate-v2'
RESTORE = ROOT/'staging/navigation-country-layout-restore-v2'

def digest(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def write(path, value):
    raw=value if isinstance(value,bytes) else value.encode()
    with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    path.chmod(0o444)

def function(source,name):
    return next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name==name)

def main():
    assert not BASE.exists()
    previous_result=json.loads((OLD/'package-result.json').read_text())
    assert previous_result['all_passed'] and previous_result['new_houses']==111608
    inventory={r['path']:r for r in json.loads((OLD/'SHA256SUMS.json').read_text())}
    for name in ['manifest.json','install_native_house_supplement.py','device_support.py',
                 'native_address_layout_restore_v1.py']:
        assert (OLD/name).stat().st_size==inventory[name]['bytes']
        assert digest(OLD/name)==inventory[name]['sha256']
    old_source=(OLD/'install_native_house_supplement.py').read_text()
    old=json.loads((OLD/'manifest.json').read_text())
    proof=json.loads((CANDIDATE/'proof.json').read_text())
    rollback=json.loads((RESTORE/'proof.json').read_text())
    assert proof['all_assigned_checks_passed'] and rollback['all_assigned_checks_passed']
    assert proof['candidate_sha256']==rollback['candidate_sha256']
    assert proof['new_integer_house_records']==130637
    manifest=copy.deepcopy(old)
    manifest['schema']='garmin-native-existing-street-house-supplement/v2'
    manifest['scope']='跨縣市18,823條既有街道新增130,637筆整數門牌，含高雄37可核對區及四個原生無區層城市範圍；非全台完整更新'
    manifest['target']['bytes']=proof['candidate_bytes']
    manifest['target']['candidate_sha256']=proof['candidate_sha256']
    previous=dict(state='previous_country_v1_candidate',bytes=old['target']['bytes'],
                  sha256=old['target']['candidate_sha256'])
    manifest['target']['accepted_predecessors'].append(previous)
    manifest['rollback']['bytes']=rollback['recipe_bytes']
    manifest['rollback']['sha256']=rollback['recipe_sha256']
    manifest['new_houses']=130637
    manifest['updated_existing_streets']=18823
    manifest['new_houses_by_leaf_level']={'4':88094,'5':40470,'6':2073}
    manifest['omitted_new_quantized_city_edge_outliers']=1
    manifest['limits']=[
      '只新增精確匹配既有街道的整數門牌；新街道、完整巷弄、子號及矛盾資料尚未完成。',
      '高雄採37個完整區界各自核對，旗津仍排除；沒有推算完整高雄市界。',
      '原廠同名門牌的原座標／相對順序保留；不是所有2016地址都已刷新到2026。',
      '此候選尚未實機安裝／驗收，原CPU有限讀取不等完整搜尋UI或路線結果。',
      'Search v2道路圖需已在此機安裝，包內提供相同版本；不更新道路、韌體或原JAI。']
    raw=(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode()
    values=dict(SCHEMA=repr(manifest['schema']),CANDIDATE_BYTES=str(proof['candidate_bytes']),
      CANDIDATE_SHA=repr(proof['candidate_sha256']),MANIFEST_BYTES=str(len(raw)),
      MANIFEST_SHA=repr(hashlib.sha256(raw).hexdigest()),RECIPE_BYTES=str(rollback['recipe_bytes']),
      RECIPE_SHA=repr(rollback['recipe_sha256']))
    source=old_source
    for name,value in values.items():
        source,count=re.subn(r'^'+name+r' = .*$',lambda _:name+' = '+value,source,count=1,flags=re.M)
        assert count==1
    predecessor_block='EXPECTED_PREDECESSORS = '+repr(manifest['target']['accepted_predecessors'])
    source,count=re.subn(r'^EXPECTED_PREDECESSORS = \[.*?\n\]',lambda _:predecessor_block,
                        source,count=1,flags=re.M|re.S)
    assert count==1
    source=source.replace('candidate may upgrade the exact stock, nine-house or Taichung candidate states.',
      'candidate may upgrade the exact stock, nine-house, Taichung or country-v1 states.')
    for name in ['transaction','execute','device_preflight','image_state','validate_recipe','load_manifest']:
        assert ast.dump(function(source,name),include_attributes=False)==ast.dump(function(old_source,name),include_attributes=False)
    ast.parse(source)
    BASE.mkdir();(BASE/'candidate').mkdir();(BASE/'roadmap').mkdir();(BASE/'validation').mkdir()
    write(BASE/'manifest.json',raw);write(BASE/'install_native_house_supplement.py',source)
    for name in ['device_support.py','native_address_layout_restore_v1.py']:
        write(BASE/name,(OLD/name).read_bytes())
    write(BASE/'restore-layout.json.gz',(RESTORE/'restore-layout.json.gz').read_bytes())
    os.link(CANDIDATE/'gmapprom1.img',BASE/'candidate/gmapprom1.img')
    os.link(OLD/'roadmap/Taiwan_OSM_SearchRepair_v2.img',BASE/'roadmap/Taiwan_OSM_SearchRepair_v2.img')
    result=dict(all_assigned_checks_passed=True,manifest_bytes=len(raw),manifest_sha256=hashlib.sha256(raw).hexdigest(),
      old_installer_sha256=inventory['install_native_house_supplement.py']['sha256'],
      new_installer_sha256=hashlib.sha256(source.encode()).hexdigest(),
      six_transaction_USB_binding_function_ASTs_identical=True,shared_helpers_byte_identical=True,
      exact_previous_country_v1_state_added=True,old_partial_paths_preserved=True,
      new_candidate_sha256=proof['candidate_sha256'],candidate_bytes=proof['candidate_bytes'],
      new_binding_controls_pending=True,native_CPU_required_before_packaging=True,
      device_IO=False,zip_created=False,image_and_road_hardlinked=True)
    write(BASE/'validation/binding-preparation-proof.json',(json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode())
    print(json.dumps(dict(prepared=True,controls_pending=True,package_ready=False,device_IO=False)))

if __name__=='__main__':main()
