#!/usr/bin/env python3
"""Small-source activation only. No IMG lookup/stat/link or recipe decoding."""
import ast
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
PRE=ROOT/'staging/navigation-AP-coherent8K-installer-integration-preparation-v1'
SHA=lambda b:hashlib.sha256(b).hexdigest()
read_receipts=[]
def read(path,pin=None):
    s=path.lstat();before=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]
    if s.st_size>65536:raise RuntimeError('Small source size cap')
    raw=path.read_bytes();after=path.lstat()
    final=[after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_nlink]
    if before!=final or (pin and SHA(raw)!=pin):raise RuntimeError('Source pin changed')
    read_receipts.append({'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':SHA(raw),'stat':final});return raw
sealraw=read(PRE/'sealed-files.json','dc59af5ef52cee72d7a7b936f276e895ceaf28c280428beef73b86b39a125008')
sealed={r['path']:r for r in json.loads(sealraw)['files']}
def previous(name):
    return read(PRE/name,sealed[str((PRE/name).relative_to(ROOT))]['sha256'])
oldsource=previous('install_native_house_supplement.py')
oldmanifest=previous('manifest.json');m=json.loads(oldmanifest)
oldproof=previous('proof.json');oldtests=previous('host-control-proof.json')
if not json.loads(oldtests)['all_assigned_checks_passed'] or json.loads(oldtests)['methods']!=9:
    raise RuntimeError('Closed9-control evidence')
newraw={}
def write(name,b):
    p=HERE/name;p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(b)
    newraw[name]=b;return {'bytes':len(b),'sha256':SHA(b)}
def encoded(v):return (json.dumps(v,ensure_ascii=False,indent=2)+'\n').encode()
names=['device_support.py','native_8k_stock_restore.py','coherent_header_overlay.py','native_coherent8k_rollback.py',
       'coherent-control-restore-binding.json','validation/actual-coherent8K-stock-verification.json',
       'validation/actual-stock-verification-source-seal.json']
for name in names:write(name,previous(name))
inventory_source=read(HERE/'coherent_bundle_inventory.py')
newraw['coherent_bundle_inventory.py']=inventory_source
helpers=dict(m['portable_helpers']);helpers['coherent_bundle_inventory.py']={'bytes':len(inventory_source),'sha256':SHA(inventory_source)}
inputs={name:{**row,'role':'portable_helper'} for name,row in helpers.items()}
inputs['coherent-control-restore-binding.json']={**m['rollback']['coherent_control_binding'], 'role':'coherent_binding'}
inputs['coherent-control-restore-binding.json']={k:v for k,v in inputs['coherent-control-restore-binding.json'].items()
                                               if k in ('bytes','sha256','role')}
for name,role in [('validation/actual-coherent8K-stock-verification.json','actual_stock_proof'),
                  ('validation/actual-stock-verification-source-seal.json','actual_source_seal')]:
    inputs[name]={'bytes':len(newraw[name]),'sha256':SHA(newraw[name]),'role':role}
for key,role in [('stock_recipe','stock_recipe'),('virtual_old_v3_binding','virtual_old_v3_binding')]:
    row=m['rollback'][key];inputs[row['bundle_path']]={k:row[k] for k in ('bytes','sha256')};inputs[row['bundle_path']]['role']=role
inputs['roadmap/Taiwan_OSM_SearchRepair_v2.img']={'bytes':131829760,
      'sha256':'664c46c99697b61ba383b5571b0a49356336746c9bbf3f94403aae583787f117','role':'road'}
inputs[m['target']['bundle_path']]={'bytes':m['target']['bytes'],'sha256':m['target']['candidate_sha256'],'role':'candidate'}
m['schema']='garmin-AP-coherent8K-experimental-map-test/v1'
m.pop('integration_preparation_only');m.pop('integration_status')
m['allowed_operation']='controlled_physical_test';m['experimental_map_test']=True
m['scope']='experimental 8K header-end-mirror對照；188870門牌body保留，checksum／renderer／實機接受未知；非修復完成或全台完整版'
m['portable_helpers']=helpers;m['bundle_input_inventory']=inputs
m['entrypoint_source_binding']={'bundle_path':'entrypoint-source-binding.json',
                               'schema':'garmin-AP-coherent8K-activated-entrypoint-source-binding/v1'}
m['installer_entrypoint']='install_native_house_supplement.py'
m['deployment_download_archive_completed']=False;m['installable']=False
m['limits']=[v for v in m['limits'] if 'preparation gate' not in v and '未複製於本scope' not in v]
m['limits'].extend(['此入口綁定NEW experimental manifest/source與完整bundle inputs；缺檔、舊preparation manifest或任一hash不符拒絕。',
                   'entrypoint完整sourceSHA由detached source-binding及外部sealed packet inventory固定，避免source/manifest wholeSHA自循環；recovery wrapper須重新綁本NEWsource。',
                   '目前healthy AP是country-v2；factory stock rollback會移除其130637補充門牌，working-v2 recovery為另一個NEW雙步rebind。'])
manifestraw=encoded(m);manifestpin=write('manifest.json',manifestraw)
text=oldsource.decode();tree=ast.parse(text);rows=text.splitlines(keepends=True)
constants={'SCHEMA':m['schema'],'MANIFEST_BYTES':manifestpin['bytes'],'MANIFEST_SHA':manifestpin['sha256'],
           'EXPECTED_HELPERS':helpers}
for n in sorted([n for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and
                 isinstance(n.targets[0],ast.Name) and n.targets[0].id in constants],key=lambda n:n.lineno,reverse=True):
    rows[n.lineno-1:n.end_lineno]=[n.targets[0].id+' = '+repr(constants[n.targets[0].id])+'\n']
text=''.join(rows).replace('import coherent_header_overlay as overlay\n',
                          'import coherent_header_overlay as overlay\nimport coherent_bundle_inventory as inventory\n')
text=text.replace('\n\ndef validate_recipe(',
                  '\nEXPECTED_INPUT_INVENTORY = '+repr(inputs)+'\nSOURCE_BINDING = \'entrypoint-source-binding.json\'\n\n\ndef validate_recipe(',1)
gate="    need(m.get('integration_preparation_only') is False and m.get('integration_status') == 'independently_reviewed_test_control', 'Preparation-only coherent control; candidate/device work is disabled')\n"
if text.count(gate)!=1:raise RuntimeError('Exactly one old preparation gate expected')
text=text.replace(gate,'')
marker="    need(m.get('portable_helpers') == EXPECTED_HELPERS, 'Unexpected portable helper identities')\n"
replacement=marker+'''    need(m.get('installer_entrypoint') == 'install_native_house_supplement.py'
         and Path(__file__).resolve() == safe_path(bundle, 'install_native_house_supplement.py').resolve(), 'Activated entrypoint outside exact bundle')
    need(m.get('entrypoint_source_binding') == {'bundle_path': SOURCE_BINDING, 'schema': 'garmin-AP-coherent8K-activated-entrypoint-source-binding/v1'}, 'Missing detached activated source binding')
    source_binding = read_json(safe_path(bundle, SOURCE_BINDING), 65536)
    need(source_binding.get('schema') == 'garmin-AP-coherent8K-activated-entrypoint-source-binding/v1'
         and source_binding.get('manifest') == {'bundle_path': 'manifest.json', 'bytes': MANIFEST_BYTES, 'sha256': MANIFEST_SHA}
         and source_binding.get('bundle_input_inventory') == EXPECTED_INPUT_INVENTORY,
         'Activated source/manifest/input-inventory binding mismatch')
    entry = source_binding.get('entrypoint', {})
    need(entry.get('bundle_path') == 'install_native_house_supplement.py' and integer(entry.get('bytes'))
         and entry['bytes'] > 0 and valid_sha(entry.get('sha256')), 'Invalid exact activated source binding')
    verify_file(safe_path(bundle, entry['bundle_path']), entry['bytes'], entry['sha256'], 'Exact externally sealed activated entrypoint source')
    need(Path(inventory.__file__).resolve() == safe_path(bundle, 'coherent_bundle_inventory.py').resolve(), 'Inventory module outside exact bundle')
    row = EXPECTED_HELPERS['coherent_bundle_inventory.py']
    verify_file(safe_path(bundle, 'coherent_bundle_inventory.py'), row['bytes'], row['sha256'], 'Pinned activated inventory verifier')
    try:
        inventory.verify_catalog(bundle, m.get('bundle_input_inventory'), EXPECTED_INPUT_INVENTORY, verify_file, safe_path)
    except (ValueError, KeyError, TypeError, OSError):
        raise Refusal('Incomplete or mismatched activated test packet input inventory') from None
'''
if text.count(marker)!=1:raise RuntimeError('One portable helper inventory guard')
text=text.replace(marker,replacement)
oldnodes={n.name:n for n in ast.parse(oldsource).body if isinstance(n,ast.FunctionDef)}
newnodes={n.name:n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
same={name:ast.dump(n,include_attributes=False)==ast.dump(newnodes[name],include_attributes=False)
      for name,n in oldnodes.items() if name!='load_manifest'}
if set(oldnodes)!=set(newnodes) or not all(same.values()):raise RuntimeError('Only new manifest/source inventory loader may change')
sourcepin=write('install_native_house_supplement.py',text.encode())
sourcebinding={'schema':'garmin-AP-coherent8K-activated-entrypoint-source-binding/v1',
               'entrypoint':{'bundle_path':'install_native_house_supplement.py',**sourcepin},
               'manifest':{'bundle_path':'manifest.json',**manifestpin},'bundle_input_inventory':inputs,
               'source_trust':'Exact detached source and manifest SHA are anchored by the external sealed test packet and recovery-wrapper rebind, not a self-referential source/manifest wholehash.',
               'actual_stock_proof_sha256':'e44ded4324705fc9482b60898edda790e6155a646a5d9e5d7b4a139e5f41aa8e',
               'old_preparation_seal_sha256':'dc59af5ef52cee72d7a7b936f276e895ceaf28c280428beef73b86b39a125008',
               'experimental_map_test':True,'UI_renderer_checksum_policy_verified':False,'installable':False}
bindingpin=write('entrypoint-source-binding.json',encoded(sourcebinding))
pack=[]
for name,row in inputs.items():
    if name in newraw:source=str((HERE/name).relative_to(ROOT))
    elif row['role']=='stock_recipe':source='staging/navigation-country-address-package-v3/restore-layout.json.gz'
    elif row['role']=='virtual_old_v3_binding':source='staging/navigation-country-address-package-v3/actual-stock-restore-binding.json'
    elif row['role']=='road':source='staging/navigation-country-address-package-v3/roadmap/Taiwan_OSM_SearchRepair_v2.img'
    else:source='staging/navigation-AP-coherent8k-actual-materialization-rollback-v1/coherent8K-end-mirror.img.disabled'
    pack.append({'bundle_path':name,'source_path':source,**row})
for name,pin in [('install_native_house_supplement.py',sourcepin),('manifest.json',manifestpin),('entrypoint-source-binding.json',bindingpin)]:
    pack.append({'bundle_path':name,'source_path':str((HERE/name).relative_to(ROOT)),**pin,'role':'source_binding' if name.endswith('.json') else 'entrypoint'})
write('PACKAGING.json',encoded({'schema':'coherent8K-activated-test-packet-copy-plan/v1','files':pack,
                             'actual_packet_assembled':False,'no_IMG_or_recipe_read_this_scope':True,
                             'hardlink_stat_change_requires_fresh_packet_validation':True}))
for name in ('candidate','roadmap'):(HERE/name).mkdir(exist_ok=True)
write('source-build-proof.json',encoded({'schema':'coherent8K-activated-entrypoint-source-build/v1',
      'all_assigned_checks_passed':True,'inputs':read_receipts,'raw_inputs_read':sum(r['bytes'] for r in read_receipts),
      'recipe_bytes_read':0,'recipe_decoded_bytes':0,'real_IMG_open_stat_read_link_chmod_write':False,
      'same_function_AST':same,'only_changed_function_from_preparation':'load_manifest',
      'entrypoint':sourcepin,'manifest':manifestpin,'source_binding':bindingpin,'bundle_input_inventory':inputs,
      'runtime_input_count':len(inputs),'detached_runtime_source_manifest_files':3,'actual_packet_assembled':False,
      'external_whole_source_and_manifest_pins_required_before_recovery_rebind':True,
      'main_CLI_unchanged':['--bundle','--install','--rollback'],'default_mode':'preflight','device_IO':False,'installable':False}))
print(json.dumps({'all_assigned_checks_passed':True,'entrypoint':sourcepin,'manifest':manifestpin,'source_binding':bindingpin,
                  'input_bytes_read':sum(r['bytes'] for r in read_receipts),'runtime_input_count':len(inputs),
                  'only_changed_function':'load_manifest','all_other_AST_same':all(same.values()),
                  'IMG_or_recipe_read':False},indent=2))
