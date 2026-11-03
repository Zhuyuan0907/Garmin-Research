#!/usr/bin/env python3
"""Small preparation only: no IMG lookup, hardlinks or device operations."""
import ast
import hashlib
import json
from pathlib import Path
import sys
import types

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
OLD=ROOT/'staging/navigation-country-address-package-v3'
OVER=ROOT/'staging/navigation-AP-coherent-control-rollback-binding-preflight-v1/eightk_inverse_header_overlay.py'
VER=ROOT/'staging/navigation-AP-coherent8k-actual-stock-verification-v2'
SHA=lambda b:hashlib.sha256(b).hexdigest()
reads=[]
def pinned(path,pin):
    before=path.stat();b=path.read_bytes();after=path.stat()
    key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink)
    if key(before)!=key(after) or SHA(b)!=pin:raise RuntimeError('Pinned small source changed: '+str(path))
    reads.append({'path':str(path.relative_to(ROOT)),'bytes':len(b),'sha256':pin,'stat':list(key(after))});return b
overraw=pinned(OVER,'284b164a568edaca06707b572f0dd1f4bd2d96b913546adb56e7a99979480dbc')
overlay=types.ModuleType('closed_coherent_overlay_preparation');overlay.__file__=str(OVER);sys.modules[overlay.__name__]=overlay
exec(compile(overraw,str(OVER),'exec'),overlay.__dict__)
inputs=overlay.prepare_fixed_inputs();reads.extend(inputs.receipts)
manifestraw=pinned(OLD/'manifest.json','c0b6fd6b70af1a1c7a1d241e51f7649d61caa1abb551b73f4c419119ff5d64bc')
installerraw=pinned(OLD/'install_native_house_supplement.py','cefe766e9b1c0380a72e588e53da1fbc5fc1037a3510cbb507cb2a1526403374')
support=pinned(OLD/'device_support.py','8c3a74b620ad75a452421777b53c60285510c409df66cd10602648bf3604f411')
restore=pinned(OLD/'native_8k_stock_restore.py','43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f')
actual=pinned(VER/'proof.json','e44ded4324705fc9482b60898edda790e6155a646a5d9e5d7b4a139e5f41aa8e')
actualseal=pinned(VER/'sealed-files.json','0c6589d72116afc30cb575cc99b6cd366cedde48ae2875f70cbc5bf447ad6410')
actualproof=json.loads(actual)
if not (actualproof['all_assigned_checks_passed'] and actualproof['candidate_full_sha256']==overlay.COHERENT8_SHA and
        actualproof['computed_inverse_original_v3_sha256']==overlay.V3_SHA and
        actualproof['exact_stock_reconstruction_sha256']==overlay.STOCK_SHA and actualproof['exact_stock_bytes']==overlay.STOCK_BYTES and
        actualproof['source_unchanged'] and actualproof['all_handles_closed'] and actualproof['whole_pipeline_one_attempt'] is False):
    raise RuntimeError('Actual root closure/both-attempt evidence')
def encoded(value):return (json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
def write(relative,b):
    p=HERE/relative;p.parent.mkdir(exist_ok=True,parents=True)
    with p.open('xb') as f:f.write(b)
    return {'bytes':len(b),'sha256':SHA(b)}
control={'schema':'garmin-AP-coherent8K-inverse-overlay-stock-restore/v1','control':'eightK_end_mirror',
         'candidate':{'bytes':overlay.V3_BYTES,'sha256':overlay.COHERENT8_SHA,'block_bytes':8192},
         'virtual_old_v3':{'bytes':overlay.V3_BYTES,'sha256':overlay.V3_SHA,'binding_sha256':
                           '0884c9d705c40d84a84512c691ba124cef419e2cee6d432155e45cee6ed1dd89',
                           'binding_is_actual_coherent_metadata':False},
         'stock':{'bytes':overlay.STOCK_BYTES,'sha256':overlay.STOCK_SHA,'recipe_sha256':
                  '6e1381006e3f56a466c8cdd93134f418eab18ee592cbfd5e57f1a55c2950c0a7'},
         'inverse_header':{'window_bytes':512,'changed_offsets':[452],
                           'corrected_header_hex':inputs.spec.corrected_header.hex(),
                           'original_header_hex':inputs.spec.original_header.hex(),
                           'corrected_sha256':SHA(inputs.spec.corrected_header),'original_sha256':SHA(inputs.spec.original_header)},
         'actual_root_verification':{'bundle_proof_path':'validation/actual-coherent8K-stock-verification.json',
                                     'proof_sha256':SHA(actual),'source_seal_sha256':SHA(actualseal),
                                     'actual_tool_terminal':'835864','actual_exit_code':0,'candidate_read_bytes':249424497,
                                     'all_handles_closed':True,'fresh_full_actual_and_inverse_SHA_verified':True},
         'inherited_candidate_original_materialization_stat':actualproof['final_source_stat'],
         'materialization_stat_is_future_bundle_path_or_hardlink_stat':False,
         'first_failed_restore_attempt_preserved':{'tool_terminal':'ea061f','reason':'ReceiptSink missing extend',
                                                  'map_or_runtime_or_native_rejection':False,
                                                  'failure_closure_sha256':'f2a1fd1d787ebd723443074c650333864aacb72088e208b7f15ec4cb45d4746e'},
         'whole_pipeline_one_attempt':False,'checksum_policy_UI_or_renderer_rootcause_verified':False,'installable':False}
controlpin=write('coherent-control-restore-binding.json',encoded(control))
adapter=HERE/'native_coherent8k_rollback.py';template=adapter.read_bytes()
if template.count(b'__CONTROL_BINDING_SHA__')!=1:raise RuntimeError('Prepared adapter template required exactly once')
adapterraw=template.replace(b'__CONTROL_BINDING_SHA__',controlpin['sha256'].encode());adapter.write_bytes(adapterraw)
helpers={name:write(name,b) for name,b in [('device_support.py',support),('native_8k_stock_restore.py',restore),
                                         ('coherent_header_overlay.py',overraw)]}
helpers['native_coherent8k_rollback.py']={'bytes':len(adapterraw),'sha256':SHA(adapterraw)}
write('validation/actual-coherent8K-stock-verification.json',actual)
write('validation/actual-stock-verification-source-seal.json',actualseal)
m=json.loads(manifestraw);m['schema']='garmin-AP-coherent8K-disabled-test-control/preparation-v1'
m['scope']='只改v3容器header byte452的本機coherent8K對照準備；188870門牌內容保留，未部署／非完整全台更新'
m['target']['bundle_path']='candidate/coherent8K-end-mirror.img.disabled';m['target']['candidate_sha256']=overlay.COHERENT8_SHA
m['rollback']={'schema':control['schema'],'stock_recipe':m['rollback']['stock_recipe'],
               'virtual_old_v3_binding':{'schema':'garmin-native-8k-stock-layout-restore/v1',
                                        'bundle_path':'virtual-old-v3-stock-restore-binding.json','bytes':292144,
                                        'sha256':'0884c9d705c40d84a84512c691ba124cef419e2cee6d432155e45cee6ed1dd89',
                                        'virtual_candidate_sha256':overlay.V3_SHA},
               'coherent_control_binding':{'schema':control['schema'],'bundle_path':'coherent-control-restore-binding.json',**controlpin}}
m['portable_helpers']=helpers;m['allowed_operation']='integration_preparation_only'
m['integration_preparation_only']=True;m['integration_status']='pending_independent_review_and_later_test_packet'
m['installable']=False;m['deployment_download_archive_completed']=False;m['actual_coherent8K_stock_rollback_verified']=True
m['actual_coherent8K_stock_verification_proof']={'bundle_path':'validation/actual-coherent8K-stock-verification.json','bytes':len(actual),'sha256':SHA(actual)}
m['actual_coherent8K_UI_verified']=False;m['road_loss_rootcause_proven']=False
m['old_regressing_v3_download_status']=410
m['limits'].extend(['本檔為preparation gate：load_manifest在IMG／裝置處理前拒絕，未產可下載或部署包。',
                    '原0884c9binding描述virtual old-v3，不是coherent實際metadata；新overlay須先fresh驗actual9af1與inverse1f468完整SHA。',
                    'Root實際stock驗證835864成功；此前ea061f缺ReceiptSink.extend失敗保留，整pipeline不是onepass。',
                    'compactrecipe與virtualoldbinding未複製於本scope；後續rootpacket須放入exact pinned sidecars。'])
manifestpin=write('manifest.json',encoded(m))
text=installerraw.decode();tree=ast.parse(text)
constants={'SCHEMA':m['schema'],'CANDIDATE':m['target']['bundle_path'],'CANDIDATE_SHA':overlay.COHERENT8_SHA,
           'MANIFEST_BYTES':manifestpin['bytes'],'MANIFEST_SHA':manifestpin['sha256'],
           'RESTORE_BINDING':'virtual-old-v3-stock-restore-binding.json','EXPECTED_ROLLBACK':m['rollback'],
           'EXPECTED_HELPERS':helpers}
lines=text.splitlines(keepends=True);edits=[]
for node in tree.body:
    if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in constants:
        name=node.targets[0].id;edits.append((node.lineno-1,node.end_lineno,name+' = '+repr(constants[name])+'\n'))
for start,end,new in sorted(edits,reverse=True):lines[start:end]=[new]
text=''.join(lines).replace('import native_8k_stock_restore as restore\n',
                          'import native_8k_stock_restore as restore\nimport native_coherent8k_rollback as coherent_restore\nimport coherent_header_overlay as overlay\n')
insert='\nCONTROL_BINDING = \'coherent-control-restore-binding.json\'\nCONTROL_BYTES = '+str(controlpin['bytes'])+'\nCONTROL_SHA = '+repr(controlpin['sha256'])+'\nACTUAL_STOCK_PROOF = \'validation/actual-coherent8K-stock-verification.json\'\nACTUAL_STOCK_PROOF_BYTES = 6062\nACTUAL_STOCK_PROOF_SHA = '+repr(SHA(actual))+'\n'
text=text.replace('\n\ndef validate_recipe(',insert+'\n\ndef validate_recipe(',1)
def replace_func(source,name,new):
    nodes={n.name:n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)};n=nodes[name]
    rows=source.splitlines(keepends=True);rows[n.lineno-1:n.end_lineno]=[new+'\n'];return ''.join(rows)
validate='''def validate_recipe(recipe, source, target):
    """Fresh coherent fullSHA/inverse view, then unchanged strict exactstock."""
    need(isinstance(recipe, dict) and set(recipe) == {'stock', 'binding', 'control'}, 'Unsupported coherent portable restore objects')
    need(target.get('bytes') == CANDIDATE_BYTES and target.get('candidate_sha256') == CANDIDATE_SHA and
         target.get('original_bytes') == ORIGINAL_BYTES and target.get('original_sha256') == ORIGINAL_SHA,
         'Coherent8K target image identity mismatch')
    try:
        coherent_restore.prepare_objects(recipe)
        with open_regular(source) as stream:
            result = coherent_restore.reconstructed_stock_hash(stream, recipe)
    except (ValueError, KeyError, TypeError, OSError, OverflowError):
        raise Refusal('Coherent8K inverse view cannot reconstruct the exact stock image') from None
    need(result['bytes'] == target['original_bytes'] and result['sha256'] == target['original_sha256'],
         'Coherent8K exact stock full hash mismatch')
    return recipe'''
text=replace_func(text,'validate_recipe',validate)
nodes={n.name:n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)};n=nodes['load_manifest']
load=''.join(text.splitlines(keepends=True)[n.lineno-1:n.end_lineno])
load=load.replace("    t, d, rb = m.get('target', {}), m.get('device', {}), m.get('rollback', {})\n",
                  "    t, d, rb = m.get('target', {}), m.get('device', {}), m.get('rollback', {})\n    need(m.get('integration_preparation_only') is False and m.get('integration_status') == 'independently_reviewed_test_control', 'Preparation-only coherent control; candidate/device work is disabled')\n")
load=load.replace("    seen = {TARGET.lower(), PARTIAL.lower(), OLD_PARTIAL.lower(), TAICHUNG_PARTIAL.lower()}\n",
'''    need(Path(coherent_restore.__file__).resolve() == safe_path(bundle, 'native_coherent8k_rollback.py').resolve()
         and Path(overlay.__file__).resolve() == safe_path(bundle, 'coherent_header_overlay.py').resolve(), 'Coherent adapters are outside this exact bundle')
    for name in ('native_coherent8k_rollback.py', 'coherent_header_overlay.py'):
        row = EXPECTED_HELPERS[name]
        verify_file(safe_path(bundle, name), row['bytes'], row['sha256'], 'Pinned portable coherent adapter')
    seen = {TARGET.lower(), PARTIAL.lower(), OLD_PARTIAL.lower(), TAICHUNG_PARTIAL.lower()}
''')
load=load.replace("    try:\n        stock = restore.load_stock_recipe(recipe_path)\n",
'''    control_path = safe_path(bundle, CONTROL_BINDING)
    verify_file(control_path, CONTROL_BYTES, CONTROL_SHA, 'Pinned actual coherent/inverse overlay binding')
    proof_path = safe_path(bundle, ACTUAL_STOCK_PROOF)
    verify_file(proof_path, ACTUAL_STOCK_PROOF_BYTES, ACTUAL_STOCK_PROOF_SHA, 'Closed actual coherent STOCK proof')
    actual = read_json(proof_path, 65536)
    need(actual.get('all_assigned_checks_passed') is True and actual.get('candidate_full_sha256') == CANDIDATE_SHA
         and actual.get('exact_stock_reconstruction_sha256') == ORIGINAL_SHA
         and actual.get('exact_stock_bytes') == ORIGINAL_BYTES and actual.get('all_handles_closed') is True,
         'Actual coherent exact-STOCK validation prerequisite missing')
    try:
        stock = restore.load_stock_recipe(recipe_path)
''')
load=load.replace("        recipe = {'stock': stock, 'binding': binding}\n",
                  "        recipe = {'stock': stock, 'binding': binding, 'control': read_json(control_path, 65536)}\n        coherent_restore.prepare_objects(recipe)\n")
text=replace_func(text,'load_manifest',load.rstrip())
blocks='''def image_blocks(source, recipe, mode):
    need(mode in ('install', 'rollback'), 'Unknown coherent image-stream mode')
    with open_regular(source) as stream:
        if mode == 'rollback':
            yield from coherent_restore.restored_stock_blocks(stream, recipe)
        else:
            for block in iter(lambda: stream.read(CHUNK), b''):
                yield block'''
text=replace_func(text,'image_blocks',blocks)
oldnodes={n.name:n for n in ast.parse(installerraw).body if isinstance(n,ast.FunctionDef)}
newnodes={n.name:n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
changed={'validate_recipe','load_manifest','image_blocks'}
identical={name:ast.dump(node,include_attributes=False)==ast.dump(newnodes[name],include_attributes=False)
           for name,node in oldnodes.items() if name not in changed}
if set(oldnodes)!=set(newnodes) or not all(identical.values()):raise RuntimeError('Unrelated installer AST changed')
write('install_native_house_supplement.py',text.encode())
for name in ('candidate','roadmap'):(HERE/name).mkdir(exist_ok=True)
preparation={'schema':'coherent8K-installer-source-preparation/v1','all_assigned_checks_passed':True,
             'source_input_receipts':reads,'actual_raw_small_inputs_read':sum(r['bytes'] for r in reads),
             'decoded_recipe_bytes':1779988,'old_installer_sha256':SHA(installerraw),'new_installer_sha256':SHA(text.encode()),
             'unchanged_functions_AST':identical,'only_changed_functions':sorted(changed),'manifest':manifestpin,
             'control_binding':controlpin,'portable_helpers':helpers,'original_authorized_and_protected_manifest_fields_unchanged':
             all(m[k]==json.loads(manifestraw)[k] for k in ('device','preserved_stock_files','required_files')),
             'accepted_predecessors_exact_v3_unchanged':m['target']['accepted_predecessors']==json.loads(manifestraw)['target']['accepted_predecessors'],
             'actual_root_proof_sha256':SHA(actual),'root_whole_pipeline_one_attempt':False,
             'candidate_IMG_open_or_stat':False,'real_IMG_bytes_read':0,'real_IMG_bytes_written':0,
             'no_original_recipe_or_binding_copies':True,'actual_payload_hardlinks':False,'preparation_gate':True,'installable':False}
write('source-preparation-proof.json',encoded(preparation))
print(json.dumps({'all_assigned_checks_passed':True,'raw_small_input_bytes':preparation['actual_raw_small_inputs_read'],
                  'decoded_recipe_bytes':1779988,'unchanged_functions_AST':identical,'new_installer_sha256':SHA(text.encode()),
                  'manifest_sha256':manifestpin['sha256'],'candidate_IMG_read_or_write':False},indent=2))
