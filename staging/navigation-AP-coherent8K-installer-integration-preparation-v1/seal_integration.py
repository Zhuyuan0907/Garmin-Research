#!/usr/bin/env python3
"""Close finite small integration preparation; no map or device access."""
import ast
import hashlib
import json
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
SHA=lambda b:hashlib.sha256(b).hexdigest()
files=[p for p in HERE.rglob('*') if p.is_file()]
raw={p:p.read_bytes() for p in files}
prep=json.loads(raw[HERE/'source-preparation-proof.json']);tests=json.loads(raw[HERE/'host-control-proof.json'])
manifest=json.loads(raw[HERE/'manifest.json']);control=json.loads(raw[HERE/'coherent-control-restore-binding.json'])
if not prep['all_assigned_checks_passed'] or not tests['all_assigned_checks_passed'] or tests['methods']!=9 or tests['errors'] or tests['failures']:
    raise RuntimeError('Source preparation/finite host controls failed')
for name,key in [('test_integration.py','test_source_sha256'),('install_native_house_supplement.py','installer_sha256'),
                 ('native_coherent8k_rollback.py','native_coherent_adapter_sha256')]:
    if SHA(raw[HERE/name])!=tests[key]:raise RuntimeError('Executed source/test hash changed')
if not manifest['integration_preparation_only'] or manifest['integration_status']!='pending_independent_review_and_later_test_packet':
    raise RuntimeError('Preparation gate was changed')
if any((HERE/'candidate').iterdir()) or any((HERE/'roadmap').iterdir()):raise RuntimeError('No actual payload in preparation')
if (HERE/'restore-layout.json.gz').exists() or (HERE/'virtual-old-v3-stock-restore-binding.json').exists():
    raise RuntimeError('Large closed sidecars must not be copied here')
for name,row in manifest['portable_helpers'].items():
    if len(raw[HERE/name])!=row['bytes'] or SHA(raw[HERE/name])!=row['sha256']:raise RuntimeError('Portable helper binding changed')
if SHA(raw[HERE/'native_8k_stock_restore.py'])!='43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f':
    raise RuntimeError('Original helper changed')
if SHA(raw[HERE/'device_support.py'])!='8c3a74b620ad75a452421777b53c60285510c409df66cd10602648bf3604f411':
    raise RuntimeError('Device protection helper changed')
final=[]
for row in prep['source_input_receipts']:
    p=ROOT/row['path'];s=p.lstat();actual=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]
    expected=row.get('stat',row.get('stat_after'))
    if not stat.S_ISREG(s.st_mode) or actual!=expected:raise RuntimeError('Closed small source stat changed')
    final.append({'path':row['path'],'sha256':row['sha256'],'bytes':row['bytes'],'stat_final':actual})
source=ast.parse(raw[HERE/'install_native_house_supplement.py'])
nodes={n.name:n for n in source.body if isinstance(n,ast.FunctionDef)}
adaptertree=ast.parse(raw[HERE/'native_coherent8k_rollback.py'])
workspace_calls=[ast.unparse(n) for n in ast.walk(adaptertree) if isinstance(n,ast.Call) and
                 isinstance(n.func,ast.Attribute) and n.func.attr=='prepare_fixed_inputs']
if workspace_calls:raise RuntimeError('Portable adapter calls original workspace loader')
astpins={name:SHA(ast.dump(nodes[name],include_attributes=False).encode()) for name in
         ('image_state','device_preflight','transaction','execute','main')}
rootproof=raw[HERE/'validation/actual-coherent8K-stock-verification.json']
if SHA(rootproof)!='e44ded4324705fc9482b60898edda790e6155a646a5d9e5d7b4a139e5f41aa8e':raise RuntimeError('Root actual proof binding')
actual=json.loads(rootproof)
receipt={'schema':'coherent8K-integration-actual-host-tool-receipts/v1','source_preparation':
         {'tool_chunk_id':'91afdc','actual_exit_code':0,'wall_time_seconds':0.100912992,
          'command':'python3 staging/navigation-AP-coherent8K-installer-integration-preparation-v1/prepare_integration.py'},
         'finite_host_tests':{'tool_chunk_id':'91afe5','actual_exit_code':0,'wall_time_seconds':0.160852209,
          'command':'python3 staging/navigation-AP-coherent8K-installer-integration-preparation-v1/test_integration.py',
          'terminal':'Ran 9 tests in 0.136s\n\nOK'},'real_IMG_read_or_write':False,'device_IO':False}
proof={'schema':'coherent8K-installer-integration-preparation/v1','all_assigned_checks_passed':True,
       'scope':'source/binding and finite host controls only; release blocked by immutable preparation manifest',
       'actual_tools':receipt,'installer_sha256':tests['installer_sha256'],
       'native_coherent_adapter_sha256':tests['native_coherent_adapter_sha256'],
       'manifest_sha256':SHA(raw[HERE/'manifest.json']),'manifest_bytes':len(raw[HERE/'manifest.json']),
       'coherent_binding_sha256':SHA(raw[HERE/'coherent-control-restore-binding.json']),
       'source_proof_sha256':SHA(raw[HERE/'source-preparation-proof.json']),
       'finite_test_proof_sha256':SHA(raw[HERE/'host-control-proof.json']),
       'only_changed_installer_functions':['validate_recipe','load_manifest','image_blocks'],
       'unchanged_functions_AST':prep['unchanged_functions_AST'],'unchanged_function_AST_sha256':astpins,
       'old_helper_byte_exact':True,'device_support_byte_exact':True,'closed_overlay_byte_exact':True,
       'portable_adapter_workspace_loader_calls':workspace_calls,
       'same_directory_sidecar_and_module_pins_required_by_load_manifest':True,
       'whole_manifest_pin_and_original_authorized_XML_USB_unit_protected_files_Searchv2_predecessor_guards_preserved':True,
       'source_small_input_final_bindings':final,
       'actual_root_stock_validation_inherited':{'proof_sha256':SHA(rootproof),'actual_terminal':'835864','exit_code':0,
            'candidate_sha256':actual['candidate_full_sha256'],'computed_inverse_sha256':actual['computed_inverse_original_v3_sha256'],
            'stock_bytes':actual['exact_stock_bytes'],'stock_sha256':actual['exact_stock_reconstruction_sha256'],
            'candidate_read_bytes':actual['actual_candidate_read_bytes'],'source_stat_final_inherited_only':actual['final_source_stat'],
            'all_handles_closed':actual['all_handles_closed'],'rerun_this_scope':False},
       'first_failed_root_pipeline_preserved':control['first_failed_restore_attempt_preserved'],
       'whole_root_pipeline_one_attempt':False,
       'actual_coherent_binding_and_virtual_old_v3_metadata_distinct':True,
       'synthetic_controls':{'methods':9,'source_max_bytes':4096,'rollback_payload_bytes':2048,
                            'bridge_only_in_test':True,'new_sink_append_extend_tested':True,
                            'full_production_stock_generator_invoked':False,'atomic_transaction_invoked':False},
       'budgets':{'raw_small_input_limit':3145728,'decoded_limit':4194304,'output_limit':262144,
                  'source_preparation_actual_raw_small_reads':prep['actual_raw_small_inputs_read'],
                  'tests_stock_recipe_binding_raw_reads':1171643,
                  'earlier_bounded_small_artifact_reads_upper_bound':57568,
                  'test_additional_closed_installer_manifest_reads':29025,
                  'own_source_runtime_or_output_reads_reserved_upper_bound':490000,
                  'total_raw_read_upper_bound':prep['actual_raw_small_inputs_read']+1171643+57568+29025+490000,
                  'total_recipe_decoded_bytes':3559976,'max_synthetic_payload_bytes':4096},
       'preparation_gate_load_manifest_refusal_actually_executed':True,
       'production_load_manifest_completed':False,'actual_bundle_payload_or_sidecars_present':False,
       'missing_payload_sidecars':{'candidate':manifest['target']['bundle_path'],
                                   'stock_recipe':manifest['rollback']['stock_recipe'],
                                   'virtual_old_v3_binding':manifest['rollback']['virtual_old_v3_binding']},
       'known_good_v2_recovery_gap':{'bytes':128356352,
              'sha256':'925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb',
              'offered_by_this_stock_only_adapter':False,'stock_rollback_loses_v2_supplemental_additions':True,
              'v2_supplemental_houses_not_preserved_by_factory_rollback':130637,
              'root_will_prepare_separate_self_contained_v2_recovery':True,
              'new_compact_v2_inverse_recipe_or_full_v2_copy_created_here':False},
       'pending':['Independent review of new portable coherent adapter and changed installer binding flow.',
                  'Later root-controlled packet assembly with exact candidate/road and closed stock recipe/virtual old-v3 binding sidecars; update only a NEW sealed release manifest/entrypoint scope.',
                  'Genuine same-bundle load_manifest validation after payload binding and readers close; not performed in this preparation.',
                  'Separate root-owned recovery to the currently working country-v2 payload; certified factory rollback alone removes its supplemental additions.',
                  'Attended physical test, UI/search/routes/renderer and checksum/admission policy remain unverified.'],
       'device_discovery_preflight_mount_sysfs_BlueZ_called':False,'services_guest_native_firmware_audio':False,
       'real_candidate_or_road_IMG_open_stat_link_chmod':False,'real_IMG_bytes_read':0,'real_IMG_bytes_written':0,
       'deployment_download_archive_completed':False,'original_v3_download_status_410_unchanged':True,
       'report_canonical_or_closed_source_modified':False,'original_full_backup_duplicated':False,
       'checksum_UI_renderer_rootcause_verified':False,'full_Taiwan_native_update_complete':False,
       'installable':False,'all_small_input_and_synthetic_memory_handles_closed':True}
if proof['budgets']['total_raw_read_upper_bound']>3145728:raise RuntimeError('Raw3MiB budget')
handoff='''# Coherent8K installer integration preparation

This is a blocked local TEST packet scaffold, not a release/installable/downloadable packet. The candidate and road directories are empty. No candidate/road IMG was opened, statted, hardlinked, chmodded, written or hashed here. No device discovery, device_preflight, transaction, execute, mount/sysfs/BlueZ, services, guest/native/firmware/audio or report change occurred.

The whole manifest is pinned; integration_preparation_only=true makes load_manifest refuse before IMG or device work. The real refusal was tested. CLI default/main, transaction/execute/image_state/device_preflight ASTs remain identical to closed v3. Exact device_support and original stock helper bytes remain unchanged. Exact authorized model/unit/USB/XML, protection inventories, Searchv2, accepted predecessors including the good country-v2 and partial/atomic guards remain.

Actual candidate is153346048B/SHA9af1e68e1308bf28deeb7f7d4c7cfab88efd0063c38f4f2df77fcde352990dd3; staged name remains .img.disabled. Searchv2 is131829760B/SHA664c46c99697b61ba383b5571b0a49356336746c9bbf3f94403aae583787f117. Good country-v2 predecessor is128356352B/SHA925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb. STOCK is96739328B/SHA864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2.

Rollback roles are explicit: coherent-control-restore-binding.json describes actual corrected9af1 plus inverse512 metadata. The292144B/0884c9... closed binding remains named virtual-old-v3-stock-restore-binding.json and describes the virtual1f468 old-v3 view, not actual coherent metadata. The new portable native_coherent8k_rollback module constructs FixedInputs using same-bundle header/control data and the unchanged helper; it never calls overlay.prepare_fixed_inputs with original ROOT paths. Before old helper consumption, it fresh-verifies actual corrected fullSHA/size/header and computed inverse fullSHA. Old strict header/FAT/profile/stock checks stay intact. A compact ReceiptSink implements append and extend without retaining23K rows.

Root actual verification835864 EXIT0 independently completed249424497B reads, full corrected/inverse hashes and exact STOCK EOF/hash. Its proof e44ded... and seal are copied as small immutable evidence. The first ea061f failure was missing ReceiptSink.extend and is preserved; the overall pipeline is not one attempt. This scope inherits that real result and does not rerun it or claim the new portable installer production load succeeded. Original materialization stat is provenance, not future package-hardlink stat.

Host source preparation91afdc and tests91afe5 EXIT0 passed9 methods. New image_blocks install/rollback transport uses4096B input/2048B synthetic rollback and a clearly test-only small generator bridge. It does not prove a full real old-stock generator/atomic transaction. Actual object bindings, preparation refusal before IMG, corrupted control/target/virtual role/fake recipe refusals, incomplete EOF propagation, append/extend and preserved AST/protected fields are checked. No closed historical suite was rerun.

Output budget prohibits copying879499B recipe or292144B old binding. Both are pinned in the manifest but absent; candidate/road payloads are absent too. Next root scope can perform finite independent review and assemble a NEW sealed reviewed test packet with exact sidecars/payload and actual local bindings, then run genuine production load_manifest. Do not edit this closed preparation gate/seal. Existing user authority covers reversible local packaging; this document adds no approval flow. Device writes await the later attended test. The old regressing v3 download remains410. Expanded4K remains a separate strict-layout task. UI/renderer/root cause/checksum policy/installable/full-Taiwan completion remain false.

The currently healthy Address Point is country-v2 SHA925a..., not factory stock. This adapter offers certified factory864d rollback only, which removes the130637 v2 supplemental houses as well as later additions. A test packet should also offer returning to the known-working128356352B v2. That recovery is a separate root-owned self-contained payload/installer preparation using the existing verified v2; this scope does not copy its full image, add a new compact inverse recipe or extend installer ASTs. The working-v2 recovery gap remains open and must not be mistaken for completion by the successful stock hash proof.
'''
def save(name,value):
    b=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode() if not isinstance(value,str) else value.encode()
    p=HERE/name
    with p.open('xb') as f:f.write(b)
    raw[p]=b
save('actual-host-tool-receipts.json',receipt);save('proof.json',proof);save('HANDOFF.md',handoff)
rows=[]
for p,b in raw.items():
    p.chmod(0o444);s=p.stat();rows.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'sha256':SHA(b),'mode':'0444',
                                       'stat':[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]})
seal={'schema':'coherent8K-installer-integration-preparation-seal/v1','all_assigned_checks_passed':True,'files':rows,
      'real_IMG_read_or_write_bytes':0,'installable':False,'all_handles_closed':True}
b=(json.dumps(seal,indent=2)+'\n').encode();total=sum(len(x) for x in raw.values())+len(b)
if total+2048>262144:raise RuntimeError('Output256KiB cap/reserve')
p=HERE/'sealed-files.json'
with p.open('xb') as f:f.write(b)
p.chmod(0o444)
print(json.dumps({'all_assigned_checks_passed':True,'installer_sha256':tests['installer_sha256'],
                  'adapter_sha256':tests['native_coherent_adapter_sha256'],'manifest_sha256':proof['manifest_sha256'],
                  'proof_sha256':SHA(raw[HERE/'proof.json']),'seal_sha256':SHA(b),'artifact_bytes_including_seal':total,
                  'methods':9,'real_IMG_bytes_read':0,'real_IMG_bytes_written':0,'all_handles_closed':True,
                  'production_load_manifest_completed':False,'installable':False},indent=2))
