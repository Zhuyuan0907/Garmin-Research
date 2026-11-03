#!/usr/bin/env python3
"""Seal the small, read-only adapter preparation only; never touch an IMG."""
import ast
import hashlib
import json
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
SHA=lambda b:hashlib.sha256(b).hexdigest()
raw={p:p.read_bytes() for p in (HERE/'eightk_inverse_header_overlay.py',HERE/'test_overlay_preflight.py',
                               HERE/'synthetic-preflight-proof.json',Path(__file__))}
tested=json.loads(raw[HERE/'synthetic-preflight-proof.json'])
if not tested['all_assigned_checks_passed'] or tested['unittest_methods']!=8 or tested['errors'] or tested['failures']:
    raise RuntimeError('Actual finite preflight failed')
for name,key in [('eightk_inverse_header_overlay.py','adapter_sha256'),('test_overlay_preflight.py','test_sha256')]:
    if SHA(raw[HERE/name])!=tested[key]:raise RuntimeError('Executed preparation source binding changed')
if any(isinstance(n,ast.Assert) for n in ast.walk(ast.parse(raw[HERE/'eightk_inverse_header_overlay.py']))):
    raise RuntimeError('Production guards depend on assert')
final=[]
for row in tested['input_receipts']:
    p=ROOT/row['path'];s=p.lstat()
    actual=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]
    if not stat.S_ISREG(s.st_mode) or actual!=row['stat_after'] or row['stat_after']!=row['stat_before']:
        raise RuntimeError('Closed small input changed after test')
    final.append({'path':row['path'],'sha256':row['sha256'],'bytes':row['bytes'],'stat_final':actual})
if tested['input_raw_bytes']!=1225362 or tested['input_decompressed_bytes']!=1779988 or tested['fixture_max_bytes']>8192:
    raise RuntimeError('Exact raw/decompressed/fixture budget evidence')
receipt={'schema':'ordinary-host-coherent-control-preflight-tool-receipt/v1','command':
         'python3 staging/navigation-AP-coherent-control-rollback-binding-preflight-v1/test_overlay_preflight.py',
         'tool_chunk_id':'f60f26','actual_exit_code':0,'wall_time_seconds':0.089190545,
         'terminal':'Ran 8 tests in 0.121s\n\nOK','methods':8,'native_guest':False,
         'real_IMG_open_or_stat':False,'real_IMG_read_bytes':0,'real_IMG_write_bytes':0}
proof={'schema':'AP-coherent-control-rollback-binding-preflight/v1','all_assigned_checks_passed':True,
       'scope':'strict fixed-input design and pure-host read-only eightK inverse overlay; no production invocation',
       'adapter':{'path':str((HERE/'eightk_inverse_header_overlay.py').relative_to(ROOT)),
                  'sha256':tested['adapter_sha256'],'bytes':len(raw[HERE/'eightk_inverse_header_overlay.py']),
                  'IMG_open_or_stat_function':False,'physical_output_writer':False,'CLI':False,
                  'source_file_descriptor_borrowed':True,'unknown_arbitrary_manifest_supported':False},
       'actual_run':receipt,'synthetic_proof_sha256':SHA(raw[HERE/'synthetic-preflight-proof.json']),
       'design':tested['design'],'closed_small_inputs_stat_final':final,
       'budgets':{'raw_limit_bytes':2097152,'decompressed_limit_bytes':4194304,'output_limit_bytes':131072,
                  'fixed_input_bytes_actual':1225362,'prior_small_seal_capture_bytes':15999,
                  'prior_helper_sed_capture_upper_bound_bytes':26600,
                  'own_small_preparation_read_reserve_bytes':262144,
                  'total_raw_upper_bound_bytes':1225362+15999+26600+262144,
                  'actual_decompressed_recipe_bytes':1779988,'largest_synthetic_fixture_bytes':8192},
       'evidence_classification':{
          'old_helper_exact_source_pinned_and_unchanged':True,
          'actual_original_stock_recipe_and_v3_binding_consistent':True,
          'old_helper_identity_and_bounded_read_via_synthetic_inverse_view_executed':True,
          'old_helper_actual_code_corrected_header_refusal_demonstrated_with_synthetic_guard_input':True,
          'old_helper_actual_code_expanded4K_size_refusal_demonstrated_with_synthetic_guard_input':True,
          'actual_coherent_candidate_fullSHA_or_full_inverseSHA_recomputed':False,
          'actual_old_v3_stock_reconstruction_inherited_previous_scope_only':True,
          'production_old_helper_full_parser_or_stock_generator_executed_this_scope':False,
          'production_convenience_generator_runtime_verified':False,
          'synthetic_declared_production_size_guard_not_a_full_container':True},
       'future_real_validation_prerequisites':[
          'Explicit authorization to open the successfully materialized coherent8K .img.disabled read-only, with its immutable final path/stat/hash receipt bound.',
          'Complete actual candidate153346048-byte EOF and actualSHA9af1e68e1308bf28deeb7f7d4c7cfab88efd0063c38f4f2df77fcde352990dd3 plus computed inverse-view SHA1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360; no view is returned on mismatch.',
          'Feed the verified inverse view to the unchanged strict old-v3 helper and closed stock recipe/binding. Consume every4096-byte STOCK block through EOF without saving a restored IMG.',
          'Record exact96739328-byte reconstruction SHA864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2, source final fd/path stat and caller-owned handle closure.',
          'Expanded4K requires an independent actual FAT/layout descriptor and explicitly bounded supported-profile adapter; never weaken the existing helper to accept arbitrary geometry.'],
       'real_IMG_open_or_stat':False,'real_IMG_bytes_read':0,'real_IMG_bytes_written':0,
       'device_IO':False,'services_or_guest_or_firmware_or_audio':False,'second_full_backup_created':False,
       'shared_canonical_or_report_mutated':False,'actual_stock_reconstruction_executed':False,
       'checksum_policy_or_UI_or_renderer_rootcause_verified':False,'installable':False,
       'all_synthetic_handles_closed_by_caller':True,'all_small_input_handles_closed':True}
handoff='''# Coherent AP control rollback binding preflight

The pure-host adapter supports only `eightK_end_mirror`. It does not open/stat an IMG, write a file, expose a CLI, install or discover a device. The original `native_8k_stock_restore.py` remains unchanged at SHA43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f.

Fixed identities:

| View | Bytes | SHA256 |
| --- | ---: | --- |
| Coherent8K actual input |153346048|9af1e68e1308bf28deeb7f7d4c7cfab88efd0063c38f4f2df77fcde352990dd3|
| Declared inverse old-v3 view |153346048|1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360|
| Exact original STOCK4K stream |96739328|864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2|
| Coherent expanded4K, unsupported here |153337856|8749b2614f0ef4cfb3ac631dd316b35dd3551e3ab97d2ac058f13a89052f50f6|

`prepare_fixed_inputs()` reads only pinned small plan/proof/header/seal/helper/recipe/binding files. The closed879499-byte stock recipe decompresses once to1779988 bytes. The old actual-v3 binding is recomputed by the unchanged helper and must match byte-parsed logical content exactly. Its source identity, all six component allocations and table descriptors remain unchanged. The inverse512 header matches the old helper's exact expected4096 header prefix. This is a declared reversible view, not direct old-helper acceptance of the coherent header.

Future authorized use, not run in this scope: load fixed inputs once; pass a caller-owned regular read-only `rb` descriptor to `verified_eightk_overlay`. It verifies exact corrected512 bytes, fullsize, actual coherent fullSHA, computed inverse fullSHA, EOF and immutable fd identity before returning any view. The view retains true fileno/mode identity and only supplies bounded read/seek/tell; it cannot write or close the borrowed source. It substitutes original bytes only for reads intersecting the first512 bytes; the only differing byte is452 (224→208). Body bytes and all new content stay untouched. A read or seek detects source stat changes.

Feed that verified view into the unchanged helper's `restored_stock_blocks` with the closed recipe and old binding. Consume through generator EOF, compare exact STOCK size/SHA and record original fd/path final stat and handle closure. The old helper still verifies strict8K header/FAT, all allocations, MDR header/directory and native profile; stock original header/FAT/L3/padding and lower stock prefixes are reconstructed by the existing recipe. No second full backup or restored IMG is needed. Real coherent-file final path/stat/receipt must first be sealed and bound; a newly materialized file has its own inode and must not inherit old source inode claims.

Ordinary-host preflight f60f26 EXIT0 passed8 methods: actual-fd inverse bounded reads via old helper, body preservation, wrong corrected header/fullSHA/inverseSHA, read-write fd refusal, post-verification source mutation and retained old guards. Each synthetic buffer/file is at most8192 bytes. The direct old helper rejects a corrected8K header at its exact-header guard; it rejects expanded4K153337856 bytes at its existing32768×4096 limit. Synthetic guards use a declared production length with small fake data and do not prove a full real container parse. No actual candidate full hash, full inverse hash, stock generator or native/UI/device result was executed here. Convenience generator production runtime is untested.

Expanded4K has a different actual FAT/layout and exceeds the old4K geometry/size profile. It needs a separately pinned exact descriptor and strict supported-profile API. Do not weaken arbitrary-file guards. Header byte15/opaque checksum, admission, UI, routes, renderer root cause and installability remain unknown/false. Old helpers, images, seals and reports are untouched. This finite preparation is sealed and stopped.
'''
def save(name,value):
    data=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode() if not isinstance(value,str) else value.encode()
    p=HERE/name
    if p.exists():raise RuntimeError('Refuse replacing closure output')
    p.write_bytes(data);raw[p]=data
save('actual-preflight-tool-receipt.json',receipt);save('proof.json',proof);save('binding-design.json',tested['design']);save('HANDOFF.md',handoff)
rows=[]
for p,b in raw.items():
    p.chmod(0o444);s=p.stat();rows.append({'path':str(p.relative_to(ROOT)),'bytes':len(b),'sha256':SHA(b),'mode':'0444',
                                       'stat':[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]})
seal={'schema':'coherent-control-rollback-preflight-seal/v1','all_assigned_checks_passed':True,'files':rows,
      'real_IMG_read_or_write_bytes':0,'all_handles_closed':True}
b=(json.dumps(seal,indent=2)+'\n').encode()
total=sum(len(x) for x in raw.values())+len(b)
if total+2048>131072:raise RuntimeError('Output128KiB including post-seal receipt reserve')
p=HERE/'sealed-files.json'
with p.open('xb') as f:f.write(b)
p.chmod(0o444)
print(json.dumps({'all_assigned_checks_passed':True,'methods':8,'actual_test_tool':'f60f26','real_IMG_read_bytes':0,
                  'real_IMG_write_bytes':0,'adapter_sha256':tested['adapter_sha256'],'proof_sha256':SHA(raw[HERE/'proof.json']),
                  'seal_sha256':SHA(b),'artifact_bytes_including_seal':total,'all_handles_closed':True},indent=2))
