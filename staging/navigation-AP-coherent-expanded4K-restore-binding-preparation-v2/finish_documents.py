import difflib,hashlib,json
from pathlib import Path
P=Path(__file__).resolve().parent
reads=[]
def get(q):
 s=q.stat();b=q.read_bytes();assert q.stat()==s
 reads.append({'path':str(q.relative_to(Path.cwd())),'bytes':len(b),'SHA256':hashlib.sha256(b).hexdigest()})
 return b
def put(name,x):(P/name).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
budget=json.loads(get(P/'preseal-budget.json'))
review=json.loads(get(P/'final-source-guard-review-and-controls.json'))
final=get(P/'expanded_4k_stock_restore.py')
executed=get(P/'executed-preparation-API-source.py.txt')
old=get(P.parent/'navigation-AP-coherent-expanded4K-restore-binding-preparation-v1/old-8K-helper-source-snapshot.py')
binding=get(P/'expanded4K-stock-restore-binding.json');binding_sha=hashlib.sha256(binding).hexdigest()
assert hashlib.sha256(final).hexdigest()==review['final_API_SHA256']
assert hashlib.sha256(old).hexdigest()=='43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f'
for fname,before,label in [('source-diff-against-old-8K.patch',old,'frozen/native_8k_stock_restore.py'),
                          ('source-diff-from-executed-preparation.patch',executed,'executed/preparation_API')]:
 (P/fname).write_text(''.join(difflib.unified_diff(before.decode().splitlines(True),final.decode().splitlines(True),
                                             fromfile=label,tofile='final/expanded_4k_stock_restore.py')))
falseflags=dict.fromkeys(['production_full_input_hash_run','production_stock_reconstruction_run','new_fullIMG',
                         'fresh_component_hashes','nativeCPU','guest','MAIN','PBF','firmware','device','audio',
                         'services','install','package','hardware_admission','checksum_verified','renderer_fix',
                         'UI_route','App','music_owner','STOP_DONE','speaker','fullgoal'],False)
put('final-scope-summary.json',{'scope':P.name,'finite_preparation_closed':True,
 'actual_bounded_preparation':'2b2f22 EXIT0','actual_final_guard_controls':'95aa48 EXIT0',
 'final_API':{'file':'expanded_4k_stock_restore.py','bytes':len(final),'SHA256':hashlib.sha256(final).hexdigest()},
 'binding':{'file':'expanded4K-stock-restore-binding.json','bytes':len(binding),'SHA256':binding_sha},
 'profile':{'image_bytes':153337856,'SHA256':'8749b2614f0ef4cfb3ac631dd316b35dd3551e3ab97d2ac058f13a89052f50f6',
            'allocation_bytes':4096,'blocks':37436,'sectors':299488,'metadata_bytes':90112,
            'header512_SHA256':'63ad71122370c5c5954520f34861c15cccac506ce0692f51856ec0cf4cc162c6','MDR_bytes':149220356},
 'read_scope':{'new_IMGbytes':120,'prior_failed_v1_IMGbytes':90884,'cumulative_IMGbytes':91004,
               'IMGcap':1048576,'wholeIMG_or_component_hash_repeated':False},
 'source_provenance':'Saved v1 metadata/header SHA+stat reused; fresh actual DIR120; closed six-component hashes inherited.',
 'executed_core_and_final_source':'Executed preparation API archived unchanged. Only prepare_restore_binding immutable-recipe guard and production generator witness checks added afterward; eight final helper controls pass, full positive production recipe rebind/restore not rerun.',
 'old8K_helper_SHA256_unchanged':'43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f',
 'old32768_block_guard_relaxed':False,
 'remaining_production_gate':['Separately provide materialized exact coherent expanded4K input; existing cc019... .disabled input is rejected by the production full-hash gate.',
   'Consume restored_stock_blocks through EOF: fresh exact153337856B/8749... hash+immutable fstat before first yield, exact metadata/FAT/MDR772/DIR120 match, complete96739328B/864d... stock hash at EOF, fstat remains equal to initial full-hash witness throughout.'],
 'falseflags':falseflags})
put('actual-preparation-terminal-receipt.json',{'chunk_id':'2b2f22','exit_code':0,'wall_time_seconds':0.008097101,
 'command':'python3 staging/navigation-AP-coherent-expanded4K-restore-binding-preparation-v2/prepare_bounded_binding.py',
 'terminal_stdout':{'finite_preparation_passed':True,'new_IMGbytes':120,'cumulative_IMGbytes':91004,
                    'artifact_raw':1410185,'artifact_decoded':2310674,'helper_controls':6,'production_reconstruction_run':False},
 'executed_API_SHA256':'29f5f11c3f6eb1b0cc2de84840e78c7bd93dd73badac787aaeeede2e294b65bb'})
put('actual-final-guard-controls-terminal-receipt.json',{'chunk_id':'95aa48','exit_code':0,'wall_time_seconds':0.000020537,
 'command':'python3 staging/navigation-AP-coherent-expanded4K-restore-binding-preparation-v2/finalize_api_guards.py',
 'terminal_stdout':{'final_API_ready':True,'final_API_SHA256':review['final_API_SHA256'],
                    'changed_functions':['prepare_restore_binding','restored_stock_blocks'],'final_helper_checks':8,
                    'artifact_raw':1513773,'artifact_decoded':2414262,'IMGread':0,'production_reconstruction_run':False}})
put('source-and-remaining-gate-checklist.json',{'supported_profile_only':True,
 'binding_external_SHA_required':binding_sha,'fresh_complete_input_hash_automatic_before_first_yield':True,
 'complete_input_fstat_kept_across_full_generator':True,'raw_directory_unknown_fields_preserved':True,
 'all_six_component_geometry_exact_FAT_bound':True,'stock_recipe_compressed_and_plain_pins_and_data_identity_guard':True,
 'original_header_FAT_small111bitL3_padding_from_closed_recipe':True,
 'original_lower6_5_4_bytealigned_prefixes_from_actual_future_table_starts':True,
 'all_original_component_physical_block_order_restored':True,'no_bit_width_conversion':True,
 'no_generic8K_or_other4K_fallback':True,'old_helper_not_edited':True,
 'preparation_positive_metadata_recipe_binding_executed_with_archived_API':True,
 'final_added_positive_recipe_guard_inherited_from_old_verified_guard_not_rerun':True,
 'final_private_helper_controls_and_negative_mutation_guards_passed':True,
 'full_candidate_hash_stock_EOF_actual_production_test_pending':True,
 'host_restore_is_not_physical_rollback_or_atomic_install':True,'falseflags':falseflags})
(P/'API.md').write_text(f'''# Coherent expanded4K host restore API

`expanded_4k_stock_restore.py` is a separate supported-profile Python API. It accepts only the coherent expanded4K target153337856B/SHA8749b2614f0ef4cfb3ac631dd316b35dd3551e3ab97d2ac058f13a89052f50f6, exact header512/SHA63ad71122370c5c5954520f34861c15cccac506ce0692f51856ec0cf4cc162c6 and metadata/FAT allocation4096B/37436blocks/299488sectors. The fixed binding SHA is `{binding_sha}`. The existing noncoherent `.disabled` source/SHA cc019c5f... is metadata provenance, not an accepted production restore input.

`restored_stock_blocks(candidate_path, recipe_path, binding_path, binding_sha256, read_receipts=None)` opens the actual input in `rb`, freshly hashes its complete exact bytes before yielding any original block, and checks fstat. It then rereads90112 metadata bytes plus MDR772/DIR120, compares the exact binding/profile, and yields original4096-byte physical blocks in their original order. The verified input fstat tuple remains tied to the whole-hash witness before and after the entire generator. Consume through `StopIteration` to run original96739328B/SHA864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2 checks at EOF. Partial consumption proves no complete rollback.

`reconstructed_stock_hash(candidate_path, recipe_path, binding_path, binding_sha256, read_receipts=None)` consumes the generator through EOF and returns the exact stock SHA after all gates. It writes no IMG. The fixed recipe is `staging/navigation-country-layout-restore-v2/restore-layout.json.gz`879499B/SHA6e1381006e3f56a466c8cdd93134f418eab18ee592cbfd5e57f1a55c2950c0a7; decoded1779988B/SHA44ac0746da599dfd67f317bcba70fa891f315576cf0995f8a483ed9ba18401aa. The binding is this scope's `expanded4K-stock-restore-binding.json`. There is no CLI, output writer, installer, caller-issued acceptance token or fallback for arbitrary IMG geometry.

Original header/FAT, small111-bit L3, original directory and tail/unused padding come from the unchanged recipe. The native lower6/5/4 original bytealigned prefixes and L1/L2 spans are read from actual expanded4K physical allocations and current v3 table offsets. L3's current23-bit/112-stride profile is retained in the candidate; original stock L3 comes from the recipe. No lower width conversion or per-record padded splice occurs. All raw native directory words are bound exactly; unknown flags are not normalized or reinterpreted.

Preparation ran finite metadata/recipe validation and host helpers, not a production full reconstruction. Executed preparation source is archived; final source adds immutable recipe-data identity and whole-hash witness fstat continuity. Final helper controls verify cross-block/out-of-order logical reads, bounds, correct/wrong fresh fixture hashes, changed fstat and changed recipe data. The12288B fixture is not an IMG or a complete-profile test. The positive final recipe rebind, complete coherent input hash and stock reconstruction must still execute in a separately authorized production test. Hardware/checksum admission, atomic rollback, UI/render/route and installation remain unproved.
''')
(P/'HANDOFF.md').write_text('''# Separate coherent expanded4K restore preparation

V1 first attempt0f1046 EXIT1 was our host-reader offset bug (690 instead of original decimal600), not source/platform rejection. It remains sealed separately. V2 reused its90112 metadata and772 header captures with exact SHA/stat and validated all dependent globals, actual profile/FAT and correct directory descriptor before fresh I/O. Actual2b2f22 EXIT0 read only DIR120. Cumulative original IMG read is90884+120=91004B; no full source/component hash or output image was added.

The separate API/binding supports exact coherent expanded4K4096B/37436blocks/299488sectors/153337856B. MDR149220356B, native tables and all six logical component identities inherit closed full readback evidence; full candidate admission is not claimed here. Header512 is exact63ad711...162c6, with original opaque checksum219 retained, not verified. Original 8K helper43e041...6fe5f and its32768/header guard remain unchanged.

`final-scope-summary.json` supplies small pins and remaining gates. `proof.json` records actual finite preparation using archived executed API29f5f...b65bb. Before seal, final source added recipe-data identity (same guard as pinned old _binding) plus fstat checks anchored across the entire generator to the initial fresh complete hash. `final-source-guard-review-and-controls.json` records AST difference restricted to those two functions and8 final host checks. No second production recipe decode, positive final-source recipe rebind or whole reconstruction was run. Both source variants and exact diffs are retained; no executed result was silently rebound to modified code.

Production `restored_stock_blocks` opens read-only paths, freshly verifies complete actual coherent8749... input SHA/stat before first yield, validates bound metadata/FAT/MDR772/DIR120, retains that stat witness through EOF and checks complete original864d... reconstruction. The existing cc019... noncoherent source cannot pass this production gate. `API.md` describes signatures and exact pending test. Consume through EOF; host reconstruction is neither an atomic install nor physical rollback. No nativeCPU/guest/MAIN/PBF/firmware/device/audio/service/package/install action or UI/render/checksum/hardware/App/full-goal success occurred. Stop after final seal.
''')
raw=budget['raw']+sum(x['bytes'] for x in reads);decoded=budget['decoded']+sum(x['bytes'] for x in reads)
assert raw<=3145728 and decoded<=4194304
put('final-document-read-receipts.json',{'actual_owned_reads':reads,'raw':raw,'decoded':decoded,
                                     'raw_cap':3145728,'decoded_cap':4194304,'new_IMGread':0})
put('preseal-budget-final.json',{'raw':raw,'decoded':decoded,'raw_cap':3145728,'decoded_cap':4194304,
                              'new_IMGbytes':120,'prior_v1_IMGbytes':90884,'cumulative_IMGbytes':91004,'IMGcap':1048576})
print(json.dumps({'final_documents_ready':True,'final_API_SHA256':hashlib.sha256(final).hexdigest(),
                  'binding_SHA256':binding_sha,'binding_bytes':len(binding),'artifact_raw_before_seal':raw,
                  'artifact_decoded_before_seal':decoded,'new_IMGread':0}))
