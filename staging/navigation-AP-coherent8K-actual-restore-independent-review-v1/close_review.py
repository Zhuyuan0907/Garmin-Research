"""Artifact-only proof and seal; never follows descriptor IMG path."""
from pathlib import Path
import hashlib,json,stat
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
A='staging/navigation-AP-coherent8k-actual-materialization-rollback-v1/'
B='staging/navigation-AP-coherent8k-actual-stock-verification-v2/'
COHERENT='9af1e68e1308bf28deeb7f7d4c7cfab88efd0063c38f4f2df77fcde352990dd3'
V3='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
STOCK='864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'
def sha(b):return hashlib.sha256(b).hexdigest()
def put(n,o):(HERE/n).write_text(json.dumps(o,ensure_ascii=False,separators=(',',':'))+'\n')
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def main():
    e=json.loads((HERE/'captured-small-evidence.json').read_text())
    p=e[B+'proof.json'];seal=e[B+'sealed-files.json'];m=e[A+'actual-materialization-receipt.json']
    d=e[A+'actual-control-output-descriptor.json'];f=e[A+'failure-closure.json'];err=e[A+'failure.json']
    t=e[B+'actual-root-tool-receipts.json'];old=e[A+'actual-root-tool-receipts.json']
    reads=json.loads((HERE/'input-read-receipts.json').read_text())
    extra=json.loads((HERE/'second-display-read-receipts.json').read_text())
    assert reads['actual_small_artifact_bytes']==112436 and extra['actual_total_input_bytes']==152275<=163840
    assert m['actual_saved_output_sha256']==m['generated_computed_full_sha256']==COHERENT
    assert m['source_actual_full_sha256']==V3 and m['actual_saved_output_fullhash_verified'] and m['published']
    assert m['source_bytes_read']==m['saved_output_bytes_read']==153346048
    assert m['all_handles_closed'] and m['source_unchanged'] and m['partial_cleanup']=='owned_partial_removed'
    assert p['candidate_full_sha256']==COHERENT and p['computed_inverse_original_v3_sha256']==V3
    assert p['exact_stock_reconstruction_sha256']==STOCK and p['exact_stock_bytes']==96739328==23618*4096
    assert p['exact_stock_blocks']==23618 and p['actual_candidate_read_bytes']==249424497<260000000
    assert p['inverse_view_receipt']['candidate_bytes_read']==153346048
    assert p['inverse_view_receipt']['inverse_view_bytes_returned']==96078449
    assert 153346048+96078449==249424497
    assert sum(p['stock_read_receipts']['purposes'].values())==p['stock_read_receipts']['logical_bytes']==96078449
    assert p['stock_read_receipts']['append_count']==23448 and not p['stock_read_receipts']['retained_per_block_receipt_list']
    candidate_pin=next(r for r in seal['files'] if r['path']==d['path'])
    assert d['final_stat']==p['final_source_stat']==candidate_pin['stat_at_seal']
    assert d['sha256']==candidate_pin['sha256']==COHERENT and d['all_nonheader_bytes_unchanged']
    assert d['changed_byte_offsets']==[452] and not d['device_installed']
    assert p['all_handles_closed'] and p['source_unchanged'] and p['new_IMG_files']==0
    assert err['error_type']=='AttributeError' and err['error']=="'ReceiptSink' object has no attribute 'extend'"
    assert f['streamed_stock_blocks_yielded']==0 and f['first_actual_restore_read_counter_not_saved']
    assert f['materializer_actual_IMG_reads']==306692096==2*153346048
    assert f['first_total_IMG_read_conservative_upper_bound']==306692096+260000000==566692096
    assert p['cumulative_IMG_reads_all_attempts_conservative_upper_bound']==566692096+249424497==816116593
    assert not p['whole_pipeline_one_attempt'] and old['terminal']['exit_code']==1 and old['terminal']['chunk_id']=='ea061f'
    assert t['terminal']['exit_code']==0 and t['terminal']['chunk_id']=='835864'
    terminal=json.loads(t['terminal']['output']);assert terminal['proof']['sha256']=='e44ded4324705fc9482b60898edda790e6155a646a5d9e5d7b4a139e5f41aa8e'
    assert terminal['actual_candidate_read_bytes']==249424497 and terminal['stock_sha256']==STOCK
    assert seal['fresh_sealer_small_file_reads']==105888 and seal['IMG_bytes_read_by_sealer']==0
    assert all(p[k] is False for k in ['full_Taiwan_update_complete','checksum_policy_verified','Garmin_UI_renderer_verified',
        'road_loss_rootcause_proven','installer_binding_and_package_completed','installable','full_goal_complete'])
    asts=json.loads((HERE/'AST-summary.json').read_text())
    names={x['path']:{n['name']:n for n in x['definitions']} for x in asts}
    v2=names['scripts/verify_actual_coherent8k_stock_restore_v2.py']
    assert 'extend' in v2 and not any('_materialize_control' in c for n in v2.values() for c in n['calls'])
    witnesses=[
      dict(path='scripts/verify_actual_coherent8k_stock_restore_v2.py',function='main',fact='CompleteReceiptSink extends inherited append; zero-byte protocol check before IMG open; existing descriptor exact binding; no materializer call'),
      dict(path='staging/navigation-AP-coherent-control-rollback-binding-preflight-v1/eightk_inverse_header_overlay.py',function='_verify_inverse_overlay',lines='169-190',fact='Full corrected153346048B SHA and computed inverse oldheader512+actualbody SHA required before returning view'),
      dict(path='scripts/verify_actual_coherent8k_stock_restore_v2.py',function='main',fact='Fresh view hash checks before restored_stock_blocks; generator consumed with forloop through EOF; complete stockSHA/bytes; stable fd/path pins; base.close before proof'),
      dict(path='staging/navigation-country-address-package-v3/native_8k_stock_restore.py',function='parse_layout',lines='88-150',fact='Unchanged strict geometry/header/root FAT, six-component order, allocated-block uniqueness/bounds, continuation metadata, part/allocation counts'),
      dict(path='staging/navigation-country-address-package-v3/native_8k_stock_restore.py',function='_layouts_and_header',lines='347-371',fact='Bound exactlayout/FAT prefix/MDR header600/120B six-row DIR inclwidths/count/flags; log.extend executes before return and before _restored_blocks yieldloop'),
      dict(path='staging/navigation-country-address-package-v3/native_8k_stock_restore.py',function='_restored_blocks',lines='374-415',fact='All original4K physicalblocks yield; perblock4096 requirement; original tails/unused metadata recipe; immutable identity and complete stockSHA at EOF')]
    put('dataflow-witnesses.json',dict(method='Read-only full source AST parsing plus focused manual branch review; never import or execute producer',witnesses=witnesses,
        helper_SHA='43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f',
        adapter_SHA='284b164a568edaca06707b572f0dd1f4bd2d96b913546adb56e7a99979480dbc'))
    put('proof.json',dict(schema='AP-coherent8K-actual-stock-restore-independent-artifact-review/v1',
        all_assigned_checks_passed=True,actual_independent_scope='static/dataflow and closed small-evidence consistency; no IMG recomputation',
        reviewed_root_proof_SHA=terminal['proof']['sha256'],reviewed_root_seal_SHA='0c6589d72116afc30cb575cc99b6cd366cedde48ae2875f70cbc5bf447ad6410',
        root_actual_success='835864 EXIT0/session47661',root_initial_success_chunk='7d65b6',preserved_failure='ea061f EXIT1',
        materializer_saved_actualSHA=COHERENT,verification_fresh_candidate_actualSHA=COHERENT,verification_computed_inverseSHA=V3,
        these_are_distinct_dataflow_stages=True,fresh_double_hash_gates_before_old_validator=True,
        original_strict_helper_source_unmodified=True,exact_stock_SHA=STOCK,stock_bytes=96739328,stock_blocks=23618,
        root_actual_verification_read_bytes=249424497,root_actual_verification_cap=260000000,
        root_verified_fullread_plus_restoration_reads=[153346048,96078449],receipt_sink_append_count=23448,
        append_and_extend_protocol_preflight=True,first_failure_before_any_stock_yield=True,
        previous_failed_root_source_archive_matches_current_v1_source=True,v2_no_materializer_rerun_or_new_IMG=True,
        root_fd_and_path_finalstats_and_closed_handles_consistent=True,
        root_sealer_small_reads=105888,root_sealer_full_IMG_reread=False,root_sealer_candidate_stat_inherited=True,
        first_failed_restore_counter_not_saved=True,cumulative_read_conservative_upper=816116593,
        cumulative_is_measured_actual=False,whole_pipeline_one_attempt=False,
        actual_reviewer_artifact_bytes=152275,cap=163840,initial_and_repeated_source_displays_accounted=True,
        review_failed_attempts=0,all_reviewer_source_handles_closed=True,
        zero_review_IO=dict(IMG_open=0,IMG_stat=0,IMG_data=0,producer_import_execution=0,guest=0,device=0,audio=0,report_services_canonical=0),
        all188870_content_semantics='Inherited from unchanged nonheader body/fullSHA evidence; no new perleaf/tree/UI validation here',
        limitations=['Small receipts cannot independently recompute the153MB candidate or96MB stock fullhash',
            'Actual fullhash/EOF success is supported by closed root terminal, pinned source dataflow and consistent receipts',
            'Recipe/fullgraph/188870 individual addresses not rescanned; original semantic proof inherited',
            'No GUI, renderer, routing, Garmin acceptance, install package or whole-goal success'],
        installable=False,GUI_renderer_addresses_verified=False,full_goal_complete=False))
    put('actual-tool-receipts.json',dict(initial_display=['76b507 EXIT0','62e365 EXIT0'],
        bounded_full_artifact_capture='2a663a EXIT0',focused_second_display='d3b8f8 EXIT0',
        actual_artifact_bytes=152275,IMG_open_stat_reads=0,producer_execution=0,all_source_handles_closed=True))
    (HERE/'HANDOFF.txt').write_text('Finite independent artifact/static review complete.\nRoot actual835864 verified existing coherent8K full9af and inverse1f468 before unchanged strict oldhelper; complete23618stockblocks/96739328B/864d at EOF,249424497 actualread bytes below260M.\nFirstea061f hostReceiptSink.extend omission occurs in metadata log before any stockblockyield. v2 adds protocol operation only and does not rerunmaterializer/create anotherIMG. Failedsource/receipt retained.\nMaterializer actualsavedSHA and fresh verification SHA are distinct stages. Original fd/pathpins/handlesclose and append+extend counters consistent. Rootsealer105888Bsmall+candidate stat has no fullIMG reread; reviewer performs zeroIMGstat/open/data.\nCumulative816116593 is conservative upper, not measured actual; firstfailedreadcounter unavailable, not onepass.188870 semantics inheritedunchangedbody only, no freshGUI/renderer/addresses/acceptance/installable/fullgoal.\n152275B smallinputs, ownoutputs<=64KiB; no producerimports/execution/guest/device/audio/report/services. STOP after seal.\n')
    put('sealer-receipt.json',dict(all_assigned_checks_passed=True,all_source_handles_closed=True,
        zero_original_input_reads_during_seal=True,IMG_stat=0,shared_mutations=0,STOP=True))
    pins=[]
    for path in sorted(HERE.rglob('*')):
        if not path.is_file() or path.name=='sealed-files.json':continue
        b=path.stat();raw=path.read_bytes();a=path.stat();assert fp(b)==fp(a)
        pins.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),mode=format(stat.S_IMODE(a.st_mode),'04o'),stat=fp(a)))
    put('sealed-files.json',dict(schema='AP-coherent8K-actual-restore-independent-review-seal/v1',
        all_assigned_checks_passed=True,files=pins,actual_mode_pinned_no_required444=True,all_handles_closed=True,STOP=True))
    output=sum(path.stat().st_size for path in HERE.rglob('*') if path.is_file());assert output<=65536
    for row in pins:assert fp((ROOT/row['path']).stat())==row['stat']
    print(json.dumps(dict(STOP=True,files=len(pins),input_bytes=152275,output_bytes=output,
        proof_sha256=sha((HERE/'proof.json').read_bytes()),seal_sha256=sha((HERE/'sealed-files.json').read_bytes()),
        all_handles_closed=True,IMG_open_stat_data=0)))
if __name__=='__main__':main()
