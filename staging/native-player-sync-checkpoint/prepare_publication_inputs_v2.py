#!/usr/bin/env python3
"""Prepare NEW frozen sync checkpoint inputs; no canonical/HTTP/VM actions.

Only terminal sync/SBC files, completed static contracts and frozen builds
are read. Live/growing independent SBC review files are deliberately excluded. Root alone
may execute the separately reviewed new publisher once.
"""
import ast
from datetime import datetime, timezone
from functools import lru_cache
import hashlib, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
B='staging/native-player-sync-checkpoint/'
U='staging/native-player-mixer-sync/'
I=U+'verification-v3/'
S='staging/native-player-sbc-sync/'
SOURCE=B+'prepare_publication_inputs_v2.py'
PUBLISHER='scripts/publish_native_sync_checkpoint_v2.py'
AUDIT='evidence/firmware-analysis/native-mmu-handoff-checkpoint-audit.json'
NATIVE_REGISTRY='staging/native-player-mmu-handoff-checkpoint/preserved-native-dependency-registry.json'
STOP_PROOF='staging/native-player-native-stop/static-review/original-mixer-stop-cleanup-next-contract.json'
STOP_SEAL='staging/native-player-native-stop/static-review/original-mixer-stop-static-seal.json'
def read(p):return json.loads((ROOT/p).read_text())
def fresh_sha(p):
    h=hashlib.sha256()
    with (ROOT/p).open('rb') as f:
        for b in iter(lambda:f.read(8<<20),b''):h.update(b)
    return h.hexdigest()
@lru_cache(None)
def sha(p):return fresh_sha(p)
def create(p,d):
    with (ROOT/p).open('x') as f:json.dump(d,f,ensure_ascii=False,indent=2);f.write('\n')
def main():
    assert not (ROOT/(B+'publication-inputs-v2.json')).exists()
    assert not (ROOT/(B+'previous-checkpoint.json')).exists()
    assert sha(AUDIT)=='30172683ef0c32fb1cf7a5396bba1f1e2d5e93b72f08164e9e0531f3fe6929a8'
    tree=ast.parse((ROOT/SOURCE).read_text())
    imports=[]
    for n in ast.walk(tree):
        if isinstance(n,ast.Import):imports.extend(x.name for x in n.names)
        if isinstance(n,ast.ImportFrom):imports.append(n.module)
    assert set(imports)<={'ast','datetime','functools','hashlib','json','pathlib'}
    state,task,public=[read(p) for p in ('evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json')]
    previous=read(AUDIT);app=state['native_app_music'];progress=public['research_progress']
    assert state['goal_status']==task['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining']
    assert not app['native_app_running'] and not app['direct_phone_music_verified']
    assert public['deep_research']==state and task['last_goal_turn']==state['last_goal_turn']
    assert len(app['static_findings'])==216 and len(progress['completed'])==174
    assert progress['estimate_percent']==33 and progress['phases'][4]['estimate_percent']==20
    assert sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==33
    assert previous['all_passed'] and len(previous['protected_sources'])==2031 and len(previous['selected_frozen_suites'])==49
    assert previous['native_unique_exact_dependencies']==1733
    frozen={};new_files={}
    def register(entries,destination):
        for p,h in entries.items():
            assert isinstance(p,str) and isinstance(h,str) and len(h)==64,p
            assert sha(p)==h,p
            assert p not in frozen or frozen[p]==h,p
            frozen[p]=h;destination[p]=h
    register(previous['protected_sources'],frozen)
    native=read(NATIVE_REGISTRY);assert len(native)==1733;register(native,frozen)
    def include(p):
        d=read(p);assert d['all_passed'] is True,p
        for field in ('source_sha256','output_sha256','generated_sha256','dependency_sha256'):
            if isinstance(d.get(field),dict):register(d[field],new_files)
        for c in d.get('cases',[]):
            if 'path' in c:register({c['path']:c['sha256']},new_files)
        register({p:sha(p)},new_files);return d
    root=include(U+'mixer-sync-v3-proof.json')
    assert sha(U+'mixer-sync-v3-proof.json')=='1203ebadc01d44f4199aabcf6ea7f0dbfdd82134a328e86520b459896bc59554'
    independent=include(I+'mixer-sync-v3-independent-file-verification.json')
    seal=include(I+'mixer-sync-v3-independent-file-seal.json')
    assert sha(I+'mixer-sync-v3-independent-file-verification.json')=='274a07d3606e4c046c0da6d41af21a6e1e89b62b383905815710cee41cd77a01'
    assert sha(I+'mixer-sync-v3-independent-file-seal.json')=='7ef5fd4c974a4d1720606d83cb864a279e556d112030642b18a9a15738ecd10b'
    assert root['case_count']==independent['case_count']==3
    for key,value in dict(CPU_stores=44931,joint_events=45065,full_original_native_returns=48,full_original_sync_returns=4,actual_original_condition_waits=4,actual_original_ACK8=4,actual_RW_case_replays_from_frozen_permission_recipe=69,unchanged_RX_return_sentinel_case_replays=3,actual_final_RX_dump_case_zones=9).items():assert independent[key]==value,key
    assert independent['serialized_controller_idle_endpoint_GP16_CPSR_SP_snapshots']==89
    assert independent['ordinary_controller_endpoint_GP16_CPSR_SP_serialized'] and independent['generic_mutex_or_46CC7A_syncwait_ACK_tail_bypassed'] is False
    assert not independent['native_heap_exclusive_STOP_DONE_hardware_phone_App_installation_or_complete_player_verified']
    assert independent['prior_V2_actual_suite_exit_code']==1 and independent['prior_V2_suite_all_passed'] is False
    receipt=read(U+'guest-v3-terminal-tool-receipt.json')
    assert receipt['terminal'] and receipt['started_session_id']==89948 and receipt['actual_terminal_result']['exit_code']==0 and receipt['actual_terminal_result']['chunk_id']=='925a2b'
    verifier=read(I+'mixer-sync-v3-independent-terminal-tool-receipt.json')
    assert verifier['terminal'] and verifier['started_session_id']==69431 and verifier['actual_terminal_result']['exit_code']==0 and verifier['actual_terminal_result']['chunk_id']=='ba9584'
    static=include(U+'static-review/original-mixer-sync-cold-initialization-contract.json')
    include(U+'static-review/original-mixer-sync-static-seal.json')
    include(U+'build-v2.json')
    stop=include(STOP_PROOF);stop_seal=include(STOP_SEAL)
    assert sha(STOP_PROOF)=='bc009d830ffe9ad297a59f3ce6b937ac247ac5b81e161e5cd39d35688e2c2a07'
    assert sha(STOP_SEAL)=='e78b5fc188a603fe8a71a90e74ea0311277fa952b0f549d8231d93e08661d3e5'
    assert stop['scope']['static_only'] and not stop['scope']['new_native_stop_cleanup_runtime_proof'] and not stop['scope']['native_STOP_DONE']
    assert stop_seal['static_analysis_only'] and not stop_seal['complete_native_stop_runtime_suite_verified']
    stop_gates=STOP_PROOF.rsplit('/',1)[0]+'/existing-compiled-stop-gates-and-link-contract.json';include(stop_gates)
    sbc_static=include(S+'static-review/sbc-pipeline-build-v3-peer-review.json')
    sbc_static_seal=include(S+'static-review/sbc-pipeline-build-v3-static-seal.json')
    assert sha(S+'static-review/sbc-pipeline-build-v3-peer-review.json')=='7705c4dfef585c508452cbce09a9a7c9099489823366881d5a61754e479e1700'
    assert sha(S+'static-review/sbc-pipeline-build-v3-static-seal.json')=='b12eef499499449ed3018205364f25326d9fe06505323868d3f333bc16dcfc5a'
    assert not sbc_static['guest_executed_by_reviewer'] and not sbc_static['phone_AVDTP_receiver_verified']
    sbc_root=include(S+'sbc-sync-v1-proof.json')
    assert sha(S+'sbc-sync-v1-proof.json')=='a4e7d6400f5ad67277b537ff9407b8ac8c1e3524aa33bbb6e0edd026002f8ad0'
    assert sbc_root['case_count']==6 and not sbc_root['independent_FILE_verification_complete']
    assert sbc_root['compiled_compressed_packet_SBC_FIR_and_typed_FIFO_to_original_mixer'] and sbc_root['expected_PCM_was_never_written_to_guest']
    assert not sbc_root['physical_speaker_phone_App_installation_or_complete_player_verified'] and not sbc_root['native_heap_exclusive_or_STOP_DONE_verified']
    sbc_runtime=read(S+'ROOT-runtime-v1-metrics.json')
    assert sbc_runtime['all_ROOT_cases_passed'] and not sbc_runtime['independent_FILE_review_complete']
    assert sbc_runtime['totals']==dict(instructions=4671894,CPU_stores=412189,joint_events=412491,tracked_zones=156,decoder_full_returns=34,successful_decoder_returns=33,full_native_returns=128,full_sync_returns=7,native_output_bytes=28672,source_PCM_bytes=4206)
    sbc_guest_receipt=read(S+'guest-v1-terminal-tool-receipt.json')
    assert sbc_guest_receipt['terminal'] and sbc_guest_receipt['started_session_id']==35422 and sbc_guest_receipt['actual_terminal_result']['exit_code']==0 and sbc_guest_receipt['actual_terminal_result']['chunk_id']=='27fd35'
    sbc=include(S+'build-v3.json')
    assert not sbc['guest_executed'] and not sbc['complete_player_image'] and not sbc['raw_PCM_test_producer']
    assert sbc['compiled_SBC_RTP_decode_and_typed_FIFO_producer'] and sbc['undefined_symbols']==[]
    assert sbc['ELF_sha256']=='c170e77c216abb44e6a6570034768ce00deb3226b20d1bd0349b70d1e564a4eb'
    register({sbc['ELF']:sbc['ELF_sha256']},new_files)
    sbcr=read(S+'build-v3-terminal-tool-receipt.json')
    assert sbcr['terminal'] and sbcr['started_session_id']==42518 and sbcr['actual_terminal_result']['exit_code']==0 and sbcr['actual_terminal_result']['chunk_id']=='df6a7a'
    # Exact allowlist: SBC ROOT V1 is terminal. No live independent review or
    # growing case/temp files are read. Failed build history remains explicit.
    for p in (U+'guest-v3-terminal-tool-receipt.json',I+'mixer-sync-v3-independent-terminal-tool-receipt.json',I+'mixer-sync-v3-independent-sealer-terminal-tool-receipt.json',S+'build-v3-terminal-tool-receipt.json',S+'guest-v1-terminal-tool-receipt.json',S+'ROOT-runtime-v1-metrics.json',S+'guest-v1/inputs-at-run.json',S+'guest-v1/runner-at-run.py',S+'build-v1-terminal-tool-receipt.json',S+'build-v2-terminal-tool-receipt.json',B+'prepare_publication_inputs_v1.py','scripts/publish_native_sync_checkpoint_v1.py',B+'historical-v1-unexecuted-draft.json',SOURCE,PUBLISHER,AUDIT):register({p:sha(p)},new_files)
    assert read(S+'guest-v1/inputs-at-run.json')==sbc_root['source_sha256']
    assert sha(S+'guest-v1/runner-at-run.py')==sha(S+'emulate_sbc_sync_v1.py')
    for version in (1,2,3):
        for p in sorted((ROOT/(S+f'build-v{version}')).rglob('*')):
            if p.is_file():register({str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT)))},new_files)
    findings={}
    rows=[
        ('native_mixer_sync_compiled_CONFIG_PLAY_bridge_v2',U+'build-v2.json','Compiled ARM CONFIG handoff before original3B9C54→46CC7A, preserving arguments and original LR; PLAY opens only after full initializer returns. Bounded companion, not installation candidate.','bounded_ARM_companion_build'),
        ('native_mixer_sync_direct_cold_inputs_static',U+'static-review/original-mixer-sync-cold-initialization-contract.json','Exact Taiwan MAIN static native Timer/rawmutex/condition constructor and infiniteACK8 ABI contract. Direct boot inputs are declared; Timer retains condition token without register/post/scheduling.','independent_original_static_contract'),
        ('native_mixer_sync_actual_ACK8_three_cases',U+'mixer-sync-v3-proof.json','ROOT session89948 EXIT0/925a2b:3 scoped original rawmutex/conditionwait/ACK8 cases,4 full46CC7A returns and48 fullpulls; new/existingM+78 paths,4 guest-only BL redirects; opaque/hardware/outputconsumer boundaries remain.','declared_guest_scoped_kernel_sync_cases'),
        ('native_mixer_sync_independent_whole_memory_and_returns',I+'mixer-sync-v3-independent-file-verification.json','Independent FILE terminalEXIT0/ba9584:44931 CPUstores/45065 events/69RW+3 RX sentinel replays,9 actualfinalRX dumps/89 endpointGP snapshots, native saved52B frames/ACKpreemption/recontention/prioritydonation/unlocktransfer/4 fullsync returns; no guest rerun.','independent_scoped_sync_file_verification'),
        ('native_mixer_sync_prior_v2_completed_case_and_failed_suite',I+'mixer-sync-v3-independent-file-verification.json','V2 first32-pull/fullsync case separately file-replayed; wholeROOTsuite actualEXIT1/d946b9 due to compiled request1..6 rejecting command7. Five failed FILE reviewer sources/actualreceipts preserved; neither prior case nor failed reviewer counts inflate V3 suite.','frozen_terminal_lineage_and_separate_prior_case_review'),
        ('native_mixer_Stop_next_original_contract',STOP_PROOF,'17 boundedstatic CFGs/572 originalinstructions:Source sends ordered15/19 then direct46CC7A command20/ACK8 barrier before original277674 source-list removal. Notice23 precedes listcount/fullreturn and is not quiescence; no Stopruntime/STOP_DONE/hardwaredrain proof.','independent_original_Stop_static_next_contract'),
        ('native_mixer_Stop_existing_gate_and_link_requirements',stop_gates,'Static compiledStop gate/GC link contract:retain held session/registration and cleanup leases through actual native retirement; oldStop is PENDING, required mutation/cancel symbols need NEW linked callers; no syntheticSTOP_DONE.','static_compiled_Stop_gate_and_link_contract'),
        ('native_SBC_sync_build_v3_compile_only',S+'build-v3.json','Actual compile/link EXIT0/df6a7a, ELF c170e77c…; compiled compressedRTP/SBC/FIR and typedFIFO lease/coherence source, zero undefinedsymbols. This selected build is compile-only: no SBCguest result or physicalApp/audio claim.','compile_only_ARM_SBC_sync_image'),
        ('native_SBC_pipeline_build_v3_static_peer_review',S+'static-review/sbc-pipeline-build-v3-peer-review.json','FILE/static-only47 sources/21 compile receipts/16 ELF function opcode ranges,18 normal+3 badCRC packets and wholepacket typedFIFO publication/lease/coherence contract. Originalphone receiver→Source POST/WAIT/capacity/lifetime is not connected; no SBCruntime independentreplay by this staticreview.','independent_static_SBC_pipeline_contract'),
        ('native_SBC_sync_ROOT_six_cases',S+'sbc-sync-v1-proof.json','ROOT session35422 EXIT0/27fd35:6 bounded compiled compressedRTP/SBC/FIR Source12→typedFIFO→originalmixer cases,34 decoderreturns/128 fullpulls/7 fullsync/4206 sourcePCMbytes. ROOTassertions only; independentFILE pending, no actualphone/heap/exclusive/STOP_DONE/hardware/App.','ROOT_declared_scoped_SBC_sync_cases'),
    ]
    for key,p,scope,kind in rows:
        assert key not in app['static_findings'];d=include(p)
        findings[key]=dict(path=p,sha256=sha(p),scope=scope,evidence_type=kind,pass_field='all_passed',physical_App_or_audio_verified=False,device_io=False)
    details=[
        '原3B9C54→46CC7A前的compiled bridge先grant CONFIG並保留原參數／LR，原3B9B66完整返回後才開PLAY；3組真ARM案例涵蓋新與既有M+78路徑，既有路徑grants1／reuses1。',
        '原Timer／raw mutex／condition constructors真正執行；Timer保留condition token但沒有register、post或排程。這些是明示direct boot inputs，尚未執行完整原26A016冷初始化。',
        '原條件等待、message20與mixer ACK8共4次真完整同步返回；ACK POST8會先搶先mixer，source再競爭並阻塞，原有效priority捐贈與mutex解鎖移交後source才完整返回。',
        '獨立純檔案核對44931筆CPU stores／45065共同事件及48次完整音訊返回；72次tracked-zone重建是69次真RW＋3次不變RX sentinel，另有9個實際finalRX dumps與89個controller／idle endpoint GP／SP／CPSR快照。',
        '原native contention／unlock saver實際保存13 words／52 bytes、format0；READY已切到下一工作後才存outgoing context，不能把current READY誤當被保存的TCB。infinite ACK8窗口不arm timednode，後段正常mixer timed WAIT可合法入列。',
        'sync V2首個32-pull／fullsync案例另獨立重建，但完整suite仍保留EXIT1：compiled request範圍1..6拒絕command7。五次FILE reviewer前提錯誤來源與actual receipts保留，未重跑guest、未算成額外成功suite。',
        '原Stop下一契約新增17個靜態CFG／572條原指令：source按序送15／19，再直接46CC7A的20／ACK8屏障，完整返回後才刪原source list；不能呼叫會再送13重選的3B9B66。原notice23早於count減少與外層unlock完整返回，不能當回收屏障。尚未執行新的native Stop cleanup／STOP_DONE。',
        '現有Stop只關閉新PLAY／producer admission並回PENDING；cleanup須保留session／registration／native_calls與storage leases。部分mutation／cancel符號在舊ELF被GC移除，下一映像須由真compiled caller保留，不能以C名稱推可呼叫或偽造STOP_DONE。',
        '新版SBC同步映像實際編譯／連結成功、ELF c170e77c…且無未解析符號；壓縮封包進入compiled Source12，expected PCM只存在host參考JSON，未寫入guest。',
        'ROOT SBC guest實際EXIT0／27fd35，6組有界案例通過：mono16k、joint-stereo44.1k、stereo48k及Stop／後段CRC拒絕恢復／profile撤銷；34次decoder完整返回中33次成功，128次原fullpull、7次原fullsync、4206bytes真source PCM。新SBC suite尚未獨立FILE核對，不能沿用原sync seal當作其證明。',
        '新版SBC pipeline另有純static來源／ELF／typed-input核對：47份來源、21個compile receipts、16段函式opcode與18個正常／3個後段CRC封包；整包FIFO publication與callback一致性契約可定位。真正receiver→Source POST／WAIT、capacity通知與跨actor lifetime仍待接線，static seal不能當SBC runtime獨立核對。',
        '本輪不證明原生heap、channel獨占、native STOP_DONE或硬體音訊；opaque allocation／policy、output activation／ring consumer及reset transport仍有明示fixture。既有MMU軟體／實體page限制保留，整體33%／App20%／goal active。',
    ]
    # All selected proof/seal/receipt/registry validation precedes new snapshots.
    snapshots=[]
    originals=[('evidence/deep-research-state.json','previous-state.json'),('evidence/task-state.json','previous-task.json'),('reports/findings.json','previous-public.json'),('reports/nuvi2565RT.html','previous-report.html'),(AUDIT,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]
    for original,name in originals:
        snapshot=B+name;raw=(ROOT/original).read_bytes();h=hashlib.sha256(raw).hexdigest();assert h==fresh_sha(original)
        with (ROOT/snapshot).open('xb') as f:f.write(raw)
        assert sha(snapshot)==h;snapshots.append(dict(original=original,snapshot=snapshot,sha256=h))
    create(B+'previous-checkpoint.json',dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),snapshots=snapshots,findings=216,public_details=174,estimate_percent=33,App_estimate_percent=20,goal_status='active',canonical_write=False,HTTP_action=False))
    create(B+'preserved-protected-file-registry.json',previous['protected_sources'])
    create(B+'preserved-native-dependency-registry.json',native)
    for p in (B+'previous-checkpoint.json',B+'preserved-protected-file-registry.json',B+'preserved-native-dependency-registry.json',*[r['snapshot'] for r in snapshots]):register({p:sha(p)},new_files)
    scope=dict(included=True,case_count=3,ROOT_terminal_session=89948,ROOT_terminal_chunk='925a2b',independent_terminal_session=69431,independent_terminal_chunk='ba9584',CPU_stores=44931,joint_events=45065,fullpull_returns=48,fullsync_returns=4,condition_waits=4,ACK8=4,true_RW_replays=69,RX_sentinel_replays=3,actual_final_RX_dump_zones=9,endpoint_GP_snapshots=89,direct_constructor_boot_inputs=True,complete_original_cold_boot=False,Timer_scheduled=False,generic_mutex_sync_bypass=False,native_heap_exclusive_STOP_DONE_hardware_phone_App_verified=False)
    manifest=dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),preparation_source=SOURCE,preparation_source_sha256=sha(SOURCE),canonical_snapshot=B+'previous-checkpoint.json',canonical_before_counts=dict(findings=216,public_details=174,estimate_percent=33,App_estimate_percent=20),frozen_files_sha256=frozen,new_files_sha256=new_files,findings=findings,public_details=details,projected_counts=dict(findings=216+len(findings),public_details=174+len(details)),preserved_protected_file_count=2031,preserved_complete_suite_count=49,preserved_native_unique_exact_dependencies=1733,preserved_selected_frozen_suites=previous['selected_frozen_suites'],preserved_protected_registry=B+'preserved-protected-file-registry.json',preserved_native_dependency_registry=B+'preserved-native-dependency-registry.json',new_complete_cold_suites=[],new_music_sync_declared_scoped_suites=[dict(path=U+'mixer-sync-v3-proof.json',sha256=sha(U+'mixer-sync-v3-proof.json'),case_count=3,scope='Original mutex/condition/ACK8 boundedkernel cases; direct constructors/fourguestredirections, not fullcoldboot or actualplayer.')],sync_scope=scope,native_Stop_static_contract=dict(path=STOP_PROOF,sha256=sha(STOP_PROOF),runtime_Stop_or_STOP_DONE_verified=False),SBC_build_scope=dict(path=S+'build-v3.json',sha256=sha(S+'build-v3.json'),ELF=sbc['ELF'],ELF_sha256=sbc['ELF_sha256'],actual_compile_session=42518,actual_compile_terminal_chunk='df6a7a',selected_build_guest_executed=False,SBC_guest_result_included=True,physical_App_or_audio_verified=False),SBC_static_contract=dict(path=S+'static-review/sbc-pipeline-build-v3-peer-review.json',sha256=sha(S+'static-review/sbc-pipeline-build-v3-peer-review.json'),static_only=True,phone_receiver_Source_event_capacity_typed_lifetime_connected=False),SBC_ROOT_scope=dict(path=S+'sbc-sync-v1-proof.json',sha256=sha(S+'sbc-sync-v1-proof.json'),actual_terminal_session=35422,actual_terminal_chunk='27fd35',actual_exit_code=0,case_count=6,ROOT_metrics=sbc_runtime['totals'],independent_FILE_review_complete=False,expected_PCM_written_to_guest=False,actual_phone_ingress_or_App_hardware_verified=False,native_heap_exclusive_STOP_DONE_verified=False),new_SBC_declared_scoped_suites=[dict(path=S+'sbc-sync-v1-proof.json',sha256=sha(S+'sbc-sync-v1-proof.json'),case_count=6,scope='ROOTactualboundedcompressedpacketSBC/FIR Source12/originalmixer cases; independentFILE pending, no fullcoldboot/phone/App/hardware.')],previous_goal_turn_classification='progress',previous_goal_turn_reason='User map-layer explanation turn also actually observed SBC build-v3 session42518 terminal EXIT0/df6a7a and wrote its actual terminal receipt.',publication_constraints=dict(estimate_percent=33,App_estimate_percent=20,goal_status='active',full_goal_complete=False,canonical_write=False,HTTP_action=False,guest_execution=False,old_sources_or_proofs_modified=False,growing_SBC_guest_JSON_read=False),root_next_actions=['Review this frozen preparation and actual terminal receipt; NEWpublisher only, no old source reruns.','Review syncV3 independentseal, staticStop scope and actual ROOT SBC terminal receipt. Independent SBCFILE review remains pending and requires NEW bundle/version.','Root may execute the reviewed NEW publisher once; fresh servicePID/HTTP/local-served hashes and uncached canonical readback are required.'])
    create(B+'publication-inputs-v2.json',manifest)
    for r in snapshots:assert fresh_sha(r['original'])==r['sha256'],'Concurrent canonical mutation '+r['original']
    print(json.dumps(dict(all_passed=True,file_only=True,guest_execution=False,canonical_write=False,HTTP_action=False,new_findings=len(findings),public_details=len(details),projected_counts=manifest['projected_counts'],preserved_protected_files=2031,selected_complete_suites=49,native_dependencies=1733,merged_frozen_paths=len(frozen),preparation_source=SOURCE,preparation_source_sha256=sha(SOURCE),output=B+'publication-inputs-v2.json',output_sha256=sha(B+'publication-inputs-v2.json'))))
if __name__=='__main__':main()
