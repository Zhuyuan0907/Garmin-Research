#!/usr/bin/env python3
"""NEW FILE-only preparation. ROOT alone runs the reviewed NEW publisher.

Only explicitly selected terminal files are read. No guest/emulator/HTTP import,
canonical edit, daemon/device action or old source rerun. This source is frozen
after its first terminal execution; subsequent changes require a NEW version.
"""
import ast
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
B='staging/native-player-ingress-checkpoint/'
G='staging/native-player-sbc-ingress/'
R=G+'static-review/'
I='staging/native-player-sbc-sync/verification-v1/'
SOURCE=B+'prepare_publication_inputs_v1.py'
PUBLISHER='scripts/publish_native_ingress_checkpoint_v1.py'
SELECTION=B+'ROOT-terminal-selection-v1.json'
AUDIT='evidence/firmware-analysis/native-sync-SBC-ROOT-checkpoint-audit.json'
NATIVE_REGISTRY='staging/native-player-sync-checkpoint/preserved-native-dependency-registry.json'

def read(path):return json.loads((ROOT/path).read_text())
def fresh_sha(path):
    h=hashlib.sha256()
    with (ROOT/path).open('rb') as handle:
        for chunk in iter(lambda:handle.read(8<<20),b''):h.update(chunk)
    return h.hexdigest()
@lru_cache(None)
def immutable_sha(path):return fresh_sha(path)
def create(path,data):
    with (ROOT/path).open('x') as f:json.dump(data,f,ensure_ascii=False,indent=2);f.write('\n')

def main():
    assert not (ROOT/(B+'publication-inputs-v1.json')).exists()
    assert not (ROOT/(B+'previous-checkpoint.json')).exists()
    assert immutable_sha(AUDIT)=='8dd85d3a008a69b68d949b2a95a4e0ebc39519ab24eaa952515f535fc38f8951'
    modules=[]
    for node in ast.walk(ast.parse((ROOT/SOURCE).read_text())):
        if isinstance(node,ast.Import):modules.extend(x.name for x in node.names)
        if isinstance(node,ast.ImportFrom):modules.append(node.module)
    assert set(modules)<={'ast','datetime','functools','hashlib','json','pathlib'}
    selection=read(SELECTION)
    assert selection['all_passed'] and selection['terminal_selection_complete']
    assert not selection['guest_executed_by_preparation_agent']
    for path,digest in selection['selected_files_sha256'].items():assert immutable_sha(path)==digest,path
    selected_receipt=read(selection['actual_ROOT_receipt'])
    assert selected_receipt['terminal'] and selected_receipt['started_session_id']==selection['actual_ROOT_session']
    actual=selected_receipt['actual_terminal_result']
    assert actual['exit_code']==selection['actual_ROOT_exit_code'] and actual['chunk_id']==selection['actual_ROOT_chunk']
    assert selection['proof_or_completed_case_scope_is_ROOT_only']
    state,task,public=[read(p) for p in ('evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json')]
    old=read(AUDIT);app=state['native_app_music'];progress=public['research_progress']
    assert state['goal_status']==task['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining']
    assert not app['native_app_running'] and not app['direct_phone_music_verified']
    assert public['deep_research']==state and task['last_goal_turn']==state['last_goal_turn']
    assert len(app['static_findings'])==226 and len(progress['completed'])==186
    assert progress['estimate_percent']==33 and progress['phases'][4]['estimate_percent']==20
    assert sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==33
    assert old['all_passed'] and len(old['protected_sources'])==2531
    assert len(old['selected_frozen_suites'])==49 and old['native_unique_exact_dependencies']==1733
    frozen={};new_files={}
    def register(entries,destination):
        for path,digest in entries.items():
            assert isinstance(path,str) and isinstance(digest,str) and len(digest)==64,path
            assert immutable_sha(path)==digest,path
            assert path not in frozen or frozen[path]==digest,path
            frozen[path]=digest;destination[path]=digest
    register(old['protected_sources'],frozen)
    native=read(NATIVE_REGISTRY);assert len(native)==1733;register(native,frozen)
    def include(path):
        d=read(path);assert d['all_passed'] is True,path
        for field in ('source_sha256','output_sha256','generated_sha256','dependency_sha256'):
            if isinstance(d.get(field),dict):register(d[field],new_files)
        for case in d.get('cases',[]):
            if 'path' in case:register({case['path']:case['sha256']},new_files)
        register({path:immutable_sha(path)},new_files);return d
    sbc=include(I+'sbc-sync-v1-independent-file-verification.json')
    seal=include(I+'sbc-sync-v1-independent-file-seal.json')
    assert immutable_sha(I+'sbc-sync-v1-independent-file-verification.json')=='b60179c4ece53bf0b3ce82682b5a029d69a7b2b0af38cdf013fa297ceca2ca0c'
    assert immutable_sha(I+'sbc-sync-v1-independent-file-seal.json')=='e83c8a5116ba1e6a0dd7918a5bf2feb385337e54a9564929bb2210b8be45fdfa'
    assert sbc['independent_FILE_ONLY'] and seal['independent_FILE_ONLY'] and sbc['case_count']==6
    expected=dict(CPU_stores=412189,joint_events=412491,tracked_whole_zones=156,
        actual_RW_zones_from_frozen_parent_permission_recipe=150,unchanged_RX_return_sentinel_tracked_as_RW=6,
        actual_final_RX_dump_zones=18,actual_decoder_full_returns=34,actual_successful_decoder_returns=33,
        actual_failed_decoder_returns=1,full_original_returns=128,full_original_sync_returns=7,
        actual_original_condition_waits=7,actual_original_ACK8=7,music_bytes=4206,
        underrun_silence_bytes=24466,total_output_bytes=28672,actual_original_and_ELF_instruction_visits=4671894)
    assert sbc['totals']==expected
    assert sbc['per_copy_live_guard_totals']['PCM_COPYING_bytes']==4206 and sbc['per_copy_live_guard_totals']['Mixer_copy_inflight_bytes']==4206
    assert sbc['per_copy_live_guard_totals']['whole_FIFO_READY_publications']==16
    assert sbc['per_copy_live_guard_totals']['whole_compressed_queue_publications']==18
    assert not sbc['actual_phone_AVDTP_receiver_or_installed_App_or_hardware_speaker_verified']
    assert not sbc['native_heap_exclusive_STOP_DONE_or_safe_unload_verified']
    assert not sbc['guest_rerun'] and not sbc['VM_import_or_instantiation']
    assert seal['actual_verifier_session']==36517 and seal['actual_verifier_terminal_chunk']=='53d269' and seal['actual_verifier_exit_code']==0
    receiver=include(R+'native-receiver-to-compiled-ingress-contract.json')
    include(R+'native-receiver-static-seal.json')
    assert immutable_sha(R+'native-receiver-to-compiled-ingress-contract.json')=='d7fff2d5f3f75c570adad92976c12793831697108537ff31afe16de285b215a9'
    assert not receiver['application_SEP_publication']['recovered_original_registration_API']
    assert not receiver['callback_lifetime']['clearing_SEP_callback_is_quiescence']
    assert not receiver['generation_and_remoteStart']['state8_or_event17_alone_opens_remoteStart']
    assert not receiver['cold_warm_and_channel8']['cold_inputs_are_warm_module_boot']
    peer=include(R+'ingress-source-v1-peer-review.json');include(R+'ingress-source-static-seal.json')
    assert peer['static_review_completed'] and not peer['guest_executed_by_reviewer']
    assert peer['v1_ABI_erratum']['concrete_runtime_blocker_found']
    assert peer['V2_source_only_repair_addendum']['exact_V1_to_V2_change_checked']
    assert not peer['actual_phone_ingress_verified'] and not peer['native_STOP_DONE_verified']
    # Old peer describes owner-v1's leases spanning POST, NOT the new owner-v2.
    assert 'while ingress leases remain held' in ' '.join(peer['source_contract']['external_packet_to_native_start'])
    build=include(G+'build-v3.json')
    assert build['ELF_sha256']=='9b767b808d0ffe58774e3a26266be1865a81d34a6e938d0c3d726c0fd63f4612'
    assert not build['guest_executed']
    register({build['ELF']:build['ELF_sha256']},new_files)
    register(selection['selected_files_sha256'],new_files)
    for path in [SOURCE,PUBLISHER,SELECTION,AUDIT,
        I+'sbc-sync-v1-independent-source-output-ledger.json',I+'sbc-sync-v1-independent-terminal-tool-receipt.json',
        I+'sbc-sync-v1-independent-sealer-terminal-tool-receipt.json',
        R+'native-receiver-static-source-output-ledger.json',R+'native-receiver-static-terminal-tool-receipt.json',
        R+'native-receiver-static-sealer-terminal-tool-receipt.json',R+'native-receiver-exact-source-fragments.json',
        R+'ingress-source-static-source-output-ledger.json',R+'ingress-source-static-terminal-tool-receipt.json',
        R+'ingress-source-static-sealer-terminal-receipt.json']:
        register({path:immutable_sha(path)},new_files)
    # Build directories are completed frozen compiler artifacts. Guest files
    # are ONLY registered through the explicit ROOT terminal allowlist above.
    for version in (1,2,3):
        for path in sorted((ROOT/(G+f'build-v{version}')).rglob('*')):
            if path.is_file():
                relative=path.relative_to(ROOT).as_posix();register({relative:immutable_sha(relative)},new_files)
    findings={}
    rows=[
      ('native_SBC_six_cases_independent_FILE_replay',I+'sbc-sync-v1-independent-file-verification.json',
       'NEW independent FILE-only review of six frozen ROOT SBC cases:412189 CPU stores/412491events,150RW+6RXsentinels,18actualfinalRX,34decoder fullreturns(33success/1CRC),128fullpull/7fullsync. No rerun, all4671894 controlflow instructions not independently traced.','independent_scoped_SBC_FILE_runtime_review'),
      ('native_SBC_wholepacket_COPYING_and_inflight_file_guards',I+'sbc-sync-v1-independent-file-verification.json',
       'Whole copied compressedqueue/PCM FIFO publication independently readback:18packet/16FIFO publications,4206PCM COPY byteguards and4206Mixer in-flight byteguards; CRC0/-6 returns with no FIFO prefix, fresh reset-reference recovery.4206music+24466explicit silence, not all output music.','independent_FILE_copy_and_wholepacket_publication_review'),
      ('native_SBC_original_ACK8_and_return_file_recheck',I+'sbc-sync-v1-independent-file-verification.json',
       'Actual original rawmutex/condition/ACK8 preemption/recontention/priority donation/native unlocktransfer, finalRX and serialized controller/fullnative/outer/sync return registers checked in SBC six-case frozen evidence. Native ownership/unload not proved.','independent_SBC_scoped_native_return_and_memory_review'),
      ('native_receiver_original_L2CAP_registration_static',R+'native-receiver-to-compiled-ingress-contract.json',
       'Exact MAIN4CCC3C→50C150 registers PSM25 descriptor+20 callback50BBB9; nonempty50BBB8→50BBC0→525138→42758E BXr7. This native L2CAP layer differs from application SEP callback publication; static-only new review.','exact_original_receiver_static_contract'),
      ('native_receiver_compiled_SEP_provider_and_lifetime_contract',R+'native-receiver-to-compiled-ingress-contract.json',
       'Historical compiled custom provider creates callback/capability SEP under originalmutex, then separately SDP90007; original SEP API unrecovered. Cached callback before unlock requires pinned code/barrier; rejectedStart state8/event17 and pendingOpen alone cannot grant remoteStart/session.','static_compiled_endpoint_and_callback_generation_contract'),
      ('native_ingress_Stage1_warm_cold_and_channel8_contract',R+'native-receiver-to-compiled-ingress-contract.json',
       'Publish new provider only after guarded resident Stage1 decoder/queue/Source READY. First externalpacket owns Source decode/register/start/fullsync. Broad277E21+18×269F6D cold inputs cannot be a warm loader recipe; channel8 active/exclusive ownership remains unproved.','static_Stage1_publication_and_warm_ownership_contract'),
      ('native_ingress_source_peer_ABI_and_POST_scope',R+'ingress-source-v1-peer-review.json',
       'Static peer found37BCE5 returns unnormalized POSTr0, not queue error; compiledsourcev2 repairs transport cast. Peer owner-v1 describes foreign typed leases spanning POST; it does not prove NEW owner-v2 release-before-POST fix. CapacityPOST may suspend Mixer borrowed frame.','static_ingress_source_peer_and_ABI_erratum'),
      ('native_ingress_build_v3_compile_only',G+'build-v3.json',
       'Actual NEW ARM image ELF9b767b80… compiled successfully; sourceowner_v2 releases borrowed input leases after copy/coherence before SourcePOST. Build success alone is not receiver execution, callback quiescence or installation.','compile_only_new_ingress_source_image'),
      ('native_ingress_ROOT_selected_terminal_scope',SELECTION,
       selection['finding_scope'],'ROOT_selected_scoped_ingress_terminal_facts')]
    for key,path,scope,kind in rows:
        assert key not in app['static_findings']
        include(path)
        findings[key]=dict(path=path,sha256=immutable_sha(path),scope=scope,evidence_type=kind,pass_field='all_passed',physical_App_or_audio_verified=False,device_io=False)
    details=[
      '新版SBC六組已有獨立FILE核對：412189筆CPU stores／412491共同事件，150次真RW＋6次不變RX sentinel、18個actual finalRX dumps；34次decoder完整返回中33成功＋1CRC、128次原fullpull及7次原同步／ACK8。4671894指令是ROOT訪問計數，不是全部非store controlflow獨立驗證。',
      '獨立讀回18次compressedqueue整包publication、16次FIFO READY publication及4206bytes COPY／4206bytesMixer in-flight guard；後段CRC實際decoder返回0／−6而FIFO沒有prefix，恢復比對fresh reset reference。輸出4206bytes真source PCM＋24466bytes明示silence，不能全算音樂。',
      '新SBC FILE review另核對原rawmutex／condition／ACK8的搶先、競爭再阻塞、優先權捐贈、解鎖移交及原完整返回；finalRX與controller／native／outer／sync GP／SP／CPSR已序列化。三次FILE reviewer前提失敗及實際receipts保留，不重跑guest。',
      '原4CCC3C透過50C150登記L2CAP PSM25的52-byte descriptor，callback+0x20=50BBB9；非空封包走50BBB8→50BBC0→525138→42758E的BX r7。這是原L2CAP receiver registration，與SEP+0的application callback登記分開。',
      '既有自製compiled SEP provider在原mutex內填callback／MTU／capability，最後設state1，再分開unlock並原607F9C啟用SDP90007；不是host先種pointer，也不是已找到原SEP registration API。舊固定caps只提供44.1／48kHz協商，16k fixture不能據此稱可由該端點協商。',
      '原media／Start／disconnect在unlock前已cache callback target；清空SEP pointer或只數已進入callback的refs不代表可卸載。必須保留module／TCB／stack與typed generation／borrowed-data期限，等待原dispatcher與consumer真正quiescence。',
      '原Start拒絕回覆成功送出後仍可寫state8並callback17；pending Open也曾送成功media。新remoteStart須用同一validated configuration／session epoch及channel／peer／callback coherence，不能只看state8、event17或LCID重用。',
      '新端點publication應在單次resident載入、保留原40TTS介面、preaccept Configure／Start及Stage1 decoder／queue／guard／Source READY後進行；第一個external copied packet才由Source解碼／register／native start及完整sync，PLAY等完整返回後開啟。靜態契約不證新Stage1已在實機接通。',
      '277E21＋18次269F6D是明示cold guest boot inputs；暖機載入不能重設全音訊／其他channel。channel8既有source／mixer activity、持續獨占與profile mutation權限仍須查證，瞬間mutex不等於durable ownership。',
      'Ingress來源peer找到37BCE5的R0是未正規化POST結果，非可靠queue send-error；sourcev2已以void transport ABI修正。該peer仍描述owner-v1跨POST保留foreign leases，不得拿來證新owner-v2修復。capacity POST可先搶先仍持borrow的Mixer，producer與Mixer leases須分別核對，不能用Source返回冒稱Mixer也返回。',
      'NEW ingress build-v3只證ARM編譯成功，ELF9b767b80…；borrowed packet／handle leases在copy及coherence後、Source POST前結束，module／TCB仍pinned，尚無完整callback quiescence／safe unload。',
      *selection['public_details'],
      '原SEP登記API、真手機input、warm channel8所有權、原生heap／exclusive／STOP_DONE／喇叭／可安裝App仍未證明；Stage1與有界source event不能縮成完整原機cold／warm。整體33%／App20%、完整goal active，既有49 complete/cold-prefix suites另保留。']
    snapshots=[]
    for original,name in [('evidence/deep-research-state.json','previous-state.json'),('evidence/task-state.json','previous-task.json'),('reports/findings.json','previous-public.json'),('reports/nuvi2565RT.html','previous-report.html'),(AUDIT,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]:
        raw=(ROOT/original).read_bytes();digest=hashlib.sha256(raw).hexdigest();assert fresh_sha(original)==digest
        path=B+name
        with (ROOT/path).open('xb') as f:f.write(raw)
        assert immutable_sha(path)==digest;snapshots.append(dict(original=original,snapshot=path,sha256=digest))
    create(B+'previous-checkpoint.json',dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),snapshots=snapshots,findings=226,public_details=186,estimate_percent=33,App_estimate_percent=20,goal_status='active',canonical_write=False,HTTP_action=False))
    create(B+'preserved-protected-file-registry.json',old['protected_sources'])
    create(B+'preserved-native-dependency-registry.json',native)
    for path in [B+'previous-checkpoint.json',B+'preserved-protected-file-registry.json',B+'preserved-native-dependency-registry.json',*[r['snapshot'] for r in snapshots]]:register({path:immutable_sha(path)},new_files)
    manifest=dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),preparation_source=SOURCE,preparation_source_sha256=immutable_sha(SOURCE),
        canonical_before_counts=dict(findings=226,public_details=186,estimate_percent=33,App_estimate_percent=20),canonical_snapshot=B+'previous-checkpoint.json',
        frozen_files_sha256=frozen,new_files_sha256=new_files,findings=findings,public_details=details,
        projected_counts=dict(findings=226+len(findings),public_details=186+len(details)),
        preserved_protected_file_count=2531,preserved_complete_suite_count=49,preserved_native_unique_exact_dependencies=1733,
        preserved_selected_frozen_suites=old['selected_frozen_suites'],new_complete_cold_suites=[],
        preserved_protected_registry=B+'preserved-protected-file-registry.json',preserved_native_dependency_registry=B+'preserved-native-dependency-registry.json',
        new_independent_SBC_FILE_scope=dict(path=I+'sbc-sync-v1-independent-file-verification.json',sha256=immutable_sha(I+'sbc-sync-v1-independent-file-verification.json'),seal=I+'sbc-sync-v1-independent-file-seal.json',independent_FILE_ONLY=True,totals=sbc['totals'],copy_guard_totals=sbc['per_copy_live_guard_totals'],existing_ROOT_case_count=6,new_guest_case_count=0),
        receiver_static_contract=dict(path=R+'native-receiver-to-compiled-ingress-contract.json',sha256=immutable_sha(R+'native-receiver-to-compiled-ingress-contract.json'),static_only=True),
        ingress_source_static_peer=dict(path=R+'ingress-source-v1-peer-review.json',sha256=immutable_sha(R+'ingress-source-v1-peer-review.json'),static_only=True,new_owner_v2_release_before_POST_verified=False),
        ingress_build_scope=dict(path=G+'build-v3.json',sha256=immutable_sha(G+'build-v3.json'),ELF=build['ELF'],ELF_sha256=build['ELF_sha256'],compile_only=True),
        ROOT_ingress_selection=selection,new_declared_ingress_scoped_suites=selection['declared_scoped_suites'],
        previous_goal_turn_classification='progress',previous_goal_turn_reason='Previous checkpoint ROOT SBC six-case terminal/receipts and actual publication advanced frozen research; this turn adds independent FILE seal and receiver/ingress contracts plus selected ROOT ingress terminal facts.',
        publication_constraints=dict(estimate_percent=33,App_estimate_percent=20,goal_status='active',full_goal_complete=False,canonical_write=False,HTTP_action=False,guest_execution=False,growing_guest_JSON_read=False,old_sources_or_proofs_modified=False),
        root_next_actions=['Review frozen input/source/actual preparation receipt; only ROOT executes NEW publisher once.','Keep ROOT ingress scoped cases separate from49 existing complete/cold-prefix suites; independent oldSBC FILE evidence is not newingress FILE proof.','Freshly verify existing service PID/HTTP no-store/local-served hash and uncached canonical readback during publication; no restart/device action.'])
    create(B+'publication-inputs-v1.json',manifest)
    for row in snapshots:assert fresh_sha(row['original'])==row['sha256'],'Concurrent canonical mutation '+row['original']
    print(json.dumps(dict(all_passed=True,file_only=True,guest_execution=False,canonical_write=False,HTTP_action=False,new_findings=len(findings),public_details=len(details),projected_counts=manifest['projected_counts'],preserved_protected_files=2531,selected_complete_suites=49,native_dependencies=1733,merged_frozen_paths=len(frozen),preparation_source=SOURCE,preparation_source_sha256=immutable_sha(SOURCE),output=B+'publication-inputs-v1.json',output_sha256=immutable_sha(B+'publication-inputs-v1.json'))))

if __name__=='__main__':main()
