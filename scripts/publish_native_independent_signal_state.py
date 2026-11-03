#!/usr/bin/env python3
"""Publish native callback entry and a separately tested control component."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import hashlib,html,json,re
from analyze_native_sections import ROOT

BASE='staging/native-player-independent-signal/'
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def hashes(doc):
    for p,s in doc['source_sha256'].items():assert sha(p)==s,p

def main():
    previous=read(BASE+'previous-checkpoint.json')
    for row in previous.values():assert sha(row['path'])==row['sha256']
    before=read(previous['state']['path']);prior=read(previous['audit']['path'])
    assert prior['all_passed'] and len(prior['scope_checks'])==20 and prior['state_sha256']==previous['state']['sha256']
    state,task,public=[read(p)for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];assert app['static_findings']==before['native_app_music']['static_findings'] and len(app['static_findings'])==101
    metapath=BASE+'independent-signal-terminal-metadata.json';meta=read(metapath)
    proofpath=meta['complete_proof'];proof=read(proofpath);hashes(proof)
    assert meta['session_id']==66913 and meta['terminal_exit_code']==0 and proof['all_passed'] and proof['case_count']==4
    assert len(proof['source_sha256'])==108 and sha(proofpath)==meta['complete_proof_sha256']
    joinpath='staging/native-player-signal-dispatch/original-join-and-independent-signal-static.json';join=read(joinpath);hashes(join)
    peerpath='staging/native-player-signal-dispatch/native-signal-resident-join-guard-note.json';peer=read(peerpath);hashes(peer)
    reviewpath=BASE+'independent-signal-static-guard-review.json';review=read(reviewpath)
    for p,s in review['inputs_sha256'].items():assert sha(p)==s,p
    guipath=BASE+'mainmenu-controller-prerequisites-static.json';gui=read(guipath);hashes(gui)
    controlpath='staging/ui-music-control-prototype/verification.json';control=read(controlpath);hashes(control)
    for p,s in control['unchanged_frozen_source_sha256'].items():assert sha(p)==s,p
    for item in control['compile_artifacts']:assert sha(item['path'])==item['sha256']
    assert control['all_passed'] and control['host_tests']['case_count']==27 and not control['ARM_unresolved_symbols']
    assert not control['native_firmware_instructions_executed'] and not control['device_install_candidate']
    app['static_findings']['native_independent_signal_runtime']=dict(evidence=proofpath,evidence_sha256=sha(proofpath),
        runtime_case_count=4,source_artifact_count=108,terminal_metadata=metapath,terminal_metadata_sha256=sha(metapath),
        actual_original_Dispatcher_MainMenu_callback_entry_verified=True,callback_body_executed=False,
        full_scoped_memory_and_native_callback_endpoint_inventory_guards_passed=True,
        original_cleanup_signal_and_Thread_retained=True,independent_signal_bytes=80,
        endpoint_scope_review=reviewpath,endpoint_scope_review_sha256=sha(reviewpath),
        foreground_device_App_direct_phone_music_or_safe_cleanup_verified=False,device_io=False,sounds_emitted=False,limits=proof['limits'])
    app['static_findings']['native_join_cleanup_signal_static']=dict(evidence=joinpath,evidence_sha256=sha(joinpath),
        complete_bounded_CFG_count=join['complete_bounded_new_local_CFG_count'],
        peer_evidence=peerpath,peer_evidence_sha256=sha(peerpath),peer_CFG_count=peer['static_CFG_count'],
        old_46388_boundary_is_stack_local_join_before_body=True,original_join_or_Thread_exit_executed=False,
        device_io=False,sounds_emitted=False,limits=join['limits'])
    app['static_findings']['native_mainmenu_foreground_prerequisites_static']=dict(evidence=guipath,evidence_sha256=sha(guipath),
        source_artifact_count=len(gui['source_sha256']),complete_bounded_CFG_count=len(gui['functions']),
        current_controller_native_API_prep_then_actual_Dispatcher_manager_required=True,
        old_settings_lock_success_hook_is_not_native_condition_proof=True,
        actual_MainMenu_body_foreground_or_device_App_verified=False,device_io=False,sounds_emitted=False,
        limits=gui['limits'])
    app['static_findings']['native_ui_music_control_actor_prototype']=dict(evidence=controlpath,evidence_sha256=sha(controlpath),
        source_artifact_count=5,host_verification_group_count=27,ARM_ELF_type='REL',ARM_unresolved_symbols=[],
        local_admission_and_generation_Start_Stop_control_implemented=True,
        cancel_request_return_zero_does_not_complete_Stop=True,callback_reference_and_owner_completion_required=True,
        existing_native_source_worker_GUI_radio_or_audio_integrated=False,
        native_IRQ_scheduler_audio_or_device_App_verified=False,device_io=False,sounds_emitted=False,limits=control['limits'])
    app['development_observations']['native_independent_signal_runtime']=dict(
        terminal_metadata=metapath,terminal_metadata_sha256=sha(metapath),runtime_session_id=66913,terminal_exit_code=0,
        complete_proof=proofpath,complete_proof_sha256=sha(proofpath),full_scoped_final_guards_passed=True,
        actual_MainMenu_callback_entry_verified=True,callback_body_executed=False,foreground_verified=False,
        native_owned_mutex_timed_node_queue_live_frame_guards_passed=True,safe_cleanup_verified=False,device_io=False,sounds_emitted=False)
    now=datetime.now(timezone.utc)
    focus=('Prepare original settings/GIR/font/menu inputs using legal current-controller native APIs and two independently inventoried Timer condition tokens; never inherit settings lock-ret0 as real initialization. '
        'Then continue actual405340 callback on Dispatcher, constructing Manager in that actor, original registry locks and seven conditional original GUI writer guards through root/frame/visibility. '
        'Independent80-byte original Signal queue/callback-entry and exact live ownership/timed/RAII/queue/frame/full-memory controls now pass. '
        'Integrate the new ARM relocatable UI/music control actor with existing source worker, native radio/config/remote-admission and cleanup/source-token completion, one bootstrap/new layout and source9 exclusive lifecycle. '
        '27 host controls prove control semantics, not native audio/IRQ/App. Accepted package, physical foreground/direct phone music and safe task unload remain unproven. Pairing preempts research; no physical candidate now.')
    state.update(updated_utc=now.isoformat(),current_priority='Native App/menu and Bluetooth music; original native Dispatcher reaches MainMenu callback entry offline, ARM Start/Stop control component implemented/tested separately. Goal active/no-achieve.')
    state['next_actions'][0]=focus;app['remaining_work']=state['next_actions'][:4]
    state['attended_testing'].update(recorded_utc=now.isoformat(),current_attended_test='No physical test needed now; real MainMenu foreground and guest UI/music worker integration remain offline.')
    state['parallel_research'].update(tasks=['native independent signal endpoint guards and join lifetime','native controller MainMenu foreground prerequisites','guest Start/Stop control component with completion/admission tests'],continued_round_completed=True)
    turn=state['last_goal_turn'];turn.update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=previous['state']['path'],previous_current_audit_snapshot=previous['audit']['path'],
        previous_turn_revalidation='Fresh20-scope101-finding checkpoint and38 frozen native suites428 exact dependencies preserved.',
        focused_evidence=proofpath,focused_evidence_sha256=sha(proofpath),latest_callback_runtime_session_id=66913,
        latest_callback_entry_full_scoped_guards_passed=True,latest_callback_body_executed=False,
        latest_dispatcher_runtime_session_id=66913,latest_dispatcher_run_full_scoped_final_guards_passed=True,
        latest_dispatcher_full_guard_scope='Four native independent Signal controls to405340 before body, with exact live endpoint ownership/timed/queue/RAII/frame/storage and whole-memory guards; no foreground/cleanup.',
        new_music_control_prototype=controlpath,new_music_control_prototype_sha256=sha(controlpath),
        next_focus=focus,goal_status='active',full_goal_complete=False)
    turn['reasons']=[
        'Four original independent80-byte Signal controls pass in session66913. Actual native Dispatcher queue/signal/free-function adapter reaches405340 before its body; stock cleanup Signal and Thread retained unchanged.',
        'Live endpoint guards cover ALL/ready/state/priorities, owned semaphores and recursion, active stack/RAII/queue/event2, Thread timed-node/state and resident idlePOST/controllerWAIT frames plus whole code/voice/interface/GUI/DB/allocation/storage/descriptor/stack guards.',
        'Old46388 boundary is original Thread destructor join, not a generic mutex or firmware fault. New19 CFG and8 CFG peer static analyses preserve that original cleanup semantics.',
        '20 bounded foreground-prerequisite CFGs separate controller preparation from actual Dispatcher manager construction, real settings Timer condition tokens/GIR locks, seven initialized-data writes and native frame transitions; body still unexecuted.',
        'New freestanding ARM1176 soft-float relocatable Start/Stop control component has no undefined symbols.27 ASan/UBSan host groups verify admission/generation/cancel-versus-completion/lifetime/preemption, not native IRQ/audio/GUI or integrated device App.',
        '32% weighted estimate unchanged, no device I/O/install/calls/sounds, goal stays active.']
    for k in ['updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research']:task[k]=state[k]
    public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    assert progress['estimate_percent']==32 and len(progress['completed'])==75
    details=[
        '獨立原廠訊號驗證：四組離線控制通過。原廠建構器建立八十位元組訊號物件，透過原廠 API 註冊並發送回呼；派送執行緒實際沿事件佇列與函式轉接到達菜單函式入口。持鎖、等待節點、事件資料、堆疊與完整記憶體檢查通過；停止點仍在菜單主體之前，尚非畫面顯示成功。',
        '原廠回收流程釐清：十九個流程與八個同儕檢查流程確認，前一次試跑碰到的是等待背景執行緒退出的 join 程序。新測試採獨立訊號，保留原廠回收回呼、背景執行緒與等待節點；沒有假造退出或跳過原廠鎖定。',
        '首頁前景前置條件：核對二十個原廠設定、資源、管理器與框架流程。設定與字型先由控制執行緒準備，管理器需由實際菜單回呼所在的派送執行緒建立；新設定鎖與原廠資料寫入都需真實執行，不能把舊模擬成功回傳當作已完成。',
        '播放控制器原型已實作：開始／停止、停止期間阻擋後續資料、播放代次與回呼生命週期已寫成 ARM 程式元件，沒有未解析符號。二十七組帶記憶體檢查的主機控制測試通過，涵蓋重複停止、停止中重啟、過期回呼與搶占。仍須接到原廠音訊、藍牙與菜單；不是已安裝的 App，也沒有新增實機音樂證據。']
    progress['completed'].extend(details);progress.update(research_updated_utc=now.isoformat(),
        next='補齊原廠設定與資源初始化，執行已到達的菜單回呼主體，驗證首頁前景與操作；將播放控制器接到原廠音訊與藍牙服務，再準備原機候選。')
    progress['phases'][4]['next']='原廠事件已到達菜單函式入口；接著驗證函式主體與前景首頁，再接上新播放控制器及原機載入。'
    card='''<div class="card"><h2>最新離線進展：原廠菜單回呼與播放控制器</h2>
<p><strong>原廠事件佇列已到達菜單函式入口。</strong>四組離線控制通過：獨立訊號由原廠建構器建立，原廠 API 註冊與發送回呼，派送執行緒沿訊號與函式轉接進入菜單入口。持鎖、事件資料、等待節點、活躍堆疊與記憶體檢查均通過；停止點在函式主體之前，還沒有完成首頁顯示或操作。</p>
<p><strong>原廠回收程序保留。</strong>之前遇到的鎖定流程會等待背景執行緒退出。這次使用獨立訊號，原有回收回呼、執行緒和等待狀態均保留；沒有假造退出或把等待直接改成成功。二十個首頁前置流程已核對，下一步讓設定、字型與畫面管理器按原廠路徑初始化，再執行菜單主體。</p>
<p><strong>播放控制器已寫成可編譯的原型。</strong>開始／停止、播放代次、停止期間的資料阻擋，以及回呼存活和清理完成判定已實作為 ARM 程式元件，二十七組主機控制測試通過。停止要求返回不等於停止完成；原型會等完整清理證據。這些测试使用介面模擬，仍須接到原廠音訊、藍牙與菜單，尚無新的原廠音訊／中斷／實機 App 驗證。</p>
<p><strong>目前還沒有能安裝到車機的整合 App。</strong>首頁前景、觸控操作、單次初始化整合、原機套件載入及手機直接藍牙音樂仍待完成。既有手機經 Pi 播音樂、原生 WAV 和圖資更新結果保留；研究元件僅供離線驗證。</p>
<p>整體估計約 32%，以研究里程碑加權計算，本輪維持不變。三個研究分支已完成這輪介面、生命週期與控制程式工作；目前不需要插機。有具體候選時會提供現場步驟，藍牙配對立即優先。麥克風取消、音質精修擱置，Android Auto 排後、Google Maps 暫緩。</p></div>'''.replace('测试','測試')
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：背景初始化、菜單回呼與播放控制</h2>.*?</div>',lambda m:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(s)+'</li>'for s in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda m:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前無需實機操作。</p>',report,count=1);assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>.*?</td></tr>',lambda m:'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>'+html.escape(progress['phases'][4]['next'])+'</td></tr>',report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>','<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    assert len(app['static_findings'])==105 and len(progress['completed'])==79
    for p,d in [('evidence/deep-research-state.json',state),('evidence/task-state.json',task),('reports/findings.json',public)]:write(p,d)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=105,estimate_percent=32,completed_items=79,updated_Taiwan=iso,callback_runtime_session=66913,host_control_groups=27)))

if __name__=='__main__':main()
