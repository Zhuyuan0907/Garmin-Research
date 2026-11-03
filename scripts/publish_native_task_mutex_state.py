#!/usr/bin/env python3
"""Publish parallel static reviews and an explicitly partial runtime probe."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import hashlib,html,json,re
from analyze_native_sections import ROOT

BASE='staging/native-player-task-mutex/'
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')

def main():
    previous=read(BASE+'previous-checkpoint.json')
    for row in previous.values():assert sha(row['path'])==row['sha256']
    before=read(previous['state']['path']);prior=read(previous['audit']['path'])
    assert prior['all_passed'] and len(prior['scope_checks'])==28
    assert prior['state_sha256']==previous['state']['sha256']
    state,task,public=[read(p)for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music']
    assert app['static_findings']==before['native_app_music']['static_findings'] and len(app['static_findings'])==95
    assert state['attended_testing']['user_present'] and not state['user_resting'] and not task['user_away']
    mutexpath=BASE+'task-mutex-static-preflight.json';mutex=read(mutexpath)
    guipath=BASE+'gui-worker-boot-preflight.json';gui=read(guipath)
    musicpath=BASE+'direct-music-integration-review.json';music=read(musicpath)
    auxpath=BASE+'auxiliary-mutex-wrapper-preflight.json';aux=read(auxpath)
    errpath=BASE+'gui-worker-boot-erratum-and-inputs.json';err=read(errpath)
    for doc in [mutex,gui,aux,err]:
        for p,s in doc['source_sha256'].items():assert sha(p)==s,p
    assert mutex['complete_bounded_CFG_count']==30 and mutex['verified_mode_transition_count']==37
    assert gui['all_assertions_passed'] and gui['complete_bounded_Thumb_CFG_count']==25
    assert music['exact_hash_audit']['all_sources_and_selected_proofs_match']
    metapath=BASE+'task-mutex-runtime-terminal-metadata.json';meta=read(metapath);probe=read(meta['probe'])
    for key in ['source','probe']:
        assert sha(meta[key])==meta[key+'_sha256']
    assert meta['session_id']==4903 and not probe['full_scoped_final_guards_passed']
    # Static analyses are complete within their bounds; runtime entries and a
    # development return remain separate from whole-program/hardware proof.
    app['static_findings']['native_task_mutex_static']=dict(evidence=mutexpath,evidence_sha256=sha(mutexpath),
        source_artifact_count=len(mutex['source_sha256']),complete_bounded_CFG_count=30,
        verified_mode_transitions=37,verified_literal_tails=4,
        auxiliary_wrapper_evidence=auxpath,auxiliary_wrapper_evidence_sha256=sha(auxpath),
        auxiliary_wrapper_complete_CFG_count=7,
        runtime_or_physical_kernel_verified=False,device_io=False,sounds_emitted=False,limits=mutex['limits'])
    app['static_findings']['native_gui_worker_boot_static']=dict(evidence=guipath,evidence_sha256=sha(guipath),
        source_artifact_count=len(gui['source_sha256']),complete_bounded_Thumb_CFG_count=25,
        two_original_GUI_workers_priority=92,second_worker_notify_route_static_only=True,
        erratum_and_inputs=errpath,erratum_and_inputs_sha256=sha(errpath),
        F08C87_and_F00510_are_initialized_data_not_zero_BSS=True,
        runtime_unblocking_deadlock_freedom_or_constructor_completion_verified=False,
        device_io=False,sounds_emitted=False,limits=gui['limitations'])
    app['static_findings']['direct_music_integration_review']=dict(evidence=musicpath,evidence_sha256=sha(musicpath),
        frozen_suites_revalidated=37,unique_recorded_dependencies=425,manifests_revalidated=7,
        artifacts_revalidated=20,UI_and_continuous_music_combined_candidate_exists=False,
        bootstrap_must_run_once=True,explicit_guest_music_boot_still_required=True,
        source9_WAV_and_channel8_continuous_music_not_integrated=True,
        device_io=False,sounds_emitted=False,limits=music['review_limitations'])
    app['development_observations']['native_multi_task_mutex_runtime']=dict(
        terminal_metadata=metapath,terminal_metadata_sha256=sha(metapath),
        development_evidence=meta['probe'],development_evidence_sha256=sha(meta['probe']),
        source=meta['source'],source_sha256=meta['source_sha256'],session_id=meta['session_id'],
        terminal_exit_code=meta['terminal_exit_code'],original_singleton_returned=probe['original_singleton_returned'],
        full_scoped_final_guards_passed=False,running_task_tracks_actual_saved_PC_destination=True,
        host_wrote_guest_mutex_owner_waiter_links_or_context_restore=False,
        native_mutex_operations=len(probe['native_mutex_operations']),
        native_contention_entries=len(probe['native_contention_entries']),
        native_condition_notification_entries=len(probe['native_condition_notifications']),
        original_condition_wait_returned=probe['native_condition_waits'][-1]['original_wait_returned'],
        original_broadcast_returned=probe['native_condition_notifications'][-1]['original_broadcast_returned'],
        native_saved_context_destinations_reached=sum(r['original_task_resume_destination_reached']for r in probe['kernel_restores']),
        scoped_allocation_descriptor_guards_passed=probe['scoped_allocation_descriptor_guards_passed'],
        resident_pending_background_mutex_operations=sum(len(rows)for rows in probe['pending_mutex_ops'].values()),
        device_io=False,sounds_emitted=False)
    runtime_message=('Development constructor returned; complete code/voice/GUI/lifecycle guards are still missing.'
        if probe['original_singleton_returned'] else 'Development constructor did not return: '+probe.get('error','unknown boundary'))
    focus=('Continue per-running-native-TCB mutex/condition observation through original waiter marker, owner transfer, ready/priority and exact caller returns. '
        '30 bounded mutex/condition/priority CFGs37 mode transitions4 literal tails and25 GUI-worker CFGs identify same-priority92 workers and native Thread broadcast route without global singleton lock before notification; static reachability is not runtime wake or deadlock freedom. '
        +runtime_message+' '
        'Then complete singleton/full final guards, original405340/controller/root foreground and touch/display. Compose one bootstrap with menu plus deferred radio/runtime activation; current source9 WAV UI and continuous channel8 remain separate, old music64-byte MAIN patches/fixtures do not inherit unpatched GUI kernel proof. '
        'Verify safe source9 callback388746 and release/lifetime, accepted VPM/SIG, then actual phone/radio/DAC. Pairing preempts research; no physical candidate now.')
    now=datetime.now(timezone.utc)
    state.update(updated_utc=now.isoformat(),current_priority='Native App/menu and phone Bluetooth music; parallel exact-original mutex, GUI boot and integration reviews complete, per-task runtime development still scoped. Goal active/no-achieve.')
    state['next_actions'][0]=focus;app['remaining_work']=state['next_actions'][:4]
    state['attended_testing'].update(recorded_utc=now.isoformat(),current_attended_test='No physical test needed now; native multi-task GUI wait/runtime and UI/music composition remain offline.')
    state['parallel_research']=dict(user_explicitly_authorized=True,agent_count=3,
        tasks=['original mutex/waiter/priority static flow','original GUI worker boot and notification flow','direct music/UI lifecycle integration review'],
        first_round_completed=True,root_owns_runtime_and_publication=True)
    turn=state['last_goal_turn']
    turn.update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=previous['state']['path'],previous_current_audit_snapshot=previous['audit']['path'],
        previous_turn_revalidation='Fresh28-scope checkpoint preserved;95 prior findings and37 selected frozen suites retained; intervening incomplete-sentence clarification was conversational only.',
        focused_evidence=mutexpath,focused_evidence_sha256=sha(mutexpath),
        latest_dispatcher_development_evidence=meta['probe'],latest_dispatcher_development_evidence_sha256=sha(meta['probe']),
        latest_dispatcher_run_full_scoped_final_guards_passed=False,
        latest_dispatcher_original_singleton_returned=probe['original_singleton_returned'],
        latest_dispatcher_runtime_session_id=meta['session_id'],next_focus=focus,goal_status='active',full_goal_complete=False)
    turn['reasons']=[
        'User authorized three parallel research agents; exact original mutex/waiter/priority preflight30 CFGs37 mode changes4 literal tails and GUI worker boot25 CFGs are complete within stated static bounds.',
        'Native Thread initial broadcast statically avoids the global singleton mutex. A signal clears condition waiter marker without transferring token ownership; actual running CPU task differs transiently from F09090 ready head.',
        runtime_message+' Per-task development entries are not claimed as complete wake, foreground, whole-program or safe cleanup proof.',
        'Direct music review freshly verified37 suites425 unique dependencies7 manifests20 artifacts and identified double-bootstrap BSS reset, explicit guest boot and source9/channel8 composition gaps.',
        '32% milestone estimate is unchanged. No physical I/O/install/call/sound, no repeated user test, goal stays active.']
    for key in ['updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research']:task[key]=state[key]
    public.update(deep_research=state,updated=now.isoformat())
    progress=public['research_progress'];assert progress['estimate_percent']==32 and len(progress['completed'])==69
    details=[
        '多執行緒鎖定研究：核對三十個原廠鎖定、等待、喚醒與優先序流程，以及三十七處 ARM／Thumb 切換。已分清實際執行中的執行緒與排程名單；通知的標記清除不等於鎖定權轉移，避免模擬器誤判。這是原程式分析，尚非完整實機排程驗證。',
        '首頁啟動研究：核對二十五個原廠背景執行緒與建構流程。新離線試跑讓背景執行緒完成通知及鎖定交接，等待流程恢復，首頁建構返回原呼叫執行緒。七次原廠切換均到達保存的目的地，配置與描述資料邊界檢查通過；完整記憶體檢查、背景流程及安全清理仍待完成。',
        '音樂功能整合研究：重新核對三十七套證據、四百二十五個依賴及七份建置資料。菜單／WAV 與連續藍牙音樂仍是分開原型；直接串接入口會重設既有狀態，已列出單次初始化、啟動、播放控制與停止釋放的整合步驟。']
    progress['completed'].extend(details)
    progress.update(research_updated_utc=now.isoformat(),next='完成各執行緒的原廠等待、通知與鎖定交接，再驗證完整首頁與前景操作；用一次初始化整合菜單與藍牙音樂，補停止釋放後才準備原機測試。')
    progress['phases'][4]['next']='首頁背景執行緒與原廠通知路徑已核對；多執行緒試跑接等待與鎖定交接，再完成前景操作、音樂服務整合及原機載入。'
    assert len(progress['completed'])==72 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==32
    status=('新試跑讓背景執行緒通知及鎖定交接，等待流程恢復，首頁建構返回原呼叫執行緒。七次原廠切換均到達保存的目的地，配置與描述資料邊界檢查通過；兩個背景鎖定／解鎖的續行仍保留，完整程式區、語音介面、畫面區與生命週期檢查未完成。'
        if probe['original_singleton_returned'] else '新試跑尚未讓首頁建構完整返回，已保存新的停止位置與執行緒狀態。')
    card='''<div class="card"><h2>最新離線進展：多線研究與首頁啟動</h2>
<p><strong>三路研究已完成第一輪。</strong>分別研究原廠鎖定與喚醒、首頁背景執行緒啟動，以及菜單和藍牙音樂的整合。三十個鎖定相關流程與二十五個首頁流程已核對。第二個背景執行緒有先通知建構流程的原廠路徑，因此目前不能直接判定韌體死鎖。</p>
<p><strong>新的多執行緒試跑仍是開發驗證。</strong>''' + status + ''' 靜態路徑和進入函式的紀錄都不當作完整喚醒或原機成功；每個執行緒分別保留等待狀態，鎖定權、優先序與核心切換由原廠指令執行。</p>
<p><strong>菜單／WAV 和連續藍牙音樂仍需整合。</strong>直接串接兩個現有入口會重設前一次初始化的狀態。下一個版本要只初始化一次，再接音樂服務的啟動、播放控制及停止釋放；目前還沒有能安裝到車機的整合 App。三十七套既有證據、四百二十五個依賴與七份建置資料已重新核對。</p>
<p><strong>四組完整原廠事件與切換控制通過的結果仍保留。</strong>首頁一般初始化已能接入播放器，但頁面仍是隱藏、零尺寸；前景顯示、正常操作、完整排程、安全清理、原機套件載入及手機直接藍牙音樂仍待驗證。新的首頁試跑尚未通過完整檢查；研究套件僅供模擬。</p>
<p>整體估計約 32%，以研究里程碑加權計算，本輪維持不變。目前不需要插機；有具體候選時會提供現場步驟，藍牙配對立即優先。麥克風取消、音質精修擱置，Android Auto 排後、Google Maps 暫緩。</p></div>'''
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：原廠事件傳送與執行緒切換</h2>.*?</div>',lambda m:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(s)+'</li>'for s in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda m:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前無需實機操作。</p>',report,count=1);assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>.*?</td></tr>',lambda m:'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>'+html.escape(progress['phases'][4]['next'])+'</td></tr>',report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>','<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task);write('reports/findings.json',public)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=98,estimate_percent=32,completed_items=72,updated_Taiwan=iso,runtime_session=meta['session_id'])))

if __name__=='__main__':main()
