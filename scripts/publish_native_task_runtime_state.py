#!/usr/bin/env python3
"""Publish guarded native task initialization and bounded UI/music reviews."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import hashlib,html,json,re
from analyze_native_sections import ROOT

BASE='staging/native-player-task-runtime-full/'
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def hashes(doc):
    for p,s in doc['source_sha256'].items():assert sha(p)==s,p

def main():
    previous=read(BASE+'previous-checkpoint.json')
    for row in previous.values():assert sha(row['path'])==row['sha256']
    before=read(previous['state']['path']);prior=read(previous['audit']['path'])
    assert prior['all_passed'] and len(prior['scope_checks'])==16
    assert prior['state_sha256']==previous['state']['sha256']
    state,task,public=[read(p)for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];assert app['static_findings']==before['native_app_music']['static_findings']
    assert len(app['static_findings'])==98 and state['attended_testing']['user_present'] and not state['user_resting']
    metapath=BASE+'full-runtime-terminal-metadata.json';meta=read(metapath)
    proofpath=meta['complete_proof'];proof=read(proofpath);hashes(proof)
    assert meta['session_id']==3875 and meta['terminal_exit_code']==0 and proof['all_passed'] and proof['case_count']==3
    assert sha(proofpath)==meta['complete_proof_sha256'] and len(proof['source_sha256'])==106
    guipath=BASE+'gui-foreground-boot-preflight.json';gui=read(guipath);hashes(gui)
    musicpath=BASE+'source9-lifecycle-preflight.json';music=read(musicpath);hashes(music)
    assert gui['all_static_assertions_passed'] and gui['complete_bounded_local_CFG_count']==32
    assert music['all_static_assertions_passed'] and music['complete_bounded_CFG_count']==29
    fillpath=BASE+'gui-stack-fill-preflight.json';fill=read(fillpath);hashes(fill)
    lifepath=BASE+'task-lifetime-guard-preflight.json';life=read(lifepath);hashes(life)
    app['static_findings']['native_task_runtime_full']=dict(evidence=proofpath,evidence_sha256=sha(proofpath),
        runtime_case_count=3,source_artifact_count=106,terminal_metadata=metapath,terminal_metadata_sha256=sha(metapath),
        whole_scoped_memory_and_native_task_inventory_guards_passed=True,original_singleton_returned=True,
        original_GUI_stack_fill_analysis=fillpath,original_GUI_stack_fill_analysis_sha256=sha(fillpath),
        native_task_lifetime_preflight=lifepath,native_task_lifetime_preflight_sha256=sha(lifepath),
        physical_foreground_device_App_direct_music_or_safe_cleanup_verified=False,device_io=False,sounds_emitted=False,
        limits=proof['limits'])
    app['static_findings']['native_gui_foreground_boot_static']=dict(evidence=guipath,evidence_sha256=sha(guipath),
        source_artifact_count=len(gui['source_sha256']),complete_bounded_local_CFG_count=32,
        original_signal_callback_route_identified=True,GUI_main_actor_separate_from_Dispatcher=True,
        new_runtime_executed=False,device_io=False,sounds_emitted=False,limits=gui['limitations'])
    app['static_findings']['native_source9_lifecycle_static']=dict(evidence=musicpath,evidence_sha256=sha(musicpath),
        source_artifact_count=len(music['source_sha256']),complete_bounded_CFG_count=29,
        start_and_async_stop_are_distinct=True,stop_return_zero_is_not_completion=True,
        exclusive_source_and_completion_before_clear_required=True,device_io=False,sounds_emitted=False,limits=music['limits'])
    for key,names in [
        ('native_task_runtime_full',['background-native-waits-review.json']),
        ('native_gui_foreground_boot_static',['dispatcher-mainmenu-callback-static-preflight.json']),
        ('native_source9_lifecycle_static',['single-bootstrap-ui-music-implementation-plan.json'])]:
        refs={}
        for name in names:
            path=BASE+name;assert (ROOT/path).exists();refs[path]=sha(path)
        app['static_findings'][key]['continued_parallel_review_sha256']=refs
    developmentpath=meta['background_development'];development=read(developmentpath)
    assert not development['full_scoped_background_final_guards_passed']
    app['development_observations']['native_background_after_full_memory_guards']=dict(
        development_evidence=developmentpath,development_evidence_sha256=sha(developmentpath),
        prior_full_proof=proofpath,prior_full_proof_sha256=sha(proofpath),
        original_controller_wait_reached_idle=development['idle_sentinel_reached'],
        pending_native_worker_mutex_operations=sum(len(v)for v in development['pending_mutex_operations'].values()),
        full_scoped_background_final_guards_passed=False,device_io=False,sounds_emitted=False)
    signalmeta='staging/native-player-signal-dispatch/signal-dispatch-terminal-metadata.json'
    signal=None;signal_development=None
    if (ROOT/signalmeta).exists():
        sm=read(signalmeta);sp=read(sm['probe']);signal_development=sp;assert sha(sm['probe'])==sm['probe_sha256']
        app['development_observations']['native_signal_dispatch']=dict(terminal_metadata=signalmeta,
            terminal_metadata_sha256=sha(signalmeta),development_evidence=sm['probe'],development_evidence_sha256=sha(sm['probe']),
            session_id=sm['session_id'],terminal_exit_code=sm['terminal_exit_code'],completed=sp['completed'],
            completed_development_groups=len(sp['cases']),error=sp.get('error'),
            original_registration_and_publication_returned=any(c['name']=='original_signal_register_and_publish_API_create_native_holder_and_queue_record'for c in sp['cases']),
            full_scoped_final_guards_passed=sp['full_scoped_final_guards_passed'],
            callback_body_foreground_device_App_direct_music_or_safe_cleanup_verified=False,device_io=False,sounds_emitted=False)
        if sm['terminal_exit_code']==0:
            signalpath=sp['complete_proof'];signal=read(signalpath);hashes(signal)
            assert signal['all_passed'] and signal['case_count']==4 and sha(signalpath)==sp['complete_proof_sha256']
            app['static_findings']['native_signal_dispatch_full']=dict(evidence=signalpath,evidence_sha256=sha(signalpath),
                runtime_case_count=4,source_artifact_count=len(signal['source_sha256']),
                actual_original_Dispatcher_callback_entry_and_memory_guards_passed=True,
                callback_body_executed=False,foreground_device_App_direct_music_or_safe_cleanup_verified=False,
                deep_endpoint_owned_mutex_timed_node_and_idle_POST_inventory_fully_checked=False,
                original_member_holder_metadata_erratum=BASE+'dispatcher-mainmenu-callback-static-preflight.json',
                original_member_holder_metadata_erratum_sha256=sha(BASE+'dispatcher-mainmenu-callback-static-preflight.json'),
                device_io=False,sounds_emitted=False,limits=signal['limits'])
    now=datetime.now(timezone.utc)
    focus=('Continue original signal registration/publication and real Dispatcher callback into405340, then MainMenu/root foreground using original manager/GUI main actor and legal frame initialization. '
        'Three native task-return/inventory/full-memory groups pass; subsequent controller WAIT background journal alone has no final memory guards. '
        'Single-bootstrap menu/music composition still needs exact layout, guest music runtime activation, exclusive source9, asynchronous STOP completion, original clear/restart and resident callback lifetime. '
        'No safe cleanup, accepted package, device App or direct phone music proof. Pairing preempts research; no physical candidate now.')
    state.update(updated_utc=now.isoformat(),current_priority='Native App/menu and Bluetooth music; full scoped background initialization verified offline, native signal callback and foreground plus one-bootstrap playback/stop lifecycle remain research. Goal active/no-achieve.')
    state['next_actions'][0]=focus;app['remaining_work']=state['next_actions'][:4]
    state['attended_testing'].update(recorded_utc=now.isoformat(),current_attended_test='No physical test needed now; signal callback, foreground and safe music lifecycle remain offline.')
    state['parallel_research'].update(tasks=['native background continuation and lifetime cross-check','original signal callback and foreground boot','single-bootstrap music control and asynchronous stop lifecycle'],continued_round=True)
    turn=state['last_goal_turn'];turn.update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=previous['state']['path'],previous_current_audit_snapshot=previous['audit']['path'],
        previous_turn_revalidation='Fresh16-scope98-finding checkpoint and37 frozen suites425 dependencies preserved.',
        focused_evidence=proofpath,focused_evidence_sha256=sha(proofpath),
        latest_dispatcher_development_evidence=developmentpath,latest_dispatcher_development_evidence_sha256=sha(developmentpath),
        latest_dispatcher_original_singleton_returned=True,latest_dispatcher_runtime_session_id=3875,
        latest_dispatcher_run_full_scoped_final_guards_passed=True,
        latest_dispatcher_full_guard_scope='Three pre-background singleton-return, exact task inventory and whole-memory groups; subsequent background journal remains separately unguarded.',
        latest_background_development_final_guards_passed=False,next_focus=focus,goal_status='active',full_goal_complete=False)
    turn['reasons']=[
        'Three scoped original singleton/broadcast/handoff, exact native ALL/ready/owned list and live saved frames, and whole memory/interface/DB/storage/descriptor/stack guards pass offline in session3875.',
        'Original GUI builder fills16384-byte stacks withFF; guard baseline is captured after original fill before task fields. Earlier harness name collision and premature baseline failures are preserved independently.',
        'Original controller WAIT drains resident worker lock/unlock continuations to idle; this separate development journal has no final whole-memory guards and proves neither task exit nor safe unloading.',
        '32 bounded UI/signal/foreground CFGs identify legal original callback publication and a separate GUI main actor;29 source9 CFGs distinguish START from asynchronous STOP and require completion before clear.',
        '32% weighted estimate remains unchanged. No physical I/O/install/call/sound; goal remains active and pairing takes priority.']
    if signal:turn['reasons'].append('Four further scoped signal-dispatch controls pass through the actual original Dispatcher callback adapter to405340 before its body; no foreground or callback completion claim.')
    for key in ['updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research']:task[key]=state[key]
    public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    assert progress['estimate_percent']==32 and len(progress['completed'])==72
    details=[
        '背景初始化完整檢查：原廠執行緒完成通知、等待恢復與鎖交接，初始化返回原呼叫者；三組控制通過，並核對執行緒名單、保存暫存器、配置生命週期、程式區、語音介面、資料庫與堆疊邊界。原廠填入堆疊的行為也納入檢查。這是離線驗證，尚無原機 App 或安全卸載證據。',
        '介面啟動路徑：核對三十二個原廠訊號、佇列、首頁與前景流程，找到透過原廠事件佇列執行菜單回呼的方法。試跑已完成註冊與發送，背景執行緒開始處理，但途中遇到新的原廠鎖定驗證邊界，尚未到達菜單回呼入口。另分清背景派送執行緒與真正的 GUI 主執行緒；首頁尺寸、顯示與操作仍需驗證。',
        '音樂播放生命週期：核對二十九個原廠來源註冊、播放、停止與釋放流程。停止要求是非同步的，函式返回不代表音訊已停止；整合版本需要確認完成後才能清除、換音源與重新播放。']
    if signal:details.append('原廠訊號派送驗證：四組離線控制通過。由原廠 API 建立回呼、寫入佇列並喚醒背景派送執行緒，實際沿原廠訊號與函式轉接進入菜單回呼，記憶體檢查通過。停止點在回呼主體之前，尚非首頁顯示成功。')
    progress['completed'].extend(details);progress.update(research_updated_utc=now.isoformat(),
        next='透過原廠事件佇列執行菜單回呼，完成首頁前景顯示與操作；用一次初始化整合菜單、藍牙音樂及可靠的停止流程，再準備原機候選。')
    progress['phases'][4]['next']='背景初始化與完整記憶體檢查通過；下一步驗證原廠回呼、前景首頁、音樂播放／停止與原機載入。'
    signaltext=('原廠 API 註冊、佇列發送與背景派送已通過四組控制，實際到達菜單回呼入口；停止點在回呼主體之前，尚未執行前景轉換。' if signal else
        '試跑已能用原廠 API 註冊並發送新的回呼，背景執行緒也開始處理；途中遇到一個尚未納入模擬器驗證範圍的原廠鎖定流程，還沒有到達菜單回呼入口。這次試跑只有部分控制通過，未通過完整最終檢查。')
    card='''<div class="card"><h2>最新離線進展：背景初始化、菜單回呼與播放控制</h2>
<p><strong>背景初始化通過三組完整檢查。</strong>原廠執行緒完成通知、等待恢復與鎖交接，初始化返回原呼叫者。執行緒名單、保存暫存器、配置生命週期、程式區、語音介面、資料庫與堆疊邊界均已核對；原廠堆疊填入也列入檢查。這些結果只涵蓋此離線範圍。</p>
<p><strong>菜單啟動接回原廠事件機制。</strong>''' + signaltext + ''' 三十二個原廠菜單、訊號與前景流程已核對；真正的 GUI 主執行緒另有啟動程序，首頁尺寸、可見狀態、繪圖與觸控還待驗證。</p>
<p><strong>音樂控制需要可靠的停止流程。</strong>二十九個來源與播放生命週期流程已核對。播放與停止是不同入口，停止要求送出後還須確認實際完成，才能清除或替換音源。菜單／WAV 和連續藍牙音樂仍需以一次初始化整合；目前還沒有能安裝到車機的整合 App。</p>
<p><strong>背景等待紀錄與完整檢查分開保留。</strong>後續原廠等待讓兩個保留的鎖定／解鎖續行完成，最後進入等待；該紀錄沒有再次完成全部記憶體檢查，不能當作執行緒退出、安全卸載或原機排程成功。四組原廠事件與切換控制的既有證據仍保留。</p>
<p>整體估計約 32%，以研究里程碑加權計算，本輪維持不變。三個研究分支持續核對介面、背景流程與音樂整合；目前不需要插機。有具體候選時會提供現場步驟，藍牙配對立即優先。麥克風取消、音質精修擱置，Android Auto 排後、Google Maps 暫緩。</p></div>'''
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：多線研究與首頁啟動</h2>.*?</div>',lambda m:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(s)+'</li>'for s in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda m:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前無需實機操作。</p>',report,count=1);assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>.*?</td></tr>',lambda m:'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>'+html.escape(progress['phases'][4]['next'])+'</td></tr>',report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>','<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    assert len(app['static_findings'])==101+bool(signal) and len(progress['completed'])==75+bool(signal)
    for p,d in [('evidence/deep-research-state.json',state),('evidence/task-state.json',task),('reports/findings.json',public)]:write(p,d)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=len(app['static_findings']),estimate_percent=32,completed_items=len(progress['completed']),updated_Taiwan=iso)))

if __name__=='__main__':main()
