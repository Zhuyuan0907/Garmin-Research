#!/usr/bin/env python3
"""Publish complete pool clock controls and distinctly failed GUI bootstrap work."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import hashlib, html, json, re
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')

def main():
    previous=read('staging/native-player-pool-clock/previous-checkpoint.json')
    before=read(previous['state']['path']);prior=read(previous['audit']['path'])
    assert prior['all_passed'] and len(prior['scope_checks'])==15
    assert sha(previous['state']['path'])==previous['state']['sha256']==prior['state_sha256']
    assert sha(previous['audit']['path'])==previous['audit']['sha256']
    state,task,public=read('evidence/deep-research-state.json'),read('evidence/task-state.json'),read('reports/findings.json')
    app=state['native_app_music']
    assert app['static_findings']==before['native_app_music']['static_findings'] and len(app['static_findings'])==91
    assert not state['user_resting'] and state['attended_testing']['user_present'] and not task['user_away']
    proofpath='evidence/firmware-analysis/native-pool-clock-emulation.json';proof=read(proofpath)
    assert proof['all_passed'] and proof['case_count']==5 and len(proof['source_sha256'])==98
    for p,s in proof['source_sha256'].items():assert sha(p)==s,p
    bases=['staging/native-player-pool-clock/','staging/native-player-gui-bootstrap/','staging/native-player-dispatcher-bootstrap/']
    indexpaths=[b+'preserved-development-evidence-index.json' for b in bases]
    for p in indexpaths:
        for f,s in read(p)['source_artifact_sha256'].items():assert sha(f)==s,f
    gui_static=bases[1]+'gui-runtime-bootstrap-static-preflight.json'
    wait_static=bases[2]+'condition-owner-static-preflight.json'
    assert read(gui_static)['complete_bounded_CFG_count']==11 and read(wait_static)['complete_bounded_CFG_count']==6
    for p in [gui_static,wait_static]:
        for f,s in read(p)['source_sha256'].items():assert sha(f)==s,f
    controller_meta=bases[0]+'controller-registry-failure-metadata.json';cm=read(controller_meta);cp=read(cm['probe'])
    dispatcher_meta=bases[2]+'unowned-condition-failure-metadata.json';dm=read(dispatcher_meta);dp=read(dm['probe'])
    assert cm['session_id']==15754 and cm['terminal_exit_code']==1 and not cp['completed']
    assert any(e['entry']=='0x38e696' and e['caller']=='0x4053d6' for e in cp['original_main_entries'])
    assert dm['session_id']==73611 and dm['terminal_exit_code']==1 and len(dp['completed_cases'])==5 and not dp['all_final_guards_passed']
    app['static_findings']['native_pool_clock']=dict(
        evidence=proofpath,evidence_sha256=sha(proofpath),case_count=5,all_passed=True,source_artifact_count=98,
        original_entry='0x3b4ba8',original_clock_reader='0x353a9c',original_lower_wait='0x3ec6aa',
        original_clock_result_plus1000_u32_and_stack_argument_verified=True,
        host_changed_wait_argument=False,explicit_absent_pool_wait_failure=1,
        original_failure_return_FF_and_unlock_verified=True,
        original_clock_inputs=[0,20,180,4294966784],native_arguments=[1000,1020,1180,488],
        real_kernel_time_units_owner_scheduler_and_successful_audio_verified=False,
        preserved_development_evidence=indexpaths[0],preserved_development_evidence_sha256=sha(indexpaths[0]),
        device_io=False,sounds_emitted=False,limits=proof['limits'])
    app['development_observations']['general_MainMenu_root_entry_after_pool_clock_development']=dict(
        terminal_metadata=controller_meta,terminal_metadata_sha256=sha(controller_meta),
        development_evidence=cm['probe'],development_evidence_sha256=sha(cm['probe']),
        preserved_development_evidence=indexpaths[0],preserved_development_evidence_sha256=sha(indexpaths[0]),
        session_id=15754,terminal_exit_code=1,original_controller_entered=True,
        original_root_registration_entered=True,original_root_registration_completed=False,
        original_controller_returned=False,full_scoped_final_guards_passed=False,
        native_failure_PC='0x351bda',missing_object='0x34a59a8',
        missing_object_is_Cpp_mutex_not_tree_or_GUI_data_map=True,
        original_terminal_metadata_missing_GUI_table_label_is_superseded_by_vtable_CFG_analysis=True,
        static_evidence=gui_static,static_evidence_sha256=sha(gui_static),complete_bounded_CFG_count=11,
        device_io=False,sounds_emitted=False)
    app['development_observations']['dispatcher_backend_and_owner_development']=dict(
        terminal_metadata=dispatcher_meta,terminal_metadata_sha256=sha(dispatcher_meta),
        development_evidence=dm['probe'],development_evidence_sha256=sha(dm['probe']),
        preserved_development_evidence=indexpaths[2],preserved_development_evidence_sha256=sha(indexpaths[2]),
        prior_GUI_development_evidence=indexpaths[1],prior_GUI_development_evidence_sha256=sha(indexpaths[1]),
        static_evidence=wait_static,static_evidence_sha256=sha(wait_static),complete_bounded_CFG_count=6,
        session_id=73611,terminal_exit_code=1,planned_case_count=6,completed_case_count=5,
        full_scoped_final_guards_passed=False,original_singleton_constructor_returned=False,
        original_backend_initializer='0x3008a0',native_zero_store_count_per_run=6,
        native_zero_bytes_per_run=24,observed_backend_initializer_runs=78,
        host_seeded_backend_fields=False,native_fatal_code='0x6e5d8016',native_fatal_caller='0x3ec5ea',
        native_wait_owner_gate='0x3ec5d8',true_mutex_thread_ownership_and_wait_scheduler_verified=False,
        original_IRQ_restore_precedes_constructor_return=True,
        earlier_journal_return_marker_is_not_actual_return_boundary_proof=True,
        pending_VM_return_marker_fix_syntax_checked_not_runtime_validated=True,
        real_boot_event_dispatch_controller_foreground_or_device_App_verified=False,
        device_io=False,sounds_emitted=False)
    actions=[
        'Recover original3009A0 mutex ownership and358D24 task identity before original3EC5C6 indefinite condition wait. Original dispatcher bootstrap73611 completes five of six controls then rejects semaphore+8 owner mismatch at3EC5D8/3EC5E6. Preserve failed six-control suite and explicit retained bootstrap token; do not patch owner fields or return successful wait. Correct native condition return journal after IRQ restore must be runtime verified. Then original5D2130 singleton/5D2232 and full405340 controller/root/foreground guards.',
        'Recover true boot/GIR/settings/kernel/UI-thread and foreground path for a visible player with normal touch/canvas/display submission. Original405340 now enters38E696 registration after exact pool clock controls, but registration/controller did not return. Prior complete ctor page remains hidden, zero-size; no visible device App.',
        'Execute original388746 callback dispatch and388676 core release; recover sourceID9 stop/repeat/cleanup and safe detach/unregister/reload/unload plus font/cache/stream reclamation. Callback0 with flags6 is not safe unregister.',
        'Verify actual accepted modified VPM/SIG loading, native continuous audio and direct phone Bluetooth with navigation coexistence/recovery. Packages remain EMULATION-ONLY. Microphone canceled, fidelity tuning deprioritized; Android Auto later, Maps deferred.',
        'User explicitly returned and is available for future physical tests. No physical test currently needed or requested. Prepare and verify live audio/agent first when needed; immediately prioritize pairing. Goal active/no-achieve.']
    now=datetime.now(timezone.utc)
    state.update(updated_utc=now.isoformat(),next_actions=actions,
        current_priority='Native player/menu App and direct phone Bluetooth music; offline dispatcher mutex/thread ownership and native condition wait next. User present; attended pairing immediately preempts research. Goal active/no-achieve.')
    app['remaining_work']=actions[:4]
    state['attended_testing'].update(recorded_utc=now.isoformat(),current_attended_test='No physical test needed now. Offline native dispatcher mutex ownership and condition wait remain incomplete.')
    state['last_goal_turn']=dict(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=previous['state']['path'],previous_current_audit_snapshot=previous['audit']['path'],
        previous_turn_revalidation='Fresh15-scope checkpoint preserved; all91 prior findings and33 selected frozen suites retained.',
        reasons=[
            'Five complete pool clock controls98 exact dependencies execute original clock+1000 and u32 wraparound; seven-slot scan, explicit unavailable-pool failure, native FF return/unlock and full guards pass.',
            'Controller15754 now enters original38E696 root registration but fails unconstructed original C++ mutex34A59A8. No completed registration/controller or final guards claimed.',
            'Eleven original mutex/bootstrap CFGs and six original condition/identity CFGs recovered. Original3008A0 now executes six zero stores over24 bounded bytes; six-control run73611 passes five partial cases then native condition owner gate rejects.',
            'Failed/partial runs, exact sources and probes preserved. Original indefinite wait, real kernel task ownership, visible App, accepted loading, lifecycle and direct audio remain unverified.',
            'User present and available; no current physical test, device I/O/write/install/call/sound or goal completion.'],
        focused_evidence=proofpath,focused_evidence_sha256=sha(proofpath),
        full_general_MainMenu_constructor_final_guards_passed=True,general_MainMenu_controller_or_visible_App_verified=False,
        latest_controller_development_evidence=cm['probe'],latest_controller_development_evidence_sha256=sha(cm['probe']),
        latest_controller_run_returned=False,latest_controller_run_root_registration_reached=True,
        latest_controller_run_full_scoped_final_guards_passed=False,
        latest_dispatcher_development_evidence=dm['probe'],latest_dispatcher_development_evidence_sha256=sha(dm['probe']),
        latest_dispatcher_run_full_scoped_final_guards_passed=False,
        device_io=False,device_files_written=False,native_firmware_or_research_package_written=False,
        automatic_calls_or_sound=False,attended_calls_or_sound=False,automatic_calls_or_sound_while_away=False,
        next_focus=actions[0],goal_status='active',full_goal_complete=False)
    for k in ['updated_utc','next_actions','current_priority','last_goal_turn','attended_testing']:task[k]=state[k]
    task.update(user_away=False,current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False)
    public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    assert progress['estimate_percent']==32 and len(progress['completed'])==61
    details=[
        '原廠音訊池等待值：五組完整離線控制通過，核對原始時鐘加 1000、整數溢位及重複呼叫。缺少可用音訊池時，原始拒絕與解鎖流程正確執行；沒有模擬播放成功，沒有更改實機。',
        '首頁與同步依賴：原廠控制器已進入頁面掛接入口，但尚未完成。查明缺少同步物件初始化，原始六次清零写入已執行；六項測試完成五項後，被原廠執行緒擁有權檢查拒絕。另完成十一個初始化及六個等待流程核對，失敗紀錄完整保留。']
    details[1]=details[1].replace('写入','寫入')
    progress['completed'].extend(details)
    progress.update(research_updated_utc=now.isoformat(),next='先補齊原廠同步物件的執行緒擁有權與等待流程，再完成首頁控制器、前景顯示及正常操作；之後驗證安全清理、實機 App 與手機直接藍牙音樂。')
    progress['phases'][4]['next']='首頁初始化整合已通過；控制器進入掛接入口，正在復原同步與等待依賴，再接前景顯示、正常操作、安全清理及原機載入。'
    assert len(progress['completed'])==63 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==32
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    card='''<div class="card"><h2>最新離線進展：原廠首頁控制器與同步流程</h2>
<p><strong>播放器已接入原廠首頁初始化；正在補齊控制器的同步依賴。</strong>前輪三組完整離線檢查仍有效：原廠載入器載入編譯的 Pi 播放器，原廠首頁初始化返回，十五格菜單資料含「Pi 播放器」名稱與按鈕；預設設定由原始程式計算、寫入並讀回。</p>
<p>本輪五組完整等待值控制通過，核對原始時鐘加 1000、整數溢位與重複呼叫；缺少可用音訊池時，原始失敗分支返回並解鎖。程式區、原廠完整語音記憶體與 40 個介面、載入模組及配置邊界檢查通過。底層時鐘、配置與同步仍包含明示的模擬輸入，沒有模擬播放成功。</p>
<p>修正等待值檢查後，原廠首頁控制器首次進入頁面掛接入口，接著因同步物件尚未初始化而停止。已核對十一個原廠初始化流程，並讓原始六次清零寫入實際執行。新的六項控制完成五項後，仍被原廠執行緒擁有權檢查拒絕；另核對六個等待與識別流程。失敗紀錄保留，這次控制器與同步初始化尚未通過完整最後檢查。</p>
<p><strong>頁面目前仍是隱藏、零尺寸；實機 App 尚未完成。</strong>下一步復原同步物件的執行緒擁有權及等待流程，再驗證控制器、前景頁面、觸控與畫面提交。安全清理、原機套件載入、原生音訊及手機直接藍牙音樂仍待驗證；研究套件僅供模擬，未安裝到車機。</p>
<p>整體進度維持約 32%，是研究里程碑的加權估計。使用者已返回並可協助實機測試，目前尚無需插機或重做音訊測試；有具體測試時會提供步驟，現場配對立即優先。麥克風取消、音質精修擱置，Android Auto 排後、Google Maps 暫緩。</p></div>'''
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：播放器已接入原廠首頁初始化</h2>.*?</div>',lambda m:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(d)+'</li>' for d in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda m:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前無需實機操作。</p>',report,count=1);assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>.*?</td></tr>',lambda m:'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>'+html.escape(progress['phases'][4]['next'])+'</td></tr>',report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>','<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task);write('reports/findings.json',public)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=92,pool_groups=5,estimate_percent=32,completed_items=63,updated_Taiwan=iso)))

if __name__=='__main__':main()
