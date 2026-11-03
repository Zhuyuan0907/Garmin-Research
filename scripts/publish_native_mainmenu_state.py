#!/usr/bin/env python3
"""Publish scoped dependency/root results with full general-menu limits."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from pathlib import Path
import hashlib,html,json,re
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')

def main():
    previous=read('staging/native-player-mainmenu/previous-checkpoint.json')
    before,audit=read(previous['state']),read(previous['audit'])
    assert audit['all_passed']and len(audit['scope_checks'])==18 and audit['state_sha256']==sha(previous['state'])
    state,task=read('evidence/deep-research-state.json'),read('evidence/task-state.json')
    assert state['user_resting']and not state['attended_testing']['user_present']
    app=state['native_app_music']
    assert app['static_findings']==before['native_app_music']['static_findings']
    focused_path='evidence/firmware-analysis/native-mainmenu-boundaries-emulation.json'
    root_path='evidence/firmware-analysis/native-custom-page-root-emulation.json'
    focused,root=read(focused_path),read(root_path)
    assert focused['all_passed']and focused['case_count']==5 and root['all_passed']and root['case_count']==3
    for proof in [focused,root]:
        for path,expected in proof['source_sha256'].items():assert sha(path)==expected,path
    stage=ROOT/'staging/native-player-mainmenu'
    frozen=[p for p in stage.iterdir()if p.name.startswith('source-at-')or '-failure'in p.name or
        '-metadata.json'in p.name or p.name.startswith('constructor-native-PNG-execution-budget-stop')or
        p.name in ['original-fatal-self-loop-terminated-run.json','root-registration-returned-development.json']]
    frozen=[p for p in frozen if p.name not in ['focused-boundaries-failure.json','custom-page-root-integration-failure.json']]
    indexed={str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT)))for p in sorted(frozen)}
    metadata=[]
    for p in sorted(stage.glob('*-metadata.json')):
        doc=read(str(p.relative_to(ROOT)))
        for field in ['source_sha256','probe_sha256']:
            assert doc[field]in indexed.values(),(p.name,field)
        metadata.append(dict(path=str(p.relative_to(ROOT)),sha256=sha(str(p.relative_to(ROOT))),
            development_positive_without_final_guards=p.name=='root-registration-returned-development-metadata.json'))
    index_path='staging/native-player-mainmenu/preserved-development-evidence-index.json'
    index=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_artifact_sha256=indexed,metadata=metadata,
        failed_or_partial_run_metadata_count=len(metadata)-1,terminated_self_loop_run='staging/native-player-mainmenu/original-fatal-self-loop-terminated-run.json',
        first_returning_root_development_not_counted_as_final_guard_pass=True,
        general_MainMenu_latest_failure='staging/native-player-mainmenu/null-map-context-boundary-failure.json',
        general_MainMenu_constructor_returned=False,general_MainMenu_controller_executed=False,
        physical_App_display_direct_music_or_installation_verified=False)
    write(index_path,index)
    static_path='staging/native-player-mainmenu/MainMenu-root-settings-preflight.json';static=read(static_path)
    assert static['complete_bounded_CFG_count']==23
    app['static_findings']['native_mainmenu_dependencies']=dict(evidence=focused_path,evidence_sha256=sha(focused_path),
        source_artifact_count=len(focused['source_sha256']),case_count=5,all_passed=True,
        full_MainMenu_integration_checkpoint=False,static_evidence=static_path,static_evidence_sha256=sha(static_path),
        complete_static_CFG_count=23,preserved_development_evidence=index_path,preserved_development_evidence_sha256=sha(index_path),
        failed_or_partial_run_metadata_count=index['failed_or_partial_run_metadata_count'],
        general_MainMenu_constructor='0x40434c',general_MainMenu_controller='0x405340',
        general_MainMenu_constructor_returned=False,general_MainMenu_controller_executed=False,
        latest_constructor_failure_PC='0x3518ec',null_context_wrapper='0x36294e',null_context_semantics_recovered=False,
        original_audio_condition_ownership_fatal_code='0x6e5d8016',
        original_audio_pool_fixture_returns_nonzero_wait_failure_not_actual_audio_success=True,
        previous_checkpoint=previous,device_io=False,sounds_emitted=False,limits=focused['limits'])
    app['static_findings']['native_custom_page_root']=dict(evidence=root_path,evidence_sha256=sha(root_path),
        source_artifact_count=len(root['source_sha256']),case_count=3,all_passed=True,
        full_scoped_custom_Page_root_final_guards_passed=True,original_custom_Page_constructor='0x5a2994',
        original_manager_registration='0x38e696',original_manager_category_getter='0x38cf80',
        native_manager_catalog_owns_custom_Page=True,custom_Page_frame=root['native_tree']['frame'],
        custom_Page_visibility_flags=root['native_tree']['flags84_85'],
        custom_Page_hidden_and_offscreen_after_stock_transition=True,visible_player_App_verified=False,
        advancing_virtual_clock_queries=len(root['virtual_clock_ticks']),
        supplied_virtual_clock_final_milliseconds=root['virtual_clock_ticks'][-1]['supplied_virtual_milliseconds'],
        transition_heap_request_count=len(root['original_transition_buffer_heap_requests']),
        full_general_MainMenu_integration=False,real_kernel_GUI_thread_touch_display_or_package_acceptance_verified=False,
        device_io=False,sounds_emitted=False,limits=root['limits'])
    app['original_custom_Page_root_catalog_and_getter_verified_offline']=True
    app['development_observations']['general_MainMenu_and_root']=dict(
        full_general_MainMenu_not_passed=True,original_general_constructor_null_context_failure_preserved=True,
        original_custom_Page_root_return_is_not_a_visible_player_App=True,
        fixed_clock_capacity_failure_hypothesis_not_isolated_by_a_single_variable_control=True,
        explicit_setting19B_and_advancing_virtual_clock_and_guarded_transition_storage_used=True,
        real_boot_kernel_audio_pool_UI_thread_framebuffer_and_safe_lifecycle_still_open=True)
    actions=[
        'Recover general PageMainMenu40434C remaining null map context at36294E ->3518C2/3518EC. Do not map null pages or manufacture GUI success. Original controller405340 still unexecuted.',
        'Resolve why stock custom Page remains hidden/offscreen after manager38E696 transition despite catalog ownership and38CF80 getter pass. Connect visible player controls to normal root/UI thread/input/display with real boot GIR/settings/clock/audio context.',
        'Establish accepted modified VPM/SIG loading and sourceID9 stop/repeat/cleanup, safe root detach/unregister/reload/unload and font/cache/stream release. Resource player stays EMULATION-ONLY; do not install.',
        'Join resident menu player to native/kernel continuous audio and direct phone Bluetooth with recovery/navigation coexistence. Stereo/fidelity deprioritized, microphone canceled; Android Auto later, Maps deferred.',
        'User still sleeping: offline only, no USB/Bluetooth/device I/O, writes, calls/sound or physical questions. Explicit return: live audio/agent preparation and pairing first. Goal active/no-achieve.']
    now=datetime.now(timezone.utc);state.update(updated_utc=now.isoformat(),next_actions=actions);app['remaining_work']=actions[:4]
    state['last_goal_turn']=dict(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=previous['state'],previous_current_audit_snapshot=previous['audit'],
        previous_turn_revalidation='Fresh18-scope resource audit saved;84 prior findings and26 frozen selected suites retained.',
        reasons=['23 bounded static CFGs locate settings/default, satellite/counter, original display-list and audio-condition ownership/failure paths.',
            'Five focused native dependency controls and full code/voice/canary/DB guards passed; not a full general-menu integration.',
            'Three scoped custom-Page manager catalog/getter/hidden-state controls and final two-onceword/font/code/voice/canary/DB guards passed.',
            'Custom Page remains hidden/offscreen; full general MainMenu still fails at3518EC with unrecovered context. Failed/partial/terminated development runs and exact sources preserved.',
            'User sleeping; no device I/O/writes/sound/install or goal completion. Native App/direct-phone music remain open.'],
        focused_evidence=focused_path,focused_evidence_sha256=sha(focused_path),
        integration_evidence=root_path,integration_evidence_sha256=sha(root_path),
        offline_integration_device_io=False,device_io=False,device_files_written=False,
        native_firmware_or_research_package_written=False,automatic_calls_or_sound=False,attended_calls_or_sound=False,
        automatic_calls_or_sound_while_away=False,next_focus=actions[0],goal_status='active',full_goal_complete=False)
    for key in ['updated_utc','last_goal_turn','next_actions','current_priority','latest_user_instruction','attended_testing','ordered_priorities','user_resting']:task[key]=state[key]
    task.update(user_away=True,original_custom_Page_root_catalog_and_getter_verified_offline=True,
        current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False)
    public=read('reports/findings.json');public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    progress['research_updated_utc']=now.isoformat()
    details=[
        '一般主選單依賴追查：23 個有界流程與五組原廠指令控制驗證，涵蓋設定不存在、硬體時鐘讀取、清單初始化、無衛星資料及音訊緩衝池失敗處理；一般首頁整體仍未通過，停在未復原的資料結構。',
        '原廠自訂頁面掛接：三組離線驗證與最後守護檢查通過，介面管理器保存頁面，原分類查詢與清單一致；原轉場後頁面仍隱藏並位於畫面外，尚未成為可見的播放器 App。']
    for detail in details:assert detail not in progress['completed'];progress['completed'].append(detail)
    assert progress['estimate_percent']==31 and len(progress['completed'])==53
    progress['next']='先復原一般首頁缺少的資料結構，釐清頁面隱藏／轉場狀態，再接可見播放器入口、原機可接受的載入與手機直接藍牙音樂。'
    progress['phases'][4]['next']='自訂頁面已由原管理器保存，但仍在畫面外；補一般首頁資料、前景顯示、實際載入與停止／重播。'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    old='<div class="card"><h2>最新離線進展：播放器圖示與文字已畫入模擬畫布</h2>';assert report.count(old)==1
    card='''<div class="card"><h2>最新離線進展：主選單依賴與頁面掛接局部驗證</h2>
<p><strong>五組底層控制、三組自訂頁面掛接驗證通過；一般首頁尚未完成。</strong>使用這台台灣 2565RT 的原廠韌體與備份，執行原廠設定讀取、GPS 無資料分支、硬體計數器、畫布清單初始化及音訊緩衝池失敗處理。靜態核對 23 個有界流程，沒有把原廠錯誤迴圈當作成功。</p>
<p>原廠自訂頁面現在可以走完介面管理器的掛接與分類查詢，管理器清單确實保存該頁面，原廠查詢與清單順序一致。完整程式、語音介面、兩個一次初始化欄位、配置邊界、字型及資料庫檢查通過。</p>
<p><strong>頁面仍隱藏且在画面外，不是可見的播放器 App。</strong>原轉場後頁面位置為 x=480，寬度 480；一般首頁執行仍停在未復原的資料結構，不能用這個自訂頁面結果宣稱一般主選單已完成。沒有原機安裝、觸控、真螢幕或手機直接藍牙音樂成功證據。</p>
<p>模擬明示提供設定清單、GPS 空資料、計數器零值、遞增的虛擬時間及有守護檢查的暫存配置。音訊緩衝池回覆的是「不可用」失敗結果，並非模擬喇叭已播放。先前失敗、容量限制、第四參數設定錯誤，以及終止原廠無限錯誤迴圈的紀錄和當時程式都保留。</p>
<p>接下來復原一般首頁資料與前景顯示，再整合可見播放器、實機可接受的載入、停止／重播和直接藍牙音樂。進度維持約 31% 的里程碑估計，並非 App 完成度。麥克風已取消，聲道／音質精修擱置，Android Auto 排後、Google Maps 暫緩；使用者休息期間沒有車機操作或聲音。</p></div>'''.replace('确實','確實').replace('画面','畫面')
    report=report.replace(old,card+'<div class="card"><h2>前輪紀錄：播放器圖示與文字已畫入模擬畫布</h2>')
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+m[3],report,count=1,flags=re.S);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>','<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task);write('reports/findings.json',public);(ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(focused_groups=5,scoped_root_groups=3,general_MainMenu_complete=False,
        findings=len(app['static_findings']),estimate_percent=31,completed_items=53,updated_Taiwan=iso)))

if __name__=='__main__':main()
