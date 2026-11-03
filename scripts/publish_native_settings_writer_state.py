#!/usr/bin/env python3
"""Publish settings controls with separate incomplete general-menu evidence."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from pathlib import Path
import hashlib,html,json,re
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')

def main():
    prefix='staging/native-player-settings-writer/'
    previous=read(prefix+'previous-checkpoint.json');before,audit=read(previous['state']),read(previous['audit'])
    assert audit['all_passed']and len(audit['scope_checks'])==12 and audit['state_sha256']==sha(previous['state'])
    assert sha(previous['state'])==previous['state_sha256']and sha(previous['audit'])==previous['audit_sha256']
    state,task=read('evidence/deep-research-state.json'),read('evidence/task-state.json');app=state['native_app_music']
    assert state['user_resting']and not state['attended_testing']['user_present']
    assert app['static_findings']==before['native_app_music']['static_findings']
    path='evidence/firmware-analysis/native-settings-writer-emulation.json';proof=read(path)
    assert proof['all_passed']and proof['case_count']==5 and len(proof['source_sha256'])==93
    for p,s in proof['source_sha256'].items():assert sha(p)==s,p
    staticpath=prefix+'settings-writer-static-preflight.json';static=read(staticpath)
    assert static['complete_bounded_CFG_count']==12
    runpath=prefix+'general-menu-settings-terminal.json';meta=read(prefix+'general-menu-settings-terminal-metadata.json');dev=read(runpath)
    assert sha(meta['source'])==meta['source_sha256']and sha(runpath)==meta['probe_sha256']
    assert meta['terminal_exit_code']==1 and not dev['completed']and not dev['full_integration_checkpoint']
    indexpath=prefix+'preserved-development-evidence-index.json';index=read(indexpath)
    for p,s in index['source_artifact_sha256'].items():assert sha(p)==s,p
    app['static_findings']['native_settings_writer']=dict(evidence=path,evidence_sha256=sha(path),case_count=5,all_passed=True,
        source_artifact_count=93,static_evidence=staticpath,static_evidence_sha256=sha(staticpath),complete_static_CFG_count=12,
        original_initializer='0x2cbd16',original_writer_cursor_initializer='0x2ca76c',original_setter='0x2ca82c',
        original_ready_headers_cursor_program_commit_reader_and_cached_replacement_executed=True,
        host_seeded_setting_headers_or_cursor=False,fixture_sector_bytes=16384,fixture_sector_count=2,
        actual_flash_geometry_or_persistence_kernel_condition_owner_and_boot_order_verified=False,
        general_MainMenu_constructor_returned=False,full_general_MainMenu_final_guards_passed=False,
        general_MainMenu_controller_executed=False,general_menu_development_evidence=runpath,
        general_menu_development_evidence_sha256=sha(runpath),latest_general_failure_PC=dev['registers']['pc'],
        latest_unmodeled_lower_read_bank=139,latest_lower_read_caller='0x35d454',
        full_original_default_setting_path_121E_in_new_MainMenu_run_not_reached=True,
        preserved_development_evidence=indexpath,preserved_development_evidence_sha256=sha(indexpath),
        previous_checkpoint=previous,device_io=False,sounds_emitted=False,limits=proof['limits'])
    app['development_observations']['general_MainMenu_native_settings']=dict(
        five_settings_controls_pass_complete_final_guards=True,latest_general_constructor_returned=False,
        latest_PC='0x26a300',latest_unknown_bank=139,latest_native_caller='0x35d454',
        new_general_run_uses_native_record_lookup_not_old19B_read_only_override=True,
        settings19B_value1_is_explicit_synthetic_control_written_by_original_setter=True,
        previous_NULL_cursor_failure_resolved_in_focused_controls_not_claimed_as_same_MainMenu_trace_success=True,
        full_constructor_GUI_voice_allocation_SQL_guards_controller_and_foreground_unverified=True)
    actions=[
        'Recover original35D430 bank139/140 metadata read semantics now reached by general40434C with native settings inventory. Latest scoped lower boundary26A300 rejects bank139/offset0/length8 from35D450; preserve native fallback and do not invent live data or NULL-page/GUI success. Then continue general constructor/controller405340 and full guards; native defaults121E/121F remain to integrate in the new general run.',
        'Join complete normal-menu and visible player Page using original boot/GIR/settings/kernel/UI-thread behavior. The previous custom Page still has frame480,0,480,272 and visibility0,0. Catalog ownership is not a visible App.',
        'Execute original388746 callback dispatch and388676 core release with safe detach/unregister/reload/unload; zero callback with flags6 remains unsafe. Recover sourceID9 stop/repeat/cleanup and font/cache/stream reclamation.',
        'Verify accepted modified VPM/SIG loading, native continuous audio and direct phone Bluetooth with navigation coexistence and recovery. All candidate research packages remain EMULATION-ONLY. Microphone canceled, fidelity tuning deprioritized; Android Auto later, Maps deferred.',
        'User still sleeping: offline only, no USB/Bluetooth/device I/O, real settings writes, calls/sound or physical questions. On explicit return prepare live audio/agent and prioritize pairing immediately. Goal active/no-achieve.']
    now=datetime.now(timezone.utc);state.update(updated_utc=now.isoformat(),next_actions=actions);app['remaining_work']=actions[:4]
    state['last_goal_turn']=dict(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=previous['state'],previous_current_audit_snapshot=previous['audit'],
        previous_turn_revalidation='Fresh12-scope heap checkpoint preserved;88 prior findings and30 selected frozen suites retained.',
        reasons=['Twelve complete bounded CFGs recover original settings initializer, cursor, header/program/commit, reader and wrappers.',
            'Five complete original-code controls initialize guarded fictional NOR storage, reject missing keys, write/read/copy, skip identical cached values, replace old records and reject invalid requests; full voice40/code/canary/DB guards pass.',
            'Geometry, lower flash driver, erased auxiliary metadata, temporary heap and retained condition token remain explicit fixtures; no measured physical geometry, real persistence, kernel ownership or boot order.',
            'General-menu run retained separately: native inventory now reaches another unmodeled bank139 read and has not returned; no full controller/foreground/device App or direct audio claim.',
            'No device I/O/write/install/call/sound or goal completion while user sleeps.'],
        focused_evidence=path,focused_evidence_sha256=sha(path),general_menu_development_evidence=runpath,
        full_general_MainMenu_final_guards_passed=False,device_io=False,device_files_written=False,
        native_firmware_or_research_package_written=False,automatic_calls_or_sound=False,attended_calls_or_sound=False,
        automatic_calls_or_sound_while_away=False,next_focus=actions[0],goal_status='active',full_goal_complete=False)
    for k in ['updated_utc','last_goal_turn','next_actions','current_priority','latest_user_instruction','attended_testing','ordered_priorities','user_resting']:task[k]=state[k]
    task.update(user_away=True,current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False)
    public=read('reports/findings.json');public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    details=[
        '原廠設定儲存：在獨立模擬儲存區執行原始初始化、建立紀錄與寫入位置；五組設定讀寫、快取更新及拒絕錯誤輸入驗證全部通過，原廠語音介面、程式區、配置邊界與備份資料庫保持一致。',
        '一般首頁整合：改用原廠設定紀錄讀取後，遇到另一筆未建模的儲存資料讀取；首頁仍未返回，完整控制器、前景播放器及實機 App 尚未完成。失敗過程與當時程式已另存。']
    for d in details:assert d not in progress['completed'];progress['completed'].append(d)
    assert progress['estimate_percent']==31 and len(progress['completed'])==59
    progress.update(research_updated_utc=now.isoformat(),next='追查首頁新增的儲存資料讀取、補設定預設值流程與控制器，再接前景播放器、安全清理、實機載入及手機直接藍牙音樂。')
    progress['phases'][4]['next']='原廠設定儲存已通過五組離線驗證；補首頁依賴、控制器、前景顯示與原機 App 載入。'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    card='''<div class="card"><h2>最新離線進展：原廠設定儲存流程已驗證</h2>
<p><strong>五組設定儲存驗證全部通過；尚未完成實機播放器 App。</strong>已用原廠程式初始化獨立模擬儲存區、建立紀錄和寫入游標，接著驗證設定寫入、讀回及複製。相同快取值不重複寫入，變更值會淘汰舊紀錄；缺少設定與錯誤輸入則走原廠拒絕分支。</p>
<p>原廠語音記憶體、40 個介面、程式區、配置邊界與備份資料庫檢查通過。模擬儲存區大小、底層寫入／清除、輔助資料與同步物件仍明示為測試輸入；沒有將模擬容量或資料持久性當成實機測量，也沒有更動車機設定。</p>
<p><strong>一般首頁仍未返回。</strong>接回首頁、改用原廠紀錄查詢後，遇到另一筆尚未還原的儲存資料讀取。五組測試通過的範圍僅為設定儲存，首頁預設值流程、完整守護檢查、控制器及前景顯示仍待完成。</p>
<p>自訂頁面仍隱藏且在畫面外，原機接受的 App 載入、觸控與手機直接藍牙音樂尚未完成。回呼清成零仍不能算作安全解除登記，停止、卸載與重載流程也需要繼續驗證。</p>
<p>進度維持約 31% 的里程碑估計，並非 App 完成度。麥克風已取消、聲道／音質精修擱置，Android Auto 排後、Google Maps 暫緩；使用者休息期間沒有車機操作、來電或播放聲音。</p></div>'''
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：記憶體回呼登記與查詢已驗證</h2>.*?</div>',lambda m:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda m:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對要求立即優先；休息期間只做離線研究。</p>',report,count=1);assert n==1
    report,n=re.subn(r'(<tr><td>原生 App 入口與功能整合</td><td>[^<]*</td><td>).*?(</td></tr>)',lambda m:m[1]+html.escape(progress['phases'][4]['next'])+m[2],report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>','<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task);write('reports/findings.json',public);(ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=len(app['static_findings']),focused_groups=5,estimate_percent=31,completed_items=59,updated_Taiwan=iso)))

if __name__=='__main__':main()
