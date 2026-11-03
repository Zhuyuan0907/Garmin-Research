#!/usr/bin/env python3
"""Publish original heap field controls while retaining incomplete UI/lifetime limits."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from pathlib import Path
import hashlib,html,json,re
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')

def main():
    prefix='staging/native-player-heap-callback/'
    previous=read(prefix+'previous-checkpoint.json');before,audit=read(previous['state']),read(previous['audit'])
    assert audit['all_passed']and len(audit['scope_checks'])==12 and audit['state_sha256']==sha(previous['state'])
    assert sha(previous['state'])==previous['state_sha256']and sha(previous['audit'])==previous['audit_sha256']
    state,task=read('evidence/deep-research-state.json'),read('evidence/task-state.json');app=state['native_app_music']
    assert state['user_resting']and not state['attended_testing']['user_present']
    assert app['static_findings']==before['native_app_music']['static_findings']
    path='evidence/firmware-analysis/native-heap-callback-emulation.json';proof=read(path)
    assert proof['all_passed']and proof['case_count']==5
    for p,s in proof['source_sha256'].items():assert sha(p)==s,p
    staticpath=prefix+'heap-callback-static-preflight.json';releasepath=prefix+'heap-release-static-preflight.json'
    static,release=read(staticpath),read(releasepath);assert static['complete_bounded_CFG_count']==4 and release['complete_bounded_CFG_count']==2
    runpath=prefix+'general-menu-development-terminal.json';meta=read(prefix+'general-menu-development-terminal-metadata.json')
    probe=read(runpath);assert sha(meta['source'])==meta['source_sha256']and sha(runpath)==meta['probe_sha256']
    assert not probe['full_integration_checkpoint']
    failures=[];indexed={}
    for stem in ['original_load_budget_failure','loaded_validator_count_assumption_failure']:
        mpath=prefix+stem+'-metadata.json';doc=read(mpath)
        for key in ['source','VM_source','probe']:
            assert sha(doc[key])==doc[key+'_sha256'];indexed[doc[key]]=sha(doc[key])
        indexed[mpath]=sha(mpath);failures.append(dict(path=mpath,sha256=sha(mpath),terminal_exit_code=doc['terminal_exit_code']))
    for p in [runpath,prefix+'general-menu-development-terminal-metadata.json']:indexed[p]=sha(p)
    indexed[meta['source']]=sha(meta['source'])
    indexpath=prefix+'preserved-development-evidence-index.json'
    write(indexpath,dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_artifact_sha256=indexed,
        failed_focused_runs=failures,general_menu_terminal_metadata=prefix+'general-menu-development-terminal-metadata.json',
        general_menu_terminal_exit_code=meta['terminal_exit_code'],general_MainMenu_constructor_returned=probe['completed'],
        full_general_MainMenu_final_guards_passed=False,device_io=False,sounds_emitted=False))
    returned=probe['completed'];pc=probe.get('registers',{}).get('pc')
    app['static_findings']['native_heap_callback']=dict(evidence=path,evidence_sha256=sha(path),case_count=5,all_passed=True,
        source_artifact_count=len(proof['source_sha256']),static_evidence=staticpath,static_evidence_sha256=sha(staticpath),
        complete_static_CFG_count=4,release_static_evidence=releasepath,release_static_evidence_sha256=sha(releasepath),
        release_complete_static_CFG_count=2,original_descriptor_validator='0x388e92',original_registration='0x388af4',
        original_pointer_query='0x388804',native_validation_body_executed_not_host_success_stub=True,
        query_preserves_registered_callback_and_flag_bits=True,zero_callback_store_not_safe_unregister=True,
        actual_callback_delivery_release_resize_or_full_heap_lifetime_verified=False,
        general_MainMenu_constructor_returned=returned,general_MainMenu_latest_failure_PC=pc,
        latest_settings_write_entry='0x2ca82c',latest_original_MainMenu_caller='0x405310',
        latest_original_MainMenu_default_setting_key='0x121e',
        latest_missing_settings_write_cache_is_fixture_gap_not_device_failure=True,
        full_general_MainMenu_final_guards_passed=False,general_MainMenu_controller_executed=False,
        general_menu_development_evidence=runpath,general_menu_development_evidence_sha256=sha(runpath),
        preserved_development_evidence=indexpath,preserved_development_evidence_sha256=sha(indexpath),
        previous_checkpoint=previous,device_io=False,sounds_emitted=False,limits=proof['limits'])
    app['development_observations']['general_MainMenu_heap_descriptor']=dict(
        native_descriptor_validation_and_field_registration_are_scoped_passes=True,
        latest_constructor_returned=returned,full_constructor_data_voice_allocation_SQL_final_guards_not_run=True,
        UI_controller_foreground_display_package_acceptance_and_safe_unload_unverified=True)
    actions=[
        'Recover settings write-cache initialization for original2CA82C: MainMenu405310 attempts default key121E after the explicit missing-record read; PC2CA8A4 reads NULL cache header. The current19B lower read-only inventory fixture does not supply a writer cache. Preserve original setters/default computation and do not mark the whole menu successful or write any real device settings. Then continue40434C/controller405340 with full final guards.',
        'Execute original388746 callback dispatch/release path and388676 core cleanup with explicit task/allocator boundaries; preserve registered callback lifetime. Zeroing callback leaves flags6 and does not disable the native indirect call. Do not claim safe unload from field-only controls.',
        'Join normal-menu foreground player to accepted modified VPM/SIG loading, sourceID9 stop/repeat/cleanup and safe root/module/font/cache/stream lifecycle. Stock custom Page remains hidden/offscreen; packages remain EMULATION-ONLY.',
        'Integrate native/kernel continuous audio and direct phone Bluetooth with navigation coexistence and recovery. Microphone canceled, stereo/fidelity deprioritized; Android Auto later, Maps deferred.',
        'User still sleeping: offline only, no USB/Bluetooth/device I/O, writes, calls/sound or physical questions. Explicit return: live audio/agent preparation and pairing first. Goal active/no-achieve.']
    now=datetime.now(timezone.utc);state.update(updated_utc=now.isoformat(),next_actions=actions);app['remaining_work']=actions[:4]
    state['last_goal_turn']=dict(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=previous['state'],previous_current_audit_snapshot=previous['audit'],
        previous_turn_revalidation='Fresh12-scope signal checkpoint preserved;87 prior findings and29 selected frozen suites retained.',
        reasons=['Four complete original heap CFGs and two release CFGs recover callback field12, flags/pointer field4 and backlink validation.',
            'Five original-code descriptor/query/registration/preservation/replacement/fatal controls pass full voice/code/canary/DB guards; original validator runs, rather than returning synthetic success.',
            'Zero callback with flags6 still leaves original release indirect-call branch enabled; dispatch/core cleanup/lifetime remain unverified.',
            'New general-menu development terminal evidence retained separately; it does not establish full MainMenu final guards, controller, visible App, actual boot/kernel/device loading or audio.',
            'Offline only while user sleeps; no device I/O/writes/sound/install or goal completion.'],
        focused_evidence=path,focused_evidence_sha256=sha(path),general_menu_development_evidence=runpath,
        full_general_MainMenu_final_guards_passed=False,device_io=False,device_files_written=False,
        native_firmware_or_research_package_written=False,automatic_calls_or_sound=False,attended_calls_or_sound=False,
        automatic_calls_or_sound_while_away=False,next_focus=actions[0],goal_status='active',full_goal_complete=False)
    for k in ['updated_utc','last_goal_turn','next_actions','current_priority','latest_user_instruction','attended_testing','ordered_priorities','user_resting']:task[k]=state[k]
    task.update(user_away=True,current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False)
    public=read('reports/findings.json');public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    status='離線構造函式已返回，但整體守護檢查、控制器及真實顯示仍待完成'if returned else'首頁整體尚未完成，新的執行停止點與程式版本已保留'
    details=[
        '記憶體回呼介面：五組原廠指令控制驗證通過，涵蓋描述表驗證、回呼登記、重複查詢保留旗標、替換與兩項無效描述表錯誤分支；完整語音、程式區、配置邊界及備份資料庫檢查通過。',
        '回呼生命週期追查：原廠釋放流程不會因回呼指標歸零而解除呼叫旗標，安全清理仍需研究。接回一般首頁後，'+status+'；尚未完成實機播放器 App。']
    for d in details:assert d not in progress['completed'];progress['completed'].append(d)
    assert progress['estimate_percent']==31 and len(progress['completed'])==57
    progress.update(research_updated_utc=now.isoformat(),next='繼續一般首頁與控制器，補回呼執行／釋放及安全清理，再接前景播放器、實機載入與手機直接藍牙音樂。')
    progress['phases'][4]['next']='回呼登記／查詢已通過局部驗證；補一般首頁、控制器、回呼釋放、前景顯示與原機載入。'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    card='''<div class="card"><h2>最新離線進展：記憶體回呼登記與查詢已驗證</h2>
<p><strong>五組原廠指令控制驗證通過；尚未完成實機播放器 App。</strong>已讓原廠驗證程式檢查記憶體描述表，再由原廠程式登記回呼、設定旗標並查詢資料指標。重複查詢保留已登記的回呼及旗標，兩項無效描述表控制也走到原廠錯誤分支。</p>
<p>完整語音記憶體、40 個介面、程式區、配置邊界與備份資料庫檢查通過。模擬明示提供配置、描述表初值、互斥鎖及不透明控制代號的轉換；原廠驗證指令並未被「成功回傳」取代，實際記憶體配置器與回呼排程仍待驗證。</p>
<p><strong>只把回呼清成零，不能算作安全解除登記。</strong>原廠程式仍保留呼叫旗標，釋放流程沒有先檢查該指標是否為零。下一步補回呼執行、物件釋放與安全清理；這輪沒有聲稱停止、卸載或重新載入已完成。</p>
<p>一般首頁進度：STATUS。自訂頁面仍隱藏且在畫面外，真實開機初始化、控制器、前景顯示、原機接受的載入、觸控及手機直接藍牙音樂均未完成。</p>
<p>進度維持約 31% 的里程碑估計，並非 App 完成度。麥克風已取消、聲道／音質精修擱置，Android Auto 排後、Google Maps 暫緩；使用者休息期間沒有車機操作、來電或播放聲音。</p></div>'''.replace('STATUS',html.escape(status))
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：找到一般首頁缺少的通知初始化</h2>.*?</div>',lambda m:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda m:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對要求立即優先；休息期間只做離線研究。</p>',report,count=1);assert n==1
    report,n=re.subn(r'(<tr><td>原生 App 入口與功能整合</td><td>[^<]*</td><td>).*?(</td></tr>)',lambda m:m[1]+html.escape(progress['phases'][4]['next'])+m[2],report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>','<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task);write('reports/findings.json',public);(ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=len(app['static_findings']),focused_groups=5,estimate_percent=31,completed_items=57,updated_Taiwan=iso,general_ctor_returned=returned)))

if __name__=='__main__':main()
