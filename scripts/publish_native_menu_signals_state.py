#!/usr/bin/env python3
"""Record scoped signal proof and distinct incomplete general-menu traces."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import hashlib,html,json,re
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')

def main():
    prefix='staging/native-player-mainmenu-context/'
    previous=read(prefix+'previous-checkpoint.json');before,audit=read(previous['state']),read(previous['audit'])
    assert audit['all_passed']and len(audit['scope_checks'])==17 and audit['state_sha256']==sha(previous['state'])
    assert sha(previous['state'])==previous['state_sha256']and sha(previous['audit'])==previous['audit_sha256']
    state,task=read('evidence/deep-research-state.json'),read('evidence/task-state.json')
    app=state['native_app_music'];assert app['static_findings']==before['native_app_music']['static_findings']
    assert state['user_resting']and not state['attended_testing']['user_present']
    proofpath='evidence/firmware-analysis/native-menu-signals-emulation.json';proof=read(proofpath)
    assert proof['all_passed']and proof['case_count']==3
    for p,s in proof['source_sha256'].items():assert sha(p)==s,p
    staticpath=prefix+'shared-signal-static-preflight.json';static=read(staticpath);assert static['complete_bounded_CFG_count']==7
    stems=['uninitialized-signal-failure','signal-init-registration-query-failure','preinspection-unmapped-BSS-failure',
        'native-tree-empty-assumption-failure','empty-callback-holder-ABI-failure']
    metadata=[];artifacts={}
    for stem in stems:
        path=prefix+stem+'-metadata.json';doc=read(path)
        for key in ['source','probe']:
            assert sha(doc[key])==doc[key+'_sha256'],doc[key]
            artifacts[doc[key]]=sha(doc[key])
        artifacts[path]=sha(path);metadata.append(dict(path=path,sha256=sha(path),terminal_exit_code=doc['terminal_exit_code']))
    first,second=read(prefix+stems[0]+'.json'),read(prefix+stems[1]+'.json')
    assert not first['completed']and first['signal_context_entries'][-1]['arguments'][1]=='0x0'
    assert not second['completed']and second['original_shared_signal_initializer_returned']
    assert second['registers']['pc']=='0x388e92'and second['registers']['lr']=='0x388b0d'
    indexpath=prefix+'preserved-development-evidence-index.json'
    write(indexpath,dict(updated_utc=datetime.now(timezone.utc).isoformat(),metadata=metadata,
        source_artifact_sha256=artifacts,failed_or_partial_run_count=5,
        before_signal_init_failure=prefix+stems[0]+'.json',after_signal_init_failure=prefix+stems[1]+'.json',
        host_preinspection_BSS_failure=prefix+stems[2]+'.json',
        general_MainMenu_constructor_returned=False,full_general_MainMenu_final_guards_passed=False,
        device_io=False,sounds_emitted=False))
    app['static_findings']['native_menu_signals']=dict(evidence=proofpath,evidence_sha256=sha(proofpath),
        case_count=3,all_passed=True,source_artifact_count=len(proof['source_sha256']),
        static_evidence=staticpath,static_evidence_sha256=sha(staticpath),complete_static_CFG_count=7,
        original_initializer='0x4a388a',original_subscription='0x4a3846 ->0x4419b8 ->0x36294e',
        shared_signal_global='0x3471c30',original_shared_signal_count=8,
        observed_missing_signal_owner_identified=True,event_meanings_or_actual_boot_order_verified=False,
        preserved_development_evidence=indexpath,preserved_development_evidence_sha256=sha(indexpath),
        general_MainMenu_constructor_returned=False,latest_general_MainMenu_failure_PC='0x388e92',
        latest_general_MainMenu_failure_caller='0x388b0c',
        latest_general_MainMenu_failure='Inherited heap descriptor fixture allows pointer queries but rejects original callback registration wrapper388AF4.',
        original_signal_init_passes_prior_NULL_boundary_only_in_partial_development=True,
        full_general_MainMenu_final_guards_passed=False,callback_delivery_verified=False,
        previous_checkpoint=previous,device_io=False,sounds_emitted=False,limits=proof['limits'])
    app['development_observations']['general_MainMenu_signal_context']=dict(
        original_missing_owner_not_connection_cleanup=True,stock_signal_initializer_recovered=True,
        before_after_source_and_failed_runs_preserved=True,
        after_init_original_menu_reaches_heap_callback_registration_fixture_boundary=True,
        partial_development_is_not_a_full_menu_or_visible_App_success=True)
    actions=[
        'Recover original388AF4 heap callback registration and388E92 descriptor ABI, whose new caller388B0C is explicitly rejected by the old pointer-query-only fixture. Use a new scoped VM/control; preserve descriptor flag/callback lifetime and do not broaden historical hooks or claim general MainMenu success.',
        'Continue unchanged general40434C constructor and405340 controller after the scoped heap boundary is validated. Actual boot signal initialization/event semantics and UI thread/display remain open; stock custom Page is still hidden/offscreen.',
        'Establish accepted modified VPM/SIG loading, foreground normal-menu player, sourceID9 stop/repeat/cleanup and safe detach/unregister/reload/unload/font/cache/stream lifetime. Research packages remain EMULATION-ONLY; do not install.',
        'Join native/kernel continuous audio to direct phone Bluetooth with recovery/navigation coexistence. Microphone canceled and stereo/fidelity deprioritized; Android Auto later, Maps deferred.',
        'User still sleeping: offline only; no USB/Bluetooth/device I/O, writes, calls/sound or physical questions. On explicit return, live audio/agent preparation and pairing first. Goal active/no-achieve.']
    now=datetime.now(timezone.utc);state.update(updated_utc=now.isoformat(),next_actions=actions);app['remaining_work']=actions[:4]
    state['last_goal_turn']=dict(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=previous['state'],previous_current_audit_snapshot=previous['audit'],
        previous_turn_revalidation='Fresh17-scope prior menu/root checkpoint saved;86 findings and28 selected frozen suites retained.',
        reasons=['Seven original bounded CFGs identify missing shared signal3471C30 and its original eight-object initializer4A388A.',
            'Three focused original-code controls and complete voice/code/canary/DB guards pass; no listeners or GUI success manufactured.',
            'The before/after development traces preserve both sources and terminal failures. Original initialization passes the prior NULL owner branch but general menu now stops at the narrowly limited heap callback-registration fixture.',
            'General MainMenu, foreground App, actual boot/event delivery/package acceptance/device display/direct-phone music remain unverified; hidden custom Page result unchanged.',
            'Sleeping user: no device I/O/writes/sound/install or goal completion.'],
        focused_evidence=proofpath,focused_evidence_sha256=sha(proofpath),
        full_general_MainMenu_final_guards_passed=False,device_io=False,device_files_written=False,
        native_firmware_or_research_package_written=False,automatic_calls_or_sound=False,attended_calls_or_sound=False,
        automatic_calls_or_sound_while_away=False,next_focus=actions[0],goal_status='active',full_goal_complete=False)
    for k in ['updated_utc','last_goal_turn','next_actions','current_priority','latest_user_instruction','attended_testing','ordered_priorities','user_resting']:task[k]=state[k]
    task.update(user_away=True,current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False)
    public=read('reports/findings.json');public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    details=[
        '一般首頁通知物件追查：七個原廠有界流程找出未初始化的通知物件；三組獨立控制驗證原廠建立八個互不共用的通知物件、樹狀資料與空回呼拒絕，程式、語音介面、配置邊界及資料庫檢查通過。',
        '補上原廠通知初始化後，首頁模擬越過前一個空物件錯誤，停在尚未提供的記憶體回呼登記介面；兩次失敗與程式版本均保留。這是局部進展，一般首頁、可見 App 與實機播放仍未完成。']
    for d in details:assert d not in progress['completed'];progress['completed'].append(d)
    assert progress['estimate_percent']==31 and len(progress['completed'])==55
    progress.update(research_updated_utc=now.isoformat(),next='先驗證記憶體回呼登記，再繼續一般首頁與前景播放器入口、實機載入及手機直接藍牙音樂。')
    progress['phases'][4]['next']='原廠通知初始化已驗證；補記憶體回呼登記、一般首頁、前景顯示、實際載入與停止／重播。'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    card='''<div class="card"><h2>最新離線進展：找到一般首頁缺少的通知初始化</h2>
<p><strong>三組獨立控制驗證通過；一般首頁仍未完整通過。</strong>追查這台台灣 2565RT 的原廠程式後，確認首頁在訂閱通知時使用了尚未建立的訊號物件。已找到原廠初始化流程，原廠指令會建立八個不同的通知物件及其資料結構；七個有界流程完成靜態核對。</p>
<p>完整語音記憶體、40 個介面、程式區、配置邊界與資料庫检查通過。空回呼控制由原廠程式拒絕；沒有讓模擬器虛構訂閱成功或收到通知。這項驗證不包含真實開機順序和通知事件的用途。</p>
<p><strong>一般首頁模擬已越過前一個空物件錯誤，接著停在記憶體回呼登記介面。</strong>既有模擬邊界只提供指標查詢，遇到新的原廠登記呼叫會明確停止。初始化前後的程式、兩次失敗及預檢讀取未映射資料的修正紀錄均保留；後者是測試環境問題，不能說車機本身有故障。</p>
<p>下一步驗證登記介面及物件存活規則，再繼續一般首頁、控制器與前景顯示。先前掛接的自訂頁面仍隱藏且在畫面外，尚未在原機安裝播放器 App，也未完成手機直接藍牙音樂。</p>
<p>進度維持約 31% 的里程碑估計，並非 App 完成度。麥克風已取消、聲道／音質精修擱置；Android Auto 排後、Google Maps 暫緩。使用者休息期間沒有車機操作、來電或播放聲音。</p></div>'''.replace('检查','檢查')
    pattern=r'<div class="card"><h2>最新離線進展：主選單依賴與頁面掛接局部驗證</h2>.*?</div>'
    report,n=re.subn(pattern,lambda m:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda m:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對要求立即優先；使用者休息期間只做離線研究。</p>',report,count=1);assert n==1
    report,n=re.subn(r'(<tr><td>原生 App 入口與功能整合</td><td>[^<]*</td><td>).*?(</td></tr>)',
        lambda m:m[1]+html.escape(progress['phases'][4]['next'])+m[2],report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>','<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task);write('reports/findings.json',public)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=len(app['static_findings']),focused_groups=3,estimate_percent=31,completed_items=55,updated_Taiwan=iso)))

if __name__=='__main__':main()
