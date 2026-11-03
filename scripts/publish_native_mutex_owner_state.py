#!/usr/bin/env python3
"""Publish complete native owner controls, retaining incomplete dispatcher scope."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import hashlib,html,json,re
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')

def main():
    base='staging/native-player-mutex-owner/'
    previous=read(base+'previous-checkpoint.json');before=read(previous['state']['path']);prior=read(previous['audit']['path'])
    assert prior['all_passed']and len(prior['scope_checks'])==19
    assert prior['state_sha256']==sha(previous['state']['path'])==previous['state']['sha256']
    assert sha(previous['audit']['path'])==previous['audit']['sha256']
    state,task,public=read('evidence/deep-research-state.json'),read('evidence/task-state.json'),read('reports/findings.json')
    app=state['native_app_music'];assert app['static_findings']==before['native_app_music']['static_findings']and len(app['static_findings'])==92
    assert not state['user_resting']and state['attended_testing']['user_present']and not task['user_away']
    proofpath='evidence/firmware-analysis/native-mutex-owner-emulation.json';proof=read(proofpath)
    staticpath=base+'mutex-owner-static-preflight.json';static=read(staticpath)
    indexpath=base+'preserved-development-evidence-index.json';index=read(indexpath)
    for p,s in index['source_artifact_sha256'].items():assert sha(p)==s,p
    for d in [proof,static]:
        for p,s in d['source_sha256'].items():assert sha(p)==s,p
    assert proof['all_passed']and proof['case_count']==5 and len(proof['source_sha256'])==99
    assert static['complete_bounded_CFG_count']==5 and static['complete_mixed_ARM_Thumb_function_count']==3
    meta_path=base+'dispatcher-native-owner-terminal-metadata.json';meta=read(meta_path);probe=read(meta['probe'])
    reacquire_path=base+'reacquisition-boundary-preflight.json';reacquire=read(reacquire_path)
    for p,s in reacquire['source_sha256'].items():assert sha(p)==s,p
    assert meta['session_id']==45010 and not probe['full_scoped_final_guards_passed']
    passed_owner=any(w['native_owner_gate_passed']for w in probe['native_condition_waits'])
    app['static_findings']['native_mutex_owner']=dict(evidence=proofpath,evidence_sha256=sha(proofpath),case_count=5,
        all_passed=True,source_artifact_count=99,static_evidence=staticpath,static_evidence_sha256=sha(staticpath),
        complete_bounded_CFG_count=5,complete_mixed_ARM_Thumb_function_count=3,verified_mode_transitions=12,
        original_lock='0x3009a0',original_unlock='0x3008b0',original_condition_constructor='0x3ec540',
        native_owner_list_recursion_and_nonhead_unlink_verified=True,host_seeded_semaphore_owner_fields=False,
        original_condition_return_after_IRQ_restore_and_LR_branch_verified=True,
        fictional96_byte_TCB_and_equal_thread_globals=True,real_scheduler_condition_wait_boot_or_App_verified=False,
        preserved_development_evidence=indexpath,preserved_development_evidence_sha256=sha(indexpath),
        device_io=False,sounds_emitted=False,limits=proof['limits'])
    app['development_observations']['dispatcher_with_native_mutex_owner']=dict(
        terminal_metadata=meta_path,terminal_metadata_sha256=sha(meta_path),development_evidence=meta['probe'],
        development_evidence_sha256=sha(meta['probe']),preserved_development_evidence=indexpath,
        preserved_development_evidence_sha256=sha(indexpath),session_id=45010,terminal_exit_code=meta['terminal_exit_code'],
        original_singleton_returned=probe['original_singleton_returned'],native_condition_owner_gate_passed=passed_owner,
        full_scoped_final_guards_passed=False,original_wake_boundary_remains_fixture=True,
        reacquisition_evidence=reacquire_path,reacquisition_evidence_sha256=sha(reacquire_path),
        native_unlock_after_wait_fatal_code='0x6e5d800b',native_unlock_after_wait_fatal_caller='0x3008e0',
        original_wait_return_seen_in_recent_trace=True,
        raw_wait_return_false_is_unupdated_journal_default=True,
        inherited_counter_only_reacquire_caller3EC692_inferred_from_CFG_and_harness=True,
        real_scheduler_foreground_controller_or_device_App_verified=False,device_io=False,sounds_emitted=False)
    now=datetime.now(timezone.utc)
    focus=('Restore original3009A0 reacquisition at caller3EC692 after original3EC5C6 wait returns; current subclass only scopes C++310408/direct/condition-ctor/auxiliary locks, so this call falls into inherited counter-only hook, leaving native owner0 and causing original3008B0 fatal6E5D800B at3008E0. Track original300BB8 release before updating observed counters; do not sweep locks or patch owner fields. '
        if passed_owner else 'Recover next original dispatcher dependency exposed by native C++ mutex ownership. ')
    focus+='Run45010 remains partial: '+probe.get('error','returned without complete final guards')+'. Raw original_wait_returned false was an unupdated default; recent6048D2 proves return. Equal fictional F09090/F090A0 remains a same-owner condition scenario, not real waiting/event delivery. Preserve native wake fixture; recover actual constructor-owner/task/ready/idle context and event post2FCF44 with prior matching context-switch evidence, then full singleton5D2130/controller405340/root/foreground guards.'
    actions=state['next_actions'];actions[0]=focus
    state.update(updated_utc=now.isoformat(),current_priority='Native player/menu App and direct phone Bluetooth music; original mutex ownership now passes scoped controls, native dispatcher wait/event/scheduler next. User present; attended pairing immediately preempts research. Goal active/no-achieve.')
    app['remaining_work']=actions[:4]
    state['attended_testing'].update(recorded_utc=now.isoformat(),current_attended_test='No physical test needed now. Continue original dispatcher wait/event delivery and context switching offline.')
    turn=state['last_goal_turn'];turn.update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=previous['state']['path'],previous_current_audit_snapshot=previous['audit']['path'],
        previous_turn_revalidation='Fresh19-scope checkpoint preserved;92 prior findings and34 selected frozen suites unchanged.',
        focused_evidence=proofpath,focused_evidence_sha256=sha(proofpath),
        latest_native_owner_full_scoped_final_guards_passed=True,
        latest_dispatcher_development_evidence=meta['probe'],latest_dispatcher_development_evidence_sha256=sha(meta['probe']),
        latest_dispatcher_native_owner_gate_passed=passed_owner,latest_dispatcher_run_full_scoped_final_guards_passed=False,
        next_focus=focus,goal_status='active',full_goal_complete=False)
    turn['reasons']=[
        'Five complete native mutex controls99 dependencies and five bounded CFGs including three mixed ARM/Thumb bodies12 verified transitions. Native owner/list/recursion stores and nonhead unlink execute without host writing semaphore owner fields.',
        'Original3EC540 constructor native owner token, same-owner300AE4, IRQ restore and actual LR return observed; explicit original unlock releases token.96-byte task inventory remains declared fixture, original globals restored and all final code/voice/canary/DB guards pass.',
        'Dispatcher45010 native owner gate passed='+str(passed_owner)+'; wait returns but subsequent unlock sees owner0 and raises6E5D800B. Reacquisition caller3EC692 still uses inherited counter-only hook (source/CFG inference); raw wait-return default false corrected by recent6048D2. Original wake/equal fictional thread identity remain fixtures. No complete dispatcher/controller/foreground guard pass.',
        'All92 previous findings and selected34 frozen suites retained. User present, no physical test/device I/O/write/install/call/sound or goal completion.']
    for k in ['updated_utc','current_priority','next_actions','last_goal_turn','attended_testing']:task[k]=state[k]
    public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    assert progress['estimate_percent']==32 and len(progress['completed'])==63
    details=[
        '原廠鎖定與解鎖：五組完整離線控制通過，原始 ARM／Thumb 指令寫入擁有者、處理重複鎖定與鏈結移除；沒有由測試程式代填鎖的擁有者。另完成五個函式、十二處指令集切換核對，原廠程式與配置邊界檢查通過。',
        '同步物件返回流程：原始初始化建立擁有者及保留鎖，確認恢復中斷狀態後才返回，再由原始解鎖釋放。新的事件物件試跑仍未通過完整檢查；底層執行緒資料、喚醒與排程尚不能當作實機行為。']
    progress['completed'].extend(details)
    progress.update(research_updated_utc=now.isoformat(),next='補齊原廠事件喚醒、等待與執行緒切換，再完成首頁控制器、前景顯示和正常操作；之後驗證安全清理、實機 App 與手機直接藍牙音樂。')
    progress['phases'][4]['next']='首頁初始化與原廠同步物件的鎖定已通過離線控制；接事件喚醒、等待及執行緒切換，再接前景顯示、操作與原機載入。'
    assert len(progress['completed'])==65 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==32
    continuation=('新的事件物件試跑已通過原廠執行緒擁有者檢查，但等待流程返回後，重新鎖定仍落入舊模擬器的計數替代，解鎖時因擁有者欄位缺失而中止。這是模擬環境仍待恢復原始指令的缺口，並非實機故障。'
        if passed_owner else '新的事件物件試跑仍未完成，下一層依賴與失敗紀錄已保存。')
    card='''<div class="card"><h2>最新離線進展：原廠鎖定與同步初始化已驗證</h2>
<p><strong>原廠鎖定、解鎖與同步物件初始化的五組完整離線控制通過。</strong>原始 ARM／Thumb 指令實際寫入擁有者與鏈結，能處理重複鎖定、移除鏈結及最後解鎖；沒有由測試程式代填鎖的擁有者。另核對五個原廠函式及十二處指令集切換。</p>
<p>原始同步初始化建立保留的鎖，確認恢復中斷狀態後才返回，並由原始解鎖釋放。原廠完整語音記憶體與 40 個介面、原廠與載入程式區、配置邊界及備份資料庫檢查通過。執行緒資料仍是明示的模擬輸入，這些結果不能當作真實開機、排程或實機音訊。</p>
<p>原廠首頁控制器與同步流程仍在整合：前輪六項控制完成五項後被擁有者檢查拒絕，原始失敗紀錄保留。'''+continuation+'''原廠喚醒服務目前仍包含模擬邊界，接下來補事件傳送、等待與執行緒切換；沒有模擬等待成功來跳過檢查。</p>
<p><strong>播放器已接入原廠首頁初始化；頁面目前仍是隱藏、零尺寸。</strong>前輪原廠載入器與十五格菜單整合的完整檢查仍有效，但前景顯示、觸控、畫面提交、停止與清理、原機套件載入及手機直接藍牙音樂仍待驗證。研究套件僅供模擬，未安裝到車機。</p>
<p>整體進度維持約 32%，是研究里程碑的加權估計；實機 App 尚未完成。目前無需插機或重做音訊測試。有具體測試時會提供步驟，現場藍牙配對立即優先。麥克風取消、音質精修擱置，Android Auto 排後、Google Maps 暫緩。</p></div>'''
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：原廠首頁控制器與同步流程</h2>.*?</div>',lambda m:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda m:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前無需實機操作。</p>',report,count=1);assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>.*?</td></tr>',lambda m:'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>'+html.escape(progress['phases'][4]['next'])+'</td></tr>',report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>','<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task);write('reports/findings.json',public)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=93,owner_groups=5,estimate_percent=32,completed_items=65,updated_Taiwan=iso)))

if __name__=='__main__':main()
