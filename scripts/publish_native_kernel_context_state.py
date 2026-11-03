#!/usr/bin/env python3
"""Publish original normal event/context controls separately from GUI integration."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import hashlib,html,json,re
from analyze_native_sections import ROOT

BASE='staging/native-player-kernel-context/'
PROOF='evidence/firmware-analysis/native-kernel-context-emulation.json'
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')

def main():
    previous=read(BASE+'previous-checkpoint.json');before=read(previous['state']['path']);prior=read(previous['audit']['path'])
    for row in previous.values():assert sha(row['path'])==row['sha256']
    assert prior['all_passed']and len(prior['scope_checks'])==25 and prior['state_sha256']==previous['state']['sha256']
    state,task,public=[read(p)for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];assert app['static_findings']==before['native_app_music']['static_findings']and len(app['static_findings'])==94
    assert state['attended_testing']['user_present']and not state['user_resting']and not task['user_away']
    proof=read(PROOF);staticpath=BASE+'kernel-context-static-preflight.json';static=read(staticpath)
    indexpath=BASE+'preserved-development-evidence-index.json';index=read(indexpath)
    for d in [proof,static]:
        for p,s in d['source_sha256'].items():assert sha(p)==s,p
    for p,s in index['source_artifact_sha256'].items():assert sha(p)==s,p
    assert proof['all_passed']and proof['case_count']==4 and len(proof['source_sha256'])==103
    metapath=BASE+'dispatcher-native-kernel-terminal-metadata.json';meta=read(metapath);probe=read(meta['probe'])
    app['static_findings']['native_kernel_context']=dict(evidence=PROOF,evidence_sha256=sha(PROOF),all_passed=True,
        case_count=4,source_artifact_count=103,static_evidence=staticpath,static_evidence_sha256=sha(staticpath),
        complete_bounded_normal_context_CFG_count=5,verified_interworking_transitions=17,
        original_normal_post='0x2fcf44',original_event_wait='0x2fd034',original_context_restore='0x358ec4',
        original_MAIN_patch_bytes=0,normal_event_context_roundtrips_verified=True,
        initial_CPU_mode_ready_membership_descriptors_and_boot_event_are_inputs=True,
        actual_GUI_dispatcher_foreground_or_device_App_verified=False,
        preserved_development_evidence=indexpath,preserved_development_evidence_sha256=sha(indexpath),
        device_io=False,sounds_emitted=False,limits=proof['limits'])
    app['development_observations']['dispatcher_with_original_kernel_context']=dict(
        terminal_metadata=metapath,terminal_metadata_sha256=sha(metapath),development_evidence=meta['probe'],
        development_evidence_sha256=sha(meta['probe']),preserved_development_evidence=indexpath,
        preserved_development_evidence_sha256=sha(indexpath),session_id=meta['session_id'],terminal_exit_code=meta['terminal_exit_code'],
        original_singleton_returned=probe['original_singleton_returned'],full_scoped_final_guards_passed=False,
        kernel_context_restores=probe['kernel_restores'],actual_foreground_or_device_App_verified=False,
        device_io=False,sounds_emitted=False)
    focus=('Recover task-scoped original mutex ownership, contention and waiter wakeups for GUI dispatcher constructor/condition wait with native kernel context switching. '
        '4812 four complete controls103 dependencies execute unchanged MAIN original post2FCF44/wait2FD034/restore358EC4; saved native destination PCs reached, timer boot roundtrip, zero-event no-wake negative control, controller block/posted1 resume. '
        'Initial system CPU mode, synthetic native-built controller/idle descriptors/stacks, initial ready membership and explicit boot event remain input fixtures, not full boot/IRQ. Idle post continuation and tasks/module stay resident. '
        'Latest GUI integration35440 remains without full guards: '+probe.get('error','constructor returned; complete final/lifetime guards still missing')+'. '
        '35440 original358CD2 inserts two extra native GUI tasks, then original condition wait switches to worker8804FB8 entry5D215C, which calls singleton5D2130; inherited single-current-controller mutex scope rejects its3009A0 C++lock request before native body. Track native mutex operations per TCB instead of controller-only identity, restore original contention/waiter queues without host owner writes or fake wake; recover remaining producer/boot order; then singleton/full guards, original405340/root foreground, touch/display and safe lifecycle. No fake success or host context/owner patch.')
    now=datetime.now(timezone.utc);state['next_actions'][0]=focus;app['remaining_work']=state['next_actions'][:4]
    state.update(updated_utc=now.isoformat(),current_priority='Native menu player App and direct phone Bluetooth music; original normal event/context controls complete, native GUI worker entered, task-scoped mutex contention and condition wake integration next. Pairing immediately preempts research; goal active/no-achieve.')
    state['attended_testing'].update(recorded_utc=now.isoformat(),current_attended_test='No physical test needed now; recover task-scoped native mutex contention, condition wake and GUI boot offline.')
    turn=state['last_goal_turn'];turn.update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=previous['state']['path'],previous_current_audit_snapshot=previous['audit']['path'],
        previous_turn_revalidation='Fresh25-scope checkpoint preserved;94 previous findings and36 selected frozen suites retained.',
        focused_evidence=PROOF,focused_evidence_sha256=sha(PROOF),latest_native_kernel_context_full_scoped_final_guards_passed=True,
        latest_context_restore_executed=True,latest_context_restore_scope='four normal-event controls, not full GUI dispatcher or device boot',
        latest_dispatcher_development_evidence=meta['probe'],latest_dispatcher_development_evidence_sha256=sha(meta['probe']),
        latest_dispatcher_run_full_scoped_final_guards_passed=False,latest_dispatcher_original_singleton_returned=probe['original_singleton_returned'],
        next_focus=focus,goal_status='active',full_goal_complete=False)
    turn['reasons']=[
        'Four original kernel task/event/context controls103 exact dependencies pass all final guards with unchanged MAIN. Native timer/controller saved PCs reached, zero-event no-wake control, original controller wait blocks and resumes event1. No Python CPU context restore or fake event success.',
        'Five bounded normal-context mixed CFGs17 interworking transitions verify native frame offset12 and CPSR/banked-register restore. Explicit initial CPU system mode repairs1399 harness mode mismatch; failed raw1399 and initial setup retained.',
        'Actual GUI integration35440 remains partial with no full final guards: '+probe.get('error','singleton returned but no complete final guards')+'. Native task-list insertion observations and wait/restore evidence preserved; no foreground/device App/direct music or safe unload proof.',
        'All94 previous findings and36 selected frozen suites preserved. User present, no physical request/I/O/write/install/call/sound or goal completion.']
    for k in ['updated_utc','current_priority','next_actions','last_goal_turn','attended_testing']:task[k]=state[k]
    public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    assert progress['estimate_percent']==32 and len(progress['completed'])==67
    details=[
        '原廠事件與執行緒切換：四組完整控制通過，計時器能被喚醒、等待並返回原呼叫者；另一組等待可阻塞再因事件恢復，零事件不會假喚醒。原廠指令保持原樣，103 項來源與記憶體邊界、語音介面及程式區檢查通過。',
        '核心切換核對：五個完整正常事件流程、十七處 ARM／Thumb 切換已核對；起始 CPU 模式與排程名單仍是明示的測試輸入。新的首頁事件整合仍未通過完整檢查，原廠流程已進入額外執行緒，但舊模擬器單一執行緒的鎖定限制阻止繼續；多執行緒等待、正常前景操作與安全清理尚在研究。']
    progress['completed'].extend(details);progress.update(research_updated_utc=now.isoformat(),
        next='補上原廠多執行緒的鎖定、等待與喚醒，再核對首頁開機依賴，再完成前景顯示、正常操作和安全清理；之後驗證原機 App 與手機直接藍牙音樂。')
    progress['phases'][4]['next']='四組原廠事件傳送／執行緒切換控制通過；首頁試跑已進入原廠額外執行緒，接多執行緒的鎖定與喚醒，再完成前景顯示、操作與原機載入。'
    assert len(progress['completed'])==69 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==32
    card='''<div class="card"><h2>最新離線進展：原廠事件傳送與執行緒切換</h2>
<p><strong>四組完整原廠事件與切換控制通過。</strong>原始程式能喚醒計時器、讓它等待，再返回原呼叫者；另一組等待可真正阻塞，收到事件後繼續原流程。零事件的控制組没有產生假喚醒。103 項來源與資料核對，以及程式區、語音介面、配置邊界、備份資料庫和執行緒堆疊邊界檢查通過。</p>
<p>這次直接執行原廠事件與核心切換指令，沒有修改韌體程式，也沒有由測試程式代填等待成功或恢復 CPU 狀態。另核對五個正常事件流程與十七處指令集切換。起始 CPU 模式、初始排程名單、部分執行緒與堆疊，以及啟動事件仍是明示的測試輸入；實機開機、硬體中斷與安全清理仍未驗證。</p>
<p><strong>首頁事件整合仍在驗證，尚未通過完整檢查。</strong>這套原廠切換已接回事件物件試跑，建立兩個額外執行緒並進入其中一個；接著被舊模擬器只允許單一執行緒鎖定的限制擋住。下一步補多執行緒的鎖定、等待與喚醒，再核對開機依賴。通過的四組核心控制與尚未完成的首頁整合分別保留原始證據。</p>
<p><strong>播放器已接入原廠首頁初始化；頁面目前仍是隱藏、零尺寸。</strong>既有菜單整合結果仍有效；前景顯示、觸控、畫面提交、停止與清理、原機套件載入及手機直接藍牙音樂仍待驗證。研究套件僅供模擬，未安裝到車機。</p>
<p>整體估計約 32%，以研究里程碑加權計算。目前不需要插機或重做音訊測試；有具體測試時會提供步驟，現場藍牙配對立即優先。麥克風取消、音質精修擱置，Android Auto 排後、Google Maps 暫緩。</p></div>'''
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：事件物件建立與原廠計時器依賴</h2>.*?</div>',lambda m:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda m:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前無需實機操作。</p>',report,count=1);assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>.*?</td></tr>',lambda m:'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>'+html.escape(progress['phases'][4]['next'])+'</td></tr>',report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>','<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task);write('reports/findings.json',public)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=95,kernel_groups=4,estimate_percent=32,completed_items=69,updated_Taiwan=iso)))

if __name__=='__main__':main()
