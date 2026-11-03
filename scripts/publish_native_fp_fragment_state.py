#!/usr/bin/env python3
"""Publish narrow cross-owner FP controls, retaining complete boot boundaries."""
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from functools import lru_cache
import hashlib,html,json,re
ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-dispatcher-fp/'
RUNTIME=BASE+'micro-vfp/'
PROOF='evidence/firmware-analysis/native-multiowner-vfp-fragment-controls.json'
STATIC={
    'native_multiowner_FP_exact_observer_contract':BASE+'fp-static/native-multiowner-vfp-observer-contract.json',
    'native_Dispatcher_actor_shape_helper_contract':BASE+'gui-static/dispatcher-actor-guard-contract.json',
    'native_outer_voice_event_loader_contract':BASE+'package-static/native-outer-voice-load-and-sig-request-contract.json',
}
AUXILIARY=[BASE+'fp-static/native-vfp-retry-and-control-branch-clarification.json',
           BASE+'fp-static/multiowner-vfp-helper-peer-review-8fc0a2bcf631.json']
def read(p):return json.loads((ROOT/p).read_text())
@lru_cache(None)
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def registry(d):
    for p,s in d.items():assert sha(p)==s,p
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def main():
    audit=read(BASE+'previous-audit.json');before=read(BASE+'previous-state.json')
    for r in read(BASE+'previous-checkpoint.json')['snapshots']:assert sha(r['snapshot'])==r['sha256']
    assert audit['all_passed'] and len(audit['scope_checks'])==31 and len(audit['protected_sources'])==751
    registry(audit['protected_sources'])
    state,task,public=[read(p) for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];assert app['static_findings']==before['native_app_music']['static_findings'] and len(app['static_findings'])==132
    assert len(public['research_progress']['completed'])==104
    proof=read(PROOF);registry(proof['source_sha256'])
    assert proof['all_passed'] and proof['case_count']==5 and proof['original_fragment_controls'] and not proof['complete_cold_boot_or_Dispatcher_integration_scenario']
    for k,p in STATIC.items():
        d=read(p);registry(d['source_sha256'])
        for f in ['rechecked_existing_source_registry','verified_protected_sources']:
            if f in d:registry(d[f])
        app['static_findings'][k]=dict(evidence=p,evidence_sha256=sha(p),static_only=True,new_guest_execution=False,
            device_io=False,sounds_emitted=False,actual_Dispatcher_or_SIG_enforcement_verified=False)
    for p in AUXILIARY:registry(read(p)['source_sha256'])
    assert read(AUXILIARY[1])['assertions_passed'] and not read(AUXILIARY[1])['concrete_micro_blockers']
    app['static_findings']['native_multiowner_FP_exact_observer_contract']['branch_clarification']={p:sha(p) for p in AUXILIARY}
    result=dict(evidence=PROOF,evidence_sha256=sha(PROOF),cases=5,original_fragment_controls=True,
        original_save148_advance152_clone40_VSTM128_VLDM128_and_saved_owner_retry_passed=True,
        whole_zone_guards_independently_replayed=True,TCBs_metadata_task_selection_and_exception_entry_are_explicit_virtual_fixtures=True,
        complete_cold_Dispatcher_integration_scenario=False,device_io=False,sounds_emitted=False,
        native_menu_App_direct_music_or_modified_package_verified=False)
    app['static_findings']['native_multiowner_FP_fragment_controls']=result
    app['development_observations']['native_multiowner_FP_fragment_controls']=result
    app['package_signature'].update(latest_native_requester_evidence=STATIC['native_outer_voice_event_loader_contract'],
        latest_native_requester_evidence_sha256=sha(STATIC['native_outer_voice_event_loader_contract']),
        native_SIG_requester_or_enforcement_identified=False)
    now=datetime.now(timezone.utc)
    focus=('Integrate new exact original multiowner FP observer into a new complete cold native controller→Signal/register/queue/WAIT→actual Dispatcher405340 run. '
        'Five original-fragment controls proved Csave/noDrestore, Dsave+clone40/Crestore, reuseCsave/Drestore and sameowner under explicit virtual task inputs; '
        'they are not native scheduler or actual Dispatcher proof. Preserve earlier complete cold boot/component and all frozen guards. '
        'Use new actor shape helper to scope manager2init/6raw/currentTCB locks, original fixedclock0, cleanup oldchain and GIR/font/cache frames. '
        'Trace higher original voice40 eventqueue/wait/selection actor for actual filename/handle/nativeSIG request; mount-active and fread count are not acceptedcode proof. '
        'Then original foreground/touch, one-bootstrap music/callback lifecycle and physical modified-code package acceptance. '
        'Pairing first; mic canceled; fidelity deferred; AA later; Maps deferred; goalactive/no-achieve.')
    state.update(updated_utc=now.isoformat(),current_priority='Complete cold native Dispatcher integration of proven FP fragment observer; active goal/no-achieve.')
    state['next_actions'][0]=focus;app['remaining_work']=state['next_actions'][:4]
    state['parallel_research'].update(tasks=['original multiowner FP observer and exact-source review','pure Dispatcher actor/frame shapes',
        'original voice event loader and native SIG requester provenance'],continued_round_completed=True,agents_currently_running=False)
    state['last_goal_turn'].update(classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=BASE+'previous-state.json',
        previous_current_audit_snapshot=BASE+'previous-audit.json',previous_turn_revalidation='Fresh31-scope132-finding checkpoint/751 protected sources snapshotted.',
        focused_evidence=PROOF,focused_evidence_sha256=sha(PROOF),latest_FP_fragment_controls=5,
        native_multiowner_FP_fragment_controls_verified=True,complete_native_Dispatcher_FP_integration_verified=False,
        native_foreground_or_multiowner_FP_verified=False,native_signature_enforcement_verified=False,
        next_focus=focus,goal_status='active',full_goal_complete=False,
        reasons=['New unchanged original handler executes actual save148/152, clone40, VSTM128 and VLDM128 across two explicit task fixtures.',
            'Five fragment controls and whole-zone independent replay pass; complete native scheduler/Dispatcher integration remains required.',
            'Three authorized branches supply exact actor guards and higher original voicequeue/selection provenance without physical acceptance claim.'])
    for k in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research']:task[k]=state[k]
    public.update(updated=now.isoformat(),deep_research=state);progress=public['research_progress']
    details=[
        '新增五項原廠浮點切換小型測試通過：實際執行保存、148 位元組申請／152 位元組前進、40 位元組資料複製與恢復；三次保存的 128 位元組暫存器資料逐筆核對。這使用明示虛擬執行緒資料，還不是完整選單派送成功。',
        '浮點返回規則已驗證：第一次交給新執行緒只保存舊資料；往返後恢復各自保存的暫存器，同一執行緒再使用時保留當下資料。完整浮點區域、原廠指令與例外堆疊檢查通過，下一步接回完整冷啟動和原廠事件流程。',
        '選單派送檢查整理成可引用的純資料工具：兩次管理器初始化、六組鎖操作、固定時鐘、既有退出資料與字型框架；35 項資料控制通過，仍需原廠選單執行緒實際走到各個分支。',
        '原廠語音程式載入已追到更上層的事件佇列、等待與選擇流程，並確認 VPM 列舉及檔名來源；仍未找到簽章讀取與強制驗證。磁碟啟用、讀檔回值或原廠程式載入，不能當成修改程式已被車機接受。',
    ]
    progress['completed'].extend(details);progress['phases'][4]['completed'].append(details[0])
    progress.update(research_updated_utc=now.isoformat(),next='將通過的浮點切換觀察器接回完整冷啟動與真正選單派送，驗證前景與觸控，再整合播放器；同步追原廠事件載入與修改程式包接受。')
    progress['phases'][4]['next']=progress['next']
    assert progress['estimate_percent']==33 and progress['phases'][4]['estimate_percent']==20
    card='<div class="card"><h2>最新離線進展：原廠浮點保存與恢復小型測試通過</h2>'
    card+='<p><strong>五項原廠指令小型測試通過：</strong>實際執行兩個虛擬執行緒間的浮點保存、資料複製與恢復，逐筆核對暫存器內容、記憶體與例外堆疊。恢復時確實取回各自保存的資料；同一執行緒則保留當下資料。</p>'
    card+='<p>這次使用明示的虛擬執行緒資料與例外入口，<strong>還不是完整選單派送或車機實測。</strong>上一輪完整冷啟動及十一個介面準備步驟成功的證據保留；接下來把這個觀察器接回完整原廠事件流程，測前景選單與觸控。<strong>目前還沒有能安裝到車機的整合 App。</strong>手機直接藍牙音樂與修改程式包接受仍待驗證。</p>'
    card+='<p>三路平行研究已補上選單管理器、鎖、時鐘與字型的精確條件，以及更上層的原廠語音程式事件載入流程。簽章宣告格式為 OpenPGP v4、DSA／SHA1，但簽章讀取者、完整公鑰驗證與強制政策仍未知；格式依據：<a href="https://www.rfc-editor.org/rfc/rfc4880.html">RFC 4880</a>。</p>'
    card+='<p>整體里程碑估計維持 33%，App 整合約 20%；百分比是研究估計，不是實機成功率。目前沒有新的實機操作需求。現場配對立即優先；麥克風取消、音質精修擱置，Android Auto 排後，Google Maps 暫緩。</p></div>'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：原廠浮點啟動與完整介面準備通過</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(x)+'</li>' for x in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前沒有新的實機操作需求。</p>',report,count=1);assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>.*?</td></tr>',lambda _:'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(progress['next'])+'</td></tr>',report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
    for name in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert n==1
    assert len(app['static_findings'])==136 and len(progress['completed'])==108
    for p,d in [('evidence/deep-research-state.json',state),('evidence/task-state.json',task),('reports/findings.json',public)]:write(p,d)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=136,completed_items=108,estimate_percent=33,App_estimate_percent=20,updated_Taiwan=iso)))
if __name__=='__main__':main()
