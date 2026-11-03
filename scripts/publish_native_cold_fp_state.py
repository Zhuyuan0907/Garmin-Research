#!/usr/bin/env python3
"""Publish actual cold native FP boot and preparation, preserving prior evidence."""
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from functools import lru_cache
import hashlib,html,json,re
ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-cold-fp-controller/'
RUNTIME=BASE+'runtime/'
PROOF='evidence/firmware-analysis/native-cold-fp-controller-emulation.json'
STATIC={
    'native_cold_FP_boot_contract_and_review':BASE+'fp-static/cold-fp-first-controller-boot-contract.json',
    'native_Dispatcher_full_run_actor_contract':BASE+'gui-static/native-dispatcher-complete-run-contract.json',
    'native_SIG_requester_DLL_host_file_API_contract':BASE+'package-static/native-sig-request-contract-v2.json',
}
AUXILIARY=[BASE+'fp-static/cold-fp-guard-copies-peer-review.json',BASE+'fp-static/cold-fp-runner-peer-review-0c4f4bb7e007.json',
    BASE+'gui-static/manager-clock-cleanup-and-cold-fp-actor-guards.json',BASE+'package-static/original-jill-file-export-binding.json']
def read(p):return json.loads((ROOT/p).read_text())
@lru_cache(None)
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def registry(d):
    for p,s in d.items():assert sha(p)==s,p
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def main():
    snap=read(BASE+'previous-checkpoint.json');before=read(BASE+'previous-state.json');audit=read(BASE+'previous-audit.json')
    for r in snap['snapshots']:assert sha(r['snapshot'])==r['sha256']
    assert audit['all_passed']and len(audit['scope_checks'])==33 and len(audit['protected_sources'])==707
    registry(audit['protected_sources'])
    state,task,public=[read(p)for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];assert app['static_findings']==before['native_app_music']['static_findings']and len(app['static_findings'])==128
    assert len(public['research_progress']['completed'])==100
    proof,meta=read(PROOF),read(RUNTIME+'terminal-metadata.json')
    registry(proof['source_sha256']);registry(proof['artifacts_sha256'])
    assert proof['all_passed']and proof['case_count']==1 and meta['completed']and meta['full_scoped_final_guards_passed']
    for k,p in STATIC.items():
        d=read(p);registry(d['source_sha256'])
        for field in ['verified_protected_sources','rechecked_existing_source_registry']:
            if field in d:registry(d[field])
        app['static_findings'][k]=dict(evidence=p,evidence_sha256=sha(p),static_only=True,new_guest_execution=False,
            device_io=False,sounds_emitted=False,physical_App_or_native_SIG_enforcement_verified=False)
    for p in AUXILIARY:registry(read(p)['source_sha256'])
    app['static_findings']['native_cold_FP_boot_contract_and_review']['peer_reviews']={p:sha(p)for p in AUXILIARY[:2]}
    app['static_findings']['native_Dispatcher_full_run_actor_contract']['actor_guards']=dict(evidence=AUXILIARY[2],sha256=sha(AUXILIARY[2]))
    app['static_findings']['native_SIG_requester_DLL_host_file_API_contract']['Jill_export_binding_static']=dict(evidence=AUXILIARY[3],sha256=sha(AUXILIARY[3]),actual_native_call_executed=False)
    result=dict(evidence=PROOF,evidence_sha256=sha(PROOF),terminal_metadata=RUNTIME+'terminal-metadata.json',
        terminal_metadata_sha256=sha(RUNTIME+'terminal-metadata.json'),session_id=meta['session_id'],terminal_exit_code=0,
        original_FP_boot_executed=True,original_FP_exit_listener_registered=True,whole_native_controller_FF_fill_checked=True,
        whole_boot_TCB108_and_released_list24_checked=True,all11_helpers_returned=True,full_scoped_final_guards_passed=True,
        declared_cold_metadata_and_architectural_inputs_are_offline_fixtures=True,
        multiowner_FP_exchange_or_foreground_or_App_or_modified_package_or_direct_music_verified=False,
        device_io=False,sounds_emitted=False)
    app['static_findings']['native_cold_FP_controller_full_endpoint']=result
    app['development_observations']['native_cold_FP_controller']=result
    app['package_signature'].update(latest_native_requester_evidence=STATIC['native_SIG_requester_DLL_host_file_API_contract'],
        latest_native_requester_evidence_sha256=sha(STATIC['native_SIG_requester_DLL_host_file_API_contract']),
        original_DLL_host_file_API_paths_traced=True,native_SIG_requester_or_enforcement_identified=False)
    now=datetime.now(timezone.utc)
    focus=('New source/namespace must extend cold native controller endpoint with actual multiowner FP exchange: '
        'original handler save148/advance152/VSTM128 and Dispatcher clone40, disjoint pool/UND/TCB/metadata journals and guarded capacity. '
        'Original Signal ctor/register/queue/controllerWAIT must enter actual Dispatcher405340, with reviewed manager2init/6raw '
        'continuations, existing cleanupchain, fixed-clock original branch and actor-specific native font/cache/GIR guards. '
        'Keep consumed initialcontrollerframe separate from live savedframes; terminalSP9503F90 differs from companionframe9503F68. '
        'No liveTCB patch/FPreset/host Dispatcher call. Then original foreground/touch, one-bootstrap UI/music, callback lifecycle '
        'and physical modified-code package acceptance. Trace actual native SIG requester via original host55 fileAPI provenance, '
        'not generic fopen=signature verification. Preserve all frozen sources/evidence. Pairing first; mic canceled; fidelity deferred; AA later; Maps deferred.')
    state.update(updated_utc=now.isoformat(),current_priority='Actual Dispatcher and cross-owner FP after complete cold native boot; active goal/no-achieve.')
    state['next_actions'][0]=focus;app['remaining_work']=state['next_actions'][:4]
    state['parallel_research'].update(tasks=['cold FP boot and exact copied-guard peer review','Dispatcher manager/clock/cleanup actor contract',
        'original DLL host file-API and native SIG requester provenance'],continued_round_completed=True,agents_currently_running=False)
    state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=BASE+'previous-state.json',previous_current_audit_snapshot=BASE+'previous-audit.json',
        previous_turn_revalidation='Fresh33-scope128-finding checkpoint and707 frozen sources verified and snapshotted.',
        focused_evidence=PROOF,focused_evidence_sha256=sha(PROOF),latest_component_runtime_session_id=meta['session_id'],
        latest_component_terminal_exit_code=0,latest_component_helpers_returned=11,latest_component_run_full_scoped_final_guards_passed=True,
        latest_cold_FP_boot_executed=True,latest_cold_FP_listener_registered=True,latest_cold_controller_metadata_and_native_fill_verified=True,
        native_foreground_or_multiowner_FP_verified=False,native_signature_enforcement_verified=False,
        next_focus=focus,goal_status='active',full_goal_complete=False,
        reasons=['New cold input uses native firstbuilder for metadata and wholeFFfill; no live TCB patch.',
            'Original FPboot/listener and complete native component pass independently replayed whole-memory guards.',
            'Dispatcher next actor contract specifies manager/clock/cleanup/font guards; crossowner FP remains unexecuted.',
            'Original DLL fileAPI is traced with distinct2/2/4 caller profiles; no nativeSIG requester or acceptance claim.'])
    for k in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research']:task[k]=state[k]
    public.update(updated=now.isoformat(),deep_research=state);progress=public['research_progress']
    details=[
        '新冷啟動試跑通過：從首次原廠執行緒建立前提供完整描述與浮點資料，原廠指令填滿並核對 16384 位元組堆疊；沒有修改上一輪存活中的執行緒。',
        '原廠浮點啟動與退出處理註冊已實際執行：完整執行緒 108 位元組及釋放後的鎖資料通過核對，三個原廠退出節點保留；重新跑完全部十一個介面準備步驟，二十二個後續區域與完整字型快取檢查通過。仍只驗證同一執行緒的浮點使用。',
        '真正選單派送的下一批條件已細化：兩個原廠管理器初始化、六個鎖操作、既有退出資料、時鐘及字型讀取都需要按選單執行緒的實際身分觀察；尚未執行跨執行緒浮點交換或宣稱可見 App。',
        '原廠程式開檔介面已追到各自的實際呼叫鏈：三份原語音程式分別有二、二、四個呼叫者；其中兩個固定檔名是語音資源，尚未找到讀取簽章的原廠呼叫者，程式包接受與完整公鑰驗證仍待確認。',
    ]
    progress['completed'].extend(details);progress['phases'][4]['completed'].append(details[1])
    progress.update(research_updated_utc=now.isoformat(),next='先驗證原廠跨執行緒浮點保存／恢復，再以原廠事件進入選單派送流程，補上管理器、時鐘與字型的實際執行檢查；同步追簽章讀取與原機程式包接受。')
    progress['phases'][4]['next']=progress['next']
    assert progress['estimate_percent']==33 and progress['phases'][4]['estimate_percent']==20
    card='<div class="card"><h2>最新離線進展：原廠浮點啟動與完整介面準備通過</h2>'
    card+='<p><strong>新冷啟動試跑通過：</strong>原廠指令建立完整執行緒資料，填入並核對整個堆疊，再執行浮點啟動及退出處理註冊。加入這些條件後，全部十一個資源、字型、選單資料與資料庫步驟再次完整返回；啟動與後續完整記憶體檢查通過。</p>'
    card+='<p>這次仍只驗證同一執行緒的浮點使用。下一步是跨執行緒保存／恢復，以及真正的選單派送、管理器、時鐘與字型處理。<strong>目前還沒有能安裝到車機的整合 App。</strong>選單前景、觸控、手機直接藍牙音樂與原機程式包接受仍待驗證。</p>'
    card+='<p>原廠程式包的簽章已辨識為 OpenPGP v4，宣告 DSA／SHA1，原程式摘要前 16 位吻合。新研究已追到原廠程式透過系統介面開檔的呼叫鏈，但其中固定檔名是語音資源；尚未找到簽章讀取者、完整公鑰驗證或強制政策。格式依據：<a href="https://www.rfc-editor.org/rfc/rfc4880.html">RFC 4880</a>。</p>'
    card+='<p>整體里程碑估計維持 33%，App 整合約 20%；百分比是研究估計，不是實機安裝成功率。三路平行查核完成，目前沒有新的實機操作需求。現場配對立即優先；麥克風取消、音質精修擱置，Android Auto 排後，Google Maps 暫緩。</p></div>'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：新增元件完成原廠資源與字型準備</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(x)+'</li>'for x in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前沒有新的實機操作需求。</p>',report,count=1);assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>.*?</td></tr>',lambda _:'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(progress['next'])+'</td></tr>',report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
    for name in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert n==1
    assert len(app['static_findings'])==132 and len(progress['completed'])==104
    for p,d in [('evidence/deep-research-state.json',state),('evidence/task-state.json',task),('reports/findings.json',public)]:write(p,d)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=132,completed_items=104,estimate_percent=33,App_estimate_percent=20,updated_Taiwan=iso,session=meta['session_id'])))
if __name__=='__main__':main()
