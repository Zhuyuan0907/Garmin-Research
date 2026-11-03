#!/usr/bin/env python3
"""Publish actual controller integration endpoints without App/device claims."""
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import hashlib,html,json,re

ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-controller-gir-integration/'
def read(path):return json.loads((ROOT/path).read_text())
def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def write(path,data):(ROOT/path).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
def registry(data):
    for path,digest in data.items():assert sha(path)==digest,path

def main():
    previous=read(BASE+'previous-checkpoint.json')
    for row in previous['snapshots']:assert sha(row['snapshot'])==row['sha256']
    before=read(BASE+'previous-state.json');prior=read(BASE+'previous-audit.json')
    assert prior['all_passed'] and len(prior['scope_checks'])==34 and len(prior['protected_sources'])==608
    registry(prior['protected_sources'])
    state,task,public=[read(path) for path in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];assert app['static_findings']==before['native_app_music']['static_findings']
    assert len(app['static_findings'])==117 and len(public['research_progress']['completed'])==91
    firstmeta_path=BASE+'runtime/terminal-metadata.json';first=read(firstmeta_path);probe=read(first['probe'])
    assert first['session_id']==38139 and first['terminal_exit_code']==1 and not first['full_scoped_final_guards_passed']
    assert sha(first['runner'])==first['runner_sha256']==sha(first['runner_snapshot'])
    assert sha(first['probe'])==first['probe_sha256'] and first['component_native_original_helpers_returned']==8
    latestmeta_path=BASE+'runtime-contiguous/terminal-metadata.json';latest=read(latestmeta_path)
    latestprobe=read(latest['probe']);observer=read(latest['actual_observer_state'])
    assert sha(latest['runner'])==latest['runner_sha256']==sha(latest['runner_snapshot'])
    assert sha(latest['probe'])==latest['probe_sha256'] and sha(latest['actual_observer_state'])==latest['actual_observer_state_sha256']
    assert not latest['device_io'] and not latestprobe['sounds_emitted']
    static_paths={
        'native_controller_GIR_runnable_input_static':BASE+'gui-static/observer-scopes-and-runnable-input-plan.json',
        'native_font_provider_SQL_lifetime_contract':BASE+'resource-static/font-provider-SQL-peer-review.json',
        'native_font_parser_stream_owner_contract':BASE+'resource-static/font-stream-owner-supplement.json',
        'native_font_cache_allocation_span_contract':BASE+'resource-static/font-cache-span-preflight.json',
        'native_cold_controller_FP_recipe':BASE+'fp-static/cold-controller-fp-recipe.json'}
    for key,path in static_paths.items():
        data=read(path);registry(data['source_sha256'])
        app['static_findings'][key]=dict(evidence=path,evidence_sha256=sha(path),static_only=True,
            new_guest_execution=False,device_io=False,sounds_emitted=False,
            physical_App_or_package_acceptance_verified=False)
    dispatcher_path=BASE+'fp-static/new-dispatcher-followup/dispatcher-body-next-call-contract.json'
    dispatcher=read(dispatcher_path);registry(dispatcher['source_sha256'])
    app['static_findings']['native_cold_controller_FP_recipe'].update(
        next_dispatcher_contract=dispatcher_path,next_dispatcher_contract_sha256=sha(dispatcher_path),
        original_signal_queue_and_dispatcher_entry_required=True,multi_owner_FP_exchange_verified=False)
    micro_path=BASE+'cache-hook-micro-v3/hook-order-controls.json';micro=read(micro_path)
    registry(micro['source_sha256']);assert micro['all_passed']and micro['case_count']==3
    candidate='scripts/probe_native_controller_gir_cache_declared.py'
    app['static_findings']['native_font_cache_allocation_span_contract'].update(
        hook_order_micro=micro_path,hook_order_micro_sha256=sha(micro_path),separate_micro_case_count=3,
        actual_Unicorn_write_callback_before_native_zero_mapping_observed=True,
        original85428_underlying_UcError_not_captured=True,original85428_cause_is_inference=True,
        next_unrun_candidate=candidate,next_unrun_candidate_sha256=sha(candidate),
        next_full_candidate_execution_verified=False)
    app['static_findings']['native_controller_GIR_component_partial']=dict(evidence=first['probe'],evidence_sha256=sha(first['probe']),
        terminal_metadata=firstmeta_path,terminal_metadata_sha256=sha(firstmeta_path),session_id=38139,terminal_exit_code=1,
        native_original_helpers_entered=9,native_original_helpers_returned=8,settings_all_scoped_guards_passed=True,
        full_scoped_final_guards_passed=False,error=probe['error'],
        original_GIR_lock_and_release_body_executed=True,whole_component_endpoint_returned=False,
        STRD_hook_writes_actually_two4byte_callbacks=True,device_io=False,sounds_emitted=False)
    app['static_findings']['native_controller_GIR_contiguous_runtime']=dict(evidence=latest['probe'],evidence_sha256=sha(latest['probe']),
        terminal_metadata=latestmeta_path,terminal_metadata_sha256=sha(latestmeta_path),
        actual_observer_state=latest['actual_observer_state'],actual_observer_state_sha256=latest['actual_observer_state_sha256'],
        session_id=latest['session_id'],terminal_exit_code=latest['terminal_exit_code'],
        native_original_helpers_entered=latest['component_native_original_helpers_entered'],
        native_original_helpers_returned=latest['component_native_original_helpers_returned'],
        completed=latest['completed'],full_scoped_final_guards_passed=latest['full_scoped_final_guards_passed'],
        phase=latest['phase'],error=latest['error'],exact_original_cache_CPU_store_count=observer['native_cache_CPU_store_count'],
        original_cache_allocations_observed=len(observer['native_cache_allocations']),
        raw_font_source_is_readonly_exact_backup=True,driver_and_new_observer_separately_attributed=True,
        native_menu_foreground_or_physical_App_verified=False,device_io=False,sounds_emitted=False)
    now=datetime.now(timezone.utc);passed=latest['full_scoped_final_guards_passed']
    if passed:
        outcome='新增介面準備元件已在原廠執行緒上完整返回，十一個原廠步驟及限定範圍內的最終記憶體檢查通過；還沒有可見選單或實機 App。'
    else:
        outcome='新增介面準備元件已在原廠執行緒上執行；最近一次有'+str(latest['component_native_original_helpers_returned'])+'個原廠步驟返回，並觀察到字型快取控制物件建立，但快取寫入觀察遇到例外，尚未通過整體最終檢查。停止位置及完整執行紀錄已保存。'
    focus='Run new declared-cache candidate: declare only exact original startup-zero cache pages before any emulation, record underlying UcError errno/from_hook, keep native allocation/free/read binding and whole786432-byte CPU/raw replay. Three isolated exact-instruction hook controls passed; old85428 underlying errno was not captured, so diagnosis remains inference. Complete native stock-GIR component on actual resident controller. Preserve both sealed terminal runs and full prior settings/kernel proofs. Then native signal/queue/controller wait must enter original Dispatcher405340 with actor-specific manager/defaults/NOR/file/mutex guards, followed by visible MainMenu/touch. No direct host Dispatcher call or preconstructed manager. Native TCB/FP metadata/pools and package acceptance/callback lifetime remain required. Pairing first; microphone canceled; fidelity deferred; Android Auto later; Maps deferred.'
    state.update(updated_utc=now.isoformat(),current_priority='Native resource/font/menu integration on actual controller; active goal/no-achieve.')
    state['next_actions'][0]=focus;app['remaining_work']=state['next_actions'][:4]
    app['development_observations']['native_controller_GIR']=app['static_findings']['native_controller_GIR_contiguous_runtime']
    state['parallel_research'].update(tasks=['native font cache/stream and music integration','native menu/Dispatcher boot integration','native task/FP prerequisites'],continued_round_completed=True)
    state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
        previous_state_snapshot=BASE+'previous-state.json',previous_current_audit_snapshot=BASE+'previous-audit.json',
        previous_turn_revalidation='Fresh34-scope117-finding checkpoint and608 protected sources verified and snapshotted.',
        focused_evidence=latest['probe'],focused_evidence_sha256=sha(latest['probe']),
        latest_component_runtime_session_id=latest['session_id'],latest_component_terminal_exit_code=latest['terminal_exit_code'],
        latest_component_helpers_returned=latest['component_native_original_helpers_returned'],
        latest_component_run_full_scoped_final_guards_passed=passed,next_focus=focus,goal_status='active',full_goal_complete=False,
        reasons=['Actual compiled component enters original native helpers on resident controller; partial and complete claims remain separate.',
            'Native font cache allocator/free and parser/stream ownership traced; raw input requires live requested payload and contiguous writable pages.',
            'Resident font streams are retained for future glyph requests; temporary probes and SQL finalizers have distinct native lifetimes.',
            'Frozen earlier failures, settings proof and source hashes preserved; no physical installation or music claim.'])
    for key in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research']:task[key]=state[key]
    public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    details=[
        '新增介面準備元件第一次在原廠執行緒上實際執行：設定讀寫、Widget、顯示與平台資訊、圖形資源註冊、目錄取得及靜態字型等八個步驟返回；原廠圖形資源鎖定與釋放也執行。外部字型讀取的跨頁檢查拒絕繼續，沒有宣稱整體成功。',
        '字型與資料庫的生命週期已釐清：八份常駐字型解析器需保留各自的原始檔串流供後續取字；臨時讀取檔與 SQL 敘述另行關閉，不能要求全部字型檔都關閉，也不能清除歷史來冒充正常結束。',
        '原廠字型快取的配置、釋放與共用來源已定位：整個快取有 786432 位元組，原始檔讀取只允許當次仍有效的單一配置範圍。三組獨立短測試確認模擬器寫入觀察先於未映射頁面的處理，事前宣告原廠啟動零頁可避免觀察器讀取失敗；完整舊試跑的底層錯誤碼未捕捉，因此原因仍是推論，修正版完整試跑尚未執行。',
        outcome,
        '下一個畫面啟動點已縮小：需由原廠事件與派送執行緒首次建立管理器，不能預先在另一條執行緒建立。跨執行緒浮點狀態、原機程式包接受及安全回呼仍待驗證；手機直接藍牙音樂未實現。']
    progress['completed'].extend(details);progress.update(research_updated_utc=now.isoformat(),
        next='完成原廠資源、字型與選單準備的整體檢查，再由原廠派送執行緒進入選單畫面；持續追原機程式包接受流程。')
    progress['phases'][4]['next']=progress['next']
    card='<div class="card"><h2>最新離線進展：新增元件已進入原廠資源與字型流程</h2>'
    card+='<p><strong>實際執行進度：</strong>'+html.escape(outcome)+'</p>'
    card+='<p>第一次試跑已有八個原廠步驟返回，包含圖形資源註冊與靜態字型。字型讀取正在核對原廠配置器、解析器與串流的歸屬，以及跨頁的可寫範圍；使用備份中的原始字型資料，沒有供應合成的字形結果。</p>'
    card+='<p><strong>目前還沒有能安裝到車機的整合 App。</strong>接下來才是原廠派送執行緒、選單前景及觸控；手機直接藍牙音樂、原機程式包接受與安全卸載尚未驗證。既有圖資、主題、Pi 音樂橋接和診斷 WAV 成果保留。</p>'
    card+='<p>整體里程碑估計維持 32%，App 整合約 10%。三路並行研究仍依使用者授權進行；現場配對與維持連線立即優先，目前沒有新的實機操作需求。麥克風取消、音質精修擱置，Android Auto 排後，Google Maps 暫緩。</p></div>'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：原廠浮點例外流程與設定初始化</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(x)+'</li>' for x in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前沒有新的實機操作需求。</p>',report,count=1);assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>.*?</td></tr>',lambda _:'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>'+html.escape(progress['next'])+'</td></tr>',report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
    for name in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert n==1
    assert len(app['static_findings'])==124 and len(progress['completed'])==96
    for path,data in [('evidence/deep-research-state.json',state),('evidence/task-state.json',task),('reports/findings.json',public)]:write(path,data)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=124,estimate_percent=32,completed_items=96,updated_Taiwan=iso,latest_component_complete=passed)))

if __name__=='__main__':main()
