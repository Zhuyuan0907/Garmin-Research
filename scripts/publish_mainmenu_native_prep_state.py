#!/usr/bin/env python3
"""Publish bounded development progress, never a successful native App claim."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import hashlib,html,json,re
from analyze_native_sections import ROOT

BASE='staging/native-player-mainmenu-native-prep/'
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def source_hashes(d):
    for p,s in d['source_sha256'].items():assert sha(p)==s,p

def main():
    previous=read(BASE+'previous-checkpoint.json')
    for row in previous['snapshots']:assert sha(row['snapshot'])==row['sha256']
    before=read(BASE+'previous-state.json');prior=read(BASE+'previous-audit.json')
    state,task,public=[read(p)for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];assert app['static_findings']==before['native_app_music']['static_findings']
    assert prior['all_passed'] and len(prior['scope_checks'])==28 and len(app['static_findings'])==105
    metapath=BASE+'journal-runtime/terminal-metadata.json';meta=read(metapath);probe=read(meta['probe'])
    assert meta['session_id']==20581 and meta['terminal_exit_code']==1 and not probe['completed']
    assert not probe['full_scoped_final_guards_passed'] and '0x388812'in probe['error']
    for k in ['runner','runner_snapshot','driver','probe']:assert sha(meta[k])==meta[k+'_sha256']
    assert len(probe['settings_init_rows'])==5 and all(r['original_body_executed'] and len(r['native_zero_writes'])==6 for r in probe['settings_init_rows'])
    ctor=[r for r in probe['condition_constructor_runs']if r['pointer']=='0x148e8ec']
    assert len(ctor)==1 and ctor[0]['native_constructor_returned'] and ctor[0]['original_mutex_lock_and_owner_store_executed']
    assert any(r['condition']=='0x148e8ec'and r['owner_matches_timer'] for r in probe['native_owner_transfers'])
    mutexpath=BASE+'mutex-static/mainmenu-native-settings-mutex-preflight.json';mutex=read(mutexpath);source_hashes(mutex)
    assert mutex['assertions_passed'] and len(mutex['raw_mutex_calls'])==36
    guipath=BASE+'gui-static/native-gir-calls-and-controller-placement.json';gui=read(guipath);source_hashes(gui)
    assert gui['static_only'] and gui['complete_bounded_local_CFG_count']==21 and not gui['new_emulation_executed']
    reviewpath=BASE+'gui-static/native-settings-journal-review.json';review=read(reviewpath)
    heappath=BASE+'heap-static/mainmenu-native-heap-mutex-preflight.json';heap=read(heappath);source_hashes(heap)
    assert heap['assertions_passed'] and not heap['device_io']
    adapterpath='staging/ui-music-native-adapter/verification.json';adapter=read(adapterpath);source_hashes(adapter)
    assert adapter['all_passed'] and not adapter['device_install_candidate']
    app['static_findings'].update(
        native_settings_kernel_prep_development=dict(evidence=meta['probe'],evidence_sha256=sha(meta['probe']),
            terminal_metadata=metapath,terminal_metadata_sha256=sha(metapath),runtime_session_id=20581,terminal_exit_code=1,
            native_five_raw_semaphore_bodies_observed=True,second_native_condition_constructor_and_Timer_transfer_observed=True,
            full_settings_initializer_returned=False,full_scoped_final_guards_passed=False,
            boundary='Original heap query388804 reaches native mutex3009A0 at caller388812/pointer3A7F18C; original heap constructor still required.',
            limits='Partial run only: settings initializer did not return and final native/memory guards did not pass. Other unspecialized service boundaries remain fixtures; original list backend initialization3CC58A still needs an explicit native observer before a complete settings proof.',
            peer_review=reviewpath,peer_review_sha256=sha(reviewpath),device_io=False,sounds_emitted=False,
            next_heap_precondition_static=heappath,next_heap_precondition_static_sha256=sha(heappath),
            foreground_or_device_App_or_safe_cleanup_verified=False),
        native_settings_exact_raw_mutex_static=dict(evidence=mutexpath,evidence_sha256=sha(mutexpath),
            raw_call_count=36,settings_CFG_count=len(mutex['settings_module_CFGs']),static_only=True,
            device_io=False,sounds_emitted=False,limits=mutex['limits']),
        native_GIR_controller_call_and_guard_static=dict(evidence=guipath,evidence_sha256=sha(guipath),
            bounded_CFG_count=21,source_method_count=len(gui['source_method_evidence']),static_only=True,
            native_GIR_or_foreground_newly_executed=False,device_io=False,sounds_emitted=False,limits=gui['limits']),
        native_music_source_adapter_prototype=dict(evidence=adapterpath,evidence_sha256=sha(adapterpath),
            concrete_source_worker_volatile_ABI_adapter_and_full_cleanup_bridge_implemented=True,
            ownership_and_session_bindings_still_required=True,missing_bindings_fail_closed=True,
            native_firmware_or_integrated_App_or_physical_stop_verified=False,device_io=False,sounds_emitted=False,
            limits=adapter['limits']))
    now=datetime.now(timezone.utc)
    focus=('Initialize the original heap manager388B6C using declared extent/listener inputs before native settings2CBD16; '
        'observe its raw mutex3A7F18C native constructor/retag and exact query/register/release/current-TCB internal mutex paths. '
        'Execute original list3CC57C/backend3008A0 at caller3CC58A for settings148E680 and empty exit-list2D226B4, never inherit backend noop or reset nonempty listeners. '
        'The20581 development run executed five raw init bodies and real second condition constructor/Timer transfer, then stopped before heap lock; no settings final guards. '
        'Continue original settings/GIR/fonts/menu preparation on actual controller, then real Dispatcher405340 manager/root/frame visibility with seven original writes and resident-frame/timed-node guards. '
        'Wire the new source adapter/whole-cleanup bridge with actual serialized ownership/future-callback/session bindings and one-bootstrap/new layout. '
        'Its host tests/ARM objects are not native runtime proof. Accepted package/direct phone music/physical App/safe unload remain unproven. Pairing first; no physical candidate.')
    state.update(updated_utc=now.isoformat(),current_priority='Native menu/settings/heap preconditions and concrete UI-to-source audio adapter; goal active/no-achieve.')
    state['next_actions'][0]=focus;app['remaining_work']=state['next_actions'][:4]
    app['development_observations']['native_settings_prep']=app['static_findings']['native_settings_kernel_prep_development']
    state['parallel_research'].update(tasks=['exact settings and heap native mutex prerequisites','controller GIR placement and journal review','concrete source worker and full cleanup adapter'],continued_round_completed=True)
    turn=state['last_goal_turn'];turn.update(classification='progress',previous_goal_turn_classification='no_progress',
        validated_utc=now.isoformat(),previous_state_snapshot=BASE+'previous-state.json',previous_current_audit_snapshot=BASE+'previous-audit.json',
        previous_turn_revalidation='Fresh28-scope105-finding checkpoint and39 native suites430 exact dependencies plus five control sources preserved.',
        focused_evidence=meta['probe'],focused_evidence_sha256=sha(meta['probe']),
        latest_settings_runtime_session_id=20581,latest_settings_initializer_returned=False,
        latest_settings_run_full_scoped_final_guards_passed=False,next_focus=focus,goal_status='active',full_goal_complete=False,
        reasons=['New observer executes original settings raw constructors and real retained-token native lock/Timer transfer from actual controller.',
            'Terminal20581 failure identifies missing native heap initialization at388812; five native initializer bodies and second condition constructor are observed, no successful settings checkpoint claimed.',
            '36 exact raw settings callsites,39 settings CFGs and21 GIR/controller CFGs plus peer write-journal review guide native preparation.',
            'New freestanding source-worker adapter/whole-cleanup bridge is compiled and host checked; actual ownership/session/call-site/native integration remains missing.',
            'All prior evidence scopes retained;32% milestone estimate unchanged, no physical I/O/install/calls/sounds.'])
    for k in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research']:task[k]=state[k]
    public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    assert progress['estimate_percent']==32 and len(progress['completed'])==79
    details=[
        '原廠設定鎖精確定位：核對三十六個鎖定與釋放呼叫、三十九個設定流程，包含設定初始化會用到的內部讀取與寫入；這是靜態分析，實際執行仍需逐一驗證。',
        '設定初始化試跑前進：五個原廠設定鎖的六次清零指令均已執行，第二個條件鎖也由原廠指令建立並移交計時工作執行緒。試跑接著停在尚未初始化的記憶體管理鎖；完整設定初始化、最終檢查與首頁顯示尚未通過。失敗紀錄已保留，下一步補原廠記憶體管理初始化。',
        '圖形資源準備與檢查範圍核對：二十一個流程確認資源鎖、控制執行緒的呼叫方式，以及派送執行緒應建立畫面管理器的時機；新增記憶體寫入紀錄核對程式，並由另一研究分支檢查。仍沒有新的首頁前景或觸控驗證。',
        '播放控制器接線層已實作：新增連接既有音訊工作狀態的程式，讀取實際播放代次與資源持有狀態，並以完整原廠清理函式返回作為停止證據之一。已編譯與主機測試；尚缺原廠所有權、連線準備與實際呼叫點整合，介面缺失時會拒絕啟動。']
    progress['completed'].extend(details);progress.update(research_updated_utc=now.isoformat(),
        next='補原廠記憶體管理初始化，再完成設定、圖形資源與首頁前景；將新音訊接線層連上真實連線與清理流程。')
    progress['phases'][4]['next']='先補原廠記憶體管理與設定初始化，再讓派送執行緒建立首頁；播放控制接線層仍需原生整合。'
    card='''<div class="card"><h2>最新離線進展：原廠設定初始化與音訊接線層</h2>
<p><strong>設定初始化試跑已前進，但尚未完成。</strong>五個原廠設定鎖的清零指令已執行，第二個條件鎖也完成原廠建立與移交計時工作執行緒的流程。試跑接著停在尚未初始化的記憶體管理鎖；完整設定初始化和最終檢查尚未通過。下一步補原廠記憶體管理初始化，不把鎖略過或直接回傳成功。</p>
<p><strong>原廠依賴核對更完整。</strong>三十六個設定鎖呼叫位置、三十九個設定流程，以及二十一個圖形資源與控制執行緒流程已核對。新增記憶體寫入紀錄程式會核對實際指令與最終記憶體內容；另一研究分支已檢查其範圍。前一輪原廠事件到達菜單函式入口的證據保留，這次仍沒有首頁顯示或觸控成功證據。</p>
<p><strong>播放控制器已有具體接線層。</strong>新增用來連接既有音訊工作狀態的程式，檢查播放代次、資源持有、原廠清理函式完整返回，以及音訊佇列和回呼是否仍在使用。程式已編譯並完成十二組主機測試；尚缺原廠所有權、連線準備和實際呼叫點整合。介面缺失時會拒絕啟動，不把停止要求的回傳當成停止完成。</p>
<p><strong>目前還沒有能安裝到車機的整合 App。</strong>首頁前景、觸控、原機套件接受、手機直接藍牙音樂與安全卸載仍未驗證。這次沒有裝置操作或播放聲音；既有手機經 Pi 播音樂、原生 WAV 和圖資更新結果保留。</p>
<p>整體里程碑估計維持 32%。現場配對與維持連線立即優先；目前不需要接機。麥克風取消、音質精修擱置，Android Auto 排後，Google Maps 暫緩。</p></div>'''
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：原廠菜單回呼與播放控制器</h2>.*?</div>',lambda m:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda m:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前無需實機操作。</p>',report,count=1);assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>.*?</td></tr>',lambda m:'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>'+html.escape(progress['phases'][4]['next'])+'</td></tr>',report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for name in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    assert len(app['static_findings'])==109 and len(progress['completed'])==83
    for p,d in [('evidence/deep-research-state.json',state),('evidence/task-state.json',task),('reports/findings.json',public)]:write(p,d)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=109,estimate_percent=32,completed_items=83,updated_Taiwan=iso)))

if __name__=='__main__':main()
