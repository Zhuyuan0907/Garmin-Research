#!/usr/bin/env python3
"""Publish native lazy-FP/runtime, static integration and acceptance separately."""
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import hashlib,html,json,re

ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-settings-vfp-context/'
def read(path):return json.loads((ROOT/path).read_text())
def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def write(path,data):(ROOT/path).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
def registry(values):
    for path,digest in values.items():assert sha(path)==digest,path

def main():
    previous=read(BASE+'previous-checkpoint.json')
    for row in previous['snapshots']:assert sha(row['snapshot'])==row['sha256']
    before=read(BASE+'previous-state.json');prior=read(BASE+'previous-audit.json');registry(prior['protected_sources'])
    assert prior['all_passed'] and len(prior['scope_checks'])==27 and len(prior['protected_sources'])==535
    state,task,public=[read(path) for path in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];assert app['static_findings']==before['native_app_music']['static_findings']
    assert len(app['static_findings'])==113
    metapath=BASE+'runtime-v2/terminal-metadata.json';meta=read(metapath);probe=read(meta['probe']);lazy=read(meta['lazy_evidence'])
    assert meta['session_id']==20619 and meta['completed']==(meta['terminal_exit_code']==0)
    registry(meta['source_sha256']);assert sha(meta['probe'])==meta['probe_sha256']
    micropath=BASE+'micro/original-lazy-vfp-micro-probe.json';micro=read(micropath)
    assert micro['all_passed'] and micro['case_count']==3 and micro['TCBs_and_exception_entry_are_explicit_fixtures']
    guipath=BASE+'gui-static/controller-gir-native-integration-contract.json';gui=read(guipath)
    registry(gui['source_sha256']);registry(gui['verified_frozen_previous_source_hashes'])
    policy_path=BASE+'acceptance-static/acceptance-policy-provenance.json';policy=read(policy_path)
    registry(policy['source_sha256']);registry(policy['protected_checkpoint']['registry'])
    assert policy['all_exact_assertions_passed'] and policy['bounded_CFG_count']==64
    fpstatic='staging/native-player-heap-settings-boot/vfp-static/native-vfp-context-preflight.json';registry(read(fpstatic)['source_sha256'])
    tcbstatic=BASE+'tcb-fp-static/native-tcb-fp-metadata-preflight.json'
    tcb=read(tcbstatic);registry(tcb['source_sha256']);assert tcb['assertions_passed'] and tcb['static_only']
    passed=meta['full_scoped_final_guards_passed']
    if passed:
        assert meta['positive_native_proof'] and sha(meta['positive_native_proof'])==meta['positive_native_proof_sha256']
        outcome='原廠設定初始化已完整返回，記憶體、五個原生執行緒、四份背景堆疊、計時節點及指令寫入紀錄的最終檢查通過。'
        focus='Integrate original stock-GIR/catalog/fonts/menu and explicit SQL provider using the compiled controller component on actual resident controller stack. Native heap/list/settings and first-owner lazy VFP endpoint passed on declared inputs. Derive actual GIR RAII SP, add exact raw callers and scoped companion input stores, validate real catalog allocations/SQL closure/font inventory, then original Dispatcher MainMenu foreground. Recover original native TCB metadata/FP pools before any multi-owner FP exchange.'
    else:
        outcome='原廠浮點例外流程已通過短測試；完整設定初始化試跑仍未通過全部最終檢查，實際停止位置與寄存器快照已保存。'
        focus='Continue the exact sealed lazy-VFP/settings runtime boundary using a new observer/source/namespace. Preserve original exception handler and full opcode/register/store/TCB/frame guards; do not fabricate a float result or certify a partial endpoint. Original TCB metadata/FP pools must be recovered before multi-owner exchange, followed by stock-GIR controller integration and original Dispatcher MainMenu foreground.'
    focus+=' Actual FAT/mount return and volume publication, voice preference/cache provenance and VPM/SIG acceptance remain required; flags alone are not success. Direct phone music/physical App/safe unload remain unproven. Pairing first, microphone canceled, fidelity deferred, Android Auto later, Maps deferred.'
    app['static_findings'].update(
        native_settings_lazy_vfp_runtime=dict(evidence=meta['probe'],evidence_sha256=sha(meta['probe']),
            terminal_metadata=metapath,terminal_metadata_sha256=sha(metapath),lazy_evidence=meta['lazy_evidence'],
            lazy_evidence_sha256=sha(meta['lazy_evidence']),session_id=20619,terminal_exit_code=meta['terminal_exit_code'],
            settings_initializer_returned=meta['settings_initializer_returned'],full_scoped_final_guards_passed=passed,
            original_lazy_handler_count=meta['original_lazy_handler_count'],positive_native_proof=meta['positive_native_proof'],
            positive_native_proof_sha256=meta['positive_native_proof_sha256'],phase=meta['phase'],error=meta['error'],
            original_FP_boot_and_listener_not_executed=True,multi_owner_FP_exchange_verified=False,
            architectural_exception_entry_and_virtual_CP_access_are_fixtures=True,
            first_failed_constructor=BASE+'runtime/constructor-terminal.json',
            corrected_mapping_preflight=BASE+'runtime/declared-mapping-preflight-v2.json',
            first_preflight_empty_candidate_overlap_field_was_incorrect_and_superseded=True,
            peer_review=meta['peer_review'],peer_review_sha256=sha(meta['peer_review']),
            original_context_static=fpstatic,original_context_static_sha256=sha(fpstatic),
            original_TCB_FP_metadata_static=tcbstatic,original_TCB_FP_metadata_static_sha256=sha(tcbstatic),
            physical_boot_or_menu_App_verified=False,device_io=False,sounds_emitted=False),
        native_first_owner_lazy_vfp_micro=dict(evidence=micropath,evidence_sha256=sha(micropath),case_count=3,
            original_disable_handler_exception_return_retry_executed=True,
            actual_float_bits_checked=True,unsafe_multi_owner_without_context_rejected=True,
            native_TCbs_or_hardware_exception_entry_verified=False,device_io=False,sounds_emitted=False),
        native_controller_GIR_integration_contract=dict(evidence=guipath,evidence_sha256=sha(guipath),
            static_only=True,bounded_CFG_count=14,exact_instruction_count=928,
            original_font_descriptors=13,external_present=8,external_missing=2,
            compiled_component_native_runtime_executed=False,device_io=False,sounds_emitted=False,limits=gui['limits']),
        native_voice_mount_policy_provenance=dict(evidence=policy_path,evidence_sha256=sha(policy_path),
            static_only=True,bounded_CFG_count=64,exact_instruction_assertions=74,
            actual_FAT_callback_and_voice_preference_cache_provenance_located=True,
            partition_active_flag_alone_not_mount_success=True,SIG_algorithm_or_enforcement_identified=False,
            modified_package_accepted_on_device=False,device_io=False,sounds_emitted=False,limits=policy['limits']))
    now=datetime.now(timezone.utc);state.update(updated_utc=now.isoformat(),current_priority='Native settings/VFP to visible player integration; active goal/no-achieve.')
    state['next_actions'][0]=focus;app['remaining_work']=state['next_actions'][:4]
    app['development_observations']['native_settings_lazy_vfp']=app['static_findings']['native_settings_lazy_vfp_runtime']
    state['parallel_research'].update(tasks=['native lazy-VFP/settings endpoint','exact compiled controller/native resource integration','original FAT/mount/preference policy provenance'],continued_round_completed=True)
    state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',
        validated_utc=now.isoformat(),previous_state_snapshot=BASE+'previous-state.json',previous_current_audit_snapshot=BASE+'previous-audit.json',
        previous_turn_revalidation='Fresh27-scope113-finding checkpoint and535 protected sources revalidated and snapshotted.',
        focused_evidence=meta['probe'],focused_evidence_sha256=sha(meta['probe']),
        latest_lazy_vfp_runtime_session_id=20619,latest_lazy_vfp_terminal_exit_code=meta['terminal_exit_code'],
        latest_lazy_vfp_settings_initializer_returned=meta['settings_initializer_returned'],
        latest_lazy_vfp_full_scoped_final_guards_passed=passed,
        latest_settings_runtime_session_id=20619,latest_settings_initializer_returned=meta['settings_initializer_returned'],
        latest_settings_run_full_scoped_final_guards_passed=passed,
        next_focus=focus,goal_status='active',full_goal_complete=False,
        reasons=['Three original handler controls verify disable/enable/retry and reject unsafe owner exchange.',
            'Actual native settings run now includes banked exception inputs with captured floating registers and exact original frame stores.',
            'Controller integration contract closes actual resources/stack/storage/SQL/font guard requirements.',
            'Actual FAT callback, mount-success witness and voice preference/cache paths recovered; SIG remains unknown.',
            'Previous evidence preserved, no physical I/O/install/call/sound;32% milestone estimate maintained.'])
    for key in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research']:task[key]=state[key]
    public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    assert progress['estimate_percent']==32 and len(progress['completed'])==87
    details=[
        '原廠浮點例外短測試完成：關閉浮點單元後，原處理程式完整返回並重試原運算，結果位元符合獨立計算；同一執行緒重試也成功，缺少保存空間的跨執行緒交換會被拒絕。例外入口與測試執行緒仍是明示輸入。',
        outcome+' 例外入口、硬體與儲存前置仍有模擬輸入；跨執行緒浮點保存需要在執行緒首次建立前備妥原廠狀態儲存結構，這項條件已靜態定位但尚未完成動態測試，也未驗證完整實機開機。',
        '介面整合條件再核對：十四個原廠流程、九百二十八條指令，以及編譯元件的堆疊、返回位置、圖形資源、字型與資料庫閉合條件已核對；仍需在原廠執行緒上實際整合。十三個字型描述中有八份外部字型存在，兩份原備份缺檔，沒有補入合成字型。',
        '載入接受條件再前進：六十四個原廠流程、七十四項指令核對，定位檔案系統讀取回呼、正式掛載狀態及語音偏好寫入快取的來源。部分旗標會先標記處理中，不能單獨證明接受；簽章驗證仍未知，沒有可安裝的修改包。']
    progress['completed'].extend(details);progress.update(research_updated_utc=now.isoformat(),
        next='依原生試跑結果完成設定，再整合圖形資源、字型、選單與資料庫；補跨執行緒浮點前置並持續追實際程式包接受流程。')
    progress['phases'][4]['next']='從原生設定與浮點前置接上介面元件，核對資源、字型與資料庫，再由派送執行緒建立可見播放器。'
    card='<div class="card"><h2>最新離線進展：原廠浮點例外流程與設定初始化</h2>'
    card+='<p><strong>原廠浮點處理已在短測試執行：</strong>原處理程式重新啟用浮點單元，恢復寄存器與堆疊，再重試原運算；結果位元符合檢查。跨執行緒若缺少狀態保存空間會拒絕繼續。例外入口是明示模擬輸入，尚未驗證實機例外向量。</p>'
    card+='<p><strong>完整設定試跑：</strong>'+html.escape(outcome)+' 尚未完成跨執行緒浮點保存、硬體開機或可見 App。</p>'
    card+='<p><strong>介面整合與載入分析：</strong>介面準備元件的堆疊、圖形資源、字型和資料庫條件已逐項核對；檔案讀取回呼、語音偏好及正式掛載狀態來源也已定位。部分旗標僅表示處理中，不能當成成功。簽章驗證流程仍未釐清。</p>'
    card+='<p><strong>目前還沒有能安裝到車機的整合 App。</strong>選單前景、觸控、手機直接藍牙音樂、原機程式包接受與安全卸載仍未驗證。本輪沒有實機操作或播放聲音；既有圖資、主題、Pi 音樂橋接及原廠 WAV 成果保留。</p>'
    card+='<p>整體里程碑估計維持 32%。現場配對與維持連線立即優先；目前不需要接機。麥克風取消、音質精修擱置，Android Auto 排後，Google Maps 暫緩。</p></div>'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：App 啟動前置與程式包載入條件</h2>.*?</div>',lambda match:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda match:match[1]+match[2]+''.join('<li>'+html.escape(item)+'</li>' for item in details)+match[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda match:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前無需實機操作。</p>',report,count=1);assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>.*?</td></tr>',lambda match:'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>'+html.escape(progress['phases'][4]['next'])+'</td></tr>',report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for name in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    assert len(app['static_findings'])==117 and len(progress['completed'])==91
    for path,data in [('evidence/deep-research-state.json',state),('evidence/task-state.json',task),('reports/findings.json',public)]:write(path,data)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=117,estimate_percent=32,completed_items=91,updated_Taiwan=iso,native_settings_guards_passed=passed)))

if __name__=='__main__':main()
