#!/usr/bin/env python3
"""Publish terminal native development and separate static/host evidence."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from pathlib import Path
import hashlib,html,json,re

ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-heap-settings-boot/'
def read(path):return json.loads((ROOT/path).read_text())
def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def write(path,data):(ROOT/path).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
def registry(values):
    for path,digest in values.items():assert sha(path)==digest,path

def main():
    previous=read(BASE+'previous-checkpoint.json')
    for row in previous['snapshots']:assert sha(row['snapshot'])==row['sha256']
    before=read(BASE+'previous-state.json');prior=read(BASE+'previous-audit.json')
    registry(prior['protected_sources'])
    state,task,public=[read(p) for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];assert app['static_findings']==before['native_app_music']['static_findings']
    assert prior['all_passed'] and len(prior['scope_checks'])==29 and len(app['static_findings'])==109
    metapath=BASE+'terminal-metadata.json';meta=read(metapath);probe=read(meta['probe'])
    assert meta['session_id']==46928 and sha(meta['probe'])==meta['probe_sha256']
    registry(meta['source_sha256']);assert meta['completed']==(meta['terminal_exit_code']==0)
    guardpath=BASE+'static/runner-667d7225-peer-review.json';guard=read(guardpath)
    assert not guard['concrete_blocking_error_found'] and guard['static_only']
    packagepath=BASE+'package-static/vpm-acceptance-preflight.json';package=read(packagepath)
    registry(package['source_sha256']);registry(package['protected_checkpoint']['registry'])
    assert package['all_static_assertions_passed'] and package['bounded_CFG_count']==60
    guipath='staging/controller-gir-prep-stock-v2/verification.json';gui=read(guipath)
    registry(gui['source_sha256']);registry(gui['verified_protected_previous_source_hashes'])
    assert gui['host_logic_control_count']==29 and not gui['new_ARM_emulation_executed'] and not gui['install_candidate']
    for field in ['ELF','flat_binary']:assert sha(gui[field])==gui[field+'_sha256']
    app['static_findings'].update(
        native_heap_settings_boot_development=dict(evidence=meta['probe'],evidence_sha256=sha(meta['probe']),
            terminal_metadata=metapath,terminal_metadata_sha256=sha(metapath),
            runtime_session_id=46928,terminal_exit_code=meta['terminal_exit_code'],phase=meta['phase'],error=meta['error'],
            settings_initializer_returned=meta['settings_initializer_returned'],
            full_scoped_final_guards_passed=meta['full_scoped_final_guards_passed'],
            original_heap_constructor_returned='heap_inventory' in probe,
            original_heap_cold_workspace_and_extent_recipe_passed=probe.get('heap_inventory',{}).get('whole_cold_workspace_recipe_checked',False),
            original_exit_and_settings_list_constructor_count=len(probe['list_constructors']),
            actual_failure_PC=probe['registers']['pc'],failure_at_original_VFP_instruction=True,
            FPEXC_at_failure_not_captured_and_exact_cause_not_verified=True,
            scope=meta['scope'],lower_heap_extent_NOR_and_service_inputs_remain_fixtures=True,
            original_code_not_reentered_after_wall_quantum=True,foreground_or_physical_App_verified=False,
            device_io=False,sounds_emitted=False),
        native_heap_settings_endpoint_peer_guard_static=dict(evidence=guardpath,evidence_sha256=sha(guardpath),
            reviewed_runner_sha256=guard['reviewed_source_sha256'],static_only=True,
            runtime_success_claimed_by_peer=False,device_io=False,sounds_emitted=False),
        native_vpm_acceptance_preflight=dict(evidence=packagepath,evidence_sha256=sha(packagepath),
            bounded_CFG_count=60,exact_instruction_assertions=65,backup_voices=13,
            SIG_verifier_identified=False,modified_package_accepted_on_device=False,
            static_only=True,device_io=False,sounds_emitted=False,limits=package['limits']),
        native_controller_gir_prep_prototype=dict(evidence=guipath,evidence_sha256=sha(guipath),
            host_logic_control_count=29,ARM_binary_bytes=gui['flat_binary_bytes'],
            first_admission_candidate_rejected_actual_stock_length=True,
            corrected_stock_GIR_length_and_range_inputs=True,native_runtime_verified=False,
            device_io=False,sounds_emitted=False,limits=gui['limits']))
    success=meta['full_scoped_final_guards_passed']
    if success:
        outcome='原廠記憶體、串列與設定初始化已在限定離線輸入下返回，並通過記憶體與原生執行緒的最終檢查。'
        focus='Integrate stock-GIR controller preparation on the actual native controller stack, then run original Dispatcher manager/MainMenu visibility; preserve whole memory/task/owned/timed/frame guards. Native heap/list/settings endpoint passed on declared extent/NOR/lower-service inputs, not hardware boot or physical App.'
    else:
        outcome='原廠記憶體管理與兩個串列初始化已返回，記憶體管理的整段內容與註冊結果符合檢查；設定流程再前進後停在原廠浮點指令，完整最終檢查尚未通過。'
        focus='Recover native VFP/context/exception prerequisites at the actual settings failure3404DC (VMOV s0,r0, caller2CC242 BLX); FPEXC at failure was not captured, exact cause remains unconfirmed. Use a new observer/namespace and preserve original instructions/store/TCB/frame checks. Then integrate stock-GIR controller preparation and original Dispatcher manager/MainMenu visibility.'
    focus+=' VPM/SIG acceptance, real source-worker ownership/session wiring, direct phone Bluetooth, physical menu App and safe unload remain unproven. Pairing immediately first; microphone canceled, fidelity deferred, Android Auto later, Maps deferred.'
    now=datetime.now(timezone.utc);state.update(updated_utc=now.isoformat(),current_priority='Native menu startup and audio App integration; goal active/no-achieve.')
    state['next_actions'][0]=focus;app['remaining_work']=state['next_actions'][:4]
    app['development_observations']['native_heap_settings_boot']=app['static_findings']['native_heap_settings_boot_development']
    state['parallel_research'].update(tasks=['exact heap/list/settings native boot and final guards','compiled stock-GIR controller preparation','exact VPM loading and acceptance boundary'],continued_round_completed=True)
    state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',
        validated_utc=now.isoformat(),previous_state_snapshot=BASE+'previous-state.json',
        previous_current_audit_snapshot=BASE+'previous-audit.json',
        previous_turn_revalidation='Fresh29-scope109-finding checkpoint and465 protected sources preserved.',
        focused_evidence=meta['probe'],focused_evidence_sha256=sha(meta['probe']),
        latest_heap_settings_runtime_session_id=46928,latest_heap_settings_terminal_exit_code=meta['terminal_exit_code'],
        latest_heap_settings_initializer_returned=meta['settings_initializer_returned'],
        latest_heap_settings_full_scoped_final_guards_passed=success,next_focus=focus,
        goal_status='active',full_goal_complete=False,
        reasons=['New guarded original heap/list/settings runtime with actual terminal attribution.',
            'Exact endpoint guards independently reviewed; no physical allocator or boot claim.',
            'Stock-GIR controller component compiled and29 host groups passed, native integration pending.',
            '60 exact VPM CFGs/65 instruction checks clarify incomplete package acceptance evidence.',
            'All previous scopes retained; milestone estimate32%, no physical I/O/install/call/sound.'])
    for key in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research']:task[key]=state[key]
    public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    assert progress['estimate_percent']==32 and len(progress['completed'])==83
    details=[outcome+' 記憶體區段、儲存與底層服務仍有明示模擬輸入，這不是完整開機或實機 App 證據。',
        '新增初始化守衛交叉核對：整段記憶體、原廠串列註冊、五個執行緒、四份背景堆疊及計時節點逐項核對；另一研究分支未發現阻擋限定試跑的具體錯誤。這是靜態審查，不代表試跑成功。',
        '介面準備元件已編譯：修正第一版對原廠圖形資源長度的限制，第二版涵蓋真實資源長度與範圍檢查，通過二十九組主機控制。尚未接入原廠執行緒驗證，沒有新選單圖示或觸控成功。',
        '程式包接受路徑再核對：六十個原廠流程、六十五項指令檢查及十三份備份語音檔已分析；簽章讀取者和驗證演算法仍未知。模擬中可載入的修改包仍不能當作實機可安裝套件。']
    progress['completed'].extend(details);progress.update(research_updated_utc=now.isoformat(),
        next='沿實際試跑結果完成原廠啟動前置，再接介面準備元件與播放器；繼續確認修改包的實機接受條件。')
    progress['phases'][4]['next']='完成設定與圖形資源的原生接線，再由派送執行緒建立可見播放器；程式包接受與音訊控制整合仍待驗證。'
    card='<div class="card"><h2>最新離線進展：App 啟動前置與程式包載入條件</h2>'
    card+='<p><strong>原廠初始化試跑：</strong>'+html.escape(outcome)+' 底層記憶體、儲存及部分服務仍有模擬輸入；完整硬體開機尚未驗證。</p>'
    card+='<p><strong>介面準備元件：</strong>已編譯 ARMv6 程式並通過二十九組主機控制，涵蓋原廠圖形資源的真實長度與越界條件。元件還需要接入原廠執行緒與介面流程，不能當成車機已執行的 App。</p>'
    card+='<p><strong>程式包載入分析：</strong>已核對六十個原廠流程與六十五項指令；簽章驗證流程仍未釐清。保留原簽章檔或模擬載入成功，都不足以證明修改後的包能被實機接受。</p>'
    card+='<p><strong>目前還沒有能安裝到車機的整合 App。</strong>菜單前景、觸控、手機直接藍牙音樂與安全卸載仍未驗證；既有手機經 Pi 播音樂、原廠 WAV、圖資與主題成功結果保留。本輪沒有實機操作或播放聲音。</p>'
    card+='<p>整體里程碑估計維持 32%。配對與維持連線立即優先，目前不需要接機。麥克風取消、音質精修擱置，Android Auto 排後，Google Maps 暫緩。</p></div>'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    report,n=re.subn(r'<div class="card"><h2>最新離線進展：原廠設定初始化與音訊接線層</h2>.*?</div>',lambda m:card,report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(d)+'</li>' for d in details)+m[3],report,count=1,flags=re.S);assert n==1
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda m:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 現場配對立即優先，目前無需實機操作。</p>',report,count=1);assert n==1
    report,n=re.subn(r'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>.*?</td></tr>',lambda m:'<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>'+html.escape(progress['phases'][4]['next'])+'</td></tr>',report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for name in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    assert len(app['static_findings'])==113 and len(progress['completed'])==87
    for path,data in [('evidence/deep-research-state.json',state),('evidence/task-state.json',task),('reports/findings.json',public)]:write(path,data)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=113,estimate_percent=32,completed_items=87,updated_Taiwan=iso,native_endpoint_guards_passed=success)))

if __name__=='__main__':main()
