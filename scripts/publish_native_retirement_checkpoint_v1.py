#!/usr/bin/env python3
"""One-shot ROOT publication of terminal, resident native Stop scopes.
Preserve prior suites and failures. No guest, device, call or service restart.
"""
import hashlib,html,json,re,subprocess,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from functools import lru_cache
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
B='staging/native-player-retirement-checkpoint/'
R='staging/native-player-sbc-retirement/'
SOURCE='scripts/publish_native_retirement_checkpoint_v1.py'
PREVIOUS='evidence/firmware-analysis/native-ingress-physical-marker-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-retirement-ROOT-checkpoint-audit.json'
CANONICAL=('evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json','reports/nuvi2565RT.html')
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):
    h=hashlib.sha256()
    with (ROOT/p).open('rb')as f:
        for b in iter(lambda:f.read(8<<20),b''):h.update(b)
    return h.hexdigest()
@lru_cache(None)
def immutable_sha(p):return sha(p)
def write(p,d):
    (ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def create(p,d):
    with (ROOT/p).open('x')as f:json.dump(d,f,ensure_ascii=False,indent=2);f.write('\n')
def service_now():
    r=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    d=dict(x.split('=',1)for x in r.stdout.splitlines()if '='in x)
    assert d==dict(MainPID='357833',ActiveState='active',SubState='running',UnitFileState='enabled')
    return d
def main():
    assert not (ROOT/B).exists()and not (ROOT/OUT).exists(),'Terminal or attempted publication preserved; NEW namespace required'
    previous=read(PREVIOUS)
    assert previous['all_passed']and len(previous['protected_sources'])==2926
    assert len(previous['selected_frozen_suites'])==49 and previous['native_unique_exact_dependencies']==1733
    assert previous['current_findings']==239 and previous['current_public_details']==205
    assert all(sha(p)==h for p,h in previous['canonical_after_sha256'].items())
    protected=dict(previous['protected_sources'])
    def register(entries):
        for p,h in entries.items():
            assert immutable_sha(p)==h,p
            assert p not in protected or protected[p]==h,p
            protected[p]=h
    register(previous['protected_sources'])
    proof_path=R+'root-file-review-v3/ROOT-retirement-six-scope-file-reconstruction.json'
    seal_path=R+'root-file-review-v3/ROOT-file-reconstruction-seal.json'
    selection_path=R+'native-retirement-selected-six-scope-v1.json'
    proof,seal,selection=[read(p)for p in (proof_path,seal_path,selection_path)]
    assert proof['all_passed']and seal['all_passed']and proof['case_count']==seal['selected_case_count']==selection['case_count']==6
    assert proof['ROOT_FILE_reconstruction']and not proof['new_independent_agent_review']
    assert not proof['VM_import_or_execution']and not proof['device_IO']
    assert not proof['native_STOP_DONE_heap_exclusive_phone_App_speaker_hardware_drain_safe_unload_verified']
    assert [x['guest_suite_terminal_exit']for x in selection['cases']]==[1,1,1,1,0,0]
    assert selection['compiled_ELF_sha256']=='79c3c94f6b04cc188002033190c74968fbeba480eb9529384a90391b3d199c5c'
    assert seal['totals']==proof['totals']
    totals=proof['totals']
    assert totals['CPU_stores']==198039 and totals['joint_events']==198234
    assert totals['full_original_stop_helpers']==24 and totals['full_original_Stop_barriers']==4
    assert totals['deferred_Stop_returns']==4 and totals['retired_private_FIFO_slots']==7
    register(seal['source_sha256'])
    for p in (SOURCE,PREVIOUS,proof_path,seal_path,selection_path,R+'root-file-review-v3/seal-terminal-tool-receipt.json'):
        register({p:immutable_sha(p)})
    receipt=read(R+'root-file-review-v3/seal-terminal-tool-receipt.json')
    assert receipt['terminal']and receipt['actual_terminal_result']['exit_code']==0 and 'session_id'not in receipt['actual_terminal_result']
    actual=json.loads(receipt['actual_terminal_result']['output'])
    assert actual['all_passed']and actual['output_sha256']==immutable_sha(seal_path)
    state,task,public=[read(p)for p in CANONICAL[:3]]
    app=state['native_app_music'];progress=public['research_progress']
    assert len(app['static_findings'])==239 and len(progress['completed'])==205
    assert state['goal_status']=='active'and not state['goal_complete']and state['required_work_remaining']
    assert not app['native_app_running']and not app['direct_phone_music_verified']
    assert progress['estimate_percent']==33 and progress['phases'][4]['estimate_percent']==20
    assert sum(x['weight']*x['estimate_percent']/100 for x in progress['phases'])==33
    original_details=list(progress['completed']);old_next=progress['phases'][4]['next']
    latest=read('evidence/report-web-latest.json');service_before=service_now()
    with urllib.request.urlopen(latest['url'],timeout=10)as r:
        served_before=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
    assert hashlib.sha256(served_before).hexdigest()==sha('reports/nuvi2565RT.html')
    (ROOT/B).mkdir()
    snapshots=[]
    for original,name in [(PREVIOUS,'previous-audit.json'),(CANONICAL[0],'previous-state.json'),(CANONICAL[1],'previous-task.json'),(CANONICAL[2],'previous-public.json'),(CANONICAL[3],'previous-report.html'),('evidence/report-web-latest.json','previous-web.json')]:
        p=B+name
        with (ROOT/p).open('xb')as f:f.write((ROOT/original).read_bytes())
        h=immutable_sha(p);assert h==sha(original);snapshots.append(dict(original=original,snapshot=p,sha256=h));register({p:h})
    create(B+'previous-checkpoint.json',dict(snapshots=snapshots,classification='progress',device_IO_this_turn=False))
    register({B+'previous-checkpoint.json':immutable_sha(B+'previous-checkpoint.json')})
    findings={
        'native_retirement_resident_ARM_image':dict(path=R+'build-v2.json',scope='ARMv6 image compiles with original Stop adapter and retained status symbols; no device installation.'),
        'native_retirement_ROOT_six_completed_scopes':dict(path=selection_path,scope='Four completed EXIT1-prefix scopes plus two new EXIT0 controls; original Stop/ACK/remove executed in declared fixtures.'),
        'native_retirement_ROOT_FILE_reconstruction':dict(path=proof_path,scope='Exact opcode/store/whole-memory and complete serialized return checks; ROOT only, not an independent agent review.'),
        'native_retirement_ROOT_terminal_seal':dict(path=seal_path,scope='Frozen sources, real terminal receipts and failed predecessors preserved; local retirement leaves module resident and control STOPPING.')}
    for key,row in findings.items():
        assert key not in app['static_findings'];row['sha256']=immutable_sha(row['path'])
        app['static_findings'][key]=dict(evidence=row['path'],evidence_sha256=row['sha256'],scope=row['scope'],evidence_type='ROOT bounded offline evidence',physical_App_or_audio_verified=False,device_io=False)
    now=datetime.now(timezone.utc)
    focus='Connect guarded Stage1 ingress to the actual native Bluetooth SEP/receiver without resetting warm audio globals. Recover accepted configuration, session epoch and durable channel ownership. Bounded original Stop/ACK/full list removal and local anchor retirement now verified in six declared scopes; retain resident module/TCBs/guard until native callback dispatcher and hardware drain are proved. Integrate real heap and menu. User away in class; original voice restored, attended Aud Ver2.10 pending. Pairing first; microphone canceled, fidelity deferred, Android Auto later, Maps deferred; full goal active.'
    next_text='接真正藍牙接收端與暖機音訊資源，補齊原生記憶體與完整退出流程，再整合 App 菜單；原廠停止／移除已完成有界離線驗證，晚點仍需確認 Aud Ver 2.10。'
    details=[
        '原生停止原型新增六個情境：播放後停止、緩衝已滿、播放端正借用資料、首包前停止、錯誤工作程序，以及音源被替換。前四組是先前失敗批次中的完整結果，後兩組另開新批次完成，未把失敗批次改列成功。',
        '原廠停止順序已實際執行：先停止播放、關閉所選音源，再送同步訊息等待原廠回覆，最後完整移除音源。四次停止屏障與二十四次原廠清理函式均完整返回；移除通知早於真正清理完成，沒有把通知當成完成訊號。',
        '停止遇到播放端借用資料會延後；三次保留播放借用，另一次雖已釋放借用，仍等回呼結束。四次都保留音源與綁定，直到所有參照釋放才清理。',
        '待播的七個私人緩衝格，均在原廠音源完整移除、綁定釋放之後才清空。錯誤工作與被替換的音源會拒絕清理；停止後仍拒收新封包。',
        'ROOT 從保存紀錄重建 198039 次記憶體寫入與 198234 個聯合事件，核對完整記憶體、唯讀程式與返回。兩次核對程式的前提錯誤已更正並保留失敗紀錄，沒有重跑原模擬；這次沒有新的獨立 agent 審查。',
        '這是離線、有明示記憶體與硬體替代條件的原型：程式、工作程序與保護仍留在記憶體，沒有宣告整個播放器可卸載或原生停止已完全結束。真手機直接藍牙、App 菜單與實機音樂仍待完成；原始語音已還原，Aud Ver 2.10 畫面對照待使用者回來。']
    state.update(updated_utc=now.isoformat(),current_priority='Actual receiver and warm ownership; bounded resident Stop verified offline; native App/menu pending.')
    state['next_actions']=[focus,'Recover actual Configure/Start peer and session epoch; copy borrowed packets then POST the original Source event.','Validate warm resident Stage1 without cold global resets; close native dispatcher/consumer lifetime, heap and exclusive ownership.','Integrate the physically accepted voice wrapper with player/menu after lifecycle closure; direct phone and physical App remain unverified.','User away in class; continue offline. Next attended task is cold restart/MeiLing/Aud Ver2.10.']
    app['remaining_work']=state['next_actions'][:4]
    app['development_observations']['native_retirement_ROOT_six_scopes']=dict(selection_path=selection_path,selection_sha256=immutable_sha(selection_path),ROOT_FILE_proof=proof_path,ROOT_FILE_seal=seal_path,totals=totals,new_independent_agent_review=False,control_STOPPING=True,module_tasks_guard_resident=True,device_IO=False)
    state['latest_user_instruction']='User offered either pausing or continued research. ROOT continues independent work; no pause or completion requested.'
    state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',
        reasons=['Six completed bounded native Stop/retirement scopes and ROOT FILE reconstruction.', 'Four real pending returns retain borrowed audio or a callback tail before cleanup.', 'Failure receipts preserved; native STOP_DONE, hardware drain, heap, receiver, App and direct phone still incomplete.'],focused_evidence=proof_path,focused_evidence_sha256=immutable_sha(proof_path),next_focus=focus,
        native_Stop_cleanup_runtime_verified_in_declared_fixture=True,native_Stop_cleanup_runtime_verified=False,ROOT_retirement_FILE_review_complete=True,new_independent_retirement_agent_review_complete=False,
        native_retirement_scoped_cases=6,native_retirement_totals=totals,device_io=False,device_files_written=False,native_firmware_or_research_package_written=False,automatic_calls_or_sound=False,attended_calls_or_sound=False,
        physical_marker_execution_verified=True,original_voice_restored_verified=True,rollback_Aud_Ver_2_10_pending=True,native_STOP_DONE_verified=False,native_exclusivity=False,complete_native_App_or_phone_audio=False,goal_status='active',full_goal_complete=False)
    for key in ('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
    task.update(user_away=True,current_device_connection_verified=False,current_connection_not_rechecked_this_offline_turn=True,device_state='Last attended observation: connected USB mass-storage, original voice restored and safely unmounted; connection not rechecked this offline turn.')
    public.update(updated=now.isoformat(),deep_research=state)
    progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
    progress.update(research_updated_utc=now.isoformat(),next=next_text);progress['phases'][4]['next']=next_text
    assert progress['completed'][:205]==original_details and len(app['static_findings'])==243 and len(progress['completed'])==211
    report=(ROOT/CANONICAL[3]).read_text()
    card='<div class="card"><h2>最新進展：原生停止與音源移除已完成離線驗證</h2>'
    card+='<p><strong>六個有界情境完成：</strong>播放後停止、緩衝已滿、播放端借用中、首包前停止，以及錯誤工作和被替換音源的拒絕。前四組取自已終止失敗批次中的完整結果，後兩組另開新批次完成；原失敗紀錄保留，沒有重跑掩蓋。</p>'
    card+='<p>原廠停止、關閉音源、同步等待／回覆與完整移除依序執行，四次停止屏障與24次清理函式完整返回。播放端或回呼仍使用資料時，停止會延後；七個待播私人緩衝格都在音源移除與綁定釋放之後才清空。ROOT已從檔案核對198039次寫入與198234個事件；沒有新的獨立agent審查。</p>'
    card+='<p><strong>尚未完成：</strong>程式、工作程序與保護仍留在記憶體，控制維持停止中，並未驗證原生STOP_DONE、可卸載、完整硬體排空或原生heap。離線測試有明示的記憶體／硬體替代條件；真手機直接藍牙音樂與App菜單尚待接通。接下來研究原藍牙receiver與暖機音訊資源。</p>'
    card+='<p><strong>實機改碼里程碑保留：</strong>先前使用者確認Aud Ver出現M7Q9，證明該修改語音模組執行。原始美玲語音已還原並核對檔案；等使用者下課回來確認畫面回到2.10。本輪沒有寫入車機、來電或聲音。</p>'
    card+='<p>整體估計33%、App整合20%，goal繼續進行。現場配對第一優先；麥克風取消、音質擱置、Android Auto排後、Google Maps暫緩。</p></div>'
    report,count=re.subn(r'<div class="card"><h2>最新進展：自製改碼已在實機執行</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert count==1
    old_row='<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(old_next)+'</td></tr>'
    assert report.count(old_row)==1
    report=report.replace(old_row,'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(next_text)+'</td></tr>',1)
    report,count=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda x:x[1]+x[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+x[3],report,count=1,flags=re.S);assert count==1
    report,count=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>',report,count=1);assert count==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
    for name in ('report-updated-time','research-updated-time'):
        report,count=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert count==1
    assert report.count('datetime="'+iso+'"')==2
    assert not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',report)and 'REDACTED_PRIVATE_ID'not in report
    assert task['last_goal_turn']==state['last_goal_turn']and public['deep_research']==state
    # Checkpoints and all immutable inputs are fixed before canonical mutation.
    for row in snapshots:assert sha(row['original'])==row['sha256']
    create(B+'publication-inputs.json',dict(all_passed=True,findings=findings,details=details,protected_sources=protected,previous_goal_turn_classification='progress',guest_execution=False,device_IO=False,goal_status='active'))
    register({B+'publication-inputs.json':immutable_sha(B+'publication-inputs.json')})
    for p,d in zip(CANONICAL[:3],(state,task,public)):write(p,d)
    (ROOT/CANONICAL[3]).write_text(report)
    after={p:sha(p)for p in CANONICAL}
    assert read(CANONICAL[0])==state and read(CANONICAL[1])==task and read(CANONICAL[2])==public
    with urllib.request.urlopen(latest['url'],timeout=10)as r:
        served,status,cache=r.read(),r.status,r.headers.get('Cache-Control','')
    assert status==200 and 'no-store'in cache and served==report.encode()
    served_sha=hashlib.sha256(served).hexdigest();assert served_sha==sha(CANONICAL[3])==after[CANONICAL[3]]
    service=service_now();assert service==service_before
    checks=dict(old2926_files_preserved=True,old49_complete_cold_suites_preserved=True,old1733_dependencies_preserved=True,new_Stop6_scopes_complete=True,ROOT_FILE_complete=True,
        failed_guest_build_and_FILE_predecessors_preserved=True,three_borrow_and_one_callback_tail_defer_verified=True,full_original_ACK_before_remove_and_anchor_before_FIFO_discard=True,
        native_STOP_DONE_heap_exclusive_App_phone_hardware_drain_unverified=True,physical2_10_pending=True,new_independent_agent_not_claimed=True,no_device_guest_call_or_restart=True,
        two_Taiwan_times_and33_App20=True,canonical_readback_and_HTTP200_no_store_exact=True,service_PID_unchanged=True)
    audit=dict(previous,all_passed=all(checks.values()),scope_checks=checks,updated_utc=datetime.now(timezone.utc).isoformat(),previous_checkpoint=B+'previous-audit.json',
        protected_sources=protected,selected_new_findings=findings,selected_declared_retirement_suites=[dict(selection=selection_path,case_count=6,ROOT_FILE=proof_path,ROOT_seal=seal_path,guest_prefix_exit1_count=4,new_exit0_controls=2)],
        native_retirement_ROOT_scope=proof_path,native_retirement_ROOT_totals=totals,new_independent_retirement_agent_review_complete=False,native_local_anchor_retirement_verified_in_declared_fixture=True,
        native_STOP_DONE_or_safe_unload_verified=False,current_findings=243,current_public_details=211,current_state_sha256=after[CANONICAL[0]],report_sha256=served_sha,
        canonical_after_sha256=after,canonical_readback_uncached=True,local_report_sha256=served_sha,served_report_sha256=served_sha,device_IO_this_turn=False,goal_status='active',full_goal_complete=False)
    write(OUT,audit)
    latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_ingress_physical_marker_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=immutable_sha(B+'previous-audit.json'),all_passed=True)
    latest.pop('current_native_ingress_physical_marker_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,local_report_sha256=served_sha,served_report_sha256=served_sha,served_latest_report=True,report_bytes=len(served),
        service=service,service_not_restarted=True,cache_control=cache,current_native_retirement_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},canonical_hash_readback_uncached=True,current_physical_test_requested=False,user_away_for_class=True,physical_2_10_display_control_pending=True)
    latest['complete_current_offline_run'].update(protected_source_count=len(protected),actual_native_retirement_new_scopes=6,native_retirement_ROOT_FILE_complete=True,native_retirement_ROOT_totals=totals,
        new_independent_retirement_agent_review_complete=False,device_io=False,device_files_written=False,sounds_emitted=False,physical_App_verified=False,native_STOP_DONE_verified=False)
    latest['progress_display_verified'].update(estimate_percent=33,completed_items=211,report_updated_time=iso,research_updated_time=iso,visual_browser_render_not_performed=True)
    write('evidence/report-web-latest.json',latest)
    assert all(sha(p)==h for p,h in after.items())
    print(json.dumps(dict(all_passed=True,findings=243,details=211,protected_sources=len(protected),preserved_complete_suites=49,native_dependencies=1733,new_Stop_scopes=6,ROOT_FILE_complete=True,
        estimate_percent=33,App_estimate_percent=20,updated_Taiwan=iso,HTTP_status=status,report_bytes=len(served),served_sha256=served_sha,current_state_sha256=after[CANONICAL[0]],goal_status='active',device_IO=False)))
if __name__=='__main__':main()
