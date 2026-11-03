#!/usr/bin/env python3
"""Publish frozen RAM-observation prototype and exact local candidate evidence.
No VM, device writes, Bluetooth, audio, flashing or daemon restart.
"""
import json,hashlib,re,html,subprocess,urllib.request
from pathlib import Path
from functools import lru_cache
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
B='staging/native-player-warm-probe-checkpoint/'
G='staging/native-player-warm-probe/'
SOURCE='scripts/publish_native_warm_probe_checkpoint_v1.py'
PREVIOUS='evidence/firmware-analysis/native-retirement-ROOT-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-warm-probe-ROOT-checkpoint-audit.json'
CANONICAL=('evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json','reports/nuvi2565RT.html')
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):
    h=hashlib.sha256()
    with (ROOT/p).open('rb')as f:
        for b in iter(lambda:f.read(8<<20),b''):h.update(b)
    return h.hexdigest()
@lru_cache(None)
def immutable_sha(p):return sha(p)
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
def create(p,d):
    with (ROOT/p).open('x')as f:json.dump(d,f,ensure_ascii=False,indent=2);f.write('\n')
def service_now():
    r=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    d=dict(x.split('=',1)for x in r.stdout.splitlines()if '='in x)
    assert d==dict(MainPID='357833',ActiveState='active',SubState='running',UnitFileState='enabled');return d
def main():
    assert not(ROOT/B).exists()and not(ROOT/OUT).exists(),'Preserve attempted publication; NEW namespace required'
    previous=read(PREVIOUS);assert previous['all_passed']and len(previous['protected_sources'])==3173
    assert len(previous['selected_frozen_suites'])==49 and previous['native_unique_exact_dependencies']==1733
    assert all(sha(p)==h for p,h in previous['canonical_after_sha256'].items())
    protected=dict(previous['protected_sources'])
    def register(entries):
        for p,h in entries.items():
            assert immutable_sha(p)==h,p;assert p not in protected or protected[p]==h,p;protected[p]=h
    register(previous['protected_sources'])
    seal_path=G+'ROOT-warm-probe-terminal-seal-v1.json';seal=read(seal_path)
    assert seal['all_passed']and seal['case_count']==8 and seal['exact_original_embedded_reader_additional_scope']==1
    assert not seal['device_IO']and not seal['new_independent_agent_review']
    assert not seal['native_warm_App_receiver_ownership_music_verified']
    register(seal['source_sha256'])
    for p in (SOURCE,PREVIOUS,seal_path,G+'seal-v1-terminal-tool-receipt.json','staging/native-player-retirement-checkpoint/publication-v1-terminal-tool-receipt.json'):register({p:immutable_sha(p)})
    receipt=read(G+'seal-v1-terminal-tool-receipt.json');result=receipt['actual_terminal_result'];assert receipt['terminal']and result['exit_code']==0 and 'session_id'not in result
    actual=json.loads(result['output']);assert actual['all_passed']and actual['seal_sha256']==immutable_sha(seal_path)
    selected=read(G+'ROOT-selected-eight-diagnostic-scopes-v1.json');proof=read(G+'ROOT-file-bundle-proof-v1.json');reader=read(G+'candidate-warm-probe-embedded-reader-v1.json');bundle=read(G+'local-warm-probe-bundle-manifest-v1.json');profile=read(G+'profile0-noop-readiness-boundary-contract-v1.json')
    assert selected['all_passed']and selected['case_count']==proof['case_count']==8 and proof['all_passed']
    assert [c['guest_suite_terminal_exit']for c in selected['cases']]==[1,0,0,0,0,0,0,0]
    assert proof['totals']==dict(CPU_stores=2860,native_field_reads=415,whole_audio_bank_bytes_per_case=28672,whole_zones=96)
    assert reader['all_passed']and reader['actual_original5_loader_callbacks_not_intercepted']and not reader['BIN_file_input_fixture_used']
    assert reader['getter_and_page_input_utf16_hex']=='W7E8\0'.encode('utf-16le').hex()
    assert bundle['candidate_sha256']==reader['candidate_sha256']==proof['candidate_sha256']==seal['candidate_sha256']
    assert bundle['candidate_sha256']=='1fa09e3258ac9e571f8e2ca6d824c5edd305d2f00e7c956c1d6b33df5a3226ba'
    assert bundle['rollback_sha256']=='b5f132ae4b073d6e804f7a7b639a60b1055573f9fbb65144f18f3b2198a5de68'
    assert profile['all_passed']and profile['actual_profile0_return']['r0']==0 and profile['after_profile_callback_pointer']==0
    state,task,public=[read(p)for p in CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress']
    assert state['goal_status']=='active'and not state['goal_complete']and state['required_work_remaining']
    assert not app['native_app_running']and not app['direct_phone_music_verified']
    assert len(app['static_findings'])==243 and len(progress['completed'])==211
    assert progress['estimate_percent']==33 and progress['phases'][4]['estimate_percent']==20
    assert sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==33
    old_details=list(progress['completed']);old_next=progress['phases'][4]['next']
    latest=read('evidence/report-web-latest.json');before_service=service_now()
    with urllib.request.urlopen(latest['url'],timeout=10)as r:
        prior=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
    assert hashlib.sha256(prior).hexdigest()==sha(CANONICAL[3])
    (ROOT/B).mkdir();snapshots=[]
    for original,name in [(PREVIOUS,'previous-audit.json'),(CANONICAL[0],'previous-state.json'),(CANONICAL[1],'previous-task.json'),(CANONICAL[2],'previous-public.json'),(CANONICAL[3],'previous-report.html'),('evidence/report-web-latest.json','previous-web.json')]:
        p=B+name
        with (ROOT/p).open('xb')as f:f.write((ROOT/original).read_bytes())
        h=immutable_sha(p);assert h==sha(original);register({p:h});snapshots.append(dict(original=original,snapshot=p,sha256=h))
    create(B+'previous-checkpoint.json',dict(snapshots=snapshots,previous_goal_turn_classification='progress'));register({B+'previous-checkpoint.json':immutable_sha(B+'previous-checkpoint.json')})
    findings={
        'native_warm_audio_RAM_diagnostic_source':dict(path=G+'warm-audio-static-and-diagnostic-source-contract-v1.json',scope='Exact original18-channel mapping and read-only12-bit RAM observation source; not native warm readiness.'),
        'native_warm_diagnostic_ROOT_eight_scopes':dict(path=G+'ROOT-selected-eight-diagnostic-scopes-v1.json',scope='One completed EXIT1-prefix cold case plus seven new EXIT0 controls. Actual40 exports/getter/cache stores retained.'),
        'native_warm_diagnostic_ROOT_FILE_replay':dict(path=G+'ROOT-file-bundle-proof-v1.json',scope='2860 CPU stores and415 read observations; whole native audio bank unchanged. ROOT FILE only, not GP effective-address or full non-store controlflow proof.'),
        'native_warm_diagnostic_local_voice_bundle':dict(path=G+'local-warm-probe-bundle-manifest-v1.json',scope='One local20MB reversible voice candidate, original DLLINFO/SIG/member payloads retained; not transferred or physically tested.'),
        'native_warm_diagnostic_original_embedded_reader':dict(path=G+'candidate-warm-probe-embedded-reader-v1.json',scope='Exact new candidate fed to original embedded container and five file callbacks; actual code/getter W7E8, with startup-zero audio and lower storage/TCB/heap fixtures.'),
        'native_profile0_noop_not_warm_readiness':dict(path=G+'profile0-noop-readiness-boundary-contract-v1.json',scope='Original profile return0 may leave callback0 when tag already0. Branch and explicit input case verified; no ownership/readiness inference.')}
    for key,row in findings.items():
        assert key not in app['static_findings'];row['sha256']=immutable_sha(row['path'])
        app['static_findings'][key]=dict(evidence=row['path'],evidence_sha256=row['sha256'],scope=row['scope'],evidence_type='ROOT bounded offline evidence',device_io=False,physical_App_or_audio_verified=False)
    now=datetime.now(timezone.utc)
    focus='Use the prepared RAM-only12-bit Aud Ver observation candidate in a later attended test after original2.10 control. Continue recovering actual native SEP/Configure/Start identity, warm initialized channels and durable ownership; do not reset all18 channels or treat profile0 return0 as callback readiness. Condition construction uses raw ownership transfer to Timer and remains outside the voice fixture. Complete native heap/menu and lifetime/dispatcher/hardware closure before full App/direct phone music. User confirmed away; no device writes/calls/sound; pairing first when present; microphone canceled, fidelity deferred, Android Auto later, Maps deferred; full goal active.'
    next_text='回來後先確認原語音 2.10，再測本機已備妥的 Wxxx 音訊狀態代碼；持續研究真正藍牙接收、正常模式音訊資源與 App 菜單，不能只靠設定回傳成功判定可播放。'
    details=[
        '查出原廠音訊通道對應表及初始化流程：全域初始化會重設十八個通道，正常导航時不能直接照搬。新的診斷程式只讀取音訊欄位，不呼叫通道重設或新增音訊功能。',
        '新增診斷代碼 W 加三位十六進位數字，表示十二項音訊狀態，包括通道、設定、回呼、音源數與播放狀態。這是語音模組初始化當下的快照，Aud Ver 顯示快取結果，不能當即時監視或獨占／就緒認證。',
        '八個新的離線觀察情境完成：冷空值、原廠通道／設定輸入、不同設定、明示忙碌資料、路徑不符、檔案鎖被占用、未知既有代碼，以及重複載入。五個實際觀察情境各讀取八十三個音訊欄位，三個拒絕情境沒有新增讀取或版本寫入。',
        'ROOT 由檔案核對2860次CPU寫入與415次音訊讀取；每組完整28672bytes音訊區域前後相同。原四十個語音介面、原模組內容、版本 getter 與 Aud Ver 輸入有保留；沒有新的獨立agent審查。',
        '新的單檔診斷語音與原檔還原包只準備在Pi，候選約20MB；只換DLLIMG.BIN，原DLLINFO、SIG與其他成員内容保持相同。原廠嵌入讀取器與五個檔案回呼已離線載入此候選，程式真正寫出W7E8；這仍不是實機新版本接受或畫面結果。',
        '發現原設定函式回傳0，有時只是設定值已相同，未重新建立音訊回呼。保存的測試確實回傳0但回呼仍是0，因此正常模式須查實際欄位，不能把設定成功當成播放器可用。',
        '兩次測試框架邊界失敗已保留：音訊RAM未映射，以及條件物件初始化的鎖／Timer轉移未涵蓋。新觀察測試只使用明示輸入，不宣稱完整暖機核心。使用者目前不在車機旁；原語音已還原，2.10確認及新Wxxx實機測試均待回來，本輪沒有改寫車機或發聲。']
    state.update(updated_utc=now.isoformat(),current_priority='Actual warm receiver/ownership and prepared read-only physical RAM diagnostic; native App/music pending.',latest_user_instruction='User asks progress, then confirms currently away from Garmin and will inspect original2.10 later; continue authorized offline work.')
    state['next_actions']=[focus,'Recover actual native SEP callback publication and accepted Configure/Start identity; preserve borrowed packet lifetime and resident storage.','Close real warm channel ownership/profile/condition/Timer provenance and native heap; original profile no-op is not initialization.','Integrate original menu and resident player after callback dispatcher/hardware lifetime closure; direct phone/native App remain unverified.','Later attended control: original cold restart/MeiLing/Aud Ver2.10, then single-file diagnostic Wxxx trial and exact rollback. No pending availability question.']
    app['remaining_work']=state['next_actions'][:4]
    app['development_observations']['native_warm_RAM_diagnostic_ROOT']=dict(seal=seal_path,ROOT_FILE=G+'ROOT-file-bundle-proof-v1.json',eight_scopes=G+'ROOT-selected-eight-diagnostic-scopes-v1.json',candidate_embedded_reader=G+'candidate-warm-probe-embedded-reader-v1.json',totals=proof['totals'],native_audio_unchanged=True,new_independent_agent_review=False,physical_new_candidate_tested=False)
    app['local_warm_audio_observation_bundle']=dict(manifest=G+'local-warm-probe-bundle-manifest-v1.json',candidate=bundle['candidate_path'],candidate_sha256=bundle['candidate_sha256'],rollback=bundle['rollback_path'],rollback_sha256=bundle['rollback_sha256'],prepared_local_only=True,physical_installed=False,physical_2_10_control_pending=True,physical_new_W_tag_test_pending=True)
    attended=state['attended_testing'];attended.update(user_present=False,waiting_for_user_return=True,user_available_for_future_physical_tests=False,no_pending_question=True,recorded_utc=now.isoformat(),user_instruction='User replied currently not at device; inspect later.',current_attended_test='Original voice restored; await original2.10 control before the prepared Wxxx observation candidate.',automatic_calls_or_sound_allowed_while_away=False)
    state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',
        focused_evidence=G+'ROOT-file-bundle-proof-v1.json',focused_evidence_sha256=immutable_sha(G+'ROOT-file-bundle-proof-v1.json'),next_focus=focus,
        reasons=['Eight completed new read-only observation scopes and ROOT FILE reconstruction.', 'Exact new local voice candidate passed original embedded container and five file callbacks.', 'Profile0 no-op branch shows success without a callback; real warm integration remains incomplete.'],
        ROOT_warm_diagnostic_scopes=8,ROOT_warm_FILE_complete=True,actual_new_candidate_embedded_reader_verified=True,new_independent_warm_diagnostic_agent_review_complete=False,
        physical_new_warm_candidate_tested=False,physical_2_10_control_pending=True,device_io=False,device_files_written=False,automatic_calls_or_sound=False,attended_calls_or_sound=False,native_firmware_or_research_package_written=False,
        complete_native_App_or_phone_audio=False,native_STOP_DONE_verified=False,native_exclusivity=False,goal_status='active',full_goal_complete=False)
    for key in ('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
    task.update(user_away=True,current_device_connection_verified=False,current_connection_not_rechecked_this_offline_turn=True)
    public.update(updated=now.isoformat(),deep_research=state);progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
    progress.update(research_updated_utc=now.isoformat(),next=next_text);progress['phases'][4]['next']=next_text
    assert progress['completed'][:211]==old_details and len(app['static_findings'])==249 and len(progress['completed'])==218
    report=(ROOT/CANONICAL[3]).read_text()
    card='<div class="card"><h2>最新進展：實機音訊狀態診斷檔已在 Pi 準備完成</h2>'
    card+='<p><strong>新增功能原型：</strong>透過原Aud Ver顯示W加三位代碼，帶出十二項音訊狀態，幫助查正常模式下哪些資源已初始化或被占用。它只讀取音訊欄位，不重設十八個通道。這是模組初始化當下的快照、不是即時監視或獨占／就緒認證。</p>'
    card+='<p><strong>八個離線情境與檔案核對完成：</strong>五個實際觀察情境各有83次讀取，三個拒絕情境沒有新增取樣或標記寫入。ROOT核對2860次CPU寫入與415次讀取，每組完整音訊區域保持相同；原語音介面有保留。原廠嵌入讀取器與五個檔案回呼另已載入新候選，離線真正執行診斷碼。沒有新的獨立agent審查。</p>'
    card+='<p><strong>關鍵發現：</strong>原廠設定回傳成功可能只表示值相同，尚未建立回呼；保存案例確實回傳0而回呼仍為0。接實機播放器前必須查真正狀態與正常模式資源。條件物件／Timer、原生heap、持續ownership與完整退出仍待驗證；真手機直接藍牙音樂及App菜單未完成。</p>'
    card+='<p><strong>實機狀態：</strong>先前M7Q9已由使用者確認，原始美玲語音已還原。本次新的約20MB診斷檔只放在Pi，尚未寫入車機或驗證實機接受。使用者目前不在車機旁，回來先確認原Aud Ver2.10，再安排Wxxx單檔測試與還原。框架失敗與模擬條件均保留記錄，本輪沒有來電或聲音。</p>'
    card+='<p>整體估計33%、App整合20%，goal持續。配對第一優先，麥克風取消、音質擱置、Android Auto排後、Google Maps暫緩。</p></div>'
    report,count=re.subn(r'<div class="card"><h2>最新進展：原生停止與音源移除已完成離線驗證</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert count==1
    old_row='<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(old_next)+'</td></tr>';assert report.count(old_row)==1
    report=report.replace(old_row,'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(next_text)+'</td></tr>',1)
    report,count=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda x:x[1]+x[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+x[3],report,count=1,flags=re.S);assert count==1
    report,count=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>',report,count=1);assert count==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
    for name in ('report-updated-time','research-updated-time'):
        report,count=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert count==1
    assert report.count('datetime="'+iso+'"')==2 and not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',report)and 'REDACTED_PRIVATE_ID'not in report
    assert task['last_goal_turn']==state['last_goal_turn']and public['deep_research']==state
    for row in snapshots:assert sha(row['original'])==row['sha256']
    create(B+'publication-inputs.json',dict(all_passed=True,findings=findings,protected_sources=protected,details=details,guest_execution=False,device_IO=False));register({B+'publication-inputs.json':immutable_sha(B+'publication-inputs.json')})
    for p,d in zip(CANONICAL[:3],(state,task,public)):write(p,d)
    (ROOT/CANONICAL[3]).write_text(report);after={p:sha(p)for p in CANONICAL}
    assert read(CANONICAL[0])==state and read(CANONICAL[1])==task and read(CANONICAL[2])==public
    with urllib.request.urlopen(latest['url'],timeout=10)as r:served,status,cache=r.read(),r.status,r.headers.get('Cache-Control','')
    assert status==200 and 'no-store'in cache and served==report.encode();served_sha=hashlib.sha256(served).hexdigest();assert served_sha==sha(CANONICAL[3])==after[CANONICAL[3]]
    service=service_now();assert service==before_service
    checks=dict(old3173_sources_preserved=True,old49_complete_suites_and1733_dependencies_preserved=True,eight_new_ROOT_diagnostics_separate_from_one_embedded_reader=True,
        native_audio_RAM_read_only_and_original_voice40_retained=True,FILE_GP_address_scope_not_overclaimed=True,profile_success_not_callback_readiness_verified=True,
        original_failed_guest_inputs_preserved=True,physical_new_probe_uninstalled_and2_10_pending=True,new_independent_agent_not_claimed=True,complete_warm_ownership_heap_App_phone_unverified=True,
        canonical_and_served_uncached_exact=True,two_Taiwan_times_33_App20=True,service_PID_unchanged=True,no_device_guest_call_or_restart=True)
    audit=dict(previous,all_passed=all(checks.values()),scope_checks=checks,updated_utc=datetime.now(timezone.utc).isoformat(),previous_checkpoint=B+'previous-audit.json',protected_sources=protected,
        selected_new_findings=findings,selected_declared_warm_diagnostic_suites=[dict(selection=G+'ROOT-selected-eight-diagnostic-scopes-v1.json',case_count=8,prefix_case_from_exit1=1,new_exit0_controls=7,ROOT_FILE=G+'ROOT-file-bundle-proof-v1.json')],
        new_exact_candidate_embedded_reader_scope=G+'candidate-warm-probe-embedded-reader-v1.json',new_readonly_local_candidate=bundle['candidate_path'],new_candidate_physical_test_pending=True,native_warm_probe_ROOT_seal=seal_path,
        current_findings=249,current_public_details=218,current_state_sha256=after[CANONICAL[0]],report_sha256=served_sha,canonical_after_sha256=after,canonical_readback_uncached=True,local_report_sha256=served_sha,served_report_sha256=served_sha,
        device_IO_this_turn=False,physical_App_or_hardware_or_audio=False,goal_status='active',full_goal_complete=False)
    write(OUT,audit)
    latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_retirement_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=immutable_sha(B+'previous-audit.json'),all_passed=True)
    latest.pop('current_native_retirement_ROOT_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,local_report_sha256=served_sha,served_report_sha256=served_sha,served_latest_report=True,report_bytes=len(served),service=service,service_not_restarted=True,
        cache_control=cache,current_native_warm_probe_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},canonical_hash_readback_uncached=True,current_physical_test_requested=False,user_away_for_class=True,physical_2_10_display_control_pending=True,new_W_probe_physical_test_pending=True)
    latest['complete_current_offline_run'].update(protected_source_count=len(protected),new_warm_diagnostic_ROOT_scopes=8,new_warm_candidate_embedded_reader_scopes=1,new_warm_ROOT_FILE_complete=True,new_independent_warm_agent_review_complete=False,
        device_io=False,device_files_written=False,sounds_emitted=False,physical_App_verified=False,new_warm_probe_physical_installed=False)
    latest['progress_display_verified'].update(estimate_percent=33,completed_items=218,report_updated_time=iso,research_updated_time=iso,visual_browser_render_not_performed=True)
    write('evidence/report-web-latest.json',latest);assert all(sha(p)==h for p,h in after.items())
    print(json.dumps(dict(all_passed=True,findings=249,details=218,protected_sources=len(protected),preserved_complete_suites=49,native_dependencies=1733,new_warm_diagnostic_cases=8,new_embedded_reader_scope=1,
        estimate_percent=33,App_estimate_percent=20,updated_Taiwan=iso,HTTP_status=status,report_bytes=len(served),served_sha256=served_sha,current_state_sha256=after[CANONICAL[0]],goal_status='active',device_IO=False)))
if __name__=='__main__':main()
