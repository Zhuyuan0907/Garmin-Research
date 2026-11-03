#!/usr/bin/env python3
"""One-shot ROOT publication of frozen ingress and attended marker evidence.

No VM, Bluetooth, device write, installation, call, sound or daemon restart.
Historical suites and receipts stay frozen. Mutable endpoint hashes are fresh.
"""
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import html
import json
from pathlib import Path
import re
import subprocess
import urllib.request
from zoneinfo import ZoneInfo

ROOT=Path(__file__).resolve().parents[1]
B='staging/native-player-ingress-checkpoint/'
G='staging/native-player-sbc-ingress/'
SOURCE='scripts/publish_native_ingress_checkpoint_v2.py'
INPUT=B+'publication-inputs-v4.json'
PREPARATION=B+'prepare-v4-terminal-tool-receipt.json'
OUT='evidence/firmware-analysis/native-ingress-physical-marker-checkpoint-audit.json'

def read(path):return json.loads((ROOT/path).read_text())
def fresh_sha(path):
    d=hashlib.sha256()
    with (ROOT/path).open('rb') as f:
        for chunk in iter(lambda:f.read(8<<20),b''):d.update(chunk)
    return d.hexdigest()
@lru_cache(None)
def immutable_sha(path):return fresh_sha(path)
def write(path,data):
    (ROOT/path).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
def service_now():
    r=subprocess.run(['systemctl','show','garmin-report-web.service',
        '--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    s=dict(line.split('=',1)for line in r.stdout.splitlines()if '='in line)
    assert s==dict(MainPID='357833',ActiveState='active',SubState='running',UnitFileState='enabled')
    return s

def main():
    assert not (ROOT/OUT).exists(),'Preserve terminal publication; NEW source required'
    m=read(INPUT);assert m['all_passed']
    c=m['publication_constraints']
    assert not c['canonical_write'] and not c['guest_execution'] and not c['growing_guest_JSON_read']
    assert c['physical_marker_execution_observed'] and c['original_voice_restored_verified'] and c['physical_Aud_Ver_2_10_pending']
    prep=read(PREPARATION)
    assert prep['command']=='python3 -B '+B+'prepare_publication_inputs_v4.py'
    assert prep['tool_result']['exit_code']==0 and 'session_id'not in prep['tool_result']
    e=json.loads(prep['tool_result']['output'].strip())
    assert e['all_passed'] and e['output_sha256']==immutable_sha(INPUT)
    assert e['preparation_source_sha256']==immutable_sha(B+'prepare_publication_inputs_v4.py')
    assert prep['source_sha256'][B+'prepare_publication_inputs_v4.py']==e['preparation_source_sha256']
    previous=read(B+'previous-audit.json')
    assert previous['all_passed'] and len(previous['protected_sources'])==2531
    assert len(previous['selected_frozen_suites'])==49 and previous['native_unique_exact_dependencies']==1733
    protected={}
    def register(entries):
        for path,digest in entries.items():
            assert immutable_sha(path)==digest,path
            assert path not in protected or protected[path]==digest,path
            protected[path]=digest
    register(m['frozen_files_sha256']);register(m['new_files_sha256'])
    assert read(B+'preserved-protected-file-registry.json')==previous['protected_sources']
    assert all(protected[p]==h for p,h in previous['protected_sources'].items())
    native=read(B+'preserved-native-dependency-registry.json');assert len(native)==1733;register(native)
    assert m['preserved_selected_frozen_suites']==previous['selected_frozen_suites']
    assert not m['new_complete_cold_suites'] and len(m['new_declared_ingress_scoped_suites'])==1
    assert m['previous_goal_turn_classification']=='progress'
    for row in read(B+'previous-checkpoint.json')['snapshots']:
        assert immutable_sha(row['snapshot'])==row['sha256']
        assert fresh_sha(row['original'])==row['sha256'],'Canonical changed since preparation: '+row['original']
    for row in m['findings'].values():
        assert immutable_sha(row['path'])==row['sha256'] and read(row['path'])[row['pass_field']]is True
    selection=m['ROOT_ingress_selection']
    assert selection==read(B+'ROOT-terminal-selection-v2.json')
    actual=read(selection['actual_ROOT_receipt'])
    assert actual['terminal'] and actual['started_session_id']==50869
    assert actual['actual_terminal_result']['exit_code']==0 and actual['actual_terminal_result']['chunk_id']=='2b40b5'
    proof=read(G+'sbc-ingress-v4-proof.json');metrics=read(G+'ROOT-runtime-v4-metrics.json')
    assert proof['all_passed'] and proof['case_count']==metrics['case_count']==6
    expected=dict(instructions=2737217,stores=256485,events=256705,zones=180,RX_zones=18,
        decoder_returns=24,CRC_returns=1,ingress_returns=15,Source_POST_events=22,capacity_posts=2,
        capacity_Source_overlap_entries=10,native_full_returns=58,native_full_sync_returns=5,
        output_bytes=12544,copied_PCM_commits=11)
    assert metrics['total']==expected
    assert not proof['original_SEP_registration_remoteStart_warm_ownership_phone_App_or_speaker_verified']
    assert not proof['native_heap_exclusive_STOP_DONE_verified'] and not proof['device_io']
    root_file=read(G+'root-file-review-v2/ROOT-ingress-v4-file-reconstruction.json')
    root_seal=read(G+'root-file-review-v2/ROOT-file-reconstruction-seal.json')
    assert root_file['all_passed'] and root_seal['all_passed']
    assert selection['proof_or_completed_case_scope_is_ROOT_only']
    assert not selection['declared_scoped_suites'][0]['new_independent_agent_runtime_review']
    positive=read(selection['physical_positive_observation']);restore=read(selection['physical_original_restore'])
    assert positive['expected_marker_observed'] and positive['positive_physical_modified_code_observation']
    assert positive['displayed_marker']=='M7Q9' and positive['rollback_2_10_control_pending']
    assert restore['readback_verified'] and restore['safely_unmounted']
    assert restore['restore_actual_terminal']['exit_code']==0 and restore['restore_actual_terminal']['chunk_id']=='f3b613'
    assert restore['physical_rollback_Aud_Ver_2_10_observation_pending']
    assert not restore['other_device_files_written'] and not restore['firmware_flashed']
    assert fresh_sha(restore['fresh_candidate_backup'])==restore['candidate_sha256']
    register({SOURCE:immutable_sha(SOURCE),INPUT:immutable_sha(INPUT),PREPARATION:immutable_sha(PREPARATION),
        restore['fresh_candidate_backup']:restore['candidate_sha256']})
    state,task,public=[read(p)for p in ('evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json')]
    prior=read(B+'previous-state.json');prior_public=read(B+'previous-public.json')
    app=state['native_app_music'];progress=public['research_progress']
    assert app['static_findings']==prior['native_app_music']['static_findings']
    assert len(app['static_findings'])==226 and len(progress['completed'])==186
    assert progress['completed']==prior_public['research_progress']['completed']
    for key,row in m['findings'].items():
        assert key not in app['static_findings']
        app['static_findings'][key]=dict(evidence=row['path'],evidence_sha256=row['sha256'],scope=row['scope'],
            evidence_type=row['evidence_type'],physical_App_or_audio_verified=False,device_io=row['device_io'])
    now=datetime.now(timezone.utc)
    focus=('Connect the guarded Stage1/source ingress to actual native SEP/receiver callbacks without resetting warm global audio; recover durable channel ownership and accepted configuration/session epoch. '
        'Execute original Stop15/19 then20/ACK8 barrier and full277674 removal before retiring storage; retain module until callback/consumer quiescence. '
        'Integrate native heap/private pages, warm loader and original menu. Exact modified Big5 voice code physically executed M7Q9; original file restored/readback verified, attended2.10 display pending. '
        'User away in class; USB remains connected, no unattended calls or sound. Pairing first when present; microphone canceled, fidelity deferred, Android Auto later, Google Maps deferred; full goal active/no-achieve.')
    next_text='先接真正藍牙接收端與暖機音訊資源，再完成原生停止／回收與 App 菜單入口；M7Q9 實機改碼執行已確認、原檔已還原，晚點待確認 Aud Ver 2.10。'
    state.update(updated_utc=now.isoformat(),current_priority='Native receiver/warm ownership, safe Stop and App integration; physical M7Q9 verified, original restored,2.10 display pending; active.')
    state['next_actions']=[focus,
        'Validate accepted Configure/Start peer/session epoch, copied packet lifetime and pre-entry cached callback barriers; pin resident module/TCB until native dispatcher return.',
        'Complete original Stop transaction, full source-list removal and explicit native storage/session retirement; native heap/exclusive/STOP_DONE remain unproved.',
        'Use exact physically accepted voice wrapper to develop resident player and menu only after warm ownership/heap/Stop validation; no full App or direct phone A2DP yet.',
        'User departed for class; original voice restored and volume safely unmounted. Next attended task is cold restart/MeiLing/Aud Ver2.10; no new question pending.']
    app['remaining_work']=state['next_actions'][:4]
    obs=app['development_observations']
    obs['native_SBC_sync_independent_FILE_six_cases']=m['new_independent_SBC_FILE_scope']
    obs['native_receiver_static_contract']=m['receiver_static_contract']
    obs['native_ingress_source_static_peer']=m['ingress_source_static_peer']
    obs['native_ingress_ROOT_six_cases']=selection
    obs['native_marker_attended_positive']=dict(path=selection['physical_positive_observation'],sha256=immutable_sha(selection['physical_positive_observation']),marker='M7Q9',exact_candidate_only=True)
    obs['native_marker_original_restored']=dict(path=selection['physical_original_restore'],sha256=immutable_sha(selection['physical_original_restore']),readback_verified=True,Aud_Ver_2_10_pending=True)
    bundle=app['local_reversible_marker_voice_bundle']
    bundle.update(physical_installed=False,physical_installation_performed=True,physical_marker_observed=True,physical_execution_verified=True,original_voice_restored=True,rollback_Aud_Ver_2_10_pending=True)
    app['modified_voice_code_execution_on_device']=True
    app['current_constraints'][0]='Exact HWID1352/SW8.00: attended M7Q9 proves execution of this modified Big5 voice candidate. Generic App/menu, continuous native player and direct phone A2DP remain unverified.'
    app['package_signature'].update(modified_package_or_DLL_code_accepted_on_device=True,exact_marker_candidate_physical_execution_verified=True,general_modified_VPM_acceptance_verified=False)
    state['latest_user_instruction']='User left for class, delegated connected USB-mode Garmin, and allowed independent research to continue; no pause requested.'
    attended=state['attended_testing']
    attended.update(user_present=False,waiting_for_user_return=True,recorded_utc=now.isoformat(),
        user_instruction='User left for class and delegated connected USB-mode device; continue independent research.',
        automatic_calls_or_sound_allowed_while_away=False,USB_or_Bluetooth_required_for_current_offline_work=False,
        no_pending_question=True,current_attended_test='M7Q9 positive observed; original voice restored/readback verified and safely unmounted. Await attended cold-start Aud Ver2.10.',user_available_for_future_physical_tests=False)
    attended['native_marker_code_test'].update(installation_performed=True,user_availability_question_pending=False,physical_mode_not_confirmed=False,
        positive_M7Q9_observed=True,original_voice_restored_verified=True,Aud_Ver_2_10_pending=True)
    state['parallel_research'].update(agents_currently_running=False,live_subagent_count=0,active_agent_tasks=[],
        continued_round_completed=False,ROOT_took_over_new_ingress_FILE_review=True,new_independent_ingress_agent_runtime_review_completed=False,
        current_agent_errors='Two agents stopped at usage limit; prior music agent errored. No retry; ROOT continues authorized local work.',live_count_observed_UTC=now.isoformat())
    state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',
        previous_goal_turn_reason=m['previous_goal_turn_reason'],validated_utc=now.isoformat(),focused_evidence=G+'sbc-ingress-v4-proof.json',
        focused_evidence_sha256=immutable_sha(G+'sbc-ingress-v4-proof.json'),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',
        reasons=['Six compiled external-ingress Source/mixer/sync cases and ROOT FILE reconstruction passed.',
            'Previous SBC six-case independent FILE review completed; new ingress independent agent runtime review did not complete.',
            'Attended M7Q9 proves exact modified voice code execution; original voice hash restored, diagnostic2.10 control remains pending.',
            'Native App/menu/direct phone music, warm ownership, heap, exclusive, native STOP_DONE and quiescence remain incomplete.'],
        actual_ROOT_ingress_cases=6,actual_ROOT_ingress_decoder_full_returns=24,actual_ROOT_ingress_native_fullpull_returns=58,
        actual_ROOT_ingress_fullsync_returns=5,ROOT_ingress_FILE_review_complete=True,new_independent_ingress_agent_runtime_review_complete=False,
        SBC_independent_FILE_review_complete=True,physical_marker_execution_verified=True,original_voice_restored_verified=True,rollback_Aud_Ver_2_10_pending=True,
        real_package_acceptance_unverified=False,general_package_acceptance_unverified=True,physical_test_availability_question_pending=False,
        native_Stop_cleanup_runtime_verified=False,native_exclusivity=False,native_STOP_DONE_verified=False,
        complete_native_App_or_phone_audio=False,physical_App_or_audio_verified=False,
        device_io=True,device_files_written=True,automatic_calls_or_sound=False,goal_status='active',full_goal_complete=False,next_focus=focus)
    for key in ('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
    task.update(user_away=True,device_state='Connected Garmin USB mass-storage observed; original Big5 voice restored and safely unmounted. Await cold-start2.10 attended control.',
        current_device_connection_verified=True,device_connection_observed_utc=restore['updated_utc'],current_connection_not_rechecked_this_offline_turn=False)
    public.update(updated=now.isoformat(),deep_research=state)
    details=m['public_details'];progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
    progress.update(research_updated_utc=now.isoformat(),next=next_text);progress['phases'][4]['next']=next_text
    assert progress['estimate_percent']==33 and progress['phases'][4]['estimate_percent']==20
    assert sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==33
    assert len(app['static_findings'])==m['projected_counts']['findings'] and len(progress['completed'])==m['projected_counts']['public_details']
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    card='<div class="card"><h2>最新進展：自製改碼已在實機執行</h2>'
    card+='<p><strong>實機里程碑：</strong>完整關機再開機、選「中文-美玲（播報路名）」後，使用者在 Aud Ver 看到 M7Q9。原版本資訊沒有直接改成這個字樣；測試模組執行後才寫入標記，因此確認這個修改版本在 Garmin 上執行。這仍是單一語音模組測試，完整音樂 App、菜單圖示與直接手機藍牙音樂尚未完成。</p>'
    card+='<p><strong>已還原：</strong>原始美玲語音讀回與備份的 SHA-256 完全一致，候選檔另有備份，USB 磁碟已安全卸載。使用者去上課，晚點再完整重開機確認 Aud Ver 回到2.10；畫面對照仍待測，不能提前列為通過。</p>'
    card+='<p><strong>接收與播放原型六組通過：</strong>外部 caller 複製壓縮封包、喚醒原廠 Source 工作；第一包有效資料才建立音源並完成原同步／ACK。緩衝塞滿後，由原 Mixer 釋出空間並喚醒 Source；壞第一包、停止後及音訊設定撤銷後均拒收。24次解碼完整返回（23成功、1CRC拒絕）、58次原音訊讀取與5次原同步完整返回。真PCM3988bytes，另外8556bytes是明示的缺資料靜音。</p>'
    card+='<p>這六組使用原廠ARM指令、核心排程及自製程式；外部caller、記憶體配置與硬體輸出仍有明示模擬條件，尚未由真手機經原Bluetooth receiver送入。ROOT已從封存檔重建記憶體寫入與返回；新獨立agent runtime審查未完成。前一批SBC六組的獨立FILE審查已完成，與這批分開記錄。</p>'
    card+='<p><strong>接下來：</strong>接真正藍牙receiver、暖機音訊資源與安全停止／回收，再完成App菜單。原生heap、持續獨占、STOP_DONE與完整callback退出仍待驗證。整體估計33%、App整合20%；goal持續進行。配對立即優先，麥克風取消、音質擱置、Android Auto排後、Google Maps暫緩。</p></div>'
    report,count=re.subn(r'<div class="card"><h2>最新離線進展：原廠同步等待與 ACK8 已接通</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert count==1
    old_next=prior_public['research_progress']['phases'][4]['next']
    old_row='<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(old_next)+'</td></tr>'
    assert report.count(old_row)==1
    report=report.replace(old_row,'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(next_text)+'</td></tr>',1)
    report,count=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda x:x[1]+x[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+x[3],report,count=1,flags=re.S);assert count==1
    report,count=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>',report,count=1);assert count==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
    for name in ('report-updated-time','research-updated-time'):
        report,count=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert count==1
    assert not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',report)
    assert 'REDACTED_PRIVATE_ID'not in report
    assert state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining']
    assert not app['native_app_running'] and not app['direct_phone_music_verified']
    assert public['deep_research']==state and task['last_goal_turn']==state['last_goal_turn']
    latest=read('evidence/report-web-latest.json');service_before=service_now()
    with urllib.request.urlopen(latest['url'],timeout=10)as response:
        prior_served=response.read();assert response.status==200 and 'no-store'in response.headers.get('Cache-Control','')
    assert hashlib.sha256(prior_served).hexdigest()==fresh_sha('reports/nuvi2565RT.html')
    # All input/scope/live/HTML checks precede canonical mutations.
    for path,data in [('evidence/deep-research-state.json',state),('evidence/task-state.json',task),('reports/findings.json',public)]:write(path,data)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    canonical_after={p:fresh_sha(p)for p in ('evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json','reports/nuvi2565RT.html')}
    assert read('evidence/deep-research-state.json')==state and read('evidence/task-state.json')==task and read('reports/findings.json')==public
    with urllib.request.urlopen(latest['url'],timeout=10)as response:served,status,cache=response.read(),response.status,response.headers.get('Cache-Control','')
    served_sha=hashlib.sha256(served).hexdigest()
    assert status==200 and 'no-store'in cache and served==report.encode()
    assert served_sha==fresh_sha('reports/nuvi2565RT.html')==canonical_after['reports/nuvi2565RT.html']
    service=service_now();assert service==service_before
    checks=dict(old2531_protected_files_preserved=True,old49_complete_suites_preserved=True,old1733_native_dependencies_preserved=True,
        old_SBC_independent_FILE_completion_separate=True,new6_ingress_scoped_cases_pass=True,ROOT_ingress_FILE_review_complete=True,
        new_independent_ingress_agent_runtime_review_not_claimed=True,exact_physical_modified_code_M7Q9_observed=True,
        original_voice_hash_restored_and_safely_unmounted=True,physical_2_10_control_explicitly_pending=True,
        true_native_receiver_phone_App_menu_heap_exclusive_STOP_DONE_unverified=True,cold_allocator_hardware_fixtures_explicit=True,
        device_write_in_physical_stage_separate_from_FILE_guest=True,publisher_no_device_calls_or_sound=True,
        fresh_canonical_and_local_served_hashes_match=True,weighted33_App20_goal_active=True,canonical_task_public_consistent=True,
        two_Taiwan_timestamps=report.count('datetime="'+iso+'"')==2,HTTP200_no_store_exact=True,live_PID_unchanged_no_restart=True)
    audit=dict(previous,updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=all(checks.values()),scope_checks=checks,
        previous_checkpoint=B+'previous-audit.json',protected_sources=protected,selected_frozen_suites=previous['selected_frozen_suites'],native_unique_exact_dependencies=1733,
        selected_new_findings=m['findings'],selected_declared_ingress_suites=m['new_declared_ingress_scoped_suites'],
        new_independent_SBC_FILE_scope=m['new_independent_SBC_FILE_scope'],native_receiver_static_contract=m['receiver_static_contract'],
        ingress_source_static_peer=m['ingress_source_static_peer'],ROOT_ingress_selection=selection,
        physical_marker_evidence=selection['physical_positive_observation'],original_voice_restore=selection['physical_original_restore'],
        source_dependency_union_revalidated_once_before_write=True,current_state_sha256=canonical_after['evidence/deep-research-state.json'],
        report_sha256=served_sha,canonical_after_sha256=canonical_after,local_report_sha256=served_sha,served_report_sha256=served_sha,canonical_readback_uncached=True,
        current_findings=len(app['static_findings']),current_public_details=len(progress['completed']),
        complete_Dispatcher_body_or_foreground_or_physical_App=False,physical_App_or_hardware_or_audio=False,
        physical_modified_code_execution_verified=True,physical_rollback_Aud_Ver_2_10_pending=True,full_goal_complete=False,goal_status='active')
    assert audit['all_passed'];write(OUT,audit)
    latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_sync_SBC_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=immutable_sha(B+'previous-audit.json'),all_passed=True)
    latest.pop('current_native_sync_SBC_ROOT_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,served_latest_report=True,local_report_sha256=fresh_sha('reports/nuvi2565RT.html'),
        served_report_sha256=served_sha,report_bytes=len(served),service=service,service_not_restarted=True,cache_control=cache,
        current_native_ingress_physical_marker_checkpoint=OUT,checkpoint_sha256={OUT:fresh_sha(OUT)},goal_status='active',full_goal_complete=False,
        canonical_hash_readback_uncached=True,current_physical_test_requested=False,user_explicitly_returned=False,
        user_away_for_class=True,physical_2_10_display_control_pending=True)
    latest['complete_current_offline_run'].update(protected_source_count=len(protected),native_frozen_suites_revalidated=49,native_unique_exact_dependencies=1733,
        actual_native_ingress_new_cases=6,actual_ingress_fullpull_returns=58,actual_ingress_fullsync_returns=5,
        SBC_independent_FILE_review_complete=True,ROOT_ingress_FILE_review_complete=True,new_independent_ingress_agent_runtime_review_complete=False,
        physical_App_verified=False,physical_modified_code_execution_verified=True,device_io=True,device_files_written=True,sounds_emitted=False)
    latest['progress_display_verified'].update(estimate_percent=33,completed_items=len(progress['completed']),report_updated_time=iso,research_updated_time=iso,visual_browser_render_not_performed=True)
    write('evidence/report-web-latest.json',latest)
    assert read('evidence/report-web-latest.json')['local_report_sha256']==fresh_sha('reports/nuvi2565RT.html')==served_sha
    print(json.dumps(dict(all_passed=True,findings=len(app['static_findings']),details=len(progress['completed']),protected_sources=len(protected),
        preserved_complete_suites=49,native_dependencies=1733,new_ingress_cases=6,ROOT_ingress_FILE_review_complete=True,
        physical_M7Q9_observed=True,original_voice_restored=True,physical_2_10_control_pending=True,
        estimate_percent=33,App_estimate_percent=20,updated_Taiwan=iso,HTTP_status=status,report_bytes=len(served),goal_status='active',
        local_and_served_report_sha256=served_sha,current_state_sha256=canonical_after['evidence/deep-research-state.json'])))

if __name__=='__main__':main()
