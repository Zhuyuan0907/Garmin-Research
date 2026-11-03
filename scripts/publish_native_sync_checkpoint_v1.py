#!/usr/bin/env python3
"""Root-only, one-shot publication of frozen native sync/static Stop/compile-only SBC evidence.

Prepared for review; the preparation agent must not execute this publisher.
No guest, device, installation or sound action. The existing report service is
observed live and is never restarted. Canonical readback is explicitly uncached.
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


ROOT = Path(__file__).resolve().parents[1]
B = 'staging/native-player-sync-checkpoint/'
U = 'staging/native-player-mixer-sync/'
I = U + 'verification-v3/'
S = 'staging/native-player-sbc-sync/'
SOURCE = 'scripts/publish_native_sync_checkpoint_v1.py'
INPUT = B + 'publication-inputs-v1.json'
PREPARATION = B + 'prepare-v1-terminal-tool-receipt.json'
OUT = 'evidence/firmware-analysis/native-sync-checkpoint-audit.json'


def read(path):
    return json.loads((ROOT / path).read_text())


def fresh_sha(path):
    digest = hashlib.sha256()
    with (ROOT / path).open('rb') as handle:
        while chunk := handle.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@lru_cache(None)
def immutable_sha(path):
    """Cache only frozen inputs; use fresh_sha for every mutable endpoint."""
    return fresh_sha(path)


def write(path, data):
    (ROOT / path).write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')


def service_now():
    result = subprocess.run(['systemctl', 'show', 'garmin-report-web.service',
        '--property=MainPID,ActiveState,SubState,UnitFileState'],
        capture_output=True, text=True, check=True)
    service = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    assert service['MainPID'] == '357833'
    assert service['ActiveState'] == 'active' and service['SubState'] == 'running'
    assert service['UnitFileState'] == 'enabled'
    return service

def main():
    assert not (ROOT / OUT).exists(), 'Preserve completed publication; NEW source required'
    manifest=read(INPUT);assert manifest['all_passed'] and not manifest['publication_constraints']['canonical_write']
    assert not manifest['publication_constraints']['guest_execution'] and not manifest['publication_constraints']['growing_SBC_guest_JSON_read']
    prep=read(PREPARATION);assert prep['command']=='python3 -B '+B+'prepare_publication_inputs_v1.py'
    assert prep['tool_result']['exit_code']==0 and 'session_id' not in prep['tool_result']
    emitted=json.loads(prep['tool_result']['output'].strip())
    assert emitted['all_passed'] and emitted['output_sha256']==immutable_sha(INPUT)
    assert emitted['preparation_source_sha256']==immutable_sha(B+'prepare_publication_inputs_v1.py')
    assert prep['source_sha256'][B+'prepare_publication_inputs_v1.py']==emitted['preparation_source_sha256']
    previous=read(B+'previous-audit.json');snapshots=read(B+'previous-checkpoint.json')['snapshots']
    assert previous['all_passed'] and len(previous['protected_sources'])==2031
    assert len(previous['selected_frozen_suites'])==49 and previous['native_unique_exact_dependencies']==1733
    protected={}
    def register(entries):
        for path,digest in entries.items():
            assert immutable_sha(path)==digest,path
            assert path not in protected or protected[path]==digest,path
            protected[path]=digest
    register(manifest['frozen_files_sha256'])
    assert read(B+'preserved-protected-file-registry.json')==previous['protected_sources']
    assert all(protected[p]==h for p,h in previous['protected_sources'].items())
    native=read(B+'preserved-native-dependency-registry.json');assert len(native)==1733;register(native)
    assert manifest['preserved_selected_frozen_suites']==previous['selected_frozen_suites']
    assert manifest['new_complete_cold_suites']==[] and len(manifest['new_music_sync_declared_scoped_suites'])==1
    assert manifest['previous_goal_turn_classification']=='no_progress'
    for row in snapshots:
        assert immutable_sha(row['snapshot'])==row['sha256']
        assert fresh_sha(row['original'])==row['sha256'],'Canonical changed since preparation: '+row['original']
    for row in manifest['findings'].values():
        assert immutable_sha(row['path'])==row['sha256'] and read(row['path'])[row['pass_field']] is True
    proof=read(I+'mixer-sync-v3-independent-file-verification.json');seal=read(I+'mixer-sync-v3-independent-file-seal.json')
    assert proof['all_passed'] and seal['all_passed'] and proof['case_count']==3
    assert proof['CPU_stores']==44931 and proof['joint_events']==45065 and proof['full_original_native_returns']==48
    assert proof['full_original_sync_returns']==proof['actual_original_condition_waits']==proof['actual_original_ACK8']==4
    assert proof['actual_RW_case_replays_from_frozen_permission_recipe']==69 and proof['unchanged_RX_return_sentinel_case_replays']==3
    assert proof['actual_final_RX_dump_case_zones']==9 and proof['serialized_controller_idle_endpoint_GP16_CPSR_SP_snapshots']==89
    assert proof['ordinary_controller_endpoint_GP16_CPSR_SP_serialized'] and not proof['generic_mutex_or_46CC7A_syncwait_ACK_tail_bypassed']
    assert not proof['native_heap_exclusive_STOP_DONE_hardware_phone_App_installation_or_complete_player_verified']
    root_receipt=read(U+'guest-v3-terminal-tool-receipt.json')
    assert root_receipt['terminal'] and root_receipt['started_session_id']==89948 and root_receipt['actual_terminal_result']['exit_code']==0 and root_receipt['actual_terminal_result']['chunk_id']=='925a2b'
    verifier_receipt=read(I+'mixer-sync-v3-independent-terminal-tool-receipt.json')
    assert verifier_receipt['terminal'] and verifier_receipt['started_session_id']==69431 and verifier_receipt['actual_terminal_result']['exit_code']==0 and verifier_receipt['actual_terminal_result']['chunk_id']=='ba9584'
    stop=read(manifest['native_Stop_static_contract']['path'])
    assert stop['scope']['static_only'] and not stop['scope']['new_native_stop_cleanup_runtime_proof'] and not stop['scope']['native_STOP_DONE']
    sbc=read(manifest['SBC_compile_only']['path'])
    assert not sbc['guest_executed'] and not sbc['complete_player_image'] and not sbc['device_io']
    assert not manifest['SBC_compile_only']['SBC_guest_result_included']
    assert sbc['ELF_sha256']=='c170e77c216abb44e6a6570034768ce00deb3226b20d1bd0349b70d1e564a4eb'
    state,task,public=[read(p) for p in ('evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json')]
    before=read(B+'previous-state.json');prior_public=read(B+'previous-public.json')
    app=state['native_app_music'];progress=public['research_progress']
    assert app['static_findings']==before['native_app_music']['static_findings']
    assert len(app['static_findings'])==216 and len(progress['completed'])==174
    assert progress['completed']==prior_public['research_progress']['completed']
    for key,row in manifest['findings'].items():
        assert key not in app['static_findings']
        app['static_findings'][key]=dict(evidence=row['path'],evidence_sha256=row['sha256'],scope=row['scope'],evidence_type=row['evidence_type'],physical_App_or_audio_verified=False,device_io=False)
    now=datetime.now(timezone.utc)
    focus=('Next verify compiled compressed RTP/SBC/FIR data in the real Source12 and current native sync module, with full packet leases and callback coherence; this selected bundle includes compile-only SBC evidence. '
           'Then execute guarded Source Stop transaction: ordered15/19, direct46CC7A20/ACK8 barrier, full native277674 retirement with session/storage leases retained; no synthetic STOP_DONE or release before fullreturn. '
           'Continue native lifetime/exclusive ownership/hardware, native heap/private-page/table provenance and App/phone integration. '
           'Pairing first; microphone canceled; fidelity deferred; Android Auto later; Google Maps deferred; full objective active/no-achieve.')
    next_text='先驗證Source12內的壓縮RTP／SBC／FIR、封包lease與FIFO callback一致性；再接原Stop15／19／20-ACK8屏障及完整list回收，保留session／storage直到全返回，原生STOP_DONE、獨占與硬體仍待完成。'
    state.update(updated_utc=now.isoformat(),current_priority='Native source synchronization, SBC worker and guarded Stop lifetime; active/no-achieve.')
    state['next_actions'][0]=focus;app['remaining_work']=state['next_actions'][:4]
    observations=app['development_observations']
    observations['native_mixer_original_sync_v3']=manifest['sync_scope']
    observations['native_Stop_static_next_contract']=manifest['native_Stop_static_contract']
    observations['native_SBC_sync_compile_only']=manifest['SBC_compile_only']
    state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='no_progress',validated_utc=now.isoformat(),
        focused_evidence=U+'mixer-sync-v3-proof.json',focused_evidence_sha256=immutable_sha(U+'mixer-sync-v3-proof.json'),
        previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',
        reasons=['Three actual original rawmutex/condition/ACK8 scoped cases and four complete initializer returns; existingMixer reuses capability.',
                 'Independent FILE stores/whole zones/52-byte savedframes/preemption/contention/priority donation/unlocktransfer; actual finalRX and controller endpoint snapshots.',
                 'Native Stop static transaction contract and compile-only SBC source/build; no Stop or SBC runtime result selected.',
                 'Physical App/phone/speaker, native heap/exclusivity and STOP_DONE remain incomplete.'],
        actual_new_music_sync_cases=3,actual_complete_original_sync_returns=4,actual_complete_native_outer_mixer_returns=48,
        actual_generic_mutex_condition_ACK8_executed=True,ordinary_controller_endpoint_GP_SP_CPSR_serialized=True,actual_final_RX_memory_dump_serialized=True,
        selected_SBC_compile_only=True,new_SBC_guest_result_included=False,native_Stop_cleanup_runtime_verified=False,
        native_exclusivity=False,native_STOP_DONE_verified=False,complete_native_App_or_phone_audio=False,physical_App_or_audio_verified=False,
        device_io=False,device_files_written=False,automatic_calls_or_sound=False,goal_status='active',full_goal_complete=False,next_focus=focus)
    for key in ('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing'):task[key]=state[key]
    public.update(updated=now.isoformat(),deep_research=state)
    details=manifest['public_details'];progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
    progress.update(research_updated_utc=now.isoformat(),next=next_text);progress['phases'][4]['next']=next_text
    assert progress['estimate_percent']==33 and progress['phases'][4]['estimate_percent']==20
    assert sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==33
    assert len(app['static_findings'])==manifest['projected_counts']['findings'] and len(progress['completed'])==manifest['projected_counts']['public_details']
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    card='<div class="card"><h2>最新離線進展：原廠同步等待與 ACK8 已接通</h2>'
    card+='<p><strong>新增3組原生同步案例：</strong>原mutex、condition wait、message20與mixer ACK8真正執行，完整同步返回4次、完整音訊返回48次；新與既有M+78路徑均通過。ACK8先搶先mixer，source再競爭並阻塞，原優先權捐贈與解鎖移交後才完整返回。CONFIG先交接、PLAY保持關閉直到完整初始化返回。</p>'
    card+='<p>獨立純檔案核對44931筆CPU stores、45065共同事件、69次真RW與3次不變RX sentinel重建；另核對9個actual finalRX dumps、89個controller／idle endpoint GP／SP／CPSR快照與原13-word／52-byte context frames。Timer由原constructor建立但沒有register／post／排程；direct boot inputs與4個guest-only call-site跳轉仍有明示scope，未證完整原coldboot。</p>'
    card+='<p><strong>下一Stop契約目前只有靜態證據：</strong>原15／19後接直接46CC7A的20／ACK8順序屏障，完整返回後才做source-list刪除；notice23早於完整刪除與unlock返回，不能當安全回收訊號。compiled Stop仍PENDING，不能偽造STOP_DONE。</p>'
    card+='<p>新版壓縮RTP／SBC／FIR與typed FIFO映像已編譯／連結，這份選取bundle只包含build成功，尚未納入SBC guest結果或實機測試。opaque allocator／policy、hardware activation／reset transport與ring consumer仍有fixture；手機原生A2DP、喇叭、可安裝App、獨占、native heap與STOP_DONE尚未完成。先前MMU軟體與實體page限制保留。</p>'
    card+='<p>sync V2完整suite的EXIT1與5次FILE verifier前提失敗均封存，首個完成案例另列；未重跑guest或把失敗改稱成功。整體估計33%、App整合20%，完整研究goal active。配對立即優先、麥克風取消、音質擱置、Android Auto排後、Google Maps暫緩。</p></div>'
    report,count=re.subn(r'<div class="card"><h2>最新離線進展：原廠音訊工作交接與 MMU 軟體分支</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert count==1
    old_next=prior_public['research_progress']['phases'][4]['next']
    old_row='<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(old_next)+'</td></tr>'
    assert report.count(old_row)==1
    report=report.replace(old_row,'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(next_text)+'</td></tr>',1)
    report,count=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(x)+'</li>' for x in details)+m[3],report,count=1,flags=re.S);assert count==1
    report,count=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>',report,count=1);assert count==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
    for name in ('report-updated-time','research-updated-time'):
        report,count=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert count==1
    assert not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',report)
    assert 'REDACTED_PRIVATE_ID' not in report
    assert state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining']
    assert not app['native_app_running'] and not app['direct_phone_music_verified']
    assert public['deep_research']==state and task['last_goal_turn']==state['last_goal_turn']
    register({SOURCE:immutable_sha(SOURCE),INPUT:immutable_sha(INPUT),PREPARATION:immutable_sha(PREPARATION)})
    latest=read('evidence/report-web-latest.json');service_before=service_now()
    with urllib.request.urlopen(latest['url'],timeout=10) as response:
        prior_served=response.read();assert response.status==200 and 'no-store' in response.headers.get('Cache-Control','')
    assert hashlib.sha256(prior_served).hexdigest()==fresh_sha('reports/nuvi2565RT.html')
    # Input/scope/HTML/live preflight checks all precede canonical mutations.
    for path,data in [('evidence/deep-research-state.json',state),('evidence/task-state.json',task),('reports/findings.json',public)]:write(path,data)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    canonical_after={p:fresh_sha(p) for p in ('evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json','reports/nuvi2565RT.html')}
    assert read('evidence/deep-research-state.json')==state and read('evidence/task-state.json')==task and read('reports/findings.json')==public
    with urllib.request.urlopen(latest['url'],timeout=10) as response:served,status,cache=response.read(),response.status,response.headers.get('Cache-Control','')
    served_sha=hashlib.sha256(served).hexdigest()
    assert status==200 and 'no-store' in cache and served==report.encode()
    assert served_sha==fresh_sha('reports/nuvi2565RT.html')==canonical_after['reports/nuvi2565RT.html']
    service=service_now();assert service==service_before
    checks=dict(old2031_protected_registry_preserved=True,old49_complete_suites_preserved=True,old1733_dependencies_preserved=True,
        new3_sync_cases_separate_from_completeboot=True,four_fullsync_original_ACK8_wait_mutex_verified=True,
        nine_finalRX_dumps_89_endpoint_snapshots_independently_verified=True,prior_v2_failed_suite_and_five_FILE_failures_preserved=True,
        native_Stop_contract_static_only=True,SBC_selected_build_compile_only_no_guestresult=True,
        direct_constructor_Timer_unscheduled_guest_redirections_and_fixtures_explicit=True,native_heap_exclusive_STOP_DONE_App_phone_hardware_unverified=True,
        uncached_canonical_and_local_served_hashes_match=True,weighted33_App20_active_goal=True,canonical_task_public_consistent=True,
        two_Taiwan_timestamps=report.count('datetime="'+iso+'"')==2,HTTP200_no_store_exact=True,live_service_same_PID_no_restart=True,no_device_writes_or_sound=True)
    audit=dict(previous,updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=all(checks.values()),scope_checks=checks,
        previous_checkpoint=B+'previous-audit.json',protected_sources=protected,selected_frozen_suites=previous['selected_frozen_suites'],native_unique_exact_dependencies=1733,
        selected_declared_music_sync_suites=manifest['new_music_sync_declared_scoped_suites'],selected_new_findings=manifest['findings'],
        native_mixer_original_sync_scope=manifest['sync_scope'],native_Stop_static_contract=manifest['native_Stop_static_contract'],SBC_compile_only=manifest['SBC_compile_only'],
        source_dependency_union_revalidated_once_before_write=True,current_state_sha256=canonical_after['evidence/deep-research-state.json'],report_sha256=canonical_after['reports/nuvi2565RT.html'],
        canonical_after_sha256=canonical_after,local_report_sha256=canonical_after['reports/nuvi2565RT.html'],served_report_sha256=served_sha,canonical_readback_uncached=True,
        current_findings=len(app['static_findings']),current_public_details=len(progress['completed']),complete_Dispatcher_body_or_foreground_or_physical_App=False,
        physical_App_or_hardware_or_audio=False,full_goal_complete=False,goal_status='active')
    assert audit['all_passed'];write(OUT,audit)
    latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_mmu_handoff_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=immutable_sha(B+'previous-audit.json'),all_passed=True)
    latest.pop('current_native_mmu_handoff_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,served_latest_report=True,local_report_sha256=fresh_sha('reports/nuvi2565RT.html'),served_report_sha256=served_sha,
        report_bytes=len(served),service=service,service_not_restarted=True,cache_control=cache,current_native_sync_checkpoint=OUT,checkpoint_sha256={OUT:fresh_sha(OUT)},goal_status='active',full_goal_complete=False,canonical_hash_readback_uncached=True)
    latest['complete_current_offline_run'].update(protected_source_count=len(protected),native_frozen_suites_revalidated=49,actual_native_mixer_sync_new_cases=3,full_original_sync_returns=4,SBC_guest_result_included=False,physical_App_verified=False,device_io=False,sounds_emitted=False)
    latest['progress_display_verified'].update(estimate_percent=33,completed_items=len(progress['completed']),report_updated_time=iso,research_updated_time=iso,visual_browser_render_not_performed=True)
    write('evidence/report-web-latest.json',latest)
    assert read('evidence/report-web-latest.json')['local_report_sha256']==fresh_sha('reports/nuvi2565RT.html')==served_sha
    print(json.dumps(dict(all_passed=True,findings=len(app['static_findings']),details=len(progress['completed']),protected_sources=len(protected),preserved_complete_suites=49,native_dependencies=1733,new_sync_cases=3,fullsync_returns=4,SBC_guest_result_included=False,estimate_percent=33,App_estimate_percent=20,updated_Taiwan=iso,HTTP_status=status,report_bytes=len(served),goal_status='active',local_and_served_report_sha256=served_sha,current_state_sha256=canonical_after['evidence/deep-research-state.json'])))

if __name__=='__main__':main()

