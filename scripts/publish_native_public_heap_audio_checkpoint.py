#!/usr/bin/env python3
"""Publish scoped actual audio/heap evidence; input manifest must be frozen."""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import hashlib
import html
import json
import re
import subprocess
import urllib.request
from publish_native_settings_scope_checkpoint_v2 import ROOT, read, sha, registry, write

B = 'staging/native-player-native-allocation/'
A = B + 'audio-session-static/'
C = 'staging/native-player-continuous-session/'
OUT = 'evidence/firmware-analysis/native-public-heap-audio-checkpoint-audit.json'


def main():
    assert not (ROOT/OUT).exists(), 'Preserve published audit'
    manifest = read(B+'publication-inputs.json')
    preparation = read(B+'prepare-terminal-tool-receipt.json')
    assert preparation['observed_session_id'] == 99167
    assert preparation['tool_result']['exit_code'] == 0 and preparation['tool_result']['chunk_id'] == '85e496'
    agent_observation = read(B+'parallel-agents-at-publication.json')
    assert agent_observation['live_subagent_count'] == 3
    previous = read(B+'previous-audit.json')
    protected = {}
    registry(previous['protected_sources'], protected)
    assert len(protected) == 1721 and previous['all_passed']
    for row in read(B+'previous-checkpoint.json')['snapshots']:
        assert sha(row['original']) == row['sha256'] == sha(row['snapshot'])
    suites = list(previous['selected_frozen_suites'])
    assert len(suites) == 48
    native_dependencies = {}
    for suite in suites:
        assert sha(suite['path']) == suite['sha256']
        d = read(suite['path'])
        assert d['all_passed'] and all(case['passed'] for case in d['cases'])
        registry(d['source_sha256'], native_dependencies)
    assert len(native_dependencies) == previous['native_unique_exact_dependencies'] == 1533
    registry(manifest['frozen_files_sha256'], protected)
    for path in (B+'prepare-terminal-tool-receipt.json',B+'parallel-agents-at-publication.json'):
        protected[path] = sha(path)
    documents = {}
    for key, row in manifest['findings'].items():
        assert sha(row['path']) == row['sha256']
        d = read(row['path'])
        assert d[row.get('pass_field', 'all_passed')] is True
        for field in ('source_sha256', 'dependency_sha256', 'verified_runtime_dependencies',
                      'artifacts_sha256', 'output_sha256', 'generated_sha256'):
            if isinstance(d.get(field), dict):
                registry(d[field], protected)
        for case in d.get('cases', []):
            assert case['passed']
            if 'path' in case:
                assert sha(case['path']) == case['sha256']
                protected[case['path']] = case['sha256']
        protected[row['path']] = row['sha256']
        documents[key] = d
    for row in manifest.get('new_complete_cold_suites', []):
        d = read(row['path'])
        assert sha(row['path']) == row['sha256'] and d['all_passed']
        assert all(case['passed'] for case in d['cases'])
        registry(d['source_sha256'], native_dependencies)
        suites.append(row)
    audio = read(A+'audio-session-emulation-v2-proof.json')
    assert audio['all_passed'] and audio['case_count'] == 2
    assert audio['actual_compiled_submit_ticket_and_original_selector_provider']
    assert audio['original_full_pull_to_compiled_FIFO_and_complete_lease_returns']
    assert not audio['original_native_mixer_caller_redirected']
    assert not audio['source_owner_to_mixer_handoff_verified']
    assert not audio['native_heap_allocator_pinning_mutex_scheduler_hardware_App_exclusive_or_STOP_DONE_verified']
    receipt = read(A+'guest-v2-terminal-tool-receipt.json')['tool_result']
    assert receipt['exit_code'] == 0 and receipt['chunk_id'] == '5fd653' and 'session_id' not in receipt
    continuous = read(C+'continuous-session-emulation-v1-proof.json')
    assert continuous['all_passed'] and continuous['case_count'] == 3
    assert continuous['actual_compiled_repeated_FIFO_submit_read_release']
    assert continuous['scoped_session_independent_of_recycled_ticket']
    assert continuous['full_original_pull_leases_retained_to_complete_return']
    assert continuous['Stop_denies_new_submit_and_fullpull']
    assert continuous['long_case_output_consumer_is_explicit_host_fixture']
    assert not continuous['source_owner_to_native_mixer_handoff_or_exclusivity_or_STOP_DONE_or_hardware_or_phone_UI_App_verified']
    continuous_receipt = read(C+'guest-v1-terminal-tool-receipt.json')
    assert continuous_receipt['observed_session_id'] == 2103
    assert continuous_receipt['tool_result']['exit_code'] == 0
    assert continuous_receipt['tool_result']['chunk_id'] == 'c99bc2'
    assert 'session_id' not in continuous_receipt['tool_result']
    continuous_cases = [read(row['path']) for row in continuous['cases']]
    assert [len(row['full_native_pull_returns']) for row in continuous_cases] == [24,5,3]
    assert [p['ticket'] for p in continuous_cases[0]['productions']] == list(range(4,49,4))
    assert all(row['session'] == 1 and row['bootstrap_registration_ticket'] == 4 for row in continuous_cases)
    continuous_files = read(C+'continuous-session-v1-independent-file-verification.json')
    assert continuous_files['all_passed'] and continuous_files['case_count'] == 3
    assert continuous_files['exact_CPU_store_count'] == 32186
    assert continuous_files['joint_event_count'] == 32271 and continuous_files['complete_native_full_returns'] == 32
    assert continuous_files['guest_rerun'] is False and continuous_files['no_VM_import'] is True
    assert continuous_files['per_store_complete_GP_CPSR_available'] is False
    assert continuous_files['actual_source_owner_to_native_mixer_handoff_verified'] is False
    heap_meta = read(B+'runtime/terminal-metadata.json')
    assert heap_meta['session_id'] == 87914 and heap_meta['actual_exec_chunk'] == '4ab59e'
    assert heap_meta['terminal_exit_code'] == 1 and heap_meta['cold_prefix_full_guards_passed']
    correction = read(B+'gui-static/native-allocation-v1-terminal-scope-correction.json')
    assert correction['actual_native_malloc_frames'] == correction['actual_native_heap_raw_ops'] == 0
    assert correction['host_return_pointer'] == '0x88246a0'
    assert not correction['original48_or8_native_allocation_success_verified']
    assert correction['inherited_terminal_after_snapshot_missing']
    heap_v3 = read(B+'runtime-v3/terminal-metadata.json')
    assert heap_v3['session_id'] == 27241 and heap_v3['actual_exec_chunk'] == '61dabd'
    assert heap_v3['terminal_exit_code'] == 1 and heap_v3['cold_prefix_full_guards_passed']
    assert not heap_v3['body_full_guards_passed'] and not heap_v3['callback_return_seen']
    state, task, public = [read(p) for p in ('evidence/deep-research-state.json',
                          'evidence/task-state.json', 'reports/findings.json')]
    app = state['native_app_music']
    before, prior_public = read(B+'previous-state.json'), read(B+'previous-public.json')
    assert app['static_findings'] == before['native_app_music']['static_findings']
    assert len(app['static_findings']) == 185
    for key, row in manifest['findings'].items():
        assert key not in app['static_findings']
        app['static_findings'][key] = dict(evidence=row['path'], evidence_sha256=row['sha256'],
            scope=row['scope'], physical_App_or_audio_verified=False, device_io=False)
    now = datetime.now(timezone.utc)
    focus = ('Integrate actual source-owner and native mixer caller with full-return leases, '
             'reselection/reprofile/cancel/STOP_DONE and exclusive lifetime; continue original '
             'native heap/constructor work without inherited host allocation substitution. '
             'Reversible single-voice code-marker package still awaits user availability/USB. '
             'Pairing first; microphone canceled; fidelity deferred; Android Auto later; '
             'Google Maps deferred; full objective remains active/no-achieve.')
    state.update(updated_utc=now.isoformat(), current_priority='Native menu/App and music integration; active/no-achieve.')
    state['next_actions'][0] = focus
    app['remaining_work'] = state['next_actions'][:4]
    app['development_observations']['native_public_heap_v1_terminal'] = manifest['heap_terminal_scope']
    app['development_observations']['native_public_heap_next_attempt'] = manifest['next_heap_attempt']
    app['development_observations']['native_audio_full_reader_actual_two_cases'] = dict(
        proof=A+'audio-session-emulation-v2-proof.json', proof_sha256=sha(A+'audio-session-emulation-v2-proof.json'),
        terminal_chunk='5fd653', full_pull_cases=2, actual_positive_PCM_bytes=512,
        original_mixer_actor_handoff=False, native_exclusive_or_STOP_DONE=False, physical_audio=False)
    app['development_observations']['native_continuous_session_actual_three_cases'] = dict(
        proof=C+'continuous-session-emulation-v1-proof.json', proof_sha256=sha(C+'continuous-session-emulation-v1-proof.json'),
        terminal_session=2103,terminal_chunk='c99bc2',actual_cases=3,complete_original_returns=32,
        positive_batches=12,positive_PCM_bytes=6144,session_identity=1,bootstrap_ticket=4,
        per_buffer_tickets=list(range(4,49,4)),output_consumer_read_index_is_fixture=True,
        native_mixer_handoff_or_exclusive_or_STOP_DONE_or_physical_audio=False)
    state['parallel_research'].update(manifest['parallel_research'])
    state['parallel_research'].update(live_subagent_count=agent_observation['live_subagent_count'],
        active_agent_tasks=agent_observation['active_agent_tasks'],
        live_count_observed_UTC=agent_observation['observation_UTC'],
        live_count_is_time_specific_observation=True)
    state['last_goal_turn'].update(classification='progress', previous_goal_turn_classification='no_progress',
        validated_utc=now.isoformat(), focused_evidence=A+'audio-session-emulation-v2-proof.json',
        focused_evidence_sha256=sha(A+'audio-session-emulation-v2-proof.json'),
        previous_state_snapshot=B+'previous-state.json', previous_current_audit_snapshot=B+'previous-audit.json',
        terminal_heap_attempt=manifest['heap_terminal_scope'], next_heap_attempt=manifest['next_heap_attempt'],
        actual_new_audio_session_cases=2, full_original_reader_return_and_live_leases_verified=True,
        actual_PCM_bytes_verified=512, native_exclusivity=False, native_STOP_DONE_verified=False,
        actual_new_continuous_session_cases=3,actual_continuous_full_returns=32,
        actual_continuous_positive_PCM_bytes=6144,explicit_output_consumer_fixture=True,
        physical_App_or_audio_verified=False, device_io=False, device_files_written=False,
        automatic_calls_or_sound=False, goal_status='active', full_goal_complete=False, next_focus=focus)
    for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', 'parallel_research', 'attended_testing'):
        task[key] = state[key]
    public.update(updated=now.isoformat(), deep_research=state)
    progress = public['research_progress']
    assert progress['completed'] == prior_public['research_progress']['completed']
    assert len(progress['completed']) == 152
    details = manifest['public_details']
    progress['completed'].extend(details)
    progress['phases'][4]['completed'].extend(details)
    next_text = '接上真正的原廠音訊執行緒與完整生命週期，繼續原廠首頁物件建立；使用者方便時做可還原的原機程式標記測試。'
    progress.update(research_updated_utc=now.isoformat(), next=next_text)
    progress['phases'][4]['next'] = next_text
    assert progress['estimate_percent'] == 33 and progress['phases'][4]['estimate_percent'] == 20
    assert sum(p['weight']*p['estimate_percent']/100 for p in progress['phases']) == 33
    report = (ROOT/'reports/nuvi2565RT.html').read_text()
    card = '<div class="card"><h2>最新離線進展：原廠音源選取與完整音訊讀取已接通</h2>'
    card += '<p><strong>音訊路徑新增兩組真 ARM 案例：</strong>新程式產生512 bytes音訊，經原廠註冊、音源選取、準備與兩次完整讀取，輸出逐byte相符。讀取期間保留音源和callback參照，等原函式完整返回才釋放；本地停止後拒絕新的讀取。</p>'
    card += '<p>目前使用單一離線執行緒及明示的配置、mutex、喚醒與混音器條件。真正原廠播放執行緒的接線、重新選取、取消、停止完成、獨占與喇叭仍未完成；這兩組案例不當作原機音樂播放。</p>'
    card += '<p><strong>持續播放新增三组真ARM案例：</strong>固定音源session與每批FIFO ticket分開，12批音訊共6144bytes經24次完整讀取逐byte相符；缺資料時輸出靜音，補資料後續播；本地Stop拒絕新提交和讀取。三案例共32次完整返回，輸出混音ring的consumer仍是明示fixture，尚非實機連續播放。</p>'
    card += '<p>持續音訊的三案例也完成獨立純檔案核對：32186筆CPU stores與32271筆CPU／fixture共同事件逐項重建，完整返回前維持參照。每筆完整GP／CPSR快照尚未記錄，核對範圍為opcode、ISA、事件順序及實際記憶體變化。</p>'
    card += '<p><strong>首頁研究：</strong>原廠記憶體池初始化已真正返回，冷啟動畫面前綴也完整執行。前兩輪後段被舊模擬配置服務攔截；第三輪已真正進入原malloc並取得原廠鎖，隨後在未核對的記憶體page分支硬停。兩筆原生配置尚未成功返回，失敗證據已保留，接續分析實際分支條件。</p>'
    card += '<p>整體里程碑估計33%、App整合20%。可還原的Big5單檔程式標記包已準備，尚未安裝。配對即時優先、麥克風取消、音質擱置；Android Auto排後、Google Maps暫緩，完整研究目標仍持續。</p></div>'
    report, n = re.subn(r'<div class="card"><h2>最新離線進展：原廠音訊註冊已接上新元件，原機程式測試包已準備</h2>.*?</div>', lambda _:card, report, count=1, flags=re.S)
    assert n == 1
    old = prior_public['research_progress']['phases'][4]['next']
    row = '<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(old)+'</td></tr>'
    assert report.count(row) == 1
    report = report.replace(row, '<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(next_text)+'</td></tr>', 1)
    report, n = re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)', lambda m:m[1]+m[2]+''.join('<li>'+html.escape(x)+'</li>' for x in details)+m[3], report, count=1, flags=re.S)
    assert n == 1
    report, n = re.subn(r'<p><strong>下一步：</strong>.*?</p>', lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>', report, count=1)
    assert n == 1
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    iso = local.isoformat(timespec='seconds')
    for name in ('report-updated-time', 'research-updated-time'):
        report, n = re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>', '<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>', report, count=1)
        assert n == 1
    assert not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', report)
    assert 'REDACTED_PRIVATE_ID' not in report
    assert state['goal_status'] == 'active' and not state['goal_complete'] and state['required_work_remaining']
    assert not app['native_app_running'] and not app['direct_phone_music_verified']
    protected[str(Path(__file__).resolve().relative_to(ROOT))] = sha(str(Path(__file__).resolve().relative_to(ROOT)))
    protected[B+'publication-inputs.json'] = sha(B+'publication-inputs.json')
    # Every assertion about evidence and HTML substitution precedes canonical writes.
    for p, d in [('evidence/deep-research-state.json', state), ('evidence/task-state.json', task), ('reports/findings.json', public)]:
        write(p, d)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    latest = read('evidence/report-web-latest.json')
    with urllib.request.urlopen(latest['url'], timeout=10) as response:
        served, status, cache = response.read(), response.status, response.headers.get('Cache-Control', '')
    service_result = subprocess.run(['systemctl', 'show', 'garmin-report-web.service', '--property=MainPID,ActiveState,SubState,UnitFileState'], capture_output=True, text=True, check=True)
    service = dict(line.split('=', 1) for line in service_result.stdout.splitlines() if '=' in line)
    assert status == 200 and served == report.encode() and 'no-store' in cache
    assert service['MainPID'] == '357833' and service['ActiveState'] == 'active' and service['UnitFileState'] == 'enabled'
    checks = dict(old1721_sources_revalidated=True, old48_suites_preserved=True,
        original_selector_full_pull_two_cases=True, no_mixer_handoff_or_STOP_DONE_claim=True,
        first_heap_host_return_correction_preserved=True, missing_inherited_terminal_scope_visible=True,
        third_heap_actual_terminal_failure_preserved=True,
        three_continuous_cases_actual_terminal=True,session_identity_distinct_from_recycled_ticket=True,
        complete32_original_pull_returns=True,explicit_output_consumer_fixture_retained=True,
        independent_continuous32186_CPU32271_joint_events=True,
        weighted33_App20_retained=True, active_full_objective=True,
        canonical_task_public_consistent=public['deep_research']==state and task['last_goal_turn']==state['last_goal_turn'],
        two_Taiwan_timestamps=report.count('datetime="'+iso+'"')==2,
        HTTP200_no_store_exact=True, service_PID_unchanged=True, no_device_writes_or_sound=True)
    audit = dict(previous, updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=all(checks.values()),
        scope_checks=checks, previous_checkpoint=B+'previous-audit.json', protected_sources=protected,
        selected_frozen_suites=suites, native_unique_exact_dependencies=len(native_dependencies),
        selected_new_audio_session_proof=A+'audio-session-emulation-v2-proof.json',
        selected_new_continuous_session_proof=C+'continuous-session-emulation-v1-proof.json',
        current_state_sha256=sha('evidence/deep-research-state.json'), report_sha256=sha('reports/nuvi2565RT.html'),
        complete_Dispatcher_body_or_foreground_or_physical_App=False, physical_App_or_hardware_or_audio=False,
        latest_heap_scope=manifest['heap_terminal_scope'], next_heap_attempt=manifest['next_heap_attempt'])
    assert audit['all_passed']
    write(OUT, audit)
    latest.setdefault('historical_offline_checkpoint_audits', {})['prior_native_queue_package_checkpoint'] = dict(
        audit=B+'previous-audit.json', audit_sha256=sha(B+'previous-audit.json'), all_passed=True)
    latest.pop('current_native_queue_package_checkpoint', None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(), HTTP_status=status,
        served_latest_report=True, local_report_sha256=sha('reports/nuvi2565RT.html'),
        served_report_sha256=hashlib.sha256(served).hexdigest(), report_bytes=len(served), service=service,
        service_not_restarted=True, cache_control=cache, current_native_public_heap_audio_checkpoint=OUT,
        checkpoint_sha256={OUT:sha(OUT)}, goal_status='active', full_goal_complete=False)
    latest['complete_current_offline_run'].update(protected_source_count=len(protected),
        native_frozen_suites_revalidated=len(suites), actual_native_audio_session_new_cases=2,
        actual_native_continuous_session_new_cases=3,
        physical_App_verified=False, device_io=False, sounds_emitted=False)
    latest['progress_display_verified'].update(estimate_percent=33, completed_items=len(progress['completed']),
        report_updated_time=iso, research_updated_time=iso, visual_browser_render_not_performed=True)
    write('evidence/report-web-latest.json', latest)
    print(json.dumps(dict(all_passed=True, findings=len(app['static_findings']), details=len(progress['completed']),
        protected_sources=len(protected), frozen_native_suites=len(suites), native_unique_integrity_dependencies=len(native_dependencies),
        updated_Taiwan=iso, HTTP_status=status, report_bytes=len(served))))


if __name__ == '__main__':
    main()
