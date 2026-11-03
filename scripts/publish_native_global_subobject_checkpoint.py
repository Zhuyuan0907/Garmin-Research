#!/usr/bin/env python3
"""Publish native-owner scheduling and bounded GUI progress without App claims."""
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
import hashlib
import html
import json
import re
import subprocess
import urllib.request
from publish_native_settings_scope_checkpoint_v2 import ROOT, read, sha, registry, write

BASE = 'staging/native-player-global-subobject/'
RUNTIME = BASE + 'runtime-v2/'
PREFIX = 'evidence/firmware-analysis/native-global-subobject-v2-cold-prefix-emulation.json'
DOCS = {
    'native_global_subobject_v2_caller_stack_contract': BASE + 'gui-static/global-subobject-observer-v2-contract.json',
    'native_global_subobject_complete_cold_prefix': PREFIX,
    'native_global_first_store_and_original_caller_stack': BASE + 'global-object-observed-prefix.json',
    'native_global_partial_journals_and_initialized_bank': RUNTIME + 'independent-partial-journals.json',
    'native_persistent_source_owner_kernel_scheduling': BASE + 'music-native/verification.json',
    'native_global_next_inline_field_setter_contract': BASE + 'gui-static/next-sfs-inline-setter/next-sfs-inline-setter-contract-v2.json',
    'native_cached_version_runtime_code_marker_contract': BASE + 'package-marker/runtime-cache-code-marker-contract.json',
}
AUX = [BASE + 'music-native/GUI-peer-review.json', BASE + 'root-v2-static-peer-review.json',
       'staging/native-player-settings-scope/package-static/passive-code-marker/passive-code-marker-visible-caller-contract.json']


def evidence_sources(doc):
    sources = doc['source_sha256']
    if isinstance(sources, str):
        return {doc['source']: sources}
    return sources


def main():
    before = read(BASE + 'previous-state.json')
    prior = read(BASE + 'previous-public.json')
    previous = read(BASE + 'previous-audit.json')
    assert previous['all_passed'] and len(previous['protected_sources']) == 1274
    protected, native_deps = {}, {}
    registry(previous['protected_sources'], protected)
    for row in read(BASE + 'previous-checkpoint.json')['snapshots']:
        assert sha(row['snapshot']) == row['sha256']
    suites = list(previous['selected_frozen_suites'])
    assert len(suites) == 45
    for suite in suites:
        assert sha(suite['path']) == suite['sha256']
        doc = read(suite['path'])
        assert doc['all_passed'] and all(case['passed'] for case in doc['cases'])
        registry(doc['source_sha256'], native_deps)
    assert len(native_deps) == 1083
    docs = {path: read(path) for path in [*DOCS.values(), *AUX]}
    for path, doc in docs.items():
        registry(evidence_sources(doc), protected)
        for key in ('artifacts_sha256', 'verified_runtime_dependencies', 'dependency_sha256'):
            if key in doc:
                registry(doc[key], protected)
        protected[path] = sha(path)
    meta = read(RUNTIME + 'terminal-metadata.json')
    probe = read(meta['probe'])
    receipt = read(meta['terminal_tool_receipt'])
    registry(meta['source_sha256'], protected)
    for key in ('runner', 'runner_snapshot', 'inputs', 'probe', 'FP_helper', 'GUI_observer', 'sealer', 'cold_prefix', 'terminal_tool_receipt'):
        assert sha(meta[key]) == meta[key + '_sha256']
    assert meta['session_id'] == receipt['session_id'] == 30399
    assert meta['terminal_exit_code'] == receipt['actual_exec_result']['exit_code'] == 1
    assert receipt['actual_exec_result']['chunk_id'] == '6ed1b9' and 'session_id' not in receipt['actual_exec_result']
    assert meta['cold_prefix_full_guards_passed'] and not meta['body_full_guards_passed']
    assert probe['callback_entry_seen'] and not probe['callback_return_seen']
    prefix = docs[PREFIX]
    partial = docs[DOCS['native_global_partial_journals_and_initialized_bank']]
    observed = docs[DOCS['native_global_first_store_and_original_caller_stack']]
    kernel = docs[DOCS['native_persistent_source_owner_kernel_scheduling']]
    marker = docs[DOCS['native_cached_version_runtime_code_marker_contract']]
    assert all(doc['all_passed'] for doc in (prefix, partial, observed, kernel, marker))
    assert observed['actual_global_stores'] == 1 and observed['settings_raw_operations'] == 0
    assert observed['next_unreviewed_writer'] == '0x44f76d0' and observed['next_target'] == '0x3aaf81c'
    assert not observed['constructor_return_verified']
    assert partial['independent_file_only_bank_replay_verified']
    assert kernel['native_kernel_group_count'] == 7 and kernel['native_instances'] == 2
    assert all(case['passed'] for case in kernel['native_kernel_groups'])
    assert kernel['actual_tool_receipt']['exit_code'] == 0 and kernel['actual_tool_receipt']['chunk_id'] == '5f5dd2'
    assert kernel['CPU_store_events_replayed'] == 1803 and kernel['explicit_fixture_mutations_replayed'] == 16
    assert not marker['actual_modified_code_or_marker_execution_verified']
    assert not marker['physical_package_acceptance_verified']
    registry(prefix['source_sha256'], native_deps)
    suites.append(dict(path=PREFIX, sha256=sha(PREFIX), case_count=1,
        scope='Complete cold component prefix; later global constructor/body stopped at unreviewed copied field setter.'))
    state, task, public = [read(path) for path in ('evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json')]
    app = state['native_app_music']
    assert app['static_findings'] == before['native_app_music']['static_findings'] and len(app['static_findings']) == 151
    assert public['research_progress']['completed'] == prior['research_progress']['completed']
    for name, path in DOCS.items():
        app['static_findings'][name] = dict(evidence=path, evidence_sha256=sha(path),
            physical_App_or_direct_phone_music_verified=False, device_io=False, sounds_emitted=False)
    app['static_findings']['native_persistent_source_owner_kernel_scheduling'].update(
        native_kernel_groups=7, native_source_loop_scheduled_in_declared_fixture=True,
        native_priority_preemption_observed=True, adapter_missing_returns_minus100=True,
        producer_busy_and_release_are_declared_RAM_fixture=True, STOP_DONE_or_audio_verified=False)
    app['development_observations']['latest_global_subobject_attempt'] = dict(
        session_id=30399, actual_terminal_exit_code=1, actual_terminal_chunk='6ed1b9',
        full_cold_prefix_passed=True, global_object_stores_observed=1, settings_raw_ops_observed=0,
        constructor_returned=False, callback_returned=False, body_fullguards=False,
        next_writer='0x44f76d0', target='0x3aaf81c', evidence=meta['probe'], evidence_sha256=sha(meta['probe']))
    app['source_owner_kernel_scope'] = dict(verified_in_declared_controller_idle_and_audio_record_fixture=True,
        evidence=DOCS['native_persistent_source_owner_kernel_scheduling'], native_kernel_groups=7,
        physical_navigation_multitasking_or_audio_or_App_verified=False)
    next_focus = ('NEW subclass for exact copied44F76CE→44F76D8 zero9-byte leaf through original462FA4 veneer, '
        'two26DD00/26DD08 calls atBASE+B14/B20 and six stores; both entry/returnR1 remainsB14. '
        'Preserve all native caller/actor/whole-page histories, then finish SFS/settings/global/base/derived '
        'returns and separate362A2C container. Actual30399 has only1of3 global stores and zero settings raw/default/memzero completions. '
        'Source-owner scheduling now verified in a bounded original-kernel fixture; exclusive/session/admission/lease '
        'and realDSP cancel/STOP_DONE/audio remain missing. Prepare a pure bounded preserving Big5 entry '
        'runtime-cache marker control with original40 API/metadata/forwarding retained; no physical candidate '
        'until actualCPUstores→getter/selection identity/lifetime is proven. SIG/physical acceptance unknown. '
        'Pairing first; mic canceled; fidelity deferred; AA later; Maps deferred; active/no-achieve.')
    now = datetime.now(timezone.utc)
    state.update(updated_utc=now.isoformat(), current_priority='Foreground player, actual audio session binding and observable native code acceptance; active/no-achieve.')
    state['next_actions'][0] = next_focus
    state['next_actions'][1] = 'Connect exclusive/session admission and lease to the natively scheduled persistent source owner; fixture scheduling is not real DSP or audio playback.'
    app['remaining_work'] = state['next_actions'][:4]
    state['parallel_research'].update(tasks=['global caller-stack and exact inline-field setter', 'persistent source-owner original-kernel scheduling', 'runtime cached-version code marker identity'],
        continued_round_completed=True, agents_currently_running=False)
    state['last_goal_turn'].update(classification='progress', validated_utc=now.isoformat(),
        previous_state_snapshot=BASE + 'previous-state.json', previous_current_audit_snapshot=BASE + 'previous-audit.json',
        focused_evidence=DOCS['native_persistent_source_owner_kernel_scheduling'],
        focused_evidence_sha256=sha(DOCS['native_persistent_source_owner_kernel_scheduling']),
        latest_dispatcher_development_evidence=meta['probe'], latest_dispatcher_development_evidence_sha256=sha(meta['probe']),
        latest_dispatcher_runtime_session_id=30399, latest_dispatcher_terminal_exit_code=1,
        latest_dispatcher_run_full_scoped_final_guards_passed=False, latest_callback_body_returned=False,
        latest_cold_prefix_full_scoped_guards_passed=True, latest_settings_raw_operations_observed=0,
        native_settings_default_branch_executed_in_latest_run=False, observed_global_object_stores=1,
        native_owner_loop_scheduled_or_STOP_DONE_verified=True,
        native_owner_loop_scheduled_in_declared_kernel_fixture=True, native_STOP_DONE_verified=False,
        physical_audio_or_native_App_verified=False, device_io=False, device_files_written=False,
        automatic_calls_or_sound=False, native_firmware_or_research_package_written=False,
        next_focus=next_focus, goal_status='active', full_goal_complete=False,
        reasons=['Original kernel and frozen compiled persistent-owner loop execute, including durable events and real preemption.',
            'Actual30399 passed cold prefix and first original global store; next copied-field boundary captured.',
            'Runtime-only visible cache marker identity and selection order mapped; no marker payload or physical acceptance claimed.'])
    for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', 'parallel_research'):
        task[key] = state[key]
    public.update(updated=now.isoformat(), deep_research=state)
    progress = public['research_progress']
    details = [
        '新增播放工作程序已在離線環境由原廠核心真正建立、喚醒、切換與恢復；七組有界原生排程案例通過，包含較高優先序程序搶占後繼續。音訊介面未綁定時仍正確拒絕，沒有實機聲音或播放完成宣告。',
        '播放器取消流程實際執行了編譯的返回與旗標清理順序；兩個原生工作配置共十六個完整記憶體區域獨立重建。忙碌與釋放條件是明示測試輸入，尚未驗證真 DSP 取消、音訊獨占或停止完成。',
        '首頁試跑完成全部十一個準備步驟；原廠全域物件的第一筆 vtable 寫入與兩次初始化旗標轉換已走過。接著在未涵蓋的原廠欄位清零停止；只觀察到三筆物件寫入中的第一筆，尚未走到設定鎖、建構返回或前景顯示。',
        '已從真正的原指令與完整堆疊紀錄確認首頁函式參數是八位元組的呼叫者堆疊資料；原未執行草稿誤認成 heap 的假設已排除。新原生試跑的七個介面、八個浮點、二十二個既有區域及完整系統資料獨立核對。',
        '下一個欄位清零缺口已縮小為五條原廠指令、兩次呼叫與六筆精確寫入；第二次呼叫的參數來源修正另行保存，尚未新增放行或重跑原機。',
        '定位既有 Aud Ver 的版本顯示來源與語音選取順序；可研究讓新程式執行後只在 RAM 留五字標記，保留磁碟版本資料。仍須證明本次載入身分、原生寫入與顯示路徑，目前沒有標記程式包或實機接受結果。',
    ]
    progress['completed'].extend(details)
    progress['phases'][1]['completed'].append(details[0])
    progress['phases'][4]['completed'].extend(details[2:4])
    progress.update(research_updated_utc=now.isoformat(), next='補齊原廠欄位初始化及前景介面，接上真實音訊工作階段；準備可由既有版本頁確認執行的程式標記測試。')
    progress['phases'][4]['next'] = progress['next']
    assert len(app['static_findings']) == 158 and len(progress['completed']) == 129
    assert progress['estimate_percent'] == 33 and progress['phases'][4]['estimate_percent'] == 20
    assert sum(p['weight'] * p['estimate_percent'] / 100 for p in progress['phases']) == 33
    report = (ROOT / 'reports/nuvi2565RT.html').read_text()
    card = '<div class="card"><h2>最新離線進展：播放器通過原廠核心排程，實機執行標記方案已定位</h2><p><strong>播放工作程序已有原生排程證據：</strong>原廠核心真正建立、喚醒、切換與恢復編譯的持續播放程序；七組案例通過，包含較高優先序搶占。音訊介面、獨占與工作階段尚未綁定；取消條件是明示測試輸入，未證明實機發聲或停止完成。</p><p><strong>首頁試跑繼續前進：</strong>全部十一個準備步驟通過，第一筆全域物件寫入與兩次初始化旗標轉換已執行；接著在另一段原廠欄位清零停止。尚未完成物件建構返回、設定讀取、首頁前景或觸控。</p><p>定位可研究的實機程式執行證據：保留原磁碟版本資料，由新程式在 RAM 留短標記，再從既有 Aud Ver 查看。這仍是靜態方案，尚未產生標記程式包或驗證原機接受。</p><p><strong>尚未有可安裝的 App，手機直接連 Garmin 播音樂仍待驗證。</strong>整體里程碑估計33%，App整合20%；百分比是研究估計。目前沒有新的實機操作需求。現場配對立即優先；麥克風取消、音質擱置，Android Auto排後，Google Maps暫緩。</p></div>'
    report, count = re.subn(r'<div class="card"><h2>最新離線進展：播放器啟停工作程序已接線，原機磁碟資料已核對</h2>.*?</div>', lambda _: card, report, count=1, flags=re.S)
    assert count == 1
    old_next = prior['research_progress']['phases'][4]['next']
    old_row = '<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>' + html.escape(old_next) + '</td></tr>'
    assert report.count(old_row) == 1
    report = report.replace(old_row, '<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>' + html.escape(progress['next']) + '</td></tr>', 1)
    report, count = re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)', lambda m: m[1] + m[2] + ''.join('<li>' + html.escape(x) + '</li>' for x in details) + m[3], report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'<p><strong>下一步：</strong>.*?</p>', lambda _: '<p><strong>下一步：</strong>' + html.escape(progress['next']) + ' 目前沒有新的實機操作需求。</p>', report, count=1)
    assert count == 1
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    iso = local.isoformat(timespec='seconds')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>', '<time id="' + name + '" datetime="' + iso + '">' + local.strftime('%Y/%m/%d %H:%M:%S') + '</time>', report, count=1)
        assert count == 1
    assert not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', report) and 'REDACTED_PRIVATE_ID' not in report
    for path, doc in (('evidence/deep-research-state.json', state), ('evidence/task-state.json', task), ('reports/findings.json', public)):
        write(path, doc)
    (ROOT / 'reports/nuvi2565RT.html').write_text(report)
    latest = read('evidence/report-web-latest.json')
    with urllib.request.urlopen(latest['url'], timeout=10) as response:
        served, status, cache = response.read(), response.status, response.headers.get('Cache-Control', '')
    result = subprocess.run(['systemctl', 'show', 'garmin-report-web.service', '--property=MainPID,ActiveState,SubState,UnitFileState'], capture_output=True, text=True, check=True)
    service = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    assert status == 200 and served == report.encode() and 'no-store' in cache
    assert service['MainPID'] == '357833' and service['ActiveState'] == 'active' and service['UnitFileState'] == 'enabled'
    assert report.count('datetime="' + iso + '"') == 2 and 'value="33"' in report
    assert public['deep_research'] == state and task['last_goal_turn'] == state['last_goal_turn']
    assert state['goal_status'] == 'active' and state['required_work_remaining'] and not state['goal_complete']
    assert not app['native_app_running'] and not app['direct_phone_music_verified']
    for path in (ROOT / BASE).rglob('*'):
        if path.is_file() and '__pycache__' not in path.parts:
            name = str(path.relative_to(ROOT))
            protected[name] = sha(name)
    sources = ['scripts/probe_native_dispatcher_global_subobject.py', 'scripts/probe_native_dispatcher_global_subobject_v2.py',
               'scripts/seal_native_global_subobject_attempt.py', 'scripts/seal_native_global_subobject_attempt_v2.py',
               'scripts/verify_native_global_subobject_cold_prefix.py', 'scripts/verify_native_global_subobject_v2_cold_prefix.py',
               'scripts/verify_native_global_subobject_partial_journals.py', 'scripts/verify_native_global_subobject_v2_partial_journals.py',
               'scripts/verify_native_global_subobject_prefix.py', 'scripts/publish_native_global_subobject_checkpoint.py',
               PREFIX, 'evidence/firmware-analysis/native-settings-scope-checkpoint-audit.json']
    for path in sources:
        protected[path] = sha(path)
    out = 'evidence/firmware-analysis/native-global-subobject-checkpoint-audit.json'
    checks = dict(prior1274_protected_hashes=True, prior45_complete_suites=True,
        evidence_hashes=True, actual30399_exit1_receipt=True, complete_cold_prefix=True,
        only_one_global_store_not_constructor_closure=True, settings_raw_default_memzero_absent=True,
        original_caller_stack_input_independently_replayed=True, partial_7_8_22_and_bank_replayed=True,
        seven_bounded_source_owner_kernel_groups=True, fixture_cancel_separate_from_STOP_DONE=True,
        no_physical_marker_execution_claim=True, previous151_findings_and123_details_retained=True,
        weighted33_App20=True, canonical_task_public_consistent=True, goal_active_remaining=True,
        physical_App_direct_phone_audio_false=True, served_exact_HTML200_no_store=True,
        existing_service_enabled_PID_unchanged=True, two_Taiwan_timestamps=True, public_HTML_no_unit_ESN_MAC=True)
    audit = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=all(checks.values()), scope_checks=checks,
        previous_checkpoint=BASE + 'previous-audit.json', selected_frozen_suites=suites,
        native_unique_exact_dependencies=len(native_deps), protected_sources=protected,
        selected_original_fragment_suites=previous['selected_original_fragment_suites'],
        selected_native_partial_exchange_proofs=previous['selected_native_partial_exchange_proofs'],
        selected_partial_decoder_proofs=previous['selected_partial_decoder_proofs'],
        selected_partial_settings_journal_proofs=previous['selected_partial_settings_journal_proofs'],
        selected_partial_global_proofs=[dict(path=DOCS['native_global_first_store_and_original_caller_stack'], sha256=sha(DOCS['native_global_first_store_and_original_caller_stack']), stores=1, constructor_returned=False)],
        selected_native_source_owner_kernel_proofs=[dict(path=DOCS['native_persistent_source_owner_kernel_scheduling'], sha256=sha(DOCS['native_persistent_source_owner_kernel_scheduling']), groups=7, native_instances=2, original_kernel_fixture=True, real_audio=False)],
        selected_full_linked_image_controls=previous['selected_full_linked_image_controls'],
        original_guest_session=30399, original_guest_terminal_exit_code=1, original_cold_prefix_complete=True,
        current_state_sha256=sha('evidence/deep-research-state.json'), report_sha256=sha('reports/nuvi2565RT.html'),
        complete_Dispatcher_body_or_foreground_or_physical_App=False)
    write(out, audit)
    latest['historical_offline_checkpoint_audits']['prior_native_settings_scope_checkpoint'] = dict(audit=BASE + 'previous-audit.json', audit_sha256=sha(BASE + 'previous-audit.json'), state_snapshot=BASE + 'previous-state.json', state_snapshot_sha256=sha(BASE + 'previous-state.json'), all_passed=True)
    latest.pop('current_native_settings_scope_checkpoint', None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(), HTTP_status=status, served_latest_report=True,
        local_report_sha256=sha('reports/nuvi2565RT.html'), served_report_sha256=hashlib.sha256(served).hexdigest(),
        report_bytes=len(served), service=service, service_not_restarted=True, cache_control=cache,
        current_native_global_subobject_checkpoint=out, checkpoint_sha256={out: sha(out)}, goal_status='active',
        full_goal_complete=False, current_physical_test_requested=False)
    latest['complete_current_offline_run'] = dict(checkpoint_all_scope_checks_passed=True,
        native_frozen_suites_revalidated=len(suites), native_unique_exact_dependencies=len(native_deps),
        original_fragment_controls=5, partial_native_exchange_proofs=1, partial_decoder_query_proofs=1,
        partial_settings_journal_proofs=1, partial_global_object_proofs=1, native_source_owner_kernel_groups=7,
        independent_bank_bytes=467532, global_object_stores=1, settings_raw_operations=0,
        protected_source_count=len(protected), latest_body_terminal_exit_code=1,
        cold_prefix_all_guards_passed=True, physical_App_verified=False, device_io=False, sounds_emitted=False)
    latest['progress_display_verified'].update(estimate_percent=33, completed_items=129,
        report_updated_time=iso, research_updated_time=iso, visual_browser_render_not_performed=True,
        current_success_and_body_failure_separated_visible=True)
    write('evidence/report-web-latest.json', latest)
    print(json.dumps(dict(all_passed=True, findings=158, completed_items=129, scope_checks=len(checks),
        native_suites=len(suites), native_deps=len(native_deps), source_owner_kernel_groups=7,
        protected_sources=len(protected), updated_Taiwan=iso, HTTP_status=status, report_bytes=len(served), url=latest['url'])))


if __name__ == '__main__':
    main()
