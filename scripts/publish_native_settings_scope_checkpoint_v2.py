#!/usr/bin/env python3
"""Publish actual terminal scope, native owner prototype and FAT input evidence."""
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo
import hashlib
import html
import json
import re
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BASE = 'staging/native-player-settings-scope/'
RUNTIME = BASE + 'runtime/'
PREFIX = 'evidence/firmware-analysis/native-settings-cold-prefix-emulation.json'
DOCS = {
    'native_Dispatcher_settings_actor_and_bounded_page_contract': BASE + 'gui-static/settings-actor-observer-contract.json',
    'native_settings_scope_complete_cold_prefix': PREFIX,
    'native_settings_scope_partial_histories_and_bank': RUNTIME + 'independent-partial-journals.json',
    'native_music_persistent_source_worker_owner_image': BASE + 'music-owner/verification.json',
    'native_outer_VPM_completion_and_raw_FAT_input': BASE + 'package-static/native-outer-VPM-completion-and-FAT-contract.json',
}
AUX = [BASE + 'gui-static/settings-global-subobject-next-writer-contract.json',
       BASE + 'music-owner/GUI-peer/settings-actor-wiring-review.json']


def read(path):
    return json.loads((ROOT / path).read_text())


@lru_cache(None)
def sha(path):
    digest = hashlib.sha256()
    with (ROOT / path).open('rb') as handle:
        while chunk := handle.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def registry(entries, target):
    for path, digest in entries.items():
        assert sha(path) == digest, path
        assert path not in target or target[path] == digest, path
        target[path] = digest


def write(path, value):
    (ROOT / path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def main():
    previous = read(BASE + 'previous-audit.json')
    before = read(BASE + 'previous-state.json')
    prior_public = read(BASE + 'previous-public.json')
    protected, native_deps = {}, {}
    for row in read(BASE + 'previous-checkpoint.json')['snapshots']:
        assert sha(row['snapshot']) == row['sha256']
    registry(previous['protected_sources'], protected)
    assert previous['all_passed'] and len(protected) == 1078
    suites = list(previous['selected_frozen_suites'])
    assert len(suites) == 44
    for suite in suites:
        assert sha(suite['path']) == suite['sha256']
        doc = read(suite['path'])
        assert doc['all_passed'] and all(case['passed'] for case in doc['cases'])
        registry(doc['source_sha256'], native_deps)
    assert len(native_deps) == 896
    docs = {path: read(path) for path in [*DOCS.values(), *AUX]}
    for path, doc in docs.items():
        sources = doc['source_sha256']
        if isinstance(sources, str):
            sources = {doc['observer_source']: sources}
        registry(sources, protected)
        for key in ('artifacts_sha256', 'verified_runtime_dependencies', 'dependency_sha256'):
            if key in doc:
                registry(doc[key], protected)
        protected[path] = sha(path)
    meta = read(RUNTIME + 'terminal-metadata.json')
    probe = read(meta['probe'])
    receipt = read(RUNTIME + 'terminal-tool-receipt.json')
    registry(meta['source_sha256'], protected)
    for key in ('runner', 'runner_snapshot', 'inputs', 'probe', 'GUI_observer', 'FP_helper', 'sealer', 'cold_prefix', 'terminal_tool_receipt'):
        assert sha(meta[key]) == meta[key + '_sha256'], key
    assert meta['session_id'] == receipt['session_id'] == 39489
    assert meta['terminal_exit_code'] == receipt['actual_exec_result']['exit_code'] == 1
    assert receipt['actual_exec_result']['chunk_id'] == '4446d3'
    assert 'session_id' not in receipt['actual_exec_result']
    prefix = docs[PREFIX]
    partial = docs[DOCS['native_settings_scope_partial_histories_and_bank']]
    owner = docs[DOCS['native_music_persistent_source_worker_owner_image']]
    fat = docs[DOCS['native_outer_VPM_completion_and_raw_FAT_input']]
    settings = probe['body_actor_observations']['settings_actor_observer']
    assert prefix['all_passed'] and partial['all_passed'] and owner['all_passed'] and fat['all_passed']
    assert meta['cold_prefix_full_guards_passed'] and not meta['body_full_guards_passed']
    assert probe['callback_entry_seen'] and not probe['callback_return_seen']
    assert not settings['raw_ops'] and not settings['defaults'] and not settings['zero_calls']
    assert probe['registers']['pc'] == '0x26de42'
    assert settings['unknown_boundaries'][0]['actual_target'] == '0x3aaf844'
    assert partial['independent_file_only_bank_replay_verified']
    assert len(partial['body_whole_zone_replays']) == 7 and len(partial['FP_whole_zone_replays']) == 8
    assert len(partial['inherited_whole_zone_replays']) == 22
    assert owner['new_owner_HOST_controls']['group_count'] == 7 and owner['host_tests']['group_count'] == 8
    assert owner['bounded_ARM_controls']['count'] == 11 and not owner['actual_ARM_ELF']['undefined_symbols']
    assert not owner['limits']['native_owner_loop_scheduled_or_nativeSTOP_DONE_proven']
    assert not fat['new_guest_or_emulator_executed'] and not fat['physical_changed_code_acceptance_verified']
    gui_contract = docs[DOCS['native_Dispatcher_settings_actor_and_bounded_page_contract']]
    assert gui_contract['pure_host_controls_passed']
    assert not gui_contract['guest_execution'] and not gui_contract['VM_instantiation']
    for item in previous['selected_original_fragment_suites']:
        assert sha(item['path']) == item['sha256']
        fragment = read(item['path'])
        assert fragment['all_passed'] and len(fragment['cases']) == item['case_count']
        assert all(case['passed'] for case in fragment['cases'])
        registry(fragment['source_sha256'], protected)
    registry(prefix['source_sha256'], native_deps)
    suites.append(dict(path=PREFIX, sha256=sha(PREFIX), case_count=1,
        scope='Complete cold component prefix; later body stopped at newly observed26DE42 global-subobject store.'))
    state, task, public = [read(path) for path in ('evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json')]
    app = state['native_app_music']
    assert app['static_findings'] == before['native_app_music']['static_findings']
    assert len(app['static_findings']) == 146
    assert public['research_progress']['completed'] == prior_public['research_progress']['completed']
    for name, path in DOCS.items():
        app['static_findings'][name] = dict(evidence=path, evidence_sha256=sha(path),
            fullbody_foreground_or_physical_App_verified=False, device_io=False, sounds_emitted=False)
    app['static_findings']['native_settings_scope_partial_histories_and_bank'].update(
        session_id=39489, actual_terminal_exit_code=1, settings_raw_operations_observed=0,
        previous_unjournaled_page_writer_now_captured=True, stop_PC='0x26de42', target='0x3aaf844',
        independent_bank_before_bytes_present=True, next_writer_contract=AUX[0], next_writer_contract_sha256=sha(AUX[0]))
    app['static_findings']['native_music_persistent_source_worker_owner_image'].update(
        total_HOST_groups=15, cold_loader_bounded_assertions=11, native_source_loop_scheduled=False,
        native_exclusive_session_admission_and_lease_missing=True, physical_install_candidate=False)
    app['development_observations']['latest_settings_scope_attempt'] = app['static_findings']['native_settings_scope_partial_histories_and_bank']
    now = datetime.now(timezone.utc)
    next_focus = ('Recover actual global subobject114612→11EAB2→26DE3C at3AAF844: original vtables C035F8/C12D50 '
        'and native26DE6C base-link store, then separate362A2C container scope. NEW source/subclass only. '
        'Latest39489 observes an earlier previously unjournaled wholepage writer; no newsettings lock/default success. '
        'Still require complete callback/foreground/touch, actual source-worker kernel scheduling, channel8 '
        'exclusive/session/admission/lease, native changed-package signature and physical acceptance. '
        'Recover original readonlyFAT path/alias and a genuinely code-executed passive voice marker. '
        'Pairing first; mic canceled; fidelity deferred; AndroidAuto later; Maps deferred; goalactive/no-achieve.')
    state.update(updated_utc=now.isoformat(), current_priority='Foreground player, real source-owner/session integration and physical changed-code acceptance; active/no-achieve.')
    state['next_actions'][0] = next_focus
    state['next_actions'][1] = 'Integrate and natively schedule the persistent source-owner image; exclusive/session witness still missing. Do not count15 HOST groups as native audio success.'
    app['remaining_work'] = state['next_actions'][:4]
    state['parallel_research'].update(tasks=['original global-subobject/page lifetime', 'native persistent source-owner and session integration', 'raw FAT and passive changed-code marker'], continued_round_completed=False, agents_currently_running=True)
    state['last_goal_turn'].update(classification='progress', validated_utc=now.isoformat(),
        previous_state_snapshot=BASE + 'previous-state.json', previous_current_audit_snapshot=BASE + 'previous-audit.json',
        focused_evidence=PREFIX, focused_evidence_sha256=sha(PREFIX),
        latest_dispatcher_development_evidence=meta['probe'], latest_dispatcher_development_evidence_sha256=sha(meta['probe']),
        latest_dispatcher_runtime_session_id=39489, latest_dispatcher_terminal_exit_code=1,
        latest_dispatcher_run_full_scoped_final_guards_passed=False, latest_callback_body_returned=False,
        latest_cold_prefix_full_scoped_guards_passed=True, complete_native_Dispatcher_FP_integration_verified=False,
        native_foreground_or_multiowner_FP_verified=False, latest_settings_raw_operations_observed=0,
        native_settings_default_branch_executed_in_latest_run=False, independent_initialized_bank_replay_verified=True,
        new_music_control_prototype=DOCS['native_music_persistent_source_worker_owner_image'],
        new_music_control_prototype_sha256=sha(DOCS['native_music_persistent_source_worker_owner_image']),
        native_owner_loop_scheduled_or_STOP_DONE_verified=False, device_io=False, device_files_written=False,
        automatic_calls_or_sound=False, native_firmware_or_research_package_written=False,
        next_focus=next_focus, goal_status='active', full_goal_complete=False,
        reasons=['Native source-owner/control/returned-cancel glue implemented and fresh ARM image verified within bounded scopes.',
            'Actual39489 complete cold prefix passed; newly observed whole-page vtable boundary stopped before settings query.',
            'Complete initial bank bytes now independently replayed; raw FAT voice identities/alias mismatch recovered.'])
    for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', 'parallel_research'):
        task[key] = state[key]
    public.update(updated=now.isoformat(), deep_research=state)
    progress = public['research_progress']
    details = [
        '播放器控制事件已接入新的原廠音訊工作程序骨架，保留原事件及取消返回後的清理順序；整體 ARM 映像編譯通過，十五組主機控制與十一項有界載入檢查通過。尚未由原生核心排程或播放音訊。',
        '新版選單模擬再次完成冷啟動與十一個準備步驟；新增整頁記憶體觀察後，在先前未完整記錄的全域物件初始化寫入處停止。這次尚未走到設定鎖，沒有把停止算作首頁或 App 成功。',
        '七個選單記憶體區域、八個浮點區域及二十二個既有區域獨立核對；現在保存完整初始資料，467,532 位元組系統資料區也可獨立重建。文字指令註解的空格差異造成的驗證器失敗另行保存，未重跑車機或原模擬程序。',
        '原機 FAT32 磁碟備份中三個語音檔的分散磁簇內容，與讀出的備份檔逐 byte 相符；實際檔案在 /Voice，既有模擬的 /Garmin/Voice 路徑仍需還原原廠對應，不能當成原生載入已完成。',
        '下一步補全原廠全域物件建立與前景介面，接入真正的音訊獨占／播放工作階段；同時找出可由現有介面確認修改程式確實執行的方法。實機 App、手機直接藍牙播放及修改程式包接受仍待驗證。',
    ]
    progress['completed'].extend(details)
    progress['phases'][4]['completed'].append(details[0])
    progress.update(research_updated_utc=now.isoformat(), next='完成原廠物件建立與前景介面，補上播放器原生排程及音訊資源；驗證原機磁碟路徑與修改程式實際執行。')
    progress['phases'][4]['next'] = progress['next']
    assert len(app['static_findings']) == 151 and len(progress['completed']) == 123
    assert progress['estimate_percent'] == 33 and progress['phases'][4]['estimate_percent'] == 20
    assert sum(phase['weight'] * phase['estimate_percent'] / 100 for phase in progress['phases']) == 33
    card = '<div class="card"><h2>最新離線進展：播放器啟停工作程序已接線，原機磁碟資料已核對</h2><p><strong>播放器的新整合映像已編譯完成：</strong>啟停控制、原事件保留與取消返回後的清理已接線；十五組主機控制與十一項有界載入檢查通過。尚需原生排程、音訊獨占／播放工作階段與介面接入。</p><p><strong>完整選單試跑已結束：</strong>冷啟動及十一個準備步驟通過；新增整頁觀察捕捉到先前未完整記錄的物件初始化寫入，因此在這個新範圍停止。這次尚未走到設定鎖，沒有首頁完成或前景顯示成功。</p><p>完整初始系統資料已保存並獨立重建。原機磁碟中三個語音檔的內容一致，但實際 /Voice 路徑與既有模擬的對應仍待還原。<strong>尚未有可安裝的 App，手機直接連 Garmin 播音樂與修改程式包接受仍待驗證。</strong></p><p>整體里程碑估計維持 33%，App 整合約 20%；百分比是研究估計。目前沒有新的實機操作需求。現場配對立即優先；麥克風取消、音質精修擱置，Android Auto 排後，Google Maps 暫緩。</p></div>'
    report = (ROOT / 'reports/nuvi2565RT.html').read_text()
    old_phase_next = prior_public['research_progress']['phases'][4]['next']
    phase_row = '<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>' + html.escape(old_phase_next) + '</td></tr>'
    assert report.count(phase_row) == 1
    replacement = '<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>' + html.escape(progress['phases'][4]['next']) + '</td></tr>'
    report = report.replace(phase_row, replacement, 1)
    report, count = re.subn(r'<div class="card"><h2>最新離線進展：播放器整體編譯完成，首頁建立流程前進</h2>.*?</div>', lambda _: card, report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)', lambda m: m[1] + m[2] + ''.join('<li>' + html.escape(x) + '</li>' for x in details) + m[3], report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'<p><strong>下一步：</strong>.*?</p>', lambda _: '<p><strong>下一步：</strong>' + html.escape(progress['next']) + ' 目前沒有新的實機操作需求。</p>', report, count=1)
    assert count == 1
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    iso = local.isoformat(timespec='seconds')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>', '<time id="' + name + '" datetime="' + iso + '">' + local.strftime('%Y/%m/%d %H:%M:%S') + '</time>', report, count=1)
        assert count == 1
    for path, doc in (('evidence/deep-research-state.json', state), ('evidence/task-state.json', task), ('reports/findings.json', public)):
        write(path, doc)
    (ROOT / 'reports/nuvi2565RT.html').write_text(report)
    verify_publication(previous, protected, native_deps, suites, state, task, public, report.encode(), iso)


def verify_publication(previous, protected, native_deps, suites, state, task, public, report_bytes, iso):
    latest = read('evidence/report-web-latest.json')
    with urllib.request.urlopen(latest['url'], timeout=10) as response:
        served, status, cache = response.read(), response.status, response.headers.get('Cache-Control', '')
    result = subprocess.run(['systemctl', 'show', 'garmin-report-web.service', '--property=MainPID,ActiveState,SubState,UnitFileState'], capture_output=True, text=True, check=True)
    service = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    assert status == 200 and served == report_bytes and 'no-store' in cache
    assert service['MainPID'] == '357833' and service['ActiveState'] == 'active' and service['UnitFileState'] == 'enabled'
    report = report_bytes.decode()
    assert 'value="33"' in report and report.count('datetime="' + iso + '"') == 2
    assert not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', report) and 'REDACTED_PRIVATE_ID' not in report
    assert public['deep_research'] == state and task['last_goal_turn'] == state['last_goal_turn']
    assert state['goal_status'] == 'active' and state['required_work_remaining'] and not state['goal_complete']
    assert not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified']
    for path in (ROOT / BASE).rglob('*'):
        if path.is_file() and '__pycache__' not in path.parts and 'passive-code-marker' not in path.parts:
            relative = str(path.relative_to(ROOT))
            protected[relative] = sha(relative)
    for path in ('scripts/probe_native_dispatcher_settings.py', 'scripts/seal_native_settings_attempt.py',
                 'scripts/verify_native_settings_cold_prefix.py', 'scripts/verify_native_settings_partial_journals.py',
                 'scripts/verify_native_settings_partial_journals_v2.py', 'scripts/publish_native_settings_scope_checkpoint.py',
                 'scripts/publish_native_settings_scope_checkpoint_v2.py',
                 PREFIX, 'evidence/firmware-analysis/native-decoder-scope-checkpoint-audit.json'):
        protected[path] = sha(path)
    out = 'evidence/firmware-analysis/native-settings-scope-checkpoint-audit.json'
    audit = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
        previous_checkpoint=BASE + 'previous-audit.json', previous_checkpoint_scopes=44,
        selected_frozen_suites=suites, native_unique_exact_dependencies=len(native_deps),
        selected_original_fragment_suites=previous['selected_original_fragment_suites'],
        selected_native_partial_exchange_proofs=previous['selected_native_partial_exchange_proofs'],
        selected_partial_decoder_proofs=previous['selected_partial_decoder_proofs'],
        selected_partial_settings_journal_proofs=[dict(path=RUNTIME + 'independent-partial-journals.json', sha256=sha(RUNTIME + 'independent-partial-journals.json'), settings_raw_operations=0, independent_bank_replay=True)],
        selected_full_linked_image_controls=dict(path=DOCS['native_music_persistent_source_worker_owner_image'], sha256=sha(DOCS['native_music_persistent_source_worker_owner_image']), host_groups=15, bounded_ARM_assertions=11, native_source_loop_scheduled=False),
        protected_sources=protected, original_guest_session=39489, original_guest_terminal_exit_code=1,
        original_cold_prefix_complete=True, complete_Dispatcher_body_or_foreground_or_physical_App=False,
        active_parallel_unsealed_work_excluded=['package-static/passive-code-marker'],
        current_state_sha256=sha('evidence/deep-research-state.json'), report_sha256=sha('reports/nuvi2565RT.html'))
    audit['scope_checks'] = {
        'prior_1078_protected_file_hashes_unchanged': True,
        'prior_snapshot_hashes_match': True,
        'prior_44_complete_native_suites_and_cases_match': True,
        'prior_896_native_integrity_dependencies_match': True,
        'new_evidence_source_and_artifact_hashes_match': True,
        'actual_terminal_receipt_is_39489_exit1_chunk4446d3': True,
        'terminal_receipt_has_no_running_session_handle': True,
        'cold_prefix_all_scoped_guards_passed': True,
        'partial_bank_independently_replayed_from_complete_before_bytes': True,
        'partial_zones_are_7_body_8_FP_22_inherited': True,
        'settings_raw_default_and_zero_operations_are_absent': True,
        'stop_is_original26DE42_store_to3AAF844': True,
        'full_body_and_callback_return_remain_false': True,
        'new_ARM_image_has_no_undefined_symbols': True,
        'HOST_groups_15_and_bounded_ARM_assertions_11_separate': True,
        'original_FP_fragment_cases_preserved': True,
        'native_source_worker_scheduling_not_claimed': True,
        'raw_FAT_contract_has_no_new_guest_or_device_execution': True,
        'GUI_observer_contract_is_host_only': True,
        'prior146_findings_and118_details_preserved': True,
        'weighted_estimate33_and_App20_unchanged': True,
        'canonical_task_public_state_consistent': True,
        'goal_active_and_required_work_remaining': True,
        'physical_App_and_direct_phone_music_remain_false': True,
        'report_HTTP200_no_store_and_exact_body_match': True,
        'existing_enabled_active_service_PID357833_unchanged': True,
        'two_Taiwan_timestamps_and33_bar_visible': True,
        'public_HTML_has_no_unit_ESN_or_Bluetooth_address': True,
    }
    write(out, audit)
    latest['historical_offline_checkpoint_audits']['prior_native_decoder_scope_checkpoint'] = dict(audit=BASE + 'previous-audit.json', audit_sha256=sha(BASE + 'previous-audit.json'), state_snapshot=BASE + 'previous-state.json', state_snapshot_sha256=sha(BASE + 'previous-state.json'), all_passed=True)
    latest.pop('current_native_decoder_scope_checkpoint', None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(), HTTP_status=status, served_latest_report=True,
        local_report_sha256=sha('reports/nuvi2565RT.html'), served_report_sha256=hashlib.sha256(served).hexdigest(),
        report_bytes=len(served), service=service, service_not_restarted=True, cache_control=cache,
        current_native_settings_scope_checkpoint=out, checkpoint_sha256={out: sha(out)},
        goal_status='active', full_goal_complete=False, current_physical_test_requested=False)
    latest['complete_current_offline_run'] = dict(checkpoint_all_scope_checks_passed=True,
        native_frozen_suites_revalidated=len(suites), native_unique_exact_dependencies=len(native_deps),
        original_fragment_controls=5, partial_native_exchange_proofs=1, partial_decoder_query_proofs=1,
        partial_settings_journal_proofs=1, independent_bank_bytes=467532, settings_raw_operations=0,
        compiled_image_HOST_groups=15, compiled_image_bounded_ARM_assertions=11,
        protected_source_count=len(protected), latest_body_terminal_exit_code=1,
        cold_prefix_all_guards_passed=True, physical_App_verified=False, device_io=False, sounds_emitted=False)
    latest['progress_display_verified'].update(estimate_percent=33, completed_items=123,
        report_updated_time=iso, research_updated_time=iso, visual_browser_render_not_performed=True,
        current_success_and_body_failure_separated_visible=True)
    write('evidence/report-web-latest.json', latest)
    print(json.dumps(dict(all_passed=True, findings=151, completed_items=123,
        native_suites=len(suites), native_deps=len(native_deps), protected_sources=len(protected),
        updated_Taiwan=iso, HTTP_status=status, report_bytes=len(served), service_PID=service['MainPID'], url=latest['url'])))


if __name__ == '__main__':
    main()
