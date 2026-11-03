#!/usr/bin/env python3
"""Publish bounded original GUI progress with the actual terminal evidence."""
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
from analyze_native_sections import NativeImage

BASE = 'staging/native-player-inline-fields/'
RUNTIME = BASE + 'runtime/'
PREFIX = 'evidence/firmware-analysis/native-inline-fields-cold-prefix-emulation.json'
OBSERVED = BASE + 'gui-static/inline-fields-observed-prefix.json'
MAP_NOTE = 'evidence/map-layer-explanation-20261005.json'
OUT = 'evidence/firmware-analysis/native-inline-fields-checkpoint-audit.json'
DOCS = {
    'native_inline_fields_original_caller_contract': BASE + 'gui-static/inline-fields-observer-contract.json',
    'native_inline_fields_complete_cold_prefix': PREFIX,
    'native_inline_fields_observed_returns_and_page_replay': OBSERVED,
    'native_inline_fields_partial_histories_and_bank': RUNTIME + 'independent-partial-journals.json',
    'native_settings_lock_memzero_and_default_observed_prefix': BASE + 'settings-observed-prefix-v3.json',
    'native_next_original_clock_caller_contract': BASE + 'gui-static/next-clock-caller-contract.json',
    'native_preserving_entry_CPU_cache_marker': BASE + 'code-marker/cache-marker-emulation-proof.json',
    'native_preserving_entry_cache_marker_independent_controls': BASE + 'code-marker/cache-marker-independent-verification.json',
    'native_marker_normal_return_and_resource_erratum': BASE + 'code-marker/return-layers-and-resource-erratum.json',
    'native_music_queue_callback_v1_ABI_rejection': BASE + 'music-session/v1-native-ABI-rejection-evidence.json',
    'native_music_session_guard_v2_HOST_and_ARM_REL': BASE + 'music-session/verification-v2.json',
}


def main():
    assert not (ROOT / OUT).exists(), 'Preserve the published checkpoint'
    before, prior, previous = [read(BASE + name) for name in
        ('previous-state.json', 'previous-public.json', 'previous-audit.json')]
    assert previous['all_passed'] and len(previous['protected_sources']) == 1363
    protected, native_deps = {}, {}
    registry(previous['protected_sources'], protected)
    for row in read(BASE + 'previous-checkpoint.json')['snapshots']:
        assert sha(row['snapshot']) == row['sha256'], row['snapshot']
    suites = list(previous['selected_frozen_suites'])
    assert len(suites) == 46
    for suite in suites:
        assert sha(suite['path']) == suite['sha256']
        doc = read(suite['path'])
        assert doc['all_passed'] and all(case['passed'] for case in doc['cases'])
        registry(doc['source_sha256'], native_deps)
    assert len(native_deps) == 1279
    docs = {path: read(path) for path in DOCS.values()}
    for path, doc in docs.items():
        assert doc.get('all_passed', True)
        for key in ('source_sha256', 'dependency_sha256', 'verified_runtime_dependencies', 'artifacts_sha256', 'output_sha256'):
            if key in doc:
                entries = doc[key]
                if isinstance(entries, str):
                    assert key == 'source_sha256' and doc.get('source_path')
                    entries = {doc['source_path']: entries}
                registry(entries, protected)
        protected[path] = sha(path)
    assert docs[BASE+'gui-static/inline-fields-observer-contract.json']['pure_host_controls_passed'] == 28
    assert docs[BASE+'gui-static/next-clock-caller-contract.json']['all_file_assertions_passed']
    marker = docs[BASE+'code-marker/cache-marker-emulation-proof.json']
    independent_marker = docs[BASE+'code-marker/cache-marker-independent-verification.json']
    marker_seal_path = BASE+'code-marker/cache-marker-seal.json'
    marker_seal = read(marker_seal_path)
    marker_ledger_path = marker_seal['sealed_source_and_output_registry_path']
    marker_ledger = read(marker_ledger_path)
    assert marker_seal['all_passed'] and marker_ledger['all_passed'] and marker_seal['immutable_after_this_seal']
    assert sha(marker_ledger_path) == marker_seal['ledger_sha256']
    assert sha(BASE+'code-marker/cache-marker-emulation-proof.json') == marker_seal['proof_sha256']
    assert sha(BASE+'code-marker/cache-marker-independent-verification.json') == marker_seal['independent_verification_sha256']
    registry(marker_ledger['source_sha256'], protected)
    registry(marker_ledger['output_sha256'], protected)
    for path in (marker_seal_path, marker_ledger_path): protected[path] = sha(path)
    marker_receipt = read(BASE+'code-marker/v4-terminal-tool-receipt.json')
    assert marker_receipt['session_id'] == 33753 and marker_receipt['authoritative_terminal']
    marker_actual = marker_receipt['actual_tool_result']
    assert marker_actual['exit_code'] == 0 and marker_actual['chunk_id'] == 'ad39a4' and 'session_id' not in marker_actual
    assert marker['case_count'] == 5 and all(c['passed'] for c in marker['cases'])
    assert marker['normal_original_bootstrap_raw_return'] == 11
    assert marker['compiled_appended_ARM_instructions_executed'] and marker['actual_five_UTF16_CPU_stores_to_native_registry_record']
    assert marker['original_2744F6_and_page_getter_callsite_executed']
    assert marker['original40_exports_and_imports_and_postheader_RAM_preserved_normal_entry']
    assert not marker['physical_changed_code_acceptance_verified'] and not marker['modified_VPM_or_SIG_generated']
    assert len(independent_marker['assertions']) == 9 and all(independent_marker['assertions'].values())
    assert independent_marker['proc_stage_VmHWM_peak_KiB'] == 164320 and independent_marker['rusage_VmHWM_disagreement_cause'].startswith('unknown')
    rejected_ABI = docs[BASE+'music-session/v1-native-ABI-rejection-evidence.json']
    assert not rejected_ABI['all_native_ABI_passed'] and rejected_ABI['v1_unusable_for_actual2704B2_binding']
    assert not rejected_ABI['v1_native_queue_execution'] and rejected_ABI['assertion_count'] == 25
    session_v2 = docs[BASE+'music-session/verification-v2.json']
    assert session_v2['host']['groups'] == 17 and session_v2['host']['ASan_UBSan']
    assert not session_v2['host']['original_native_instructions'] and not session_v2['host']['certified_native_ownership']
    assert session_v2['original_queue_ABI']['static_mapping_verified'] and not session_v2['original_queue_ABI']['native_execution_verified']
    assert session_v2['ARM']['type'] == 'ET_REL' and session_v2['ARM']['machine'] == 40 and not session_v2['ARM']['full_image']
    assert len(session_v2['ARM']['undefined_symbols']) == 26
    for path in (BASE+'music-session/v2-tool-terminal-receipt.json', BASE+'music-session/v2-relocation-boundaries.json'):
        extra = read(path)
        for key in ('source_sha256', 'artifacts_sha256'):
            if key in extra: registry(extra[key], protected)
        protected[path] = sha(path)
    stock = NativeImage()
    for row in rejected_ABI['original_opcode_assertions']:
        raw = bytes.fromhex(row['opcode_hex']); assert stock.read(int(row['PC'],16),len(raw)) == raw
    meta, receipt = read(RUNTIME + 'terminal-metadata.json'), read(RUNTIME + 'terminal-tool-receipt.json')
    probe, observed = read(meta['probe']), docs[OBSERVED]
    registry(meta['source_sha256'], protected)
    for key in ('runner', 'runner_snapshot', 'inputs', 'probe', 'FP_helper', 'GUI_observer', 'sealer', 'cold_prefix', 'terminal_tool_receipt'):
        assert sha(meta[key]) == meta[key + '_sha256'], key
    assert meta['session_id'] == receipt['session_id'] == 35110
    actual = receipt['actual_exec_result']
    assert 'session_id' not in actual and actual['exit_code'] == meta['terminal_exit_code']
    assert meta['cold_prefix_full_guards_passed'] and not meta['body_full_guards_passed']
    assert observed['actual_inline_operations'] == 2 and observed['actual_inline_stores'] == 6
    assert observed['both_actual_returns_seen'] and not observed['full_dispatcher_body_or_foreground_verified']
    assert docs[RUNTIME + 'independent-partial-journals.json']['independent_file_only_bank_replay_verified']
    settings_proof = docs[BASE + 'settings-observed-prefix-v3.json']
    assert settings_proof['actual_raw_operations'] == 2 and settings_proof['actual_memzero_returns'] == 1
    assert settings_proof['page_memzero_store_events'] == 518 and settings_proof['actual_default_stores'] == 1
    assert not settings_proof['actual_physical_NV_settings_read_verified']
    next_entry = probe['registers']['pc']
    assert next_entry == '0x353a9c' and observed['next_unreviewed_writer'] is None
    assert probe['registers']['lr'] == '0x39552d' and probe['registers']['sp'] == '0x8803fb0'
    registry(docs[PREFIX]['source_sha256'], native_deps)
    suites.append(dict(path=PREFIX, sha256=sha(PREFIX), case_count=1,
        scope='Complete original cold component prefix; later GUI body and foreground remain separate.'))
    map_note = read(MAP_NOTE)
    registry(map_note['local_evidence_sha256'], protected)
    protected[MAP_NOTE] = sha(MAP_NOTE)
    state, task, public = [read(path) for path in
        ('evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json')]
    app = state['native_app_music']
    assert app['static_findings'] == before['native_app_music']['static_findings']
    assert len(app['static_findings']) == 158
    assert public['research_progress']['completed'] == prior['research_progress']['completed']
    for name, path in DOCS.items():
        app['static_findings'][name] = dict(evidence=path, evidence_sha256=sha(path),
            physical_App_or_direct_phone_music_verified=False, device_io=False, sounds_emitted=False)
    app['development_observations']['latest_inline_fields_attempt'] = dict(
        session_id=35110, actual_terminal_exit_code=meta['terminal_exit_code'], actual_terminal_chunk=actual['chunk_id'],
        full_cold_prefix_passed=True, inline_calls=2, inline_stores=6, both_actual_returns_seen=True,
        global_object_stores_observed=observed['actual_global_stores'],
        settings_raw_ops_observed=observed['settings_raw_operations'],
        constructor_returned=observed['constructor_return_verified'], callback_returned=probe['callback_return_seen'],
        body_fullguards=False, next_writer=None, next_target=None, next_execution_boundary=next_entry,
        next_original_caller='0x395528', default_branch_lower_record_is_declared_fixture=True,
        evidence=meta['probe'], evidence_sha256=sha(meta['probe']))
    app['native_component_execution_marker_in_declared_fixture'] = dict(evidence=BASE+'code-marker/cache-marker-emulation-proof.json',
        evidence_sha256=sha(BASE+'code-marker/cache-marker-emulation-proof.json'), cases=5, independent_bounded_assertions=9,
        actual_compiled_CPU_stores_and_native_getter=True, original40_exports_and_imports_preserved=True,
        original_normal_raw_return=11, real_UI_render_or_package_acceptance_or_App_verified=False)
    state['map_update']['layer_inventory_explanation'] = dict(evidence=MAP_NOTE, evidence_sha256=sha(MAP_NOTE),
        stock_layers_preserved=True, new_DEM_3D_or_JCV_installed=False,
        physical_DEM_3D_compatibility_verified=False, physical_address_search_or_routing_verified=False)
    next_focus = ('Continue original SFS/settings/base/derived/container through the actual clock entry '
        + next_entry + ' from original395528/caller39552C, withSP8803FB0'
        + '; preserve original page/stack/actor histories and foreground/callback guards. '
        'Two copied inline9 constructors now executed with six original stores and actual native returns. '
        'Continue corrected native queue ABI/channel8 admission/borrow/session leases. '
        'Preserving-entry marker now executed in five bounded declared fixtures; prepare stricter unique currentloader/path/lifetime and repeated-entry controls before a local reversible package. No physical App or direct-phone audio acceptance. Pairing first; mic canceled; fidelity deferred; '
        'AA later; Maps deferred; goal active/no-achieve.')
    now = datetime.now(timezone.utc)
    state.update(updated_utc=now.isoformat(), current_priority='Native menu/player, real audio session binding and changed-code acceptance; active/no-achieve.')
    state['next_actions'][0] = next_focus
    state['next_actions'][1] = 'Cover original admission and full reader return with session/borrow leases; prevent delayed reused-index callbacks before reading descriptors.'
    app['remaining_work'] = state['next_actions'][:4]
    state['parallel_research'].update(tasks=['original GUI inline-field initialization and next boundary',
        'corrected channel8 ABI and borrowed-reader generation', 'stricter local reversible marker package preparation'],
        continued_round_completed=False, agents_currently_running=True)
    state['last_goal_turn'].update(classification='progress', previous_goal_turn_classification='progress',
        validated_utc=now.isoformat(), previous_state_snapshot=BASE + 'previous-state.json',
        previous_current_audit_snapshot=BASE + 'previous-audit.json',
        previous_turn_revalidation='Previous actual global-object checkpoint and all1363 protected sources revalidated; same original live35110 was continued, not restarted.',
        focused_evidence=OBSERVED, focused_evidence_sha256=sha(OBSERVED),
        latest_dispatcher_development_evidence=meta['probe'], latest_dispatcher_development_evidence_sha256=sha(meta['probe']),
        latest_dispatcher_runtime_session_id=35110, latest_dispatcher_terminal_exit_code=meta['terminal_exit_code'],
        latest_dispatcher_run_full_scoped_final_guards_passed=False, latest_callback_body_returned=probe['callback_return_seen'],
        latest_cold_prefix_full_scoped_guards_passed=True,
        latest_settings_raw_operations_observed=observed['settings_raw_operations'],
        native_settings_default_branch_executed_in_latest_run=True,
        native_settings_lower_record_is_declared_fixture=True,
        observed_global_object_stores=observed['actual_global_stores'],
        actual_inline_field_stores=6, both_inline_native_returns_verified=True,
        native_compiled_cache_marker_CPU_and_native_getter_verified_offline=True, marker_original_normal_raw_return=11,
        native_music_v1_queue_ABI_rejected=True, real_package_acceptance_unverified=True,
        physical_audio_or_native_App_verified=False, device_io=False, device_files_written=False,
        automatic_calls_or_sound=False, native_firmware_or_research_package_written=False,
        next_focus=next_focus, goal_status='active', full_goal_complete=False,
        reasons=['Original two inline constructors execute through native ARM veneer, five Thumb instructions and actual caller returns.',
            'Whole page, initialized bank and original actor/caller histories independently replayed; later body boundary preserved.',
            'Actual compiled preserving entry writes fourUTF16 marker characters plusNUL; native getter consumes them, originalmetadata/40exports preserved in bounded fixtures.',
            'Wrong native lower queue ABI caught by exact opcode review before native use; hostmock success is explicitly insufficient.',
            'Original map-layer inventory explained without changing stock maps or claiming new DEM/3D compatibility.'])
    for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', 'parallel_research'):
        task[key] = state[key]
    public.update(updated=now.isoformat(), deep_research=state)
    progress = public['research_progress']
    details = [
        '首頁模擬已走過先前停止的兩次原廠欄位初始化：真正執行六筆精確寫入與兩次返回，保留間隔資料、呼叫者堆疊及原指令，沒有預填結果或略過原函式。',
        '這次再次完成全部十一個原廠準備步驟；後段完整記憶體與系統資料紀錄另行重建。這是有界首頁初始化進展，尚未完成整體首頁前景、觸控或實機 App。',
        '最新首頁邊界與實際終止結果已保存；全域物件寫入觀察到' + str(observed['actual_global_stores']) + '筆、設定鎖操作' + str(observed['settings_raw_operations']) + '次。下一段原廠程式仍須補齊，不能把部分初始化視為播放器完成。',
        '設定分支已另行核對：原廠鎖取得與釋放均真正返回，原清零函式處理2832位元組並返回，之後走原預設值分支。設定不存在是明示離線輸入，未證明讀取車機實際設定。',
        '自製程式標記已由靜態方案推進到真正 ARM 指令執行：五組有界控制通過，程式在 RAM 寫入四字標記與終止字元，原廠版本讀取函式及頁面讀取入口收到標記。保留原磁碟版本資料、四十個原介面與輸入轉接；尚未驗證實機載入或畫面顯示。',
        '標記試驗的原模組正常返回已實測為11，另用明示版本輸入驗證6與重試分支，沒有代填成功返回。九項獨立斷言通過；記憶體樣本約160MiB，舊統計值與本次程序樣本差異及失敗紀錄另存，原因尚未確定。',
        '音訊攔截原型的底層函式參數順序已由原廠指令查出不符；舊主機模擬測試只證明其自身狀態邏輯。這版排除原生接線，正以新來源修正，尚未取得音訊獨占或播放工作階段認證。',
        '修正底層參數順序後的新音訊元件已完成 ARM 編譯與17組主機競態控制，包含舊編號、停止／重新啟動及錯誤工作程序的拒絕。仍有26個明示連結邊界，未執行原廠呼叫流程，原生獨占認證保持拒絕。',
        '查核原廠地圖檔與 Garmin 官方說明：目前新增 OSM 詳細道路／景點與地址索引，保留原道路、地址點、底圖與 JCV。尚未新增 DEM 或 3D 建築，也未證明這台支援新增圖層。',
    ]
    progress['completed'].extend(details)
    progress['phases'][4]['completed'].extend(details[:-1])
    progress.update(research_updated_utc=now.isoformat(), next='補齊原廠首頁初始化與前景，接上播放器音訊工作階段；同步驗證自製程式寫入標記後的原生讀取路徑。')
    progress['phases'][4]['next'] = progress['next']
    assert len(app['static_findings']) == 169 and len(progress['completed']) == 138
    assert progress['estimate_percent'] == 33 and progress['phases'][4]['estimate_percent'] == 20
    assert sum(p['weight'] * p['estimate_percent'] / 100 for p in progress['phases']) == 33
    report = (ROOT / 'reports/nuvi2565RT.html').read_text()
    card = '<div class="card"><h2>最新離線進展：首頁初始化與自製程式執行標記已完成有界驗證</h2><p><strong>首頁初始化往前推進：</strong>原廠兩個欄位建構真正執行六筆寫入與兩次返回；間隔資料、原指令與堆疊紀錄保持核對。十一個準備步驟完整通過；原廠設定鎖取得／釋放、清零函式與預設值分支均執行。設定不存在是明示模擬輸入，未讀取車機實際設定。下一停止點為另一個原廠時鐘呼叫的觀察範圍，沒有寫入目標。</p><p><strong>自製程式已有離線執行證據：</strong>五組 ARM 控制通過，新程式真正在 RAM 寫入短標記，原廠版本讀取函式與頁面讀取入口收到標記；原磁碟版本資料與四十個介面保留。這是明示檔案系統、記憶體與單工作程序條件下的有界測試，尚未證明車機接受修改程式包或顯示標記。</p><p>音訊原型的底層參數順序不符已查明；舊主機測試不足以證明原生接線，新來源已修正並通過17組主機競態控制；仍未接上原廠呼叫流程或完整播放器映像。可逆測試包仍在準備，尚未傳入車機。</p><p><strong>尚未有可安裝的 App，手機直接連 Garmin 播音樂仍待驗證。</strong>整體里程碑估計33%，App整合20%；百分比是研究估計。目前沒有新的實機操作需求。現場配對立即優先；麥克風取消、音質擱置，Android Auto排後，Google Maps暫緩。</p></div>'
    report, count = re.subn(r'<div class="card"><h2>最新離線進展：播放器通過原廠核心排程，實機執行標記方案已定位</h2>.*?</div>', lambda _: card, report, count=1, flags=re.S)
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
    # Other agents' live prototype directories must not be frozen mid-write.
    for directory in (ROOT / BASE / 'gui-static', ROOT / BASE / 'runtime'):
        for path in directory.rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts:
                protected[str(path.relative_to(ROOT))] = sha(str(path.relative_to(ROOT)))
    for path in (ROOT / BASE).iterdir():
        if path.is_file():
            protected[str(path.relative_to(ROOT))] = sha(str(path.relative_to(ROOT)))
    for path in ('scripts/probe_native_dispatcher_inline_fields.py', 'scripts/seal_native_inline_fields_attempt.py',
            'scripts/verify_native_inline_fields_cold_prefix.py', 'scripts/verify_native_inline_fields_partial_journals.py',
            'scripts/verify_native_inline_fields_settings_prefix.py', 'scripts/verify_native_inline_fields_settings_prefix_v2.py',
            'scripts/verify_native_inline_fields_settings_prefix_v3.py',
            'scripts/publish_native_inline_fields_checkpoint.py',
            BASE+'publication-v1-failure/source-at-run.py', BASE+'publication-v1-failure/actual-terminal-tool-receipt.json',
            BASE+'publication-v1-failure/unchanged-current-files.json',
            str(Path(__file__).resolve().relative_to(ROOT)), PREFIX,
            'evidence/firmware-analysis/native-global-subobject-checkpoint-audit.json'):
        protected[path] = sha(path)
    checks = dict(previous1363_protected=True, previous46_complete_suites=True, evidence_hashes=True,
        actual35110_terminal_receipt=True, complete_cold_prefix=True,
        actual_two_inline_calls_six_stores_and_returns=True, independent_page_and_padding_replay=True,
        native_settings_lock_memzero_default_in_declared_lower_fixture=True,
        next_clock_scope_has_no_fabricated_frame_or_write_target=True,
        later_constructor_callback_foreground_separate=True, initialized_bank_independent_replay=True,
        marker_five_actual_ARM_controls_and_nine_independent_assertions=True,
        marker_metadata_and_original40_exports_preserved=True, marker_normal11_and_typed6_controls_separate=True,
        marker_resource_failure_and_uncertain_cause_preserved=True,
        music_v1_wrong_native_ABI_excluded_before_native_use=True,
        music_v2_17_HOST_groups_and_ARM_REL_separate_from_native_execution=True,
        old158_findings_and129_details_retained=True, map_layer_inventory_without_device_writes=True,
        ongoing_agent_drafts_excluded=True, weighted33_App20=True, canonical_task_public_consistent=True,
        goal_active_remaining=True, physical_App_direct_phone_false=True, served_HTML200_no_store=True,
        enabled_service_PID_unchanged=True, two_Taiwan_timestamps=True, public_HTML_no_ESN_MAC=True)
    audit = dict(previous, updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=all(checks.values()),
        scope_checks=checks, previous_checkpoint=BASE + 'previous-audit.json', selected_frozen_suites=suites,
        native_unique_exact_dependencies=len(native_deps), protected_sources=protected,
        selected_native_entry_cache_marker_proofs=[dict(path=BASE+'code-marker/cache-marker-emulation-proof.json',
            sha256=sha(BASE+'code-marker/cache-marker-emulation-proof.json'), bounded_ARM_controls=5, independent_assertions=9,
            normal_original_raw_return=11, native_UI_or_hardware_or_changed_package_acceptance=False)],
        selected_HOST_music_session_guard_proofs=[dict(path=BASE+'music-session/verification-v2.json',
            sha256=sha(BASE+'music-session/verification-v2.json'), HOST_groups=17, ARM_type='ET_REL', unresolved_symbols=26, native_execution=False)],
        selected_negative_native_queue_ABI_proofs=[dict(path=BASE+'music-session/v1-native-ABI-rejection-evidence.json',
            sha256=sha(BASE+'music-session/v1-native-ABI-rejection-evidence.json'), exact_static_assertions=25, native_ABI_passed=False)],
        selected_partial_inline_field_proofs=[dict(path=OBSERVED, sha256=sha(OBSERVED), operations=2, stores=6,
            both_actual_returns_seen=True, complete_Dispatcher_body_or_foreground=False)],
        original_guest_session=35110, original_guest_terminal_exit_code=meta['terminal_exit_code'],
        original_cold_prefix_complete=True, current_state_sha256=sha('evidence/deep-research-state.json'),
        report_sha256=sha('reports/nuvi2565RT.html'), complete_Dispatcher_body_or_foreground_or_physical_App=False)
    write(OUT, audit)
    latest['historical_offline_checkpoint_audits']['prior_native_global_subobject_checkpoint'] = dict(
        audit=BASE + 'previous-audit.json', audit_sha256=sha(BASE + 'previous-audit.json'),
        state_snapshot=BASE + 'previous-state.json', state_snapshot_sha256=sha(BASE + 'previous-state.json'), all_passed=True)
    latest.pop('current_native_global_subobject_checkpoint', None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(), HTTP_status=status, served_latest_report=True,
        local_report_sha256=sha('reports/nuvi2565RT.html'), served_report_sha256=hashlib.sha256(served).hexdigest(),
        report_bytes=len(served), service=service, service_not_restarted=True, cache_control=cache,
        current_native_inline_fields_checkpoint=OUT, checkpoint_sha256={OUT: sha(OUT)}, goal_status='active',
        full_goal_complete=False, current_physical_test_requested=False)
    latest['complete_current_offline_run'].update(checkpoint_all_scope_checks_passed=True,
        native_frozen_suites_revalidated=len(suites), native_unique_exact_dependencies=len(native_deps),
        protected_source_count=len(protected), latest_body_terminal_exit_code=meta['terminal_exit_code'],
        cold_prefix_all_guards_passed=True, inline_field_stores=6, both_inline_actual_returns=True,
        global_object_stores=observed['actual_global_stores'], settings_raw_operations=observed['settings_raw_operations'],
        marker_bounded_ARM_controls=5, marker_independent_assertions=9, music_native_queue_ABI_v1_excluded=True,
        physical_App_verified=False, device_io=False, sounds_emitted=False)
    latest['progress_display_verified'].update(estimate_percent=33, completed_items=138,
        report_updated_time=iso, research_updated_time=iso, visual_browser_render_not_performed=True,
        current_success_and_body_failure_separated_visible=True)
    write('evidence/report-web-latest.json', latest)
    print(json.dumps(dict(all_passed=True, findings=169, completed_items=138, scope_checks=len(checks),
        native_suites=len(suites), native_deps=len(native_deps), protected_sources=len(protected),
        updated_Taiwan=iso, HTTP_status=status, report_bytes=len(served), url=latest['url'])))


if __name__ == '__main__':
    main()
