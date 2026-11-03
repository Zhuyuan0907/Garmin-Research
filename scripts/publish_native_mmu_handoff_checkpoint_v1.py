#!/usr/bin/env python3
"""Root-only, one-shot publication of frozen MMU/music-handoff evidence.

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
B = 'staging/native-player-mmu-handoff-checkpoint/'
M = 'staging/native-player-mmu-software/'
U = 'staging/native-player-mixer-handoff/'
I = U + 'verification-v5/'
SOURCE = 'scripts/publish_native_mmu_handoff_checkpoint_v1.py'
INPUT = B + 'publication-inputs-v2.json'
PREPARATION = B + 'prepare-v2-terminal-tool-receipt.json'
OUT = 'evidence/firmware-analysis/native-mmu-handoff-checkpoint-audit.json'


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
    assert not (ROOT / OUT).exists(), 'Preserve terminal publication; use a NEW publisher'
    manifest = read(INPUT)
    assert manifest['all_passed'] and manifest['publication_constraints']['canonical_write'] is False
    assert manifest['publication_constraints']['guest_execution'] is False
    prep = read(PREPARATION)
    assert prep['command'] == 'python3 -B ' + B + 'prepare_publication_inputs_v2.py'
    assert prep['tool_result']['exit_code'] == 0 and 'session_id' not in prep['tool_result']
    prep_output = json.loads(prep['tool_result']['output'].strip())
    assert prep_output['all_passed'] and prep_output['canonical_write'] is False
    assert prep_output['output_sha256'] == immutable_sha(INPUT)
    assert prep_output['preparation_source_sha256'] == immutable_sha(B + 'prepare_publication_inputs_v2.py')
    assert prep['source_sha256'][B + 'prepare_publication_inputs_v2.py'] == prep_output['preparation_source_sha256']

    previous = read(B + 'previous-audit.json')
    snapshots = read(B + 'previous-checkpoint.json')['snapshots']
    assert previous['all_passed'] and len(previous['protected_sources']) == 1849
    assert len(previous['selected_frozen_suites']) == 49
    protected = {}

    def register(entries):
        for path, digest in entries.items():
            assert immutable_sha(path) == digest, path
            assert path not in protected or protected[path] == digest, path
            protected[path] = digest

    # Revalidate the merged frozen union once before writes; identical backup
    # paths across all inherited registries are hashed only once in this run.
    register(manifest['frozen_files_sha256'])
    assert all(protected[path] == digest for path, digest in previous['protected_sources'].items())
    assert read(B + 'preserved-protected-file-registry.json') == previous['protected_sources']
    native_dependencies = read(B + 'preserved-native-dependency-registry.json')
    assert len(native_dependencies) == previous['native_unique_exact_dependencies'] == 1733
    register(native_dependencies)
    assert manifest['preserved_selected_frozen_suites'] == previous['selected_frozen_suites']
    suites = list(previous['selected_frozen_suites'])
    documents = {}
    for key, row in manifest['findings'].items():
        d = read(row['path'])
        assert immutable_sha(row['path']) == row['sha256'] and d[row['pass_field']] is True
        documents[key] = d
    for row in snapshots:
        assert immutable_sha(row['snapshot']) == row['sha256']
        assert fresh_sha(row['original']) == row['sha256'], 'Canonical changed since preparation: ' + row['original']
    assert manifest['new_complete_cold_suites'] == []
    assert len(manifest['new_original_software_fragment_suites']) == 1
    assert len(manifest['new_music_declared_scoped_suites']) == 1

    software = read(M + 'software-mapping-v2-independent-file-verification.json')
    assert software['all_passed'] and software['case_count'] == 10
    assert software['actual_original_CPU_stores'] == 74 and software['actual_original_table_stores'] == 14
    assert software['whole_zone_case_replays'] == 30
    assert software['final_return_GP16_CPSR_SP_serialized'] is False
    assert software['complete_native_return_state_proof'] is False
    assert software['synthetic_L1_L2_inputs'] and software['model_MMU_disabled']
    software_receipt = read(M + 'guest-v2-terminal-tool-receipt.json')['tool_result']
    assert software_receipt['exit_code'] == 0 and software_receipt['chunk_id'] == '538421'
    music = read(U + 'mixer-handoff-v5-proof.json')
    assert music['all_passed'] and music['case_count'] == 3
    assert music['actual_original_kernel_source_and_mixer_handoff']
    assert music['three_guest_only_original_call_site_branches']
    assert not music['native_heap_mutex_exclusive_or_STOP_DONE_verified']
    assert not music['physical_speaker_phone_App_installation_or_complete_player_verified']
    music_receipt = read(U + 'guest-v5-terminal-tool-receipt.json')
    assert music_receipt['started_session_id'] == 3366 and music_receipt['terminal']
    assert music_receipt['actual_terminal_result']['exit_code'] == 0
    assert music_receipt['actual_terminal_result']['chunk_id'] == '317e2a'
    music_files = read(I + 'mixer-handoff-v5-independent-file-verification.json')
    assert music_files['all_passed'] and music_files['case_count'] == 3
    assert music_files['CPU_stores'] == 42368 and music_files['joint_events'] == 42499
    assert music_files['full_original_native_returns'] == 48
    assert music_files['actual_RW_case_replays_from_frozen_permission_recipe'] == 69
    assert music_files['unchanged_RX_return_sentinel_case_replays'] == 3
    assert music_files['full_mixer_native_and_outer_return_GP16_CPSR_SP_serialized']
    assert not music_files['ordinary_controller_function_return_GP16_CPSR_SP_serialized']
    music_seal = read(I + 'mixer-handoff-v5-independent-file-seal.json')
    assert music_seal['all_passed'] and music_seal['actual_independent_verifier_terminal_chunk'] == '9ca580'
    assert music_seal['actual_independent_verifier_exit_code'] == 0

    state, task, public = [read(path) for path in ('evidence/deep-research-state.json',
                         'evidence/task-state.json', 'reports/findings.json')]
    before = read(B + 'previous-state.json')
    prior_public = read(B + 'previous-public.json')
    app = state['native_app_music']
    progress = public['research_progress']
    assert app['static_findings'] == before['native_app_music']['static_findings']
    assert len(app['static_findings']) == 205 and len(progress['completed']) == 163
    assert progress['completed'] == prior_public['research_progress']['completed']
    for key, row in manifest['findings'].items():
        assert key not in app['static_findings']
        app['static_findings'][key] = dict(evidence=row['path'], evidence_sha256=row['sha256'],
            scope=row['scope'], evidence_type=row['evidence_type'],
            physical_App_or_audio_verified=False, device_io=False)
    now = datetime.now(timezone.utc)
    focus = ('First test candidate3B9C54-to46CC7A wrapper capability grant before originalwait for new/existingM+78; '
             'original13 is already queued, so verify originalpost/genericmutex yield and message20/wait/ack. '
             'Then complete genuine native mixer source lifetime, exclusive ownership, cancellation/STOP_DONE, '
             'connect the previously verified SBC decoder and hardware boundaries; continue original native heap/private-page and cold-table '
             'provenance without host substitution. Ordinary controller final returns and final RX dumps '
             'remain separate evidence gaps. Reversible code-marker package awaits user availability/USB. '
             'Pairing first; microphone canceled; fidelity deferred; Android Auto later; Google Maps deferred; '
             'full objective active/no-achieve.')
    state.update(updated_utc=now.isoformat(), current_priority='Native menu/App and source/mixer music integration; active/no-achieve.')
    state['next_actions'][0] = focus
    app['remaining_work'] = state['next_actions'][:4]
    app['development_observations']['historical_cached_publication_hash_erratum'] = dict(
        evidence=B + 'historical-publication-hash-cache-erratum.json',
        evidence_sha256=immutable_sha(B + 'historical-publication-hash-cache-erratum.json'),
        old_audit_preserved=True, new_canonical_hash_readback_uncached=True)
    app['development_observations']['original_MMU_software_ten_cases'] = manifest['actual_MMUs_only_scope']
    app['development_observations']['native_source_mixer_handoff_v5'] = manifest['music_handoff']
    app['development_observations']['next_original_initializer_sync_contract'] = manifest['next_original_initializer_sync_contract']
    state['last_goal_turn'].update(classification='progress', previous_goal_turn_classification='no_progress',
        validated_utc=now.isoformat(), focused_evidence=U + 'mixer-handoff-v5-proof.json',
        focused_evidence_sha256=immutable_sha(U + 'mixer-handoff-v5-proof.json'),
        previous_state_snapshot=B + 'previous-state.json', previous_current_audit_snapshot=B + 'previous-audit.json',
        reasons=['Actual original kernel-created source/mixer handoff with3 declared guest-only BL redirects;48 complete native/outer mixer returns.',
                 'Ten original software MMU branch cases with synthetic tables/model MMU disabled; independent files retain missing final return-register snapshots.',
                 'Independent music69 trueRW plus3 unchangedRX sentinel/return evidence and explicit fixture/RX/controller limits; v1-v4 failures preserved.',
                 'Physical App/phone/speaker, SBC integration in this new handoff module, native exclusive ownership and STOP_DONE remain incomplete.'],
        actual_new_MMU_software_cases=10, actual_new_music_handoff_cases=3,
        actual_complete_native_outer_mixer_returns=48, native_exclusivity=False,
        native_STOP_DONE_verified=False, complete_native_App_or_phone_audio=False,
        physical_App_or_audio_verified=False, device_io=False, device_files_written=False,
        automatic_calls_or_sound=False, goal_status='active', full_goal_complete=False, next_focus=focus)
    for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', 'attended_testing'):
        task[key] = state[key]
    public.update(updated=now.isoformat(), deep_research=state)
    details = manifest['public_details']
    progress['completed'].extend(details)
    progress['phases'][4]['completed'].extend(details)
    next_text = '先驗證3B9C54→46CC7A候選能力交接及原post／yield／message20／wait／ack，涵蓋新與既有mixer；再補生命週期、獨占、停止、既有SBC解碼器與硬體。'
    progress.update(research_updated_utc=now.isoformat(), next=next_text)
    progress['phases'][4]['next'] = next_text
    assert progress['estimate_percent'] == 33 and progress['phases'][4]['estimate_percent'] == 20
    assert sum(p['weight'] * p['estimate_percent'] / 100 for p in progress['phases']) == 33
    assert len(app['static_findings']) == manifest['projected_counts']['findings']
    assert len(progress['completed']) == manifest['projected_counts']['public_details']

    report = (ROOT / 'reports/nuvi2565RT.html').read_text()
    card = '<div class="card"><h2>最新離線進展：原廠音訊工作交接與 MMU 軟體分支</h2>'
    card += '<p><strong>音訊工作交接新增3組真ARM案例：</strong>原kernel建立source與mixer工作，執行post／get／wait及context restore。3個guest-only原call-site跳轉接上新能力交接與FIFO；48次完整原讀取／外層mixer返回共取得3072bytes測試PCM及7680bytes靜音，重新選取與reset後可續作，本地Stop和profile切換會撤銷能力並拒絕新pull。</p>'
    card += '<p>獨立純檔案核對42368筆CPU stores、42499共同事件及72次tracked-zone重建，其中69次真正RW、3次不變RX return sentinel；native／outer mixer完整返回的GP／SP／CPSR已記錄。普通controller RETURN並未每次記錄，其他RX有runtime斷言及store history，沒有獨立finalRX memory dump。v1至v4的失敗與v4兩組失敗前觀察均保留。</p>'
    card += '<p>測試仍使用配置、generic mutex、硬體啟動、ring consumer與沒有driver回覆的reset transport等明示fixture；跳過一處原同步等待。本輪尚未串接既有SBC解碼器；實際手機、喇叭、可安裝App、原生獨占或STOP_DONE尚未完成，這是離線交接證據。</p>'
    card += '<p><strong>MMU新增10組原軟體分支案例：</strong>明示合成L1／L2與停用的模型MMU下，type0回復IRQ狀態後返回而不寫mapping。獨立核對74筆CPU stores、14筆table stores、607條原指令及30次整區重建；最終GP／SP／CPSR未序列化，只有runtime返回斷言。原BOOT／MAIN的stock recipe仍未映射測試位址18305000，實體page與硬體translation未證明。</p>'
    card += '<p>原malloc前綴及24個既有區域的actual terminal after已獨立核對，但48／8-byte配置仍未返回。8192-byte private pool在離線條件下耗盡，下一步須取得可驗證的page與table來源。歷史audit曾留下前輪快取雜湊；舊檔保留，本輪以新讀回與實際served bytes核對。</p>'
    card += '<p>整體里程碑估計33%、App整合20%，完整研究目標持續。可還原程式標記包尚未安裝；配對立即優先、麥克風取消、音質擱置，Android Auto排後、Google Maps暫緩。</p></div>'
    report, count = re.subn(r'<div class="card"><h2>最新離線進展：原廠音源選取與完整音訊讀取已接通</h2>.*?</div>', lambda _: card, report, count=1, flags=re.S)
    assert count == 1
    old_next = prior_public['research_progress']['phases'][4]['next']
    old_row = '<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>' + html.escape(old_next) + '</td></tr>'
    assert report.count(old_row) == 1
    report = report.replace(old_row, '<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>' + html.escape(next_text) + '</td></tr>', 1)
    report, count = re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',
        lambda m: m[1] + m[2] + ''.join('<li>' + html.escape(x) + '</li>' for x in details) + m[3], report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'<p><strong>下一步：</strong>.*?</p>', lambda _: '<p><strong>下一步：</strong>' + html.escape(next_text) + '</p>', report, count=1)
    assert count == 1
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    iso = local.isoformat(timespec='seconds')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
            '<time id="' + name + '" datetime="' + iso + '">' + local.strftime('%Y/%m/%d %H:%M:%S') + '</time>', report, count=1)
        assert count == 1
    assert not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', report)
    assert 'REDACTED_PRIVATE_ID' not in report
    assert state['goal_status'] == 'active' and not state['goal_complete'] and state['required_work_remaining']
    assert not app['native_app_running'] and not app['direct_phone_music_verified']
    assert public['deep_research'] == state and task['last_goal_turn'] == state['last_goal_turn']
    register({SOURCE: immutable_sha(SOURCE), INPUT: immutable_sha(INPUT), PREPARATION: immutable_sha(PREPARATION)})
    latest = read('evidence/report-web-latest.json')
    service_before = service_now()

    # All scope/input/hash/HTML assertions above precede canonical mutations.
    for path, data in [('evidence/deep-research-state.json', state), ('evidence/task-state.json', task), ('reports/findings.json', public)]:
        write(path, data)
    (ROOT / 'reports/nuvi2565RT.html').write_text(report)
    canonical_after = {path: fresh_sha(path) for path in ('evidence/deep-research-state.json',
        'evidence/task-state.json', 'reports/findings.json', 'reports/nuvi2565RT.html')}
    assert read('evidence/deep-research-state.json') == state
    assert read('evidence/task-state.json') == task and read('reports/findings.json') == public
    with urllib.request.urlopen(latest['url'], timeout=10) as response:
        served, status, cache = response.read(), response.status, response.headers.get('Cache-Control', '')
    served_sha = hashlib.sha256(served).hexdigest()
    assert status == 200 and 'no-store' in cache and served == report.encode()
    assert served_sha == fresh_sha('reports/nuvi2565RT.html') == canonical_after['reports/nuvi2565RT.html']
    service = service_now()
    assert service == service_before
    checks = dict(old1849_protected_registry_preserved=True, old49_complete_suites_preserved=True,
        old1733_native_dependencies_preserved=True, new10_MMU_cases_separate_from_completeboot=True,
        synthetic_tables_disabled_MMU_and_missing_final_GP_SP_CPSR_limits=True,
        stockcold_VA18305000_type0_unmapped_retained=True, heap48_8_allocation_return_unverified=True,
        new3_declaredmusic_cases48_complete_native_outer_returns=True,
        three_guestonly_BL_redirects_and_explicit_service_hardware_fixtures=True,
        independent72_tracked_69_trueRW_3_RXsentinel_replays_and_controller_RX_limits=True,
        no_native_exclusivity_STOP_DONE_decoder_phone_App_hardware_claim=True,
        immutable_v1_v4_terminal_failures_preserved=True, historical_cached_hash_erratum_preserved=True,
        uncached_canonical_and_local_served_hashes_match=True, weighted33_App20_and_active_goal=True,
        canonical_task_public_consistent=True, two_Taiwan_timestamps=report.count('datetime="' + iso + '"') == 2,
        HTTP200_no_store_exact=True, live_service_same_PID_no_restart=True, no_device_writes_or_sound=True)
    audit = dict(previous, updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=all(checks.values()),
        scope_checks=checks, previous_checkpoint=B + 'previous-audit.json', protected_sources=protected,
        selected_frozen_suites=suites, native_unique_exact_dependencies=1733,
        selected_original_software_fragment_suites=manifest['new_original_software_fragment_suites'],
        selected_declared_music_handoff_suites=manifest['new_music_declared_scoped_suites'],
        selected_new_findings=manifest['findings'], source_dependency_union_revalidated_once_before_write=True,
        historical_hash_cache_erratum=B + 'historical-publication-hash-cache-erratum.json',
        current_state_sha256=canonical_after['evidence/deep-research-state.json'],
        report_sha256=canonical_after['reports/nuvi2565RT.html'], canonical_after_sha256=canonical_after,
        local_report_sha256=canonical_after['reports/nuvi2565RT.html'], served_report_sha256=served_sha,
        canonical_readback_uncached=True, current_findings=len(app['static_findings']),
        current_public_details=len(progress['completed']), complete_Dispatcher_body_or_foreground_or_physical_App=False,
        physical_App_or_hardware_or_audio=False, full_goal_complete=False, goal_status='active')
    assert audit['all_passed']
    write(OUT, audit)
    latest.setdefault('historical_offline_checkpoint_audits', {})['prior_native_public_heap_audio_checkpoint'] = dict(
        audit=B + 'previous-audit.json', audit_sha256=immutable_sha(B + 'previous-audit.json'), all_passed=True,
        historical_cached_canonical_hash_erratum=B + 'historical-publication-hash-cache-erratum.json')
    latest.pop('current_native_public_heap_audio_checkpoint', None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(), HTTP_status=status,
        served_latest_report=True, local_report_sha256=fresh_sha('reports/nuvi2565RT.html'),
        served_report_sha256=served_sha, report_bytes=len(served), service=service,
        service_not_restarted=True, cache_control=cache, current_native_mmu_handoff_checkpoint=OUT,
        checkpoint_sha256={OUT: fresh_sha(OUT)}, goal_status='active', full_goal_complete=False,
        canonical_hash_readback_uncached=True)
    latest['complete_current_offline_run'].update(protected_source_count=len(protected),
        native_frozen_suites_revalidated=49, new_original_software_MMU_cases=10,
        actual_native_mixer_handoff_new_cases=3, physical_App_verified=False, device_io=False, sounds_emitted=False)
    latest['progress_display_verified'].update(estimate_percent=33, completed_items=len(progress['completed']),
        report_updated_time=iso, research_updated_time=iso, visual_browser_render_not_performed=True)
    write('evidence/report-web-latest.json', latest)
    assert read('evidence/report-web-latest.json')['local_report_sha256'] == fresh_sha('reports/nuvi2565RT.html') == served_sha
    print(json.dumps(dict(all_passed=True, findings=len(app['static_findings']), details=len(progress['completed']),
        protected_sources=len(protected), preserved_complete_suites=49, native_dependencies=1733,
        new_MMU_cases=10, new_music_declared_cases=3, estimate_percent=33, App_estimate_percent=20,
        updated_Taiwan=iso, HTTP_status=status, report_bytes=len(served), goal_status='active',
        local_and_served_report_sha256=served_sha, current_state_sha256=canonical_after['evidence/deep-research-state.json'])))


if __name__ == '__main__':
    main()
