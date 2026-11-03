#!/usr/bin/env python3
"""Freeze FILE-ONLY MMU/heap inputs for a new root-owned checkpoint publisher.

No guest imports, emulation, canonical mutation, HTTP, service or device actions.
Successful/terminal sources and evidence are read once and never regenerated.
Includes only finalized music handoff proof, actual ROOT terminal receipt and
independent file seal; prior failed guests remain explicit negative evidence.
"""
import ast
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
B = 'staging/native-player-mmu-handoff-checkpoint/'
H = 'staging/native-player-native-allocation/'
V = H + 'verification-v3/'
M = 'staging/native-player-mmu-software/'
SOURCE = B + 'prepare_publication_inputs_v2.py'
U = 'staging/native-player-mixer-handoff/'
I = U + 'verification-v5/'
PUBLISHER = 'scripts/publish_native_mmu_handoff_checkpoint_v1.py'
AUDIT = 'evidence/firmware-analysis/native-public-heap-audio-checkpoint-audit.json'
OLD_AUDIT_SHA = '57292255cbc3e9891eaa99a3bbb9aa62af42db69ac0489e56e79db06f87cde4d'
REGISTRY_FIELDS = ('source_sha256', 'dependency_sha256', 'verified_runtime_dependencies',
                   'artifacts_sha256', 'output_sha256', 'generated_sha256', 'sources')


def read(path):
    return json.loads((ROOT / path).read_text())


@lru_cache(None)
def sha(path):
    """A single hash per path, including the unchanged 3.88GB backup."""
    digest = hashlib.sha256()
    with (ROOT / path).open('rb') as handle:
        while chunk := handle.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def write_new(path, data):
    with (ROOT / path).open('x') as handle:
        handle.write(json.dumps(data, ensure_ascii=False, indent=2) + '\n')


def main():
    # Static self-inspection only: no local helper or guest module is imported.
    tree = ast.parse((ROOT / SOURCE).read_text())
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module)
    assert set(imports) <= {'ast', 'datetime', 'functools', 'hashlib', 'json', 'pathlib'}
    output = B + 'publication-inputs-v2.json'
    assert not (ROOT / output).exists(), 'Preserve frozen preparation; use a NEW source/namespace'
    assert not (ROOT / (B + 'previous-checkpoint.json')).exists(), 'Preserve existing snapshots'
    assert sha(AUDIT) == OLD_AUDIT_SHA

    state = read('evidence/deep-research-state.json')
    task = read('evidence/task-state.json')
    public = read('reports/findings.json')
    previous = read(AUDIT)
    app = state['native_app_music']
    progress = public['research_progress']
    assert state['goal_status'] == task['goal_status'] == 'active'
    assert not state['goal_complete'] and state['required_work_remaining']
    assert not app['native_app_running'] and not app['direct_phone_music_verified']
    assert public['deep_research'] == state and task['last_goal_turn'] == state['last_goal_turn']
    assert len(app['static_findings']) == 205 and len(progress['completed']) == 163
    assert progress['estimate_percent'] == 33 and progress['phases'][4]['estimate_percent'] == 20
    assert sum(p['weight'] * p['estimate_percent'] / 100 for p in progress['phases']) == 33
    assert previous['all_passed'] and len(previous['protected_sources']) == 1849
    assert len(previous['selected_frozen_suites']) == 49
    assert previous['native_unique_exact_dependencies'] == 1733
    # Historical cached audit values are preserved, not asserted as current.
    web = read('evidence/report-web-latest.json')
    assert previous['current_state_sha256'] == sha(H + 'previous-state.json')
    assert previous['report_sha256'] == sha(H + 'previous-report.html')
    assert previous['current_state_sha256'] != sha('evidence/deep-research-state.json')
    assert previous['report_sha256'] != sha('reports/nuvi2565RT.html')
    assert web['served_report_sha256'] == sha('reports/nuvi2565RT.html')
    assert web['local_report_sha256'] == previous['report_sha256']

    frozen = {}
    new_files = {}
    native_dependencies = {}

    def register(entries, destination):
        for path, digest in entries.items():
            assert isinstance(path, str) and isinstance(digest, str) and len(digest) == 64, path
            assert sha(path) == digest, path
            assert path not in destination or destination[path] == digest, path
            assert path not in frozen or frozen[path] == digest, path
            destination[path] = digest
            frozen[path] = digest

    # Retain the complete old registry; memoization avoids repeat backup hashes
    # when the same dependency appears in many suite or artifact registries.
    register(previous['protected_sources'], frozen)
    for suite in previous['selected_frozen_suites']:
        assert sha(suite['path']) == suite['sha256']
        d = read(suite['path'])
        assert d['all_passed'] and all(case['passed'] for case in d['cases'])
        register(d['source_sha256'], native_dependencies)
    assert len(native_dependencies) == 1733

    findings = {}
    artifacts = {}

    def include(path, passed=True):
        d = read(path)
        if passed:
            assert d['all_passed'] is True, path
        for field in REGISTRY_FIELDS:
            if isinstance(d.get(field), dict):
                register(d[field], new_files)
        for case in d.get('cases', []):
            if 'passed' in case:
                assert case['passed'] is True, path
            if 'path' in case:
                register({case['path']: case['sha256']}, new_files)
        register({path: sha(path)}, new_files)
        artifacts[path] = d
        return d

    def add(key, path, scope, evidence_type):
        assert key not in app['static_findings'] and key not in findings
        include(path)
        findings[key] = dict(path=path, sha256=sha(path), scope=scope,
                             pass_field='all_passed', evidence_type=evidence_type,
                             physical_App_or_audio_verified=False, device_io=False)

    snapshots = []
    snapshot_paths = [
        ('evidence/deep-research-state.json', B + 'previous-state.json'),
        ('evidence/task-state.json', B + 'previous-task.json'),
        ('reports/findings.json', B + 'previous-public.json'),
        ('reports/nuvi2565RT.html', B + 'previous-report.html'),
        (AUDIT, B + 'previous-audit.json'),
        ('evidence/report-web-latest.json', B + 'previous-web.json'),
    ]
    for original, snapshot in snapshot_paths:
        content = (ROOT / original).read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        assert digest == sha(original), 'Canonical changed during preparation: ' + original
        with (ROOT / snapshot).open('xb') as handle:
            handle.write(content)
        assert sha(snapshot) == digest
        snapshots.append(dict(original=original, snapshot=snapshot, sha256=digest))
    snapshot_manifest = dict(updated_utc=datetime.now(timezone.utc).isoformat(),
        snapshots=snapshots, state=dict(path=B + 'previous-state.json', sha256=sha(B + 'previous-state.json')),
        audit=dict(path=B + 'previous-audit.json', sha256=sha(B + 'previous-audit.json')),
        findings=205, public_details=163, estimate_percent=33, App_estimate_percent=20,
        goal_status='active', all_passed=True, file_only=True, canonical_write=False,
        no_HTTP_or_service_or_device_actions=True)
    write_new(B + 'previous-checkpoint.json', snapshot_manifest)
    write_new(B + 'preserved-native-dependency-registry.json', native_dependencies)
    write_new(B + 'preserved-protected-file-registry.json', previous['protected_sources'])
    for path in (SOURCE, B + 'previous-checkpoint.json', B + 'preserved-native-dependency-registry.json',
                 B + 'preserved-protected-file-registry.json', *(snapshot for _, snapshot in snapshot_paths)):
        register({path: sha(path)}, new_files)


    cache_sources = {path: sha(path) for path in (
        SOURCE, B + 'prepare_publication_inputs_v1.py', B + 'prepare-v1-terminal-tool-receipt.json',
        'scripts/publish_native_public_heap_audio_checkpoint.py',
        'scripts/publish_native_settings_scope_checkpoint_v2.py', AUDIT,
        H + 'previous-state.json', H + 'previous-report.html',
        B + 'previous-state.json', B + 'previous-report.html', B + 'previous-web.json')}
    # Static AST facts establish that cached sha was imported and used before
    # and after canonical writes. Actual stale values equal exact185 snapshots.
    old_publisher = ast.parse((ROOT / 'scripts/publish_native_public_heap_audio_checkpoint.py').read_text())
    assert any(isinstance(n, ast.ImportFrom) and n.module == 'publish_native_settings_scope_checkpoint_v2'
               and any(a.name == 'sha' for a in n.names) for n in ast.walk(old_publisher))
    helper = ast.parse((ROOT / 'scripts/publish_native_settings_scope_checkpoint_v2.py').read_text())
    assert any(isinstance(n, ast.FunctionDef) and n.name == 'sha' and any(
        isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name) and dec.func.id == 'lru_cache'
        for dec in n.decorator_list) for n in ast.walk(helper))
    write_new(B + 'historical-publication-hash-cache-erratum.json', dict(all_passed=True,
        pure_static_and_file_comparison=True, source_sha256=cache_sources,
        historical_published_audit=AUDIT, historical_audit_sha256=sha(AUDIT),
        stale_published_state_sha256=previous['current_state_sha256'],
        stale_published_local_report_sha256=previous['report_sha256'],
        actual_current205_state_sha256=sha(B + 'previous-state.json'),
        actual_current_report_sha256=sha(B + 'previous-report.html'),
        old_recorded_served_report_sha256=web['served_report_sha256'],
        stale_values_equal_previous185_snapshot_hashes=True,
        exact_cause='Old publisher imported lru_cached sha, hashed originals before writes and reused cached values after writes. Fresh served digest equals current local report.',
        old_audit_or_successful_publisher_modified=False, HTTP_recheck_performed=False,
        canonical_write=False, guest_execution=False,
        future_fix='NEW publisher uses explicit uncached canonical readback after mutations and fresh local/served comparison.'))

    rows = [
        ('native_public_heap_v3_independent_observed_prefix',
         H + 'gui-static/native-allocation-v3-observed-native-prefix-review.json',
         'FILE-ONLY review of terminal EXIT1/61dabd: actual24 inherited/7body/8FP/bank after snapshots,7 allocator frames,21 PUSH stores,13 allocator/mutex stores;48/8 malloc returns remain false.',
         'independent_terminal_prefix_file_review'),
        ('native_public_heap_private_page_next_contract',
         H + 'gui-static/native-allocation-v3-next-private-page-contract.json',
         'Static/file-observed correction:38806C is private-page pop, stopped before body; declared8192-byte pool exhausted. No pagepop return or physical backing; future extent/table inputs must be new explicit scope.',
         'static_next_input_contract'),
        ('native_MMU_input_contract_independent_review',
         V + 'native-MMU-input-contract-independent-review.json',
         'Independent static original-opcode and frozen-contract review; reuses completed GUI file proof without reexecuting partial replay or guest. Actual future L1/L2 bytes are missing; no malloc/App closure.',
         'independent_static_contract_review'),
        ('native_stock_BOOT_MAIN_table_provenance',
         V + 'table-provenance/stock-BOOT-MAIN-table-provenance.json',
         'Bounded stock BOOT/MAIN static table-producer provenance: original clear recipe and11 descriptor setups; synthetic VA18305000 remains type0/unmapped in this recipe. Hardware boot input and actual tables absent.',
         'bounded_original_static_provenance'),
        ('native_MMU_original_software_branch_cases',
         M + 'software-mapping-v2-proof.json',
         'Actual root EXIT0/538421:10 original software mapping branches using declared synthetic L1/L2 and disabled model MMU, with no function hooks/code patches. Type0 returns saved IRQ flags without mapping store; no heap or hardware translation.',
         'bounded_original_software_fragment_cases'),
        ('native_MMU_software_independent_file_review',
         M + 'software-mapping-v2-independent-file-verification.json',
         'FILE-ONLY EXIT0/ea8f2a:10 cases/74 CPUstores/14 table stores/607 original instructions/30 whole-zone replays. Complete post-return GP16/SP/CPSR was not serialized: final return only runtime-asserted; no full returned-register proof.',
         'independent_software_fragment_file_review'),
    ]
    rows.extend([
        ('historical_publication_cached_hash_erratum', B + 'historical-publication-hash-cache-erratum.json',
         'Historical publication metadata erratum:cached state/local-report digests equal185-finding snapshots; actual205 current bytes are freshly frozen. Oldaudit/publisher preserved; no previous runtime result invalidated.',
         'historical_publication_metadata_erratum'),
        ('native_mixer_handoff_ARM_build_v5', U + 'build-v5.json',
         'Freestanding ARM ET_EXEC13b3d117…/zero undefined symbols with raw PCM producer and frozen FIFO reader; not SBC decoder, complete player or installation candidate.',
         'bounded_ARM_companion_build'),
        ('native_mixer_source_kernel_handoff_v5_actual_three_cases', U + 'mixer-handoff-v5-proof.json',
         'Actual ROOT session3366 EXIT0/317e2a:original kernel created source/mixer tasks and scheduled handoff, selector and two fullpull branches use3 guest-only BL redirects;48 full returns,3072 music PCM+7680 silencebytes;fixtures and native ownership/STOP_DONE limits remain.',
         'declared_guest_scoped_kernel_and_audio_cases'),
        ('native_mixer_handoff_v5_independent_file_review', I + 'mixer-handoff-v5-independent-file-verification.json',
         'Independent FILE-ONLY3 cases:42368 CPUstores/42499 joint events/72 tracked-zone replays=69trueRW+3 unchangedRX return sentinels;48 full native/outer mixer returns. Those returned GP16/SP/CPSR serialized; ordinarycontroller RETURN endpoints and finalRX memorydump unavailable. No guest rerun or hardware proof.',
         'independent_declared_scoped_guest_file_review'),
    ])
    for row in rows:
        add(*row)

    support = [
        V + 'native-MMU-input-contract-independent-review-seal.json',
        V + 'native-MMU-input-contract-review-source-output-ledger.json',
        V + 'native-MMU-input-contract-review-terminal-tool-receipt.json',
        V + 'table-provenance/stock-BOOT-MAIN-table-provenance-seal.json',
        V + 'table-provenance/stock-BOOT-MAIN-table-provenance-terminal-tool-receipt.json',
        M + 'software-mapping-v2-independent-file-seal.json',
        M + 'software-mapping-v2-independent-source-output-ledger.json',
        M + 'software-mapping-v2-independent-verifier-terminal-tool-receipt.json',
        M + 'guest-v2-terminal-tool-receipt.json',
        M + 'guest-v2/inputs-at-run.json',
        M + 'guest-v2/runner-at-run.py',
        I + 'mixer-handoff-v5-independent-file-seal.json',
        I + 'mixer-handoff-v5-independent-source-output-ledger.json',
        I + 'mixer-handoff-v5-independent-terminal-tool-receipt.json',
        U + 'guest-v5-terminal-tool-receipt.json', U + 'build-v5-terminal-tool-receipt.json',
        U + 'static-review-v1/mixer-handoff-build-v4-source-and-priority-review.json',
        U + 'static-review-v1/mixer-handoff-build-v4-static-review-seal.json',
        U + 'static-review-v1/build-v4-static-review-source-output-ledger.json',
        U + 'static-review-v1/build-v4-static-review-terminal-tool-receipt.json',
        U + 'static-review-v1/runner-v4-and-reset-transport-peer-review.json',
        U + 'static-review-v1/runner-v4-and-reset-transport-peer-review-seal.json',
    ]
    for path in support:
        if path.endswith('.json') and not path.endswith('inputs-at-run.json'):
            include(path, passed='receipt' not in path)
        else:
            register({path: sha(path)}, new_files)
    register(read(M + 'guest-v2/inputs-at-run.json'), new_files)
    assert sha(M + 'guest-v2/runner-at-run.py') == sha(M + 'emulate_mapping_v2.py')

    observed = artifacts[rows[0][1]]
    contract = artifacts[rows[1][1]]
    independent_contract = artifacts[rows[2][1]]
    provenance = artifacts[rows[3][1]]
    software = artifacts[rows[4][1]]
    files = artifacts[rows[5][1]]
    assert observed['actual_guest_session'] == 27241
    assert observed['actual_guest_terminal_chunk'] == '61dabd'
    assert observed['actual_guest_terminal_exit_code'] == 1
    assert [len(observed[k]) for k in ('actual_inherited_whole_zone_replays',
           'actual_body_whole_zone_replays', 'actual_FP_whole_zone_replays')] == [24, 7, 8]
    assert observed['actual_native_allocator_body_frames'] == 7
    assert observed['actual_native_PUSH_CPU_stores'] == 21
    assert observed['actual_native_allocator_and_mutex_CPU_stores'] == 13
    assert not observed['genuine_native_handle_or_malloc48_8_return_verified']
    assert not observed['original_page_pop_body_executed']
    assert not observed['original_MMU_page_mapping_executed']
    assert contract['no_remaining_private_page_available_in_current_fixture']
    assert contract['current_fixture_private_bytes'] == 8192
    assert contract['page_pop_body_not_executed_at_this_boundary']
    assert not independent_contract['original_pagepop_or_mapping_executed']
    assert not independent_contract['native_malloc48_8_return_verified']
    assert independent_contract['equivalent_partial_replay_reexecuted'] is False
    assert provenance['fixture_virtual18305000']['not_covered_by_this_stock_cold_recipe']
    assert provenance['fixture_virtual18305000']['after_original_clear_and_recipe'] == 'type0/zero absent a separate later producer'
    assert provenance['RAM_size_producer']['hardware_word_captured'] is False
    assert not provenance['actual_table_before_after_available']
    assert len(provenance['first11_descriptor_argument_setups']) == 11
    assert software['all_passed'] and software['case_count'] == 10
    assert software['no_function_hooks_or_original_code_patches']
    assert not software['captured_original_boot_MMU_state']
    assert not software['real_hardware_MMU_page_backing_cache_TLB_or_native_heap_or_App_verified']
    guest_receipt = artifacts[M + 'guest-v2-terminal-tool-receipt.json']['tool_result']
    assert guest_receipt['exit_code'] == 0 and guest_receipt['chunk_id'] == '538421'
    assert 'session_id' not in guest_receipt
    seal = artifacts[M + 'software-mapping-v2-independent-file-seal.json']
    verifier_receipt = artifacts[M + 'software-mapping-v2-independent-verifier-terminal-tool-receipt.json']['tool_result']
    assert verifier_receipt['exit_code'] == 0 and verifier_receipt['chunk_id'] == 'ea8f2a'
    assert seal['actual_file_verifier_exit_code'] == 0 and seal['actual_file_verifier_terminal_chunk'] == 'ea8f2a'
    assert files['case_count'] == 10 and files['actual_original_CPU_stores'] == 74
    assert files['actual_original_table_stores'] == 14 and files['actual_original_instructions'] == 607
    assert files['whole_zone_case_replays'] == 30 and not files['actual_guest_rerun']
    assert files['frozen_runtime_source_checked_final_R0_saved_flags_SP_and_CPSR']
    assert not files['final_return_GP16_CPSR_SP_serialized']
    assert not files['final_return_registers_independently_readback_verified']
    assert not files['complete_native_return_state_proof']
    assert files['synthetic_L1_L2_inputs'] and files['model_MMU_disabled']
    missing = read(M + 'guest-v2/missing_L1_returns_without_mapping.json')
    assert missing['passed'] and missing['exact_table_store_count'] == 0
    assert missing['original_mapping_function_returned'] and missing['actual_IRQ_flags_and_SP_restored']
    assert missing['declared_synthetic_input']['L1_type'] == 0
    assert not missing['real_MMU_translation_or_physical_backing_or_cache_TLB_verified']


    music = artifacts[U + 'mixer-handoff-v5-proof.json']
    assert music['case_count'] == 3 and music['actual_original_kernel_source_and_mixer_handoff']
    assert music['three_guest_only_original_call_site_branches']
    assert not music['physical_speaker_phone_App_installation_or_complete_player_verified']
    assert not music['native_heap_mutex_exclusive_or_STOP_DONE_verified']
    receipt = artifacts[U + 'guest-v5-terminal-tool-receipt.json']
    assert receipt['started_session_id'] == 3366 and receipt['terminal']
    assert receipt['actual_terminal_result']['exit_code'] == 0
    assert receipt['actual_terminal_result']['chunk_id'] == '317e2a'
    assert 'session_id' not in receipt['actual_terminal_result']
    assert sha(U + 'mixer-handoff-v5-proof.json') == 'bbeece455499503f1eb8c26e257d6db427b649f914740150bcace782e306b954'
    build = artifacts[U + 'build-v5.json']
    assert build['undefined_symbols'] == [] and not build['complete_player_image']
    register({build['ELF']: build['ELF_sha256']}, new_files)
    assert build['ELF_sha256'] == '13b3d11761e107c0481903e8786d8d8ef28f078ed248ac91ca014838a5ea11a1'
    music_files = artifacts[I + 'mixer-handoff-v5-independent-file-verification.json']
    # The independent verifier's detailed limits are retained verbatim in its
    # selected proof, not broadened to all controller endpoints or final RX.
    assert music_files['all_passed'] and music_files['case_count'] == 3
    assert sha(I + 'mixer-handoff-v5-independent-file-verification.json') == '9ec61d88808c2658386613a4204105800f52f45b7be676b11460143761374a41'
    assert sha(I + 'mixer-handoff-v5-independent-file-seal.json') == '7df80d63a90481c428d51105a750c9217d327f034fb0be4bb375167c18b392b8'
    assert music_files['CPU_stores'] == 42368 and music_files['joint_events'] == 42499
    assert music_files['full_original_native_returns'] == 48
    assert music_files['tracked_whole_zone_case_replays'] == 72
    assert music_files['actual_RW_case_replays_from_frozen_permission_recipe'] == 69
    assert music_files['unchanged_RX_return_sentinel_case_replays'] == 3
    assert music_files['full_mixer_native_and_outer_return_GP16_CPSR_SP_serialized']
    assert not music_files['ordinary_controller_function_return_GP16_CPSR_SP_serialized']
    assert not music_files['complete_all_instruction_GP_or_controlflow_or_kernel_lifetime_proof']
    assert music_files['independent_after_declared_patches_RX_baseline_verified']
    assert music_files['explicit_46CC7A_original_syncwait_ack_tail_bypassed']
    assert not music_files['native_heap_mutex_exclusive_STOP_DONE_hardware_phone_App_installation_or_complete_player_verified']
    music_verifier_receipt = artifacts[I + 'mixer-handoff-v5-independent-terminal-tool-receipt.json']['tool_result']
    assert music_verifier_receipt['exit_code'] == 0 and music_verifier_receipt['chunk_id'] == '9ca580'
    assert 'session_id' not in music_verifier_receipt
    lineage = []
    lineage_sources = {}
    for version in range(1, 5):
        directory = U + f'guest-v{version}/'
        failure = read(directory + 'terminal-failure.json')
        old_receipt = read(U + f'guest-v{version}-terminal-tool-receipt.json')
        assert failure['all_passed'] is False
        assert old_receipt['actual_terminal_result']['exit_code'] == 1 and old_receipt['terminal']
        register(failure['source_sha256'], new_files)
        register(read(directory + 'inputs-at-run.json'), new_files)
        for path in (directory + 'terminal-failure.json', directory + 'inputs-at-run.json',
                     directory + 'runner-at-run.py', U + f'guest-v{version}-terminal-tool-receipt.json'):
            lineage_sources[path] = sha(path)
        for prior_case in failure['cases_completed']:
            assert prior_case['passed']
            lineage_sources[prior_case['path']] = prior_case['sha256']
        lineage.append(dict(version=version, terminal_exit_code=1,
            actual_terminal_chunk=old_receipt['actual_terminal_result']['chunk_id'],
            actual_error=failure['error'], completed_case_count=len(failure['cases_completed']),
            completed_cases=failure['cases_completed'], whole_guest_all_passed=False))
    assert [row['completed_case_count'] for row in lineage] == [0, 0, 0, 2]
    register(lineage_sources, new_files)
    build_failure = U + 'build-v1-terminal-failure-receipt.json'
    register({build_failure: sha(build_failure)}, new_files)
    for path in (U + 'ROOT-attempt-history-and-scope-v1.json', U + 'next-original-initializer-sync-contract-v1.json',
                 U + 'next-original-initializer-sync-contract-v2.json', B + 'parallel-agents-at-preparation.json'):
        register({path: sha(path)}, new_files)
    initializer_contract = read(U + 'next-original-initializer-sync-contract-v2.json')
    for version in (1, 2):
        register(read(U + f'next-original-initializer-sync-contract-v{version}.json')['source_sha256'], new_files)
    assert initializer_contract['original_sync_executed'] is False
    write_new(B + 'mixer-handoff-v1-v4-terminal-lineage-review.json', dict(all_passed=True,
        pure_frozen_file_review=True, source_sha256=dict(lineage_sources), terminal_attempts=lineage,
        preserved_build_v1_failure_receipt=build_failure,
        prior_v4_two_completed_cases_are_observed_prefix_only=True,
        original_failed_guest_results_relabelled_success=False, guest_execution=False,
        canonical_write=False, device_io=False))
    add('native_mixer_handoff_v1_v4_terminal_lineage', B + 'mixer-handoff-v1-v4-terminal-lineage-review.json',
        'FILE-ONLY immutable development history:v1/v2/v3 all terminal failures;v4 two valid completed cases precede actual revoke-case failure. Prior observations are not another allpass suite.',
        'frozen_negative_and_partial_terminal_lineage')
    register({PUBLISHER: sha(PUBLISHER), B + 'prepare_publication_inputs_v1.py': sha(B + 'prepare_publication_inputs_v1.py'),
              B + 'prepare-v1-terminal-tool-receipt.json': sha(B + 'prepare-v1-terminal-tool-receipt.json')}, new_files)

    details = [
        '第三輪原生配置的terminal檔案已獨立重建24個既有區域、7個body區域、8個FP區域及完整初始資料bank；原malloc有7個frame／21筆PUSH與13筆配置／鎖寫入，但48／8-byte配置尚未返回。',
        '38806C已核對為尚未執行body的private-page pop；目前8192-byte離線pool由4096-byte前綴與4096-byte descriptor頁耗盡。現場實體page與後續原生配置仍未知，不能用host指標替代。',
        '下一MMU輸入契約已由純檔案與原opcode獨立核對；原221D34分支需要明示L1／L2 before bytes。這輪不重跑guest，也不把新契約當作配置成功。',
        '原BOOT／MAIN的表格清除與11組mapping輸入已靜態追到來源；測試虛擬位址18305000在這份stock cold recipe仍為type0未映射。硬體RAM選擇值与實際啟動表格尚未讀出。',
        '原MMU軟體分支新增10組實際ARM案例，使用明示合成L1／L2且模型MMU停用；type0會恢復IRQ狀態後返回而不寫mapping。此結果不證明硬體translation、實體page、原生heap或App。',
        '10組MMU案例另由獨立純檔案核對74筆CPU stores、14筆table stores、607條原指令及30次整區重建；最終GP／SP／CPSR未序列化，只保留runtime返回斷言與原POP前證據，不能宣稱完整返回暫存器已獨立驗證。',
    ]
    details.extend([
        '歷史publisher的hash快取曾把前輪185-finding的state／local-report雜湊寫入本輪audit；實際205 findings與已served報告bytes保持正確。舊audit及來源不改，新publisher將以無快取讀回核對目前檔案。',
        '新增3組原生source／mixer工作交接案例：原kernel建立並用post／get／wait／context restore排程，source priority12、mixer priority23；3個guest-only原call-site跳轉接上新能力交接與FIFO，未改實機韌體。',
        '48次完整原fullpull／外層mixer返回共讀出3072bytes測試PCM及7680bytes靜音；reselection／reset後可繼續，本地Stop與實際profile transition會撤銷能力、拒絕新pull。hardware reset transport仍是沒有driver回覆的fixture。',
        '3組交接另由獨立純檔案核對42368筆CPU stores、42499共同事件及72次tracked-zone重建，其中69次真正RW、3次不變RX return sentinel；完整native／outer mixer返回有GP／SP／CPSR，普通controller RETURN並未每次序列化，其他RX只有runtime不變斷言與store history，無獨立finalRX dump。',
        'v1至v4失敗與actual terminal receipts完整保留；v4兩個已完成案例屬失敗前的局部觀察，不能列成全組成功。最新交接尚未串接既有SBC解碼器，實機手機／喇叭／App、原生獨占或STOP_DONE仍未完成；配置、mutex、硬體啟動與ring consumer仍有明示fixture。',
    ])
    manifest = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
        preparation_source=SOURCE, preparation_source_sha256=sha(SOURCE),
        evidence_type='FILE-ONLY frozen checkpoint publication inputs',
        canonical_snapshot=B + 'previous-checkpoint.json', canonical_before_counts=dict(
            findings=205, public_details=163, estimate_percent=33, App_estimate_percent=20),
        frozen_files_sha256=frozen, new_files_sha256=new_files, findings=findings,
        public_details=details, projected_counts=dict(findings=205 + len(findings), public_details=163 + len(details)),
        preserved_protected_registry=B + 'preserved-protected-file-registry.json',
        preserved_protected_file_count=1849, preserved_selected_frozen_suites=previous['selected_frozen_suites'],
        preserved_native_dependency_registry=B + 'preserved-native-dependency-registry.json',
        preserved_native_unique_exact_dependencies=1733, preserved_complete_suite_count=49,
        new_complete_cold_suites=[], new_original_software_fragment_suites=[dict(
            path=M + 'software-mapping-v2-proof.json', sha256=sha(M + 'software-mapping-v2-proof.json'),
            case_count=10, evidence_type='bounded original software fragment; synthetic tables/model MMU disabled')],
        actual_MMUs_only_scope=dict(guest_terminal_chunk='538421', guest_terminal_exit_code=0,
            independent_file_verifier_terminal_chunk='ea8f2a', independent_file_verifier_exit_code=0,
            cases=10, original_CPU_stores=74, original_table_stores=14, original_instructions=607,
            whole_zone_replays=30, final_GP_SP_CPSR_serialized=False,
            full_return_only_runtime_asserted=True, complete_native_return_state_proof=False,
            stock_cold_recipe_VA18305000_type0_unmapped=True, type0_returns_IRQ_flags_without_mapping_store=True,
            actual_native_heap_allocation_return=False, physical_App_or_hardware=False,
            actual_hardware_MMU_translation=False, device_io=False),
        music_handoff=dict(included=True, actual_ROOT_terminal_session=3366,
            actual_ROOT_terminal_chunk='317e2a', terminal_exit_code=0, case_count=3,
            actual_independent_file_verifier_terminal_chunk='9ca580',
            actual_independent_file_verifier_exit_code=0,
            full_native_and_outer_mixer_returns=48, original_CPU_stores=42368,
            joint_events=42499, whole_tracked_zone_replays=72, true_RW_replays=69,
            unchanged_RX_return_sentinel_replays=3, music_PCM_bytes=3072, silence_bytes=7680,
            source_priority_byte=12, mixer_priority_byte=23, guest_only_BL_redirects=3,
            actual_native_kernel_created_and_scheduled_source_mixer=True,
            full_native_outer_return_GP_SP_CPSR_serialized=True,
            every_ordinary_controller_return_GP_SP_CPSR_serialized=False,
            independent_final_RX_memory_dump_available=False,
            original_hardware_reset_transport_is_unacked_fixture=True,
            native_ownership_witness=-200, native_STOP_DONE=False,
            SBC_decoder_connected_to_new_handoff_module_or_actual_phone_or_App_or_hardware_speaker_verified=False,
            generic_mutex_opaque_allocator_hardware_activation_ring_consumer_are_fixtures=True,
            guest_executed_by_preparation=False, growing_temporary_case_JSON_read=False),
        new_music_declared_scoped_suites=[dict(path=U + 'mixer-handoff-v5-proof.json',
            sha256=sha(U + 'mixer-handoff-v5-proof.json'), case_count=3,
            scope='Declared guest-only call-site branches/native kernel; explicit services and hardware boundaries; not completecoldboot or real player.')],
        next_original_initializer_sync_contract=dict(path=U + 'next-original-initializer-sync-contract-v2.json',
            sha256=sha(U + 'next-original-initializer-sync-contract-v2.json'),
            original_sync_executed=False, next='Candidate3B9C54-to46CC7A wrapper grants capability before originalwait for new/existingM+78; original13 is already queued. Verify originalpost/genericmutex yield and message20/wait/ack next; static proposal only, not implemented or guest-verified.'),
        publication_constraints=dict(estimate_percent=33, App_estimate_percent=20,
            goal_status='active', full_goal_complete=False, native_App_or_phone_music_complete=False,
            canonical_write=False, HTTP_action=False, guest_execution=False,
            old_successful_sources_or_proofs_or_publishers_modified=False,
            old_protected_registry_preserved=True, old_dependency_registry_preserved=True),
        root_next_actions=[
            'Review this NEW frozen input manifest and actual preparation terminal receipt; do not run existing terminal/successful preparation or publishers.',
            'Review finalized3-case music proof and independent file seal; preserve v1-v4 terminal failures, ordinarycontroller endpoint and finalRX limits.',
            'Review scripts/publish_native_mmu_handoff_checkpoint_v1.py using frozen snapshots and merged dependencies; keep49 complete suites separate from10 bounded MMU/3 declaredmusic cases, and retain33%/App20%/goalactive.',
            'Before canonical mutation, validate exact canonical snapshot hashes, every new selected proof/seal, limits and final music outcome. Publish once only after all assertions pass.'
        ])
    write_new(output, manifest)
    # These originals were never write targets; bypass the digest cache for the
    # six small canonical endpoints to catch concurrent mutation before success.
    for row in snapshots:
        assert hashlib.sha256((ROOT / row['original']).read_bytes()).hexdigest() == row['sha256'], row['original']
    print(json.dumps(dict(all_passed=True, file_only=True, guest_execution=False,
        canonical_write=False, HTTP_action=False, new_findings=len(findings), public_details=len(details),
        preserved_protected_files=1849, selected_complete_suites=49, native_dependencies=1733,
        new_frozen_paths=len(new_files), merged_frozen_paths=len(frozen),
        preparation_source=SOURCE, preparation_source_sha256=sha(SOURCE),
        output=output, output_sha256=sha(output)), ensure_ascii=False))


if __name__ == '__main__':
    main()
