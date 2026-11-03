#!/usr/bin/env python3
"""Freeze FILE-ONLY MMU/heap inputs for a new root-owned checkpoint publisher.

No guest imports, emulation, canonical mutation, HTTP, service or device actions.
Successful/terminal sources and evidence are read once and never regenerated.
Music handoff is deliberately deferred to a NEW supplement after its terminal
receipt, proof and independent file seal are supplied by root.
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
SOURCE = B + 'prepare_publication_inputs_v1.py'
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
    output = B + 'publication-inputs-v1.json'
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
    assert previous['current_state_sha256'] == sha('evidence/deep-research-state.json')
    assert previous['report_sha256'] == sha('reports/nuvi2565RT.html')

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

    details = [
        '第三輪原生配置的terminal檔案已獨立重建24個既有區域、7個body區域、8個FP區域及完整初始資料bank；原malloc有7個frame／21筆PUSH與13筆配置／鎖寫入，但48／8-byte配置尚未返回。',
        '38806C已核對為尚未執行body的private-page pop；目前8192-byte離線pool由4096-byte前綴與4096-byte descriptor頁耗盡。現場實體page與後續原生配置仍未知，不能用host指標替代。',
        '下一MMU輸入契約已由純檔案與原opcode獨立核對；原221D34分支需要明示L1／L2 before bytes。這輪不重跑guest，也不把新契約當作配置成功。',
        '原BOOT／MAIN的表格清除與11組mapping輸入已靜態追到來源；測試虛擬位址18305000在這份stock cold recipe仍為type0未映射。硬體RAM選擇值与實際啟動表格尚未讀出。',
        '原MMU軟體分支新增10組實際ARM案例，使用明示合成L1／L2且模型MMU停用；type0會恢復IRQ狀態後返回而不寫mapping。此結果不證明硬體translation、實體page、原生heap或App。',
        '10組MMU案例另由獨立純檔案核對74筆CPU stores、14筆table stores、607條原指令及30次整區重建；最終GP／SP／CPSR未序列化，只保留runtime返回斷言與原POP前證據，不能宣稱完整返回暫存器已獨立驗證。',
    ]
    manifest = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
        preparation_source=SOURCE, preparation_source_sha256=sha(SOURCE),
        evidence_type='FILE-ONLY frozen checkpoint publication inputs',
        canonical_snapshot=B + 'previous-checkpoint.json', canonical_before_counts=dict(
            findings=205, public_details=163, estimate_percent=33, App_estimate_percent=20),
        frozen_files_sha256=frozen, new_files_sha256=new_files, findings=findings,
        public_details=details, projected_MMUs_only_counts=dict(findings=211, public_details=169),
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
        deferred_music_handoff=dict(included=False, success_claim=False, live_artifacts_read=False,
            requires='Root supplies finalized actual terminal receipt/proof and independent-file verification/seal; prepare a NEW supplement source, never rerun this preparation.'),
        publication_constraints=dict(estimate_percent=33, App_estimate_percent=20,
            goal_status='active', full_goal_complete=False, native_App_or_phone_music_complete=False,
            canonical_write=False, HTTP_action=False, guest_execution=False,
            old_successful_sources_or_proofs_or_publishers_modified=False,
            old_protected_registry_preserved=True, old_dependency_registry_preserved=True),
        root_next_actions=[
            'Review this NEW frozen input manifest and actual preparation terminal receipt; do not run existing terminal/successful preparation or publishers.',
            'After music handoff finishes, supply its actual ROOT terminal receipt/proof and independently sealed file verification; append only through a NEW supplement source/manifest.',
            'Create/review a NEW checkpoint publisher using frozen snapshots and merged dependencies; keep49 complete suites separate from10 bounded MMU cases, and retain33%/App20%/goalactive.',
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
