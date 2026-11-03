#!/usr/bin/env python3
"""Audit new metadata/predicate evidence, frozen builds and published scope."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from analyze_native_sections import NativeImage, ROOT
from emulate_native_memory_notice import check_manifest


def read(path):
    return json.loads((ROOT/path).read_text())


def digest(path):
    return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()


def main():
    stock = NativeImage()
    metadata_name = 'evidence/firmware-analysis/native-voice-metadata-emulation.json'
    enumeration_name = 'evidence/firmware-analysis/native-voice-enumeration-static.json'
    predicate_name = 'evidence/firmware-analysis/native-voice-predicate-emulation.json'
    proof, enumeration, predicate = [read(p) for p in
                                    (metadata_name, enumeration_name, predicate_name)]
    counts = {}
    for path in (metadata_name, enumeration_name, predicate_name,
                 'evidence/firmware-analysis/native-vpm-filesystem-emulation.json',
                 'evidence/firmware-analysis/native-vpm-filesystem-static.json',
                 'evidence/firmware-analysis/native-loaded-playback-emulation.json',
                 'evidence/firmware-analysis/native-app-component-emulation.json'):
        dependencies = read(path)['source_sha256']
        for source, expected in dependencies.items():
            assert digest(source) == expected, source
        counts[path] = len(dependencies)
    previous = read('evidence/firmware-analysis/native-source-worker-checkpoint-audit.json')
    builds = {}
    for name, expected in previous['compiled_manifests'].items():
        manifest = check_manifest(ROOT/'staging'/name/'manifest.json')
        assert manifest['elf_sha256'] == expected, name
        builds[name] = expected
    combined = []
    for path in sorted((ROOT/'staging/native-app-component-emulation').glob('*/manifest.json')):
        manifest = json.loads(path.read_text())
        for filekey, hashkey in (('extension_elf', 'extension_elf_sha256'),
                                ('extension_flat', 'extension_flat_sha256'),
                                ('combined_binary', 'combined_sha256')):
            assert digest(manifest[filekey]) == manifest[hashkey], manifest[filekey]
        for source, expected in manifest['source_sha256'].items():
            assert digest(source) == expected, source
        combined.append(str(path.relative_to(ROOT)))
    references = read('evidence/firmware-analysis/native-loaded-playback-checkpoint-audit.json')[
        'additional_reference_inputs_hashes_audited_after_run']
    for source, expected in references.items():
        assert digest(source) == expected, source
    packages = [p for p in read('evidence/firmware-analysis/tts-vpm-containers.json')['containers']
                if p['native_module_container']]
    for package in packages:
        assert digest(package['file']) == package['sha256'], package['file']
    cases = proof['cases']
    changes = {p['kind']: p for p in proof['memory_only_controls']}
    positive = ['dll_payload_changed_metadata_sum_stale', 'signature_content_zeroed',
                'checksum_tag_zero', 'checksum_tag_missing']
    negative = ['required_language_tag_missing', 'bad_END_marker', 'missing_END_member']
    state = read('evidence/deep-research-state.json')
    latest = state['native_app_music']['static_findings']['native_voice_metadata']
    report = (ROOT/'reports/nuvi2565RT.html').read_text()
    code_hash = hashlib.sha256(stock.read(0x274acc, 0x275c70-0x274acc)).hexdigest()
    scope = {
        'three_original_packages_pass_metadata': len(cases) == 3 and
            {p['voice'] for p in cases} == {Path(p['file']).name for p in packages} and
            all(p['metadata_status'] == 1 for p in cases),
        'original_DLL_and_package_hashes_match_backup': all(
            case['dll_sha256'] == package['files']['DLLIMG.BIN']['sha256'] and
            case['package_sha256'] == package['sha256'] for case, package in zip(cases, packages)),
        'original_metadata_parser_conversion_and_normalization_executed': all(
            p['metadata_parser_executed'] and
            all(p['original_functions_executed_before_module_load'][hex(a)] > 0
                for a in (0x275590, 0x274acc, 0x2734e6, 0x2fcd0a, 0x2fc9bc)) for p in cases),
        'three_original_loaders_return11_after_metadata': all(
            p['original_loader_after_metadata']['status'] == 11 for p in cases),
        'original_runtime_and40_interfaces_match_control': all(
            p['original_loader_after_metadata']['matches_independent_original_loader_control'] and
            p['original_loader_after_metadata']['original40_trampolines_match'] for p in cases),
        'all5_original_loader_callbacks_executed': all(
            len(p['original_loader_after_metadata']['file_callback_entries_executed_during_load']) == 5 and
            all(p['original_loader_after_metadata']['file_callback_entries_executed_during_load'].values())
            for p in cases),
        'exact_seven_memory_only_controls': len(changes) == 7 and set(changes) == set(positive+negative),
        'four_changed_controls_accepted_by_metadata_function': all(
            changes[k]['metadata_status'] == 1 for k in positive),
        'stale_DLL_sum_control_changes_content': not changes[positive[0]]['metadata_matches_dll_byte_sum'] and
            changes[positive[0]]['dll_sha256'] != cases[0]['dll_sha256'],
        'zero_SIG_control_preserves_DLL': changes[positive[1]]['signature_sha256'] == hashlib.sha256(bytes(72)).hexdigest() and
            changes[positive[1]]['dll_sha256'] == cases[0]['dll_sha256'],
        'zero_and_missing_checksum_native_values': changes[positive[2]]['parsed_checksum'] == 0 and
            changes[positive[3]]['parsed_checksum'] == 0xffffffff,
        'required_language_rejected_after_original_parser': changes[negative[0]]['metadata_status'] == 0 and
            changes[negative[0]]['metadata_parser_executed'],
        'bad_and_missing_END_rejected_before_parser': all(
            changes[k]['metadata_status'] == 0 and not changes[k]['metadata_parser_executed'] for k in negative[1:]),
        'metadata_opens_only_info_and_END': all(
            p['metadata_open_attempts'] and set(n.lower() for n in p['metadata_open_attempts']) <=
            {'dllinfo.txt', 'imgend.tst'} for p in cases+list(changes.values())),
        'changed_modules_never_initialized_or_executed': all(
            not p['modified_module_instructions_executed'] and p['original_loader_after_metadata'] is None and
            all(c['entry'] != '0x23c3c4' for c in p['native_calls']) for p in changes.values()),
        'native_record_and_heap_guards_closed': all(
            p['metadata_record_and_temporary_buffer_guards_intact'] and
            p['native_files_closed_and_temporary_heap_released'] for p in cases+list(changes.values())),
        'stock_metadata_code_unchanged': all(p['stock_metadata_code_sha256_before_after'] == code_hash
            for p in cases+list(changes.values())),
        'actual_pointer_query_and_noop_wrappers_executed': all(
            p['original_pointer_query_wrapper_executed'] > 0 and p['original_noop_wrapper_executed'] > 0 for p in cases) and
            stock.read(0x388b22, 2) == b'\x70\x47',
        'nine_complete_metadata_static_CFGs': len(proof['static_functions']) == 9 and all(
            not f['instruction_limit_reached'] and not f['unresolved_exits'] for f in proof['static_functions'].values()),
        'ten_complete_enumeration_static_CFGs': len(enumeration['functions']) == 10 and all(
            not f['instruction_limit_reached'] and not f['unresolved_exits'] for f in enumeration['functions'].values()),
        'two_outer_metadata_callers_and_additional_gate': enumeration['normal_Thumb_BL_metadata_call_candidates'][
            '0x275590'] == ['0x1d8632', '0x1d8a12'] and
            enumeration['metadata_success_alone_is_insufficient_for_registration'],
        'six_predicate_cases_cover_both_results': len(predicate['cases']) == 6 and
            [p['result'] for p in predicate['cases']] == [1, 0, 1, 0, 1, 1],
        'native_primary_cache_and_read_failure': predicate['cases'][3]['native_cache_after'] == 0xa1e and
            predicate['cases'][5]['storage_reads'][0]['return'] == 0xffffffff,
        'predicate_original_code_unchanged': all(p['original_code_unchanged'] and p['all_passed'] for p in predicate['cases']),
        'secondary_lazy_initializer_and_live_values_unverified': not predicate['secondary_lazy_initialization_executed'] and
            not predicate['actual_unit_storage_fields_or_predicate_result_verified'] and predicate['no_inference_that_key13A_is_HWID'],
        'complete_outer_selection_and_modified_acceptance_not_claimed': not enumeration['outer_enumeration_executed'] and
            not proof['outer_voice_enumeration_selection_and_signature_policy_verified'] and
            not latest['complete_outer_selection_or_modified_package_acceptance_verified'],
        'evidence_state_hashes_current': latest['evidence_sha256'] == digest(metadata_name) and
            latest['enumeration_evidence_sha256'] == digest(enumeration_name) and
            latest['predicate_evidence_sha256'] == digest(predicate_name),
        'report_and_state_current': read('reports/findings.json')['deep_research'] == state and
            '原廠高層資訊檢查已完成新一輪模擬' in report and '零值或缺少校驗欄位' in report,
        'frozen_playback_builds_and_references_preserved': len(builds) == 6 and len(combined) == 3 and
            counts['evidence/firmware-analysis/native-loaded-playback-emulation.json'] == 94,
        'no_actual_App_direct_music_or_goal_completion': not state['native_app_music']['native_app_running'] and
            not state['native_app_music']['direct_phone_music_verified'] and not state['goal_complete'],
        'goal_active_Maps_deferred_and_new_progress': state['goal_status'] == 'active' and
            state['google_maps']['research_deferred_by_user'] and state['required_work_remaining'] and
            state['last_goal_turn']['classification'] == 'progress',
        'no_device_IO_saved_VPM_or_install_candidate': not proof['device_io'] and not predicate['device_io'] and
            not proof['modified_vpm_saved'] and not proof['device_install_candidate'] and not predicate['device_install_candidate'],
    }
    assert all(scope.values()), {k: v for k, v in scope.items() if not v}
    result = {
        'updated_utc': datetime.now(timezone.utc).isoformat(), 'all_passed': True,
        'scope_checks': scope, 'dependency_counts_checked': counts,
        'state_sha256': digest('evidence/deep-research-state.json'),
        'report_sha256': digest('reports/nuvi2565RT.html'),
        'evidence_sha256': {p: digest(p) for p in (metadata_name, enumeration_name, predicate_name)},
        'unchanged_compiled_manifests': builds, 'unchanged_combined_manifests': combined,
        'legacy_reference_inputs_preserved': references,
        'audit_script_sha256': digest(str(Path(__file__).relative_to(ROOT))),
        'goal_status': 'active', 'full_goal_complete': False, 'device_io': False,
    }
    path = ROOT/'evidence/firmware-analysis/native-voice-metadata-checkpoint-audit.json'
    path.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'audit': str(path.relative_to(ROOT)), 'all_passed': True,
                      'scope_checks': len(scope), 'metadata_dependencies': counts[metadata_name],
                      'frozen_playback_dependencies': 94}))


if __name__ == '__main__':
    main()
