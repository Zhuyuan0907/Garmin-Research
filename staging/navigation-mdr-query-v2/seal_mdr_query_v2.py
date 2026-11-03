#!/usr/bin/env python3
"""Seal the completed new finite v2 MDR file review, without reopening IMG."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = Path(__file__).resolve().parent


def need(condition, message):
    if not condition:
        raise ValueError(message)


def small_read(path):
    need(path.is_file() and path.stat().st_size <= 2 * 1024 * 1024,
         'Seal only small frozen sources and results, never full IMG/backup')
    return path.read_bytes()


def digest(path):
    return hashlib.sha256(small_read(path)).hexdigest()


def read(relative):
    return json.loads(small_read(ROOT / relative))


def write_new(path, value):
    with path.open('x') as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def main():
    output = BASE / 'file-seal-v2.json'
    ledger = BASE / 'source-output-ledger-v2.json'
    need(not output.exists() and not ledger.exists(), 'Do not rerun completed sealer')
    proof_path = BASE / 'candidate-mdr-query-proof-v3.json'
    proof = json.loads(small_read(proof_path))
    receipt = read('staging/navigation-mdr-query-v2/candidate-mdr-query-v3-terminal-tool-receipt.json')
    failure = read('staging/navigation-mdr-query-v2/candidate-mdr-query-v2-terminal-failure-receipt.json')
    manifest_path = ROOT / 'staging/navigation-repair-v2/build-manifest.json'
    manifest = json.loads(small_read(manifest_path))
    need(digest(manifest_path) == '55b3a4ce14f9292b6bc923fa2405ea6b68f04410ba1adf7eb90a67d6ff9ad42b',
         'ROOT selected final manifest changed')
    need(proof['all_passed'] is True and len(proof['checks']) == 20 and
         all(value is True for value in proof['checks'].values()), 'Completed finite checks')
    need(receipt['actual_tool_result']['exit_code'] == 0 and
         receipt['actual_tool_result']['session_id'] == 87865 and
         receipt['actual_tool_result']['terminal_chunk_id'] == '9c3b4b' and
         receipt['actual_tool_result']['terminal'] is True, 'Actual terminal reader receipt')
    need(digest(ROOT / receipt['source']) == receipt['source_sha256'] == proof['source_sha256'],
         'Terminal successful reader source binding')
    need(digest(proof_path) == receipt['proof_sha256'], 'Terminal output binding')
    need(failure['all_passed'] is False and failure['actual_tool_result']['exit_code'] == 1 and
         failure['actual_tool_result']['chunk_id'] == 'ffd872' and
         digest(ROOT / failure['source']) == failure['source_sha256'], 'Preserved original reader failure')
    old = small_read(ROOT / failure['source']).decode()
    new = small_read(ROOT / receipt['source']).decode()
    expected = old.replace("        need(len(page_offsets) == 255, 'Selected writer must materialize all missing BMP pages')",
        "        missing_pages = [page for page, relative in self.pages.items() if relative == -1]\n"
        "        need(missing_pages == list(range(0xd8, 0xe0)) and len(page_offsets) == 247,\n"
        "             'Selected writer leaves only eight surrogate pages absent')")
    expected = expected.replace('candidate-mdr-query-proof-v2.json', 'candidate-mdr-query-proof-v3.json')
    expected = expected.replace('materialized_page_count=len(page_offsets), char_maxima=maxima,',
        'materialized_page_count=len(page_offsets), absent_surrogate_pages=missing_pages, char_maxima=maxima,')
    need(new == expected, 'New source changes limited to corrected page guard, metadata and new output')
    need(manifest['state'] == 'compiled_candidate_not_device_verified' and manifest['exit_code'] == 0,
         'ROOT terminal compiled candidate')
    need(proof['candidate']['path'] == manifest['image'] and
         proof['candidate']['bytes'] == manifest['image_bytes'] and
         proof['candidate']['ROOT_terminal_build_sha256'] == manifest['image_sha256'],
         'Inherited ROOT compiled candidate binding')
    need(manifest['image_sha256'] == '664c46c99697b61ba383b5571b0a49356336746c9bbf3f94403aae583787f117',
         'Selected ROOT candidate digest declaration')
    need(proof['candidate']['whole_IMG_hash_repeated'] is False and
         proof['candidate']['bytes_or_metadata_changed'] is False, 'No image digest replay or mutation')
    for flag in ['native_all_levels_compatibility_verified', 'native_Garmin_address_caller_verified',
                 'candidate_installation_or_device_search_verified', 'native_probe_executed_by_this_reader',
                 'full_instruction_semantics_or_UI_success_verified']:
        need(proof[flag] is False, 'Finite scope flag: ' + flag)
    srt = proof['SRT_metadata']
    need(srt['raw_flags'] == '0x6f02' and
         (srt['primary_bits'], srt['secondary_bits'], srt['tertiary_bits']) == (16, 10, 6),
         'Actual packed SRT decoder scope')
    need(srt['materialized_page_count'] == 247 and srt['absent_surrogate_pages'] == list(range(0xd8, 0xe0)) and
         srt['actual_char_records_checked'] == 63487 and srt['actual_expansion_records_checked'] == 2610,
         'Actual surrogate/page/record counts')
    controls = proof['finite_producer_controls']
    need(controls['path'] == manifest['producer_controls'] and
         digest(ROOT / controls['path']) == controls['sha256'] == manifest['producer_controls_sha256'],
         'Final Java producer controls binding')
    need((controls['Java_KEY_labels_checked'], controls['Java_CMP_level_comparisons_checked']) == (51, 69),
         'Finite producer controls:48 bounded labels plus3 host long-buffer controls;23pairsx3')
    need(controls['original_native_probe_rerun'] is False, 'No native probe replay')
    need(all(proof['target_reachability'][name]['Taichung_mdr20_count'] > 0 for name in
             ['民權路', '民和路一段', '民和路二段']), 'Three distinct Taichung names reachable')
    paths = [p for p in BASE.iterdir() if p.is_file() and p not in [output, ledger]]
    paths += [manifest_path, ROOT / 'staging/navigation-repair-v2/build-manifest-terminal-original.json',
              ROOT / 'staging/navigation-repair-v2/build-terminal-receipt.json',
              ROOT / 'staging/navigation-repair-v2/sort-verification.json',
              ROOT / controls['path'], ROOT / controls['root_finite_validation_path'],
              ROOT / controls['native_sort_source'],
              ROOT / 'staging/navigation-firmware-sort-v1/packed-shadow-source-receipt-v2.json',
              ROOT / 'staging/navigation-firmware-sort-v1/packed-shadow-src-v2/uk/me/parabola/imgfmt/app/srt/SRTFile.java']
    hashes = {str(path.relative_to(ROOT)):digest(path) for path in sorted(set(paths))}
    now = datetime.now(timezone.utc).isoformat()
    write_new(ledger, dict(sealed_utc=now, scope='Focused new small source/output dependencies only',
        sha256=hashes, source_count=len(hashes), whole_IMG_or_backup_digest_repeated=False,
        old_protected_registry_rehashed=False, old_MDR_v1_scope_rerun=False,
        excluded_self_referential_outputs=[str(ledger.relative_to(ROOT)), str(output.relative_to(ROOT))]))
    seal = dict(sealed_utc=now, all_passed=True, scope='File-only sealing of completed new v2 MDR reader evidence',
        proof=str(proof_path.relative_to(ROOT)), proof_sha256=digest(proof_path),
        successful_reader_source=receipt['source'], successful_reader_source_sha256=receipt['source_sha256'],
        actual_terminal_tool_receipt='staging/navigation-mdr-query-v2/candidate-mdr-query-v3-terminal-tool-receipt.json',
        actual_terminal_tool_receipt_sha256=digest(BASE / 'candidate-mdr-query-v3-terminal-tool-receipt.json'),
        ledger=str(ledger.relative_to(ROOT)), ledger_sha256=digest(ledger),
        checks_passed=20, finite_Java_producer_KEY_labels=51, finite_Java_CMP_level_comparisons=69,
        target_reachability=proof['target_reachability'],
        prior_failure_preserved=True, new_source_scopefix='Only D8..DF surrogate pages are absent; serialized247/index255',
        inherited_ROOT_candidate_sha256=manifest['image_sha256'], whole_IMG_digest_repeated=False,
        old_native_probes_or_NET_RGN_suite_rerun=False, old_protected_registry_rehashed=False,
        native_all_levels_compatibility_verified=False, native_Garmin_address_caller_verified=False,
        candidate_installation_or_device_search_verified=False, canonical_service_or_device_modified=False,
        limitations=proof['limitations'])
    write_new(output, seal)
    print(json.dumps(dict(all_passed=True, seal=str(output.relative_to(ROOT)), seal_sha256=digest(output),
        ledger=str(ledger.relative_to(ROOT)), ledger_sha256=digest(ledger), focused_small_dependencies=len(hashes)),
        ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
