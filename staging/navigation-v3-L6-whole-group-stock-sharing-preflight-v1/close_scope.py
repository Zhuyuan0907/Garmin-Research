#!/usr/bin/env python3
"""Close this finite artifact-only predicate; do not reopen source gzip or IMG."""
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
reads = []


def read_json(name):
    path = BASE / name
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    reads.append({'name': name, 'bytes': len(raw), 'SHA256': hashlib.sha256(raw).hexdigest()})
    return json.loads(raw)


def write_json(name, value):
    (BASE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


audit = read_json('own-summary-audit-and-bound.json')
prep = read_json('final-document-preparation-read-counts.json')
counterexamples = audit['actual_allstockmatched_groups']
assert [(x['new_first'], x['new_count'], x['stockhit0_rows']) for x in counterexamples] == [
    (2020017, 5, 0), (2034445, 17, 0)]
assert sum(x['new_count'] for x in counterexamples) == 22
assert audit['wholegroup_optimistic_savings_bound']['sum'] == 10772
assert audit['wholegroup_optimistic_savings_bound']['required'] == 71359
raw_before = prep['cumulative_raw_bytes']
decoded_before = prep['cumulative_decoded_bytes']
# Explicit AST-only file read 481bfe occurred after preparation counters were saved.
# Account for that read here rather than hiding it in the earlier recorded totals.
ast_read_adjustment = 22017
raw_after = raw_before + ast_read_adjustment + sum(x['bytes'] for x in reads)
decoded_after = decoded_before + ast_read_adjustment + sum(x['bytes'] for x in reads)
assert raw_after < 6291456 and decoded_after < 67108864

falseflags = dict.fromkeys([
    'IMG_read', 'IMG_constructed', 'compactor', 'PBF', 'MAIN', 'nativeCPU', 'guest',
    'device', 'audio', 'App', 'native_backend_ownership', 'STOP_DONE', 'speaker',
    'install', 'renderer_fix', 'route_UI', 'full_goal'], False)
limits = [
    'No contiguous ordered original-stock donor sequence was identified for either counterexample.',
    'Source metadata and closed producer integration bind full emitted groups; no fresh actual/native incoming-reference census was performed.',
    'Unknown partial-range references, aliases, external lower-ID indices, caches and high-flag ABI remain held.',
    'Immutable stock donors need no byte writes and may already have incoming references; overlapping donor groups alone do not disqualify sharing. Every known clone incoming edge must be redirected before a clone can be discarded.',
    'This upper bound covers complete emitted v3 groups sharing into original-stock ranges only. It does not exclude partial splitting, free-run/in-place reuse, new encoding, expanded 4K/header controls or other formats.',
    '128 MiB is the original declared container capacity; this analysis does not establish a physical hardware limit or renderer cause.',
    'No addresses were removed and no candidate IMG was constructed.',
]

write_json('actual-main-terminal-receipt.json', {
    'receipt_type': 'recorded actual exec_command result',
    'command': 'python3 staging/navigation-v3-L6-whole-group-stock-sharing-preflight-v1/measure_group_predicate.py',
    'chunk_id': '175368', 'exit_code': 0, 'wall_time_seconds': 0.7472,
    'terminal_stdout_lines': [
        {'phase': 'streaming groupmetadata', 'groups': 5000, 'decoded_artifact_bytes': 5371870},
        {'phase': 'streaming groupmetadata', 'groups': 10000, 'decoded_artifact_bytes': 9461810},
        {'phase': 'streaming groupmetadata', 'groups': 15000, 'decoded_artifact_bytes': 13561451},
        {'phase': 'streaming groupmetadata', 'groups': 20000, 'decoded_artifact_bytes': 17636322},
        {'phase': 'streaming groupmetadata', 'groups': 25000, 'decoded_artifact_bytes': 21708180},
        {'all_assigned_artifact_checks_completed': True, 'all_original_group_rows': 29866,
         'L6groups': 4676, 'groups_with_stockhit0': 4674,
         'whole_v3_groups_excluded': False, 'old_v2_optimistic_bound': 10750,
         'required_rows': 71359, 'wholegroup_capacity_route_excluded_conditionally': False,
         'actual_raw_artifact_bytes': 4890625, 'actual_decoded_artifact_bytes': 25656713,
         'current_mm_peak_KiB': 26496, 'IMGreads': 0}],
    'semantics': 'The universal predicate is false; EXIT0 means assigned file checks completed, not successful stock reuse.',
    'original_proof_timing': 'proof.json copied resource counters before final completed=true; actual-file-handle-closure.json records final completed=true and both source handles closed.',
})
write_json('actual-own-summary-audit-terminal-receipt.json', {
    'receipt_type': 'recorded actual exec_command result',
    'command': 'python3 staging/navigation-v3-L6-whole-group-stock-sharing-preflight-v1/audit_selected_summary.py',
    'chunk_id': '6cf791', 'exit_code': 0,
    'terminal_stdout': {
        'ownsummary_audit_completed': True,
        'counterexamples': [{k: x[k] for k in ('new_first', 'new_count', 'new_integer_leaf_count', 'stockhit0_rows')} for x in counterexamples],
        'additional_v3_rows_optimistically_savable': 22,
        'loose_wholegroup_bound': 10772, 'required': 71359,
        'route_bound_insufficient_conditionally': True,
        'actual_raw_artifact_read_bytes': 5531800,
        'actual_decoded_artifact_bytes': 28482143, 'IMGread': 0},
    'no_source_gzip_or_IMG_reread': True,
})

write_json('conditional-capacity-bound-proof.json', {
    'schema': 'complete-emitted-L6-group-originalstock-sharing-conditional-bound/v1',
    'actual_main': {'chunk_id': '175368', 'exit_code': 0},
    'actual_own_summary_audit': {'chunk_id': '6cf791', 'exit_code': 0},
    'original_universal_predicate': False,
    'original_proof_and_result_preserved_without_mutation': True,
    'measured_groups': {'all': 4676, 'with_stockhit0': 4674, 'without_stockhit0': 2},
    'counterexamples': counterexamples,
    'counterexample_rows': 22,
    'finite_negative_predicate': 'A stockhit0 row has no exact 68-bit match anywhere in original-stock L6; an entire group containing that row cannot equal any ordered original-stock group.',
    'optimistic_complete_group_only_bound': {
        'prior_v2_poststock_all_rows_assumed_savable': 10750,
        'all_two_counterexample_groups_assumed_wholly_savable': 22,
        'maximum_rows': 10772, 'required_rows': 71359,
        'remaining_gap_rows': 60587, 'insufficient': True,
        'safe_actual_reuse_count': None,
        'meaning': 'An upper bound assuming both exceptional groups are fully reusable, not a donor or reference-safety proof.',
    },
    'bound_contract': [
        'Each emitted v3 L6 group is retained intact or redirected as a whole into an identical ordered original-stock range.',
        'Mixed groups are not split and their inserted address rows are not removed.',
        'Every v2 post-stock row may optimistically be saved even though this was not proved.',
        'The closed combined L4+L5 capacity arithmetic and original component/layout assumptions are retained.',
    ],
    'source_binding': {
        'groups_compressed_SHA256': 'c0dadf01b3197a332ce1bd9d430d61dd4fe4f729ccbf0053600b6f30c5d16fe3',
        'groups_decoded_SHA256': 'a0f365882e6d8916fc6fd4be5487226f6de3b6e37886161bfd90f4f57208ce05',
        'counter_compressed_SHA256': '17d910c60343f68d5ef3d565078de266dc757ab6456057d563c8fd6e1f65d4cf',
        'counter_decoded_SHA256': 'd66445f6a4cc1d45bce1d07583ced2cfb5f4e7161d6f04c5cd5fb834db64a842',
        'counter_global_ordinal': '1973317+i, i=0..89454; closed source flow plus actual counter uniqueness and digest',
        'whole_JSONL_EOF_groups': 29866,
        'L6_suffix': {'first': 1984067, 'last': 2062771, 'rows': 78705, 'inserted': 13615, 'cloned': 65090},
        'L6_explicit_child_pointer_patch_count': 0,
        'current_incoming_scope': 'Nominal emitted owner metadata and closed writer integration; not fresh actual/native reference inventory.',
    },
    'selected_summary_actual_read_pin': audit['selected_summary_actual_read_pin'],
    'holds': limits, 'falseflags': falseflags,
})

summary = {
    'scope': BASE.name, 'closed_finite_artifact_result': True,
    'actual_main_EXIT0': '175368', 'actual_summary_audit_EXIT0': '6cf791',
    'all_source_groups_parsed': 29866, 'L6_groups': 4676,
    'whole_v3_L6_universal_exclusion': False,
    'mixed_groups': 4674, 'counterexample_groups': [
        {k: x[k] for k in ('new_first', 'new_count', 'new_integer_leaf_count', 'stockhit0_rows')} for x in counterexamples],
    'optimistic_complete_group_only_savings_ceiling': 10772,
    'required_rows': 71359, 'shortfall_rows': 60587,
    'complete_group_only_branch_capacity_insufficient_conditionally': True,
    'ordered_stock_donor_and_actual_incoming_safety_proved': False,
    'source_and_original_result_unchanged': True,
    'source_handles_closed': True, 'raw_artifact_limit_bytes': 6291456,
    'decoded_artifact_limit_bytes': 67108864,
    'counts_before_final_sealing': {'raw': raw_after, 'decoded': decoded_after},
    'final_counts_file': 'sealed-files.json',
    'notes': [
        'The two exceptions are preserved; four inserted rows have stock hits, so inserted count alone never proved a per-group negative.',
        'EXIT0 reports completed file analysis, not address deletion or reusable donor acceptance.',
        'Original proof completed=false was a pre-final snapshot; separate actual-file-handle-closure completed=true is the final state.',
        'No byte capture or full IMG/source table was added.',
    ],
    'holds': limits, 'falseflags': falseflags,
}
write_json('scope-summary.json', summary)
assert (BASE / 'scope-summary.json').stat().st_size <= 8192
write_json('preseal-artifact-read-budget.json', {
    'scope': BASE.name, 'base_from_final_document_preparation': {'raw': raw_before, 'decoded': decoded_before},
    'explicit_AST_read_481bfe_adjustment': ast_read_adjustment,
    'actual_close_scope_small_reads': reads,
    'raw_artifact_bytes': raw_after, 'decoded_artifact_bytes': decoded_after,
    'raw_cap': 6291456, 'decoded_cap': 67108864,
    'counts_include_explicit_file_content_reads': True,
    'normal_python_interpreter_and_tool_stdout_reads_not_represented_as_source_artifact_reads': True,
    'IMGreads': 0,
})
(BASE / 'HANDOFF.md').write_text('''# Finite artifact-only L6 whole-group stock-sharing preflight

Closed main run `175368 EXIT0` parsed all 29,866 group rows and all 89,455 ordinal counters with full gzip digest/EOF/CRC and unchanged source stat. No IMG was read. The universal hypothesis is **false**: 4,674 of 4,676 v3 L6 groups contain a row without any original-stock 68-bit match. Two groups do not: new range 2020017/count5 and 2034445/count17, each with one inserted leaf. Their 22 rows are counterexamples, not proven contiguous stock donors.

Own output audit `6cf791 EXIT0` reread the 633,064-byte selected summary, verified compressed and decoded digest, and preserved both exceptions. Assuming all 10,750 prior-v2 tail rows plus all 22 exceptional v3 rows could be saved gives an optimistic whole-group-only ceiling **10,772**, below the closed capacity requirement **71,359** by **60,587**. This bounds only intact emitted-group sharing into original-stock ranges. It does not justify removing mixed-group addresses, exclude other layouts or demonstrate a hardware capacity limit.

Original `proof.json` and `result-summary.json` retain the false universal predicate and the initial non-derived capacity conclusion. The separate `conditional-capacity-bound-proof.json` records the stronger conditional bound from measured exceptions. The original proof resource snapshot says `completed:false` because it was copied before finalization; `actual-file-handle-closure.json` records `completed:true` and both source handles closed. No original source or old seal was changed.

Use `scope-summary.json` for the small report, `conditional-capacity-bound-proof.json` for the contract and holds, and `own-summary-audit-and-bound.json` for actual counterexample metadata. The selected summary carries counts and digests, with no labels, coordinates or copied original ledger. Final sealing reuses its already measured compressed SHA plus exact unchanged stat instead of rereading it. The manifest labels this exception explicitly; other small files are freshly hashed once. Final explicit artifact counters include the earlier 22,017-byte AST source read, omitted from the recorded preparation counters.

Immutable identical stock leaves can already have incoming references or overlap without byte mutation. Actual donor order, all clone incoming redirects, unknown partial-range references, alias/index/cache and high-flag ABI are still held. Closed producer metadata/full-append integration was reviewed, not a fresh runtime-reference census. No safe writer, IMG output, compactor, native CPU, MAIN, guest, PBF, device, audio, install, route/UI/render fix, App or full-goal completion is claimed. All music ownership/STOP_DONE/speaker claims remain false. Scope stops after final seal; further work requires a separate scope.
''')
print(json.dumps({'documents_complete': True, 'raw_artifact_bytes_before_seal': raw_after,
                  'decoded_artifact_bytes_before_seal': decoded_after,
                  'optimistic_savings_ceiling': 10772, 'required': 71359, 'IMGreads': 0}))
