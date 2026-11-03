#!/usr/bin/env python3
"""Observe saved actual old names; no native query/test or source DB replay."""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path

ROOT=Path('/root/garmin')
HERE=Path(__file__).resolve().parent


def sha(raw):return hashlib.sha256(raw).hexdigest()


def signature(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def pinned_json(path,expected,limit):
    before=signature(path);assert before[2]<=limit
    raw=path.read_bytes();after=signature(path);assert before==after and sha(raw)==expected
    return json.loads(raw),dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),
                               stat_before=before,stat_after=after,stat_unchanged=True)


def save(name,value):
    raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    with (HERE/name).open('xb') as handle:handle.write(raw);handle.flush();os.fsync(handle.fileno())
    return dict(path=str((HERE/name).relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))


def main():
    snapshot,source=pinned_json(ROOT/'staging/navigation-native-jai-new-street-plan-v1/original-family-snapshot.json',
        '929a52d912f1622f3aa9fecea8a8fc0d71517fed349a0f995e84d983e85f04d6',350000)
    earlier,earlier_binding=pinned_json(HERE/'proof.json',
        '7098cea3208a9f0faf9bbfe1f688b8a19dd6c25a96fbb268773a7a13c6c0c98b',10000)
    witness=next(r for r in snapshot['actual_tiny_prefix_segment_witnesses'] if r['character']=='敦')
    assert witness['index_record']=='tkfadgj' and witness['prefix_rows']==[]
    rows=[r for r in snapshot['old_info_rows'] if r['label'].startswith('敦')]
    assert {r['label'] for r in rows}=={'敦化路一段','敦化路二段','敦平一街','敦平二街','敦平街'}
    assert all(r['index_record'].startswith(witness['index_record']) for r in rows)
    infos={r['info_id'] for r in rows}
    full_FTS=[r for r in snapshot['old_FTS8_rows'] if r['record_info']>>8 in infos and
              r['index_record']==next(x['index_record'] for x in rows if x['info_id']==r['record_info']>>8)]
    assert len(full_FTS)==5
    observation=dict(schema='original-Dun-name-prefix-absence-observation/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        script_sha256=sha(Path(__file__).read_bytes()),actual_saved_original_family=source,
        actual_original_prefix_query=witness,actual_original_named_rows_starting_Dun=rows,
        actual_original_full_name_FTS8_tuples=full_FTS,
        exact_source_names_already_use_same_firstchar_and_encoded_token=True,
        single_char_prefix_row_required_for_all_streets_cannot_be_inferred=True,
        no_prefix_alone_does_not_prove_new_frontend_failure=True,
        original_frontend_success_for_these5_not_tested_here=True,
        prefix_table_semantics_or_fallback_resolved=False,
        earlier_handoff_prefix_blocker_wording_is_unproven_frontend_inference=True,
        concrete_next_gap='Locate actual SQL+0x2C/+0x30 reachable caller and its no-prefix behavior; determine whether prefix entry is mandatory, optional, compressed multi-char or a separate suggestion path.',
        original_DB_MAIN_device_opened=False,old_host_or_CPU_cases_replayed=False,
        official_alias_district_or_physical_newroad_verified=False)
    observation_artifact=save('prefix-segment-name-observation.json',observation)
    final=dict(schema='native-JAI-prefix-selected-adapter-final-proof/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        executed_adapter_and_SQL_diagnostic_proof=earlier_binding,
        later_saved_actual_name_observation=observation_artifact,
        source_inputs=[source],executed_focused_new_adapter_controls=8,
        original_MAIN_bounded_content_bytes_read_total=12288,original_DB_not_opened_or_copied=True,
        native_CPU_case_executed=False,original_prefix_segment_consumer_not_located=True,
        selected1444_FTS_scope_API_with_unrelated_rows_preservation_prepared=True,
        host_fixture_scope_only_not_complete_original_DB_certification=True,
        missing_Dun_prefix_does_not_alone_establish_frontend_failure=True,
        source_example_is_pending_alias_district_geometry_prototype=True,
        all_source_and_candidate_handles_closed=True,device_IO=False,
        sealed_v3_or_other_source_mutated=False,install_candidate=False,
        full_Taiwan_native_update_complete=False)
    final_artifact=save('final-proof.json',final)
    print(json.dumps(dict(all_assigned_checks_passed=True,existing_Dun_firstchar_streets=5,
                          no_prefix_failure_inference_rejected=True,observation=observation_artifact,
                          final_proof=final_artifact),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
