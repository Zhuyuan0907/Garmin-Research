#!/usr/bin/env python3
"""Seal only the new single-district source geometry evidence."""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent


def sha(raw):return hashlib.sha256(raw).hexdigest()


def save(name,value):
    raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    with (HERE/name).open('xb') as handle:handle.write(raw);handle.flush();os.fsync(handle.fileno())
    return dict(path=str((HERE/name).relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))


def main():
    proof=json.loads((HERE/'proof.json').read_bytes())
    control=json.loads((HERE/'new-membership-control-proof.json').read_bytes())
    assert proof['all_assigned_geometry_preparation_checks_passed'] and control['all_assigned_new_wrapper_checks_passed']
    assert proof['source_and_exact_quantized_point_inside_same_source_district']
    assert control['control_count']==7 and len(proof['actual_external_commands'])==4
    receipt=save('actual-receipts.json',dict(schema='single-Beitun-source-geometry-actual-receipts/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        initial_preparation=dict(actual_terminal_chunk='f3656c',actual_exit_code=1,
            reason='Unsupported exactly-one-total-relation assertion; getid-r correctly included42 source subareas.',
            initial_script='failed-prepare-single-relation-assumption.py',failure_receipt='failed-assumption-receipt.json',
            actual_getid_commands_completed_exit0=True),
        corrected_preparation=dict(command=['python3','staging/navigation-beitun-district-geometry-v1/prepare_beitun_geometry.py'],
            environment={'PYTHONDONTWRITEBYTECODE':'1'},actual_terminal_chunk='80d17c',actual_exit_code=0,
            tool_wall_seconds=0.241164432,existing_extraction_reused=True,actual_check_refs_exit0=True,actual_export_exit0=True,
            source_small_admin_content_hash_passes_across_both_preparations=2,source_small_admin_bytes_per_hash_pass=4349834,
            getid_recursive_internal_source_read_passes_not_independently_traced=True,
            full_Taiwan_PBF_never_opened=True),
        new_wrapper_controls=dict(command=['python3','staging/navigation-beitun-district-geometry-v1/check_new_membership_api.py'],
            environment={'PYTHONDONTWRITEBYTECODE':'1'},actual_terminal_chunk='988247',actual_exit_code=0,controls=7,
            source_API_sha256='fa424f632cdc41b1e797e59f46246d5a1d0992749b0cd982338142d67e9fffb6',
            previous_geometry_or_CPU_suites_executed=False,temporary_corrupt_fixture_removed=True),
        source_relation=2959946,source_city_parent_relation=2921154,source_and_exact_raw24_same_district_gate=True,
        alias_or_official_street_validated=False,all_source_handles_closed=True,
        closed_fullDB_gap_proof_or_other_sealed_sources_mutated=False,device_IO=False,install_candidate=False))
    files=[]
    for path in sorted(HERE.iterdir()):
        assert path.is_file() and path.name!='sealed-files.json'
        raw=path.read_bytes();path.chmod(0o444)
        files.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),mode='0444'))
    seal=save('sealed-files.json',dict(schema='single-Beitun-source-district-geometry-seal/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        source_and_raw24_same_district=True,official_alias_or_street_not_proved=True,
        file_count=len(files),files=files,scope='One existing small-admin primary-source district and explicit parent membership only.'))
    (HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True,file_count=len(files),seal=seal,receipt=receipt,
        source_and_raw24_same_district=True,all_handles_closed=True,install_candidate=False),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
