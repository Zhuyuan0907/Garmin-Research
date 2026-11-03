#!/usr/bin/env python3
"""Seal the completed finite source example; no source ledger or device reads."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

ROOT=Path('/root/garmin')
HERE=Path(__file__).resolve().parent


def save(name, value):
    raw=(json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode()
    with (HERE/name).open('xb') as handle:
        handle.write(raw);handle.flush();os.fsync(handle.fileno())
    return hashlib.sha256(raw).hexdigest()


def main():
    proof=json.loads((HERE/'proof.json').read_bytes())
    assert proof['all_assigned_checks_passed'] is True
    assert proof['candidate']['sha256']=='d26c874e67b87232836f0810acaaa5a779251481d853e5c31efc20ccfb4c817c'
    receipts=dict(schema='garmin-finite-source-example-actual-receipts/v1',
        created_utc=datetime.now(timezone.utc).isoformat(), all_assigned_checks_passed=True,
        final_preparation=dict(command=['python3','staging/navigation-native-new-street-source-example-v1/prepare_source_example.py'],
            environment={'PYTHONDONTWRITEBYTECODE':'1'},actual_terminal_chunk='9e1da2',actual_exit_code=0,
            tool_wall_seconds=0.197315893,source_inputs=len(proof['source_inputs']),
            actual_small_source_content_bytes_read=sum(r['bytes'] for r in proof['source_inputs']),
            script_self_hash_read_in_addition=True,source_group_content_bytes_read=0,
            no_full_source_EOF_or_full_source_SHA_claim=True),
        earlier_final_adaptive_prefix=dict(actual_terminal_chunk='dfd1a1',actual_exit_code=0,
            compressed_bytes_read=3145728,decompressed_bytes_produced=25165824,
            complete_rows=46470,gzip_EOF=False,unconsumed_compressed_tail_bytes=740947,
            receipt='final-source-prefix-budget-receipt.json'),
        earlier_exploratory_prefixes=dict(total_compressed_content_bytes_read=917504,
            terminal_chunks=['d1a81a','c38b1d','d10ebe','b90336'],all_actual_exit_codes=0,
            partial_prefix_reads=True,not_countrywide_or_source_EOF=True),
        auxiliary_inspection_failures=[
            dict(actual_terminal_chunk='f8411e',actual_exit_code=2,
                 reason='Initial filename lookup used absent helper names; corrected via bounded rg --files. No source ledger content read.'),
            dict(actual_terminal_chunk='240539',actual_exit_code=1,
                 reason='Family metadata inspection treated array rows as objects; corrected inspection7e5905 EXIT0 and final runner uses explicit arrays.')],
        independent_actual_family_receipt=dict(actual_terminal_chunk='a67d00',actual_exit_code=0,
            agent='native_address_candidate_check',source_snapshot='staging/navigation-native-jai-new-street-plan-v1/original-family-snapshot.json',
            sha256='929a52d912f1622f3aa9fecea8a8fc0d71517fed349a0f995e84d983e85f04d6',
            original_AP_bounded_bytes_read_by_other_agent=54456,
            original_DB_not_reopened_by_this_agent=True),
        final_output=dict(candidate_bytes=10020,
            candidate_sha256='d26c874e67b87232836f0810acaaa5a779251481d853e5c31efc20ccfb4c817c',
            proof_bytes=10086,proof_sha256='c9033395961cf1d13abaeea76881d479070630abdc189e3580d8630d18db9c3d'),
        pending_alias_prototype_only=True,district_geometry_not_proved=True,
        device_IO=False,sealed_v3_mutated=False,new_native_data_emitted=False,
        all_open_source_handles_closed=True,full_Taiwan_native_update_complete=False)
    save('actual-receipts.json', receipts)
    files=[]
    for path in sorted(HERE.iterdir()):
        assert path.is_file(), 'Only bounded namespace files expected'
        assert path.name!='sealed-files.json'
        raw=path.read_bytes();path.chmod(0o444)
        files.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                          mode='0444'))
    sealed=dict(schema='garmin-finite-source-example-seal/v1',
                created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
                file_count=len(files),files=files,scope='This finite source example only; no v3 or native data mutation.')
    seal_sha=save('sealed-files.json',sealed);(HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True,file_count=len(files),seal_sha256=seal_sha,
                          source_example='staging/navigation-native-new-street-source-example-v1/candidate.json',
                          pending_alias_prototype_only=True,device_IO=False),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
