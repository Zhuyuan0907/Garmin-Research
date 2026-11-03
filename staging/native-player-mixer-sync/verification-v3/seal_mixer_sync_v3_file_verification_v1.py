#!/usr/bin/env python3
"""Seal frozen independent FILE review; no guest imports or canonical writes."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, json
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def create(p,d):
    with p.open('x') as f:json.dump(d,f,indent=2);f.write('\n')
def main():
    proof=HERE/'mixer-sync-v3-independent-file-verification.json'
    receipt=HERE/'mixer-sync-v3-independent-terminal-tool-receipt.json'
    ledger=HERE/'mixer-sync-v3-independent-source-output-ledger.json'
    seal=HERE/'mixer-sync-v3-independent-file-seal.json'
    assert not ledger.exists() and not seal.exists()
    p=json.loads(proof.read_text());r=json.loads(receipt.read_text())
    assert p['all_passed'] and p['independent_FILE_ONLY']
    assert not p['VM_import_or_instantiation'] and not p['guest_rerun']
    assert r['terminal'] and r['actual_terminal_result']['exit_code']==0
    assert r['actual_terminal_result']['chunk_id']=='ba9584' and r['started_session_id']==69431
    emitted=json.loads(r['actual_terminal_result']['output'].strip().splitlines()[-1])
    assert emitted['proof']==rel(proof) and emitted['proof_sha256']==sha(proof)=='274a07d3606e4c046c0da6d41af21a6e1e89b62b383905815710cee41cd77a01'
    sources=dict(p['source_sha256'])
    sources[rel(Path(__file__).resolve())]=sha(Path(__file__).resolve())
    for name,h in sources.items():assert sha(ROOT/name)==h,name
    for name,h in {**r['source_sha256'],**r['output_sha256']}.items():assert sha(ROOT/name)==h,name
    outputs={rel(proof):sha(proof),rel(receipt):sha(receipt)}
    stamp=datetime.now(timezone.utc).isoformat()
    create(ledger,dict(all_passed=True,updated_utc=stamp,source_sha256=dict(sorted(sources.items())),output_sha256=outputs,
        independent_FILE_ONLY=True,actual_file_verifier_terminal_session=69431,actual_file_verifier_terminal_chunk='ba9584',actual_file_verifier_exit_code=0,
        actual_ROOT_guest_terminal_session=89948,actual_ROOT_guest_terminal_chunk='925a2b',actual_ROOT_guest_exit_code=0,guest_execution=False,canonical_write=False))
    outputs[rel(ledger)]=sha(ledger)
    create(seal,dict(all_passed=True,updated_utc=stamp,source_sha256=dict(sorted(sources.items())),output_sha256=outputs,
        independent_FILE_ONLY=True,complete_scoped_V3_joint_and_native_sync_file_verification=True,complete_original_cold_boot_or_kernel_lifetime_proof=False,
        actual_file_verifier_receipt=rel(receipt),actual_file_verifier_terminal_session=69431,actual_file_verifier_terminal_chunk='ba9584',actual_file_verifier_exit_code=0,
        CPU_stores=44931,joint_events=45065,full_original_native_returns=48,full_original_sync_returns=4,actual_original_condition_waits=4,actual_original_ACK8=4,
        tracked_whole_zone_case_replays=72,actual_RW_case_replays_from_frozen_permission_recipe=69,unchanged_RX_return_sentinel_case_replays=3,actual_final_RX_dump_case_zones=9,serialized_controller_idle_endpoint_snapshots=89,
        prior_V2_actual_suite_exit_code=1,prior_V2_completed_first_case_replayed_separately=True,prior_V2_counts_added_to_V3_totals=False,preserved_failed_FILE_verifier_count=5,
        immutable_prior_sources_or_proofs_modified=False,guest_execution=False,VM_import_or_instantiation=False,device_io=False,canonical_write=False,
        native_heap_exclusive_STOP_DONE_hardware_phone_App_installation_or_complete_player_verified=False,
        frozen_files=[*outputs,rel(Path(__file__).resolve()),rel(HERE/'verify_mixer_sync_v3_files_v6.py'),rel(seal)]))
    for name,h in sources.items():assert sha(ROOT/name)==h,name
    for name,h in outputs.items():assert sha(ROOT/name)==h,name
    for path in [proof,receipt,ledger,seal,Path(__file__).resolve(),HERE/'verify_mixer_sync_v3_files_v6.py']:path.chmod(0o444)
    print(json.dumps(dict(all_passed=True,proof=rel(proof),proof_sha256=sha(proof),seal=rel(seal),seal_sha256=sha(seal),ledger_sha256=sha(ledger),receipt_sha256=sha(receipt),source_sha256=sha(Path(__file__).resolve()),source_count=len(sources),guest_execution=False)))
if __name__=='__main__':main()
