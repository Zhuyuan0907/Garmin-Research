#!/usr/bin/env python3
"""Seal new static outputs only; no VM imports/execution or old edits."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        while b:=f.read(1<<20):h.update(b)
    return h.hexdigest()

def rel(p):return str(p.relative_to(ROOT))
def main():
    proof=HERE/'original-mixer-sync-cold-initialization-contract.json'
    receipt=HERE/'original-mixer-sync-static-terminal-tool-receipt.json'
    ledger=HERE/'original-mixer-sync-static-source-output-ledger.json'
    seal=HERE/'original-mixer-sync-static-seal.json'
    assert not ledger.exists() and not seal.exists(),'New outputs only'
    p=json.loads(proof.read_text());r=json.loads(receipt.read_text())
    assert p['all_passed'] and not p['scope']['guest_execution']
    assert not p['scope']['VM_import_or_instantiation']
    assert r['actual_tool_result']['exit_code']==0
    emitted=json.loads(r['actual_tool_result']['output'])
    assert emitted['proof']==rel(proof) and emitted['proof_sha256']==sha(proof)
    sources=dict(p['source_sha256'])
    sources[rel(Path(__file__).resolve())]=sha(Path(__file__).resolve())
    for name,h in sources.items():assert sha(ROOT/name)==h,name
    outputs={rel(proof):sha(proof),rel(receipt):sha(receipt)}
    stamp=datetime.now(timezone.utc).isoformat()
    ledger.write_text(json.dumps(dict(all_passed=True,updated_utc=stamp,
        source_sha256=dict(sorted(sources.items())),output_sha256=outputs,
        proof_kind=p['proof_kind'],guest_execution=False,
        actual_file_analysis_chunk=r['actual_tool_result']['chunk_id'],
        actual_file_analysis_exit_code=0),indent=2)+'\n')
    outputs[rel(ledger)]=sha(ledger)
    seal.write_text(json.dumps(dict(all_passed=True,updated_utc=stamp,
        source_sha256=dict(sorted(sources.items())),output_sha256=outputs,
        static_analysis_only=True,complete_native_sync_runtime_suite_verified=False,
        actual_file_analysis_receipt=rel(receipt),actual_file_analysis_exit_code=0,
        frozen_files=[*outputs,*[rel(Path(__file__).resolve()),
                               rel(HERE/'analyze_original_mixer_sync_contract.py')],rel(seal)],
        immutable_prior_sources_or_proofs_modified=False,
        guest_execution=False,device_io=False,canonical_writes=False),indent=2)+'\n')
    for name,h in sources.items():assert sha(ROOT/name)==h,name
    for name,h in outputs.items():assert sha(ROOT/name)==h,name
    for path in [proof,receipt,ledger,seal,Path(__file__).resolve(),
                 HERE/'analyze_original_mixer_sync_contract.py']:path.chmod(0o444)
    print(json.dumps(dict(all_passed=True,proof=rel(proof),proof_sha256=sha(proof),
        seal=rel(seal),seal_sha256=sha(seal),ledger_sha256=sha(ledger),
        source_count=len(sources),guest_execution=False)))

if __name__=='__main__':main()
