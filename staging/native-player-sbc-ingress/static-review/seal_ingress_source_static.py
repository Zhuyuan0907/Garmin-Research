#!/usr/bin/env python3
"""Seal NEW FILE-only review. No VM, old output mutation, or canonical writes."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BASE = Path(__file__).resolve().parent


def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def rel(p):
    return str(p.relative_to(ROOT))


def write(p, value):
    with p.open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


proof = BASE / 'ingress-source-v1-peer-review.json'
d = json.loads(proof.read_text())
assert d['all_passed'] and d['static_review_completed']
assert not d['guest_executed_by_reviewer'] and not d['device_io']
assert d['v1_ABI_erratum']['concrete_runtime_blocker_found']
assert not d['v1_ABI_erratum']['V1_source_safe_for_guest_without_repair']
assert d['V2_source_only_repair_addendum']['exact_V1_to_V2_change_checked']
sources = dict(d['source_sha256'])
sources[rel(Path(__file__).resolve())] = sha(Path(__file__).resolve())
for path, digest in sources.items():
    assert sha(ROOT / path) == digest, path
receipt = BASE / 'ingress-source-static-terminal-tool-receipt.json'
rd = json.loads(receipt.read_text())
assert rd['actual_tool_result']['exit_code'] == 0
assert rd['actual_tool_result']['chunk_id']
assert not rd['guest_executed']
outputs = {rel(proof): sha(proof), rel(receipt): sha(receipt)}
ledger = BASE / 'ingress-source-static-source-output-ledger.json'
write(ledger, dict(all_passed=True, source_sha256=sources, output_sha256=outputs,
                  static_only=True, guest_executed=False))
seal = BASE / 'ingress-source-static-seal.json'
write(seal, dict(all_passed=True, proof=rel(proof), proof_sha256=sha(proof),
                ledger=rel(ledger), ledger_sha256=sha(ledger), source_sha256=sources,
                output_sha256=outputs, static_only=True, guest_executed=False,
                concrete_V1_ABI_blocker_preserved=True, V2_addendum_source_only=True,
                actual_phone_ingress_verified=False, complete_player_verified=False))
for p in BASE.iterdir():
    if p.is_file():
        p.chmod(0o444)
print(json.dumps(dict(all_passed=True, proof=rel(proof), proof_sha256=sha(proof),
                      seal=rel(seal), seal_sha256=sha(seal), ledger_sha256=sha(ledger),
                      source_count=len(sources), guest_executed=False)))
