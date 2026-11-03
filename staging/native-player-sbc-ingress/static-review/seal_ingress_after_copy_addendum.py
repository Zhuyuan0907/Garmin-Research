#!/usr/bin/env python3
"""Seal NEW lifetime addendum files only; no guest imports/execution."""
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


def write(p, d):
    with p.open('x') as f:
        json.dump(d, f, indent=2)
        f.write('\n')


proof = BASE / 'ingress-after-copy-lease-lifetime-addendum.json'
d = json.loads(proof.read_text())
assert d['all_passed'] and not d['guest_executed_by_reviewer']
assert d['preserved_failed_guest']['exit_code'] == 1
assert not d['after_copy_lease_contract']['callback_references0_is_full_native_callback_quiescence']
assert not d['native_module_quiescence_verified']
receipt = BASE / 'ingress-after-copy-addendum-terminal-tool-receipt.json'
rd = json.loads(receipt.read_text())
assert rd['actual_tool_result']['exit_code'] == 0 and not rd['guest_executed']
sources = dict(d['source_sha256'])
sources[rel(Path(__file__).resolve())] = sha(Path(__file__).resolve())
for path, digest in sources.items():
    assert sha(ROOT / path) == digest, path
outputs = {rel(proof): sha(proof), rel(receipt): sha(receipt)}
ledger = BASE / 'ingress-after-copy-addendum-source-output-ledger.json'
write(ledger, dict(all_passed=True, source_sha256=sources, output_sha256=outputs,
                  static_only=True, guest_executed=False))
seal = BASE / 'ingress-after-copy-addendum-seal.json'
write(seal, dict(all_passed=True, proof=rel(proof), proof_sha256=sha(proof),
                ledger=rel(ledger), ledger_sha256=sha(ledger), source_sha256=sources,
                output_sha256=outputs, static_only=True, guest_executed=False,
                preserved_ROOT_guest_v1_failed=True,
                current_pinned_after_lease_POST_source_contract_valid=True,
                native_callback_quiescence_verified=False,
                complete_player_verified=False))
for name in [
    'analyze_ingress_after_copy_lease_lifetime.py',
    'analyze_ingress_after_copy_lease_lifetime_v2.py',
    'ingress-after-copy-addendum-v1-premise-failure-receipt.json',
    'ingress-after-copy-lease-lifetime-addendum.json',
    'ingress-after-copy-addendum-terminal-tool-receipt.json',
    'ingress-after-copy-addendum-source-output-ledger.json',
    'ingress-after-copy-addendum-seal.json',
    'seal_ingress_after_copy_addendum.py',
]:
    (BASE / name).chmod(0o444)
print(json.dumps(dict(all_passed=True, proof=rel(proof), proof_sha256=sha(proof),
                      seal=rel(seal), seal_sha256=sha(seal), ledger_sha256=sha(ledger),
                      source_count=len(sources), guest_executed=False)))
