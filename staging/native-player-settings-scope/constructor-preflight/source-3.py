#!/usr/bin/env python3
"""Seal new native settings attempt from the actual terminal tool receipt."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
BASE = 'staging/native-player-settings-scope/runtime/'


def read(path):
    return json.loads((ROOT / path).read_text())


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def main():
    out = ROOT / BASE / 'terminal-metadata.json'
    assert not out.exists(), 'Preserve terminal metadata'
    receipt = read(BASE + 'terminal-tool-receipt.json')
    actual = receipt['actual_exec_result']
    assert 'session_id' not in actual and actual['exit_code'] in (0, 1)
    inputs, probe = read(BASE + 'inputs-before-run.json'), read(BASE + 'terminal-probe.json')
    for path, digest in inputs['source_sha256'].items():
        assert sha(path) == digest, path
    runner = 'scripts/probe_native_dispatcher_settings.py'
    snapshot = BASE + 'runner-at-run.py'
    assert sha(runner) == sha(snapshot) == inputs['source_sha256'][runner] == probe['source_sha256_before_run']
    assert actual['exit_code'] == (0 if probe['completed'] else 1)
    paths = dict(runner=runner, runner_snapshot=snapshot,
        inputs=BASE + 'inputs-before-run.json', probe=BASE + 'terminal-probe.json',
        FP_helper='scripts/native_dispatcher_multiowner_vfp.py',
        GUI_observer='staging/native-player-settings-scope/gui-static/settings_actor_observer.py',
        sealer=str(Path(__file__).resolve().relative_to(ROOT)),
        terminal_tool_receipt=BASE + 'terminal-tool-receipt.json')
    if probe.get('cold_prefix_evidence'):
        paths['cold_prefix'] = probe['cold_prefix_evidence']
        assert sha(paths['cold_prefix']) == probe['cold_prefix_evidence_sha256']
    metadata = dict(updated_utc=datetime.now(timezone.utc).isoformat(),
        session_id=receipt['session_id'], terminal_exit_code=actual['exit_code'],
        actual_exec_chunk=actual['chunk_id'], authoritative_terminal_result_received_from_exec=True,
        **paths, **{key + '_sha256': sha(path) for key, path in paths.items()},
        source_sha256=inputs['source_sha256'], completed=probe['completed'], phase=probe['phase'],
        error=probe.get('error'), cold_prefix_full_guards_passed=probe['cold_prefix_full_guards_passed'],
        body_full_guards_passed=probe['body_full_guards_passed'],
        callback_entry_seen=probe.get('callback_entry_seen', False),
        callback_return_seen=probe.get('callback_return_seen', False),
        post_cold_FP_rows=len(probe.get('original_lazy_handler_rows', [])) if probe.get('callback_entry_seen') else 0,
        device_io=False, sounds_emitted=False,
        physical_App_direct_music_or_package_acceptance_verified=False)
    with out.open('x') as handle:
        json.dump(metadata, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps({key: metadata[key] for key in (
        'session_id', 'terminal_exit_code', 'actual_exec_chunk', 'phase', 'error',
        'cold_prefix_full_guards_passed', 'callback_entry_seen', 'body_full_guards_passed')}))


if __name__ == '__main__':
    main()
