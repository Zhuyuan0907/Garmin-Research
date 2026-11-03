#!/usr/bin/env python3
"""Small runner spies only. Never imports or calls either real installer."""
import contextlib
import copy
import io
import json
from pathlib import Path
import recover_working_v2 as w

OUT = Path(__file__).resolve().parent

def reply(phase, already=False):
    rollback = phase == 1
    mode = 'rollback' if rollback else 'install'
    state = 'original' if rollback else 'candidate'
    size = w.STOCK['bytes'] if rollback else w.WORKING_V2['bytes']
    r = {'mode': mode, 'state': ('already_original_verified' if rollback else 'already_installed_verified')
         if already else ('rolled_back_exact_original_verified' if rollback else 'installed_readback_verified'),
         'manifest_sha256': w.PHASE1_PREPARATION_MANIFEST_SHA if rollback else w.PHASE2_MANIFEST_SHA,
         'physical_device_present': True, 'unmounted': True, 'bundle_candidate_and_rollback_verified': True,
         'device_path': w.TARGET, 'image_committed': not already, 'device_files_written': not already,
         'preflight': {'preserved_file_hashes_verified': True, 'image_state': state, 'image_bytes': size}}
    if not already:
        r['transaction'] = {'mode': mode, 'changed': True, 'committed': True, 'image_state': state,
            'destination_bytes': size, 'readback_verified': True, 'preserved_file_hashes_verified': True}
    return r

def main():
    results = []
    encoded_unique = set()
    def case(name, r1=None, r2=None, code1=0, expected_calls=1, success=False, role=None):
        calls = []
        def runner(command):
            calls.append(command)
            r = r1 if len(calls) == 1 else r2
            text = r if type(r) is str else json.dumps(r, separators=(',', ':'))
            encoded_unique.add(text.encode())
            return (code1 if len(calls) == 1 else 0), text
        ok = False
        try:
            value = w.run_sequence('/portable-packet', runner, w.roles() if role is None else role)
            ok = value['working_v2_restored'] is True
        except w.Refusal:
            pass
        if ok != success or len(calls) != expected_calls:
            raise ValueError(name)
        if calls:
            if calls[0] != w.commands('/portable-packet')[0]:
                raise ValueError('wrong phase-one CLI')
            if len(calls) == 2 and calls[1] != w.commands('/portable-packet')[1]:
                raise ValueError('wrong phase-two CLI')
        results.append({'name': name, 'passed': True, 'installer_spy_calls': len(calls), 'success_reply': ok})
    case('verified rollback then unchanged v2 install', reply(1), reply(2), expected_calls=2, success=True)
    case('already stock then already working v2', reply(1, True), reply(2, True), expected_calls=2, success=True)
    r = reply(1); r['state'] = 'waiting_for_usb'; r['physical_device_present'] = False
    case('zero exit waiting for USB is not rollback success', r)
    r = reply(1); r['unmounted'] = False
    case('unmount failure blocks second installer', r)
    case('nonzero phase one blocks second installer', reply(1), code1=1)
    r = reply(1); r['manifest_sha256'] = w.PHASE2_MANIFEST_SHA
    case('working-v2 manifest cannot stand in for stock rollback', r)
    r = reply(1); r['transaction']['destination_bytes'] = w.WORKING_V2['bytes']
    case('wrong rollback image-size role blocks phase two', r)
    r = reply(1); r['transaction']['readback_verified'] = False
    case('unverified stock readback blocks phase two', r)
    r = reply(1); r['recovery_required'] = True
    case('postcommit recovery requirement blocks phase two', r)
    r = reply(1); r['preflight']['preserved_file_hashes_verified'] = False
    case('protected roads verification missing blocks phase two', r)
    bad = w.roles(); bad['phase1_input']['sha256'] = w.OLD_VIRTUAL_V3_SHA
    case('virtual old-v3 SHA cannot replace coherent actual input', role=bad, expected_calls=0)
    bad = w.roles(); bad['phase2_input'], bad['phase2_output'] = bad['phase2_output'], bad['phase2_input']
    case('stock and working-v2 SHA roles cannot be swapped', role=bad, expected_calls=0)
    case('malformed JSON cannot advance', '{')
    r = reply(2); r['state'] = 'waiting_for_usb'
    case('phase-two zero exit waiting does not claim restored', reply(1), r, expected_calls=2)
    with contextlib.redirect_stdout(io.StringIO()) as captured:
        rc = w.main(['--packet', '/portable-packet', '--execute'])
    refusal = json.loads(captured.getvalue())
    if rc != 2 or refusal['installer_calls'] != 0 or refusal['IMG_operations'] != 0:
        raise ValueError('preparation execution gate')
    results.append({'name': 'public execute remains refused before installers and IMG', 'passed': True, 'installer_spy_calls': 0})
    synthetic_bytes = sum(len(b) for b in encoded_unique)
    if synthetic_bytes > 8192:
        raise ValueError('Synthetic reply budget exceeded')
    proof = {'schema': 'working-v2-recovery-host-spies/v1', 'all_controls_passed': True,
        'controls': results, 'unique_encoded_synthetic_reply_bytes': synthetic_bytes, 'synthetic_reply_cap': 8192,
        'largest_synthetic_reply': max(map(len, encoded_unique)), 'real_installer_imports_or_calls': 0,
        'real_IMG_operations': 0, 'device_operations': 0, 'actual_orchestration_executed': False,
        'preparation_success_replies_are_synthetic_and_cannot_be_emitted_by_current_phase_one': True}
    (OUT / 'host-spy-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps({'passed': len(results), 'synthetic_bytes': synthetic_bytes, 'device_operations': 0}))

if __name__ == '__main__':
    main()
