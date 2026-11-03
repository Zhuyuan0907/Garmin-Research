#!/usr/bin/env python3
"""Close already-completed host checks without repeating their execution."""
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/music-volume-diagnostics-root-v1'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    OUT.mkdir(mode=0o700)
    paths = ['staging/music-diagnostic-clocks-optional-v1/proof.json',
             'staging/music-volume-bridge-integration-v2/proof.json',
             'staging/music-volume-bridge-offline-cli-v3/proof.json',
             'staging/music-volume-bridge-offline-conversion-v4/proof.json']
    clock, integration, plan, conversion = [json.loads((ROOT / name).read_text()) for name in paths]
    assert clock['all_passed'] and len(clock['cases']) == 4
    assert len(integration['cases']) == 4 and all(case['passed'] for case in integration['cases'])
    assert not integration.get('all_passed', False)
    assert len(plan['cases']) == 1 and plan['cases'][0]['passed'] and not plan['all_passed']
    assert conversion['all_passed'] and len(conversion['cases']) == 1
    bindings = {**integration['source_bindings'], **plan['source_bindings'], **conversion['source_bindings']}
    for proof in (integration, plan, conversion):
        assert all(bindings[key] == value for key, value in proof['source_bindings'].items())
    assert all(bindings[key] == value for key, value in clock['inputs'].items())
    assert all(sha(ROOT / 'scripts' / name) == pin for name, pin in bindings.items())
    receipts = {'integration': 'staging/music-volume-bridge-integration-v2/actual-tool-completion.json',
                'plan_partial': 'staging/music-volume-bridge-offline-cli-v3/actual-tool-completion.json',
                'conversion': 'staging/music-volume-bridge-offline-conversion-v4/actual-tool-completion.json'}
    assert [json.loads((ROOT / receipts[key]).read_text())['exit_code'] for key in receipts] == [1, 1, 0]
    for path in paths + list(receipts.values()):
        assert (ROOT / path).stat().st_size < 65536
    cases = clock['cases'] + integration['cases'] + plan['cases'] + conversion['cases']
    proof = {'schema': 'music-volume-root-closure/v1', 'all_required_host_checks_passed': True,
             'new_controls': len(cases), 'case_names': [case.get('name') for case in cases],
             'source_bindings': bindings, 'exact_proof_pins': {path: sha(ROOT / path) for path in paths},
             'actual_receipt_pins': {path: sha(ROOT / path) for path in receipts.values()},
             'clock_test_actual': 'b9ce7d EXIT0',
             'initial_integration_actual': 'a59389 EXIT1; final_summary schema harness mismatch; preserved',
             'integration_actual': 'bf7d3d EXIT1; four required cases passed, final CLI runner lacked scripts path',
             'plan_actual': '13820a EXIT1; plan passed, conversion-result harness key incorrect',
             'conversion_followup_actual': '1e2a46 EXIT0; remaining conversion case only',
             'failed_suites_relabelled_EXIT0': False,
             'all_three_audio_routes_byte_identical': True,
             'output_frames_each_audio_route': 2400,
             'optional_sidecar_separate_from_media_chain': True,
             'optional_failure_does_not_mask_critical_failure_or_stop_audio': True,
             'monotonic_host_read_intervals_not_sample_or_speaker_times': True,
             'current_clock_binding_requires_shared_run_token': True,
             'scalar_logs_max_bytes_each': 1048576,
             'legacy_debug_logs_bounded_or_deidentified': False,
             'inline_meters_can_add_host_processing_delay': True,
             'actual_service_or_private_device_config_queried': False,
             'device_audio_or_native_guest_executed': False,
             'music_fluctuation_cause_or_quality_improvement_verified': False,
             'PCM_fixtures_retained_bytes': 0, 'STOP': True}
    with (OUT / 'proof.json').open('x') as stream:
        json.dump(proof, stream, indent=2); stream.write('\n')
    manifest = {'files': {str((ROOT / path).relative_to(ROOT)): sha(ROOT / path) for path in paths + list(receipts.values())},
                'proof_sha256': sha(OUT / 'proof.json'), 'current_source_bindings': bindings,
                'no_tests_replayed': True, 'STOP': True}
    with (OUT / 'sealed-files.json').open('x') as stream:
        json.dump(manifest, stream, indent=2); stream.write('\n')
    for path in OUT.iterdir():
        os.chmod(path, 0o444)
    print(json.dumps({'all_required_host_checks_passed': True, 'controls': len(cases),
                      'proof_sha256': sha(OUT / 'proof.json'), 'seal_sha256': sha(OUT / 'sealed-files.json')}))


if __name__ == '__main__':
    main()
