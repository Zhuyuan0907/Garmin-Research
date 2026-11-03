#!/usr/bin/env python3
"""Review saved SDP JSON and public Android observations; no native execution."""
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/native-music-android-AVDTP-contract-readonly-20261007-v1'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def create(name, value):
    raw = json.dumps(value, ensure_ascii=False, indent=2).encode() + b'\n'
    path = OUT / name
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o444)
    return {'path': name, 'bytes': len(raw), 'sha256': digest(raw)}


def read(name, cap):
    path = OUT / name
    if path.stat().st_size > cap:
        raise ValueError('Saved input cap: ' + name)
    raw = path.read_bytes()
    return raw, {'path': name, 'bytes': len(raw), 'sha256': digest(raw)}


def main():
    packed, cache_pin = read('sdp-metadata-capture.json.gz', 20000)
    raw = gzip.decompress(packed)
    assert len(raw) == 82724
    assert digest(raw) == '1863ae6815194a99dec9aa225a6015c5c0abbe7f9cc6174e1030147a82f4396c'
    sdp = json.loads(raw)
    sink = next(r for r in sdp['records'] if r['handle'] == '0x90007')
    attrs = {a['id']: a for a in sink['attributes']}

    def pairs(attribute):
        return {a['value'][0]['value']: a['value'][1]['value']
                for a in attrs[attribute]['decoded']['value']}

    protocols = pairs(4)
    profiles = pairs(9)
    assert protocols == {0x100: 25, 25: 0x100}
    assert profiles == {0x110d: 0x100}
    observations_raw, observations_pin = read('aosp-observations.json', 6000)
    observations = json.loads(observations_raw)
    assert digest(observations_raw) == '8ea03f1fcb6d2fd523a81974f2a35b1c10b57c63b7177df2abc1957c96cfac83'
    assert observations[0]['facts']['GetAllCapabilities_requires_peer_and_local_version_at_least'] == '1.3'
    assert observations[1]['facts']['true_choice'] == 'GET_ALLCAP'
    assert observations[1]['facts']['false_choice'] == 'GETCAP'
    signals_raw, signals_pin = read('aosp-signals-actual-tool-receipt.json', 6000)
    assert digest(signals_raw) == 'eefde71e4a7a6a06b5028de5ab916cd76aab833a00eec893713b775bde8d80f7'
    signals_receipt = json.loads(signals_raw)
    assert signals_receipt['terminal']['exit_code'] == 0
    observed = json.loads(signals_receipt['terminal']['output'])
    defs = next(r for r in observed if r['url'].endswith('/avdt_defs.h'))
    assert defs['bytes'] == 7876
    identifiers = {}
    for row in defs['symbol_definitions']:
        match = re.match(r'#define\s+(AVDT_SIG_\w+)\s+(\d+)\b', row['value'])
        assert match
        identifiers[match.group(1)] = int(match.group(2))
    assert identifiers == {'AVDT_SIG_GETCAP': 2, 'AVDT_SIG_GETCONFIG': 4, 'AVDT_SIG_GET_ALLCAP': 12}
    versions_raw, versions_pin = read('aosp-versions-actual-tool-receipt.json', 6000)
    assert digest(versions_raw) == '56f3cfa4d055a4b7125ebb622104daf15ee8a27e421ffa70b46e22ee74739bd2'
    versions_receipt = json.loads(versions_raw)
    assert versions_receipt['terminal']['exit_code'] == 0
    assert json.loads(versions_receipt['terminal']['output'])['sources'] == observations
    now = datetime.now(timezone.utc).isoformat()
    ledger = {
        'schema': 'saved-template-and-Android-capability-choice-FILE/v1', 'updated_utc': now,
        'inputs': [cache_pin, observations_pin, signals_pin, versions_pin],
        'sdp_template': {'handle': '0x90007', 'class': 'Audio Sink', 'L2CAP_PSM': 25,
                         'AVDTP_version_uint16': 0x100, 'A2DP_profile_version_uint16': 0x100,
                         'source_metadata_sha256': digest(raw), 'source_metadata_bytes': len(raw),
                         'actual_device_service_activation_or_advertisement_verified': False},
        'public_Android': {'sources': observations, 'signal_definitions_source': {
            'url': defs['url'], 'bytes': defs['bytes'], 'sha256': defs['sha256'],
            'line_numbers': {r['value'].split()[1]: r['line'] for r in defs['symbol_definitions']}},
            'identifiers': identifiers, 'exact_Pixel_OS_build_or_live_traffic_inspected': False,
            'whole_AOSP_build_identity_across_two_commits_claimed': False},
        'conditional_inference': {
            'if_unchanged_template_advertised_and_phone_follows_reviewed_branch':
                'peer AVDTP 1.0 fails the >=1.3 condition; request uses GetCapabilities (2)',
            'GetConfiguration_4_is_GetAllCapabilities': False,
            'all_capabilities_12_proven_required_for_this_Pixel_or_this_device': False,
            'physical_A2DP_endpoint_or_negotiation_proven': False},
        'next_action': 'Verify actual service-version advertisement and ordinary GetCapabilities/SetConfiguration bindings before treating unreviewed signal12 as the cause. Do not advertise a higher version without its handlers.',
        'activity': {'original_firmware_ASM_MAIN_ELF_RAM_read': False, 'native_compile_import_guest': False,
                     'native_source_or_call_site_changed': False, 'device_BT_DBUS_audio': False,
                     'interrupted_guest_retry': False},
        'root_accounting_scope': {'SDP_source_body_reads': 2, 'SDP_source_body_bytes': 165448,
                                  'public_source_decoded_body_bytes': sum(r['bytes'] for r in observed) + sum(r['whole_source_bytes'] for r in observations),
                                  'entire_network_or_filesystem_IO_total_claimed': False,
                                  'prior_stat_cap_observation': {'chunk_id': '07f66b', 'exit_code': 1,
                                      'body_read': False, 'observed_metadata_size': 82724, 'cap': 65536},
                                  'later_fixed_metadata_cap': 98304, 'whole_turn_all_commands_passed': False},
        'native_install_ready': False, 'full_goal_complete': False,
    }
    ledger_pin = create('android-capability-choice-ledger.json', ledger)
    proof = create('proof.json', {'schema': 'Android-capability-choice-review-proof/v1',
                                'all_assigned_metadata_checks_passed': True, 'STOP': True,
                                'ledger': ledger_pin, 'source_template_version': 'AVDTP1.0/A2DP1.0',
                                'signal_ids': identifiers, 'conditional_inference_only': True,
                                'physical_test_or_native_execution': False, 'goal_complete': False})
    source = Path(__file__).read_bytes()
    create('reviewer-source-pin.json', {'path': str(Path(__file__).relative_to(ROOT)),
                                      'bytes': len(source), 'sha256': digest(source)})
    print(json.dumps({'all_assigned_metadata_checks_passed': True, 'proof_sha256': proof['sha256'],
                      'ledger_sha256': ledger_pin['sha256'], 'original_template_AVDTP': '1.0',
                      'signal4_is_GetConfiguration': True, 'signal12_is_GetAllCapabilities': True,
                      'GetAll_required_on_Pixel_proven': False, 'native_execution': False, 'device_IO': False}))


if __name__ == '__main__':
    main()
