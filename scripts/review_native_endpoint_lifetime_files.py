#!/usr/bin/env python3
"""Review sealed own C/H text only; never import or execute native producers."""
import gzip
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CAPTURES = ROOT / 'staging/native-music-callback-lifetime-readonly-20261007-v1'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def captured(path, limit=8192):
    with gzip.GzipFile(fileobj=io.BytesIO(path.read_bytes())) as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Capture exceeds finite source bound')
    return data


def main():
    manifest_raw = (CAPTURES / 'input-captures.json').read_bytes()
    manifest = json.loads(manifest_raw)
    if len(manifest['rows']) != 6 or manifest['fresh_original_bytes'] != 21486:
        raise ValueError('Unexpected reviewed capture set')
    texts = {}
    for row in manifest['rows']:
        raw = captured(CAPTURES / row['capture'])
        if len(raw) != row['bytes'] or digest(raw) != row['sha256']:
            raise ValueError('Capture changed: ' + row['path'])
        texts[row['path']] = raw.decode('utf-8')
    entry_path = ROOT / 'staging/native-music-frontend-membership-readonly-20261007-v1/resident-entry.c.gz'
    entry_raw = captured(entry_path)
    if digest(entry_raw) != '2fdc2a5899ba0f42485c13af80c09dee0eefc7fba32da6f2b60791b04bd19c3a':
        raise ValueError('Prior entry capture changed')
    endpoint = texts['native/music-endpoint/endpoint.c']
    gate = texts['native/avdtp-gate/gate.c']
    policy = texts['native/avdtp-policy/policy.c']
    release = gate.split('int music_gate_release(', 1)[1].split('static int rejection(', 1)[0]
    unbind = policy.split('int music_guard_unbind(', 1)[1].split('int music_guard_packet(', 1)[0]
    assertions = {
        'prepare_stores_callback_in_native_SEP': '*(volatile uint32_t *)s=callback;' in endpoint,
        'prepare_stores_module_caps_pointer_in_native_descriptor': '*(volatile uint32_t *)d=(uint32_t)music_endpoint_sbc_caps;' in endpoint,
        'prepare_publishes_SEP_state': 's[0x12]=1;' in endpoint,
        'gate_release_clears_only_its_local_binding_on_success': 'music_gate_bindings[seid-1u].callback=0;return 0;' in release,
        'gate_release_comments_require_separate_quiescence': 'require a separate quiescence' in release,
        'no_binding_configuration_delegates_to_stock': 'if(!owner)return ((stock_handler)0x00574acdu)' in gate,
        'policy_unbind_only_marks_guard_inactive': 'g->active=0;return 0;' in unbind,
        'endpoint_header_explicitly_supplies_no_unload_unregister': 'No unload/unregister path is supplied.' in texts['native/music-endpoint/endpoint.h'],
        'entry_contract_explicitly_disclaims_loader_pin': 'does not claim a loader pin or an unload protocol.' in entry_raw.decode('utf-8'),
    }
    if not all(assertions.values()):
        raise ValueError('Reviewed statements no longer match the sealed text')
    review = {
        'updated_utc': datetime.now(timezone.utc).isoformat(),
        'scope': 'Finite own C/H source contracts and prior cached entry text only; no compile, producer import, native binary, instruction, emulator, or device access',
        'capture_manifest_sha256': digest(manifest_raw),
        'fresh_original_source_bytes': manifest['fresh_original_bytes'],
        'source_pins': manifest['rows'],
        'prior_cached_entry': {'path': str(entry_path.relative_to(ROOT)), 'bytes': len(entry_raw), 'sha256': digest(entry_raw)},
        'exact_text_checks': assertions,
        'findings': [
            {'function': 'music_guard_unbind', 'source': 'native/avdtp-policy/policy.c', 'lines': [87, 91],
             'effect': 'Clears active for an exact current session and retains the session high-water mark; this is packet-policy state, not endpoint retirement.'},
            {'function': 'music_gate_release', 'source': 'native/avdtp-gate/gate.c', 'lines': [36, 44],
             'effect': 'Successful path clears only music_gate_bindings[seid-1].callback after checking the original SEP is idle and matches.',
             'not_cleared_by_this_function': ['native SEP callback pointer', 'native descriptor capabilities pointer', 'published SEP state', 'music_endpoint_owners', 'SDP publication'],
             'follow_on': 'Configuration dispatch without the local binding falls through to the original handler; this does not prove retirement or quiescence.'},
            {'function': 'music_endpoint_prepare', 'source': 'native/music-endpoint/endpoint.c', 'lines': [28, 43],
             'effect': 'Publishes a callback and module-owned capability pointer. Prior native bytes are stack-local rollback data for claim failure, not a retained unregister record.'},
            {'source': 'native/music-endpoint/endpoint.h', 'lines': [4, 9],
             'effect': 'The supplied contract requires code/callback/capabilities pinned until reboot and explicitly provides no unload/unregister path.'},
            {'source': 'staging/native-player-loaded-single-image/resident_entry_v1.c', 'lines': [1, 4, 20, 21],
             'effect': 'The added bootstrap contract says later voice loads can overwrite the fixed stock DLL buffer and disclaims a loader pin/unload protocol; its phase word is reloaded on each file load.'},
        ],
        'action_changed': 'Do not treat gate release or policy unbind as module unloading permission. A typed owner must retain code/data lifetime, retire native endpoint publication and drain callbacks/work before replacement, or prove a supported always-pinned design.',
        'limits': [
            'No complete candidate call graph or other generated lifecycle sources were reviewed here; this does not establish absence of an external retirement mechanism.',
            'No actual voice replacement, concurrent callback, stop completion, hardware audio, cold boot, or loader pin was tested.',
            'Source contract assertions are not native execution or installation validation.',
        ],
        'native_module_quiescence_verified': False,
        'native_endpoint_unregister_verified': False,
        'native_menu_App_or_direct_phone_A2DP_or_speaker_verified': False,
        'install_ready': False,
        'native_execution': False,
        'device_IO': False,
        'full_goal_complete': False,
    }
    destination = CAPTURES / 'callback-lifetime-review.json'
    if destination.exists():
        raise FileExistsError('Preserve the existing review')
    raw = (json.dumps(review, ensure_ascii=False, indent=2) + '\n').encode()
    destination.write_bytes(raw)
    print(json.dumps({'path': str(destination.relative_to(ROOT)), 'sha256': digest(raw),
                      'scope': 'Own source text only', 'source_text_matches': True,
                      'runtime_or_installation_success': False}, ensure_ascii=False))


if __name__ == '__main__':
    main()
