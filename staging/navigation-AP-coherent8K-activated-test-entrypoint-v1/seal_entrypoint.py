#!/usr/bin/env python3
"""Close this finite source-only scope; never open payloads or recipe."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LIMIT = 262144


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def stat(p):
    s = p.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink]


def main():
    require(not (HERE / 'sealed-files.json').exists(), 'Already sealed')
    paths = sorted(p for p in HERE.rglob('*') if p.is_file())
    require(all(p.suffix != '.img' and not p.name.endswith('.img.disabled') for p in paths), 'Unexpected IMG')
    require(all(p.name not in ('restore-layout.json.gz', 'virtual-old-v3-stock-restore-binding.json') for p in paths), 'Unexpected large sidecar')
    cache = {str(p.relative_to(HERE)): p.read_bytes() for p in paths}
    require(sum(map(len, cache.values())) <= LIMIT, 'Initial small output budget')
    build = json.loads(cache['source-build-proof.json'])
    tests = json.loads(cache['host-control-proof.json'])
    manifest = json.loads(cache['manifest.json'])
    binding = json.loads(cache['entrypoint-source-binding.json'])
    plan = json.loads(cache['PACKAGING.json'])
    require(build['all_assigned_checks_passed'] and tests['all_assigned_checks_passed'], 'Source/control proof')
    require(tests['methods'] == 9 and tests['failures'] == tests['errors'] == 0, 'Nine finite controls')
    require(all(build['same_function_AST'].values()), 'Unchanged non-loader functions')
    require(tests['synthetic_max_aggregate_data_bytes'] <= 8192 and tests['synthetic_max_injected_metadata_bytes'] <= 8192, 'Synthetic budget')
    for name, key in (('install_native_house_supplement.py', 'entrypoint'), ('manifest.json', 'manifest'), ('entrypoint-source-binding.json', 'source_binding')):
        require(len(cache[name]) == build[key]['bytes'] and sha(cache[name]) == build[key]['sha256'], 'Exact tested ' + name)
    require(sha(cache['test_entrypoint.py']) == tests['test_sha256'], 'Exact tested test source')
    require(manifest['bundle_input_inventory'] == binding['bundle_input_inventory'] == build['bundle_input_inventory'], 'Whole inventory parity')
    require(len(plan['files']) == 15 and len(manifest['bundle_input_inventory']) == 12, 'Runtime inventory coverage')
    for row in plan['files']:
        name = row['bundle_path']
        if name in cache:
            require(len(cache[name]) == row['bytes'] and sha(cache[name]) == row['sha256'], 'Packaging small-file pin ' + name)
    stable = []
    for row in build['inputs']:
        if row['path'].startswith(str(HERE.relative_to(ROOT)) + '/'):
            continue
        p = ROOT / row['path']
        require(stat(p) == row['stat'], 'Closed source stat changed: ' + row['path'])
        stable.append(row['path'])
    receipts = {
        'schema': 'coherent8K-activated-entrypoint-actual-tools/v1',
        'tools': [
            {'chunk_id': 'e98de6', 'exit_code': 0, 'purpose': 'new source/manifest/detached binding build', 'wall_time_seconds': 0.000019037},
            {'chunk_id': '2d4264', 'exit_code': 0, 'purpose': '9 finite host controls', 'wall_time_seconds': 0.068470878,
             'terminal': 'Ran 9 tests in 0.032s\nOK'},
        ],
        'real_IMG_or_recipe_read': False, 'device_IO': False,
        'full_packet_load_manifest_executed': False,
    }
    proof = {
        'schema': 'coherent8K-activated-test-entrypoint-preparation-proof/v1',
        'all_assigned_checks_passed': True,
        'scope': 'new activated source/manifest and finite host guards; no production payload load or installation',
        'source_build_sha256': sha(cache['source-build-proof.json']),
        'host_control_proof_sha256': sha(cache['host-control-proof.json']),
        'entrypoint': build['entrypoint'], 'manifest': build['manifest'], 'source_binding': build['source_binding'],
        'packaging': {'bytes': len(cache['PACKAGING.json']), 'sha256': sha(cache['PACKAGING.json']), 'member_count': 15},
        'runtime_required_input_count': 12,
        'same_function_AST': build['same_function_AST'],
        'only_changed_function_from_preparation': 'load_manifest',
        'new_inventory_helper_sha256': sha(cache['coherent_bundle_inventory.py']),
        'whole_source_manifest_pins_are_detached_and_externally_sealed': True,
        'no_selfhash_cycle': True,
        'closed_external_small_source_stats_unchanged': stable,
        'methods_passed': 9,
        'source_build_measured_raw_input_bytes': build['raw_inputs_read'],
        'closure_measured_small_bytes_read': sum(map(len, cache.values())),
        'test_raw_read_total_instrumented': False,
        'scope_artifact_read_conservative_upper_bound_bytes': 2097152,
        'scope_artifact_read_bound_basis': 'build149632 + <=4 loader controls reading <=200KiB each + <=300KiB import/direct AST metadata + <=256KiB closure + <=64KiB inspection; standard-library modules excluded',
        'raw_artifact_limit_bytes': 3145728, 'recipe_read_bytes': 0, 'recipe_decoded_bytes': 0,
        'synthetic_max_aggregate_data_bytes': tests['synthetic_max_aggregate_data_bytes'],
        'synthetic_max_injected_metadata_bytes': tests['synthetic_max_injected_metadata_bytes'],
        'real_IMG_open_stat_read_link_chmod_write': False,
        'inherited_actual_stock_proof_sha256': 'e44ded4324705fc9482b60898edda790e6155a646a5d9e5d7b4a139e5f41aa8e',
        'inherited_actual_stock_source_seal_sha256': '0c6589d72116afc30cb575cc99b6cd366cedde48ae2875f70cbc5bf447ad6410',
        'inherited_root_success_tool': '835864 EXIT0',
        'inherited_pipeline_attempts': 2,
        'inherited_first_failure': 'ea061f: receipt sink missing extend; preserved host pipeline failure, not map/native rejection',
        'fresh_actual_map_or_stock_hash_this_scope': False,
        'old_preparation_review_only': {'review_sha256': '010f653c3a4c9e02d6f7ead010b5855d2f9c1567021037103c99b3d5ac91f0ff',
                                        'seal_sha256': 'a4274ba746b73f1c460b667147bf9588512f4776e22f658314a87d0e42904f21'},
        'new_activated_independent_review_passed': False,
        'complete_actual_packet_load_manifest_passed': False,
        'production_payload_sidecars_present': False,
        'installable': False, 'physical_UI_renderer_checksum_rootcause_verified': False,
        'device_IO': False, 'guest_native_firmware_audio_service_IO': False,
        'known_working_v2_recovery_requires_new_exact_source_rebind': True,
        'factory_rollback_loses_v2_supplemental_new_houses': 130637,
        'operation_lock_optional_workspace_lookup_preserved': True,
        'all_handles_closed': True,
    }
    handoff = '''# Activated coherent8K experimental test entrypoint

This NEW source scope is complete: source build e98de6 EXIT0 and 9 host control methods 2d4264 EXIT0. The controls include genuine missing-packet and old-preparation-manifest refusals; small memory fixtures do not establish full payload loading, physical transactions, renderer acceptance, or a repaired device.

Use PACKAGING.json as the exact 15-member same-directory copy plan. It records every packet-relative name, original source path, bytes, SHA256, and role. The manifest hard-pins 12 input members; the detached entrypoint-source-binding.json and external seal pin the entire NEW entrypoint and manifest without self-hash cycles. The packet/recovery wrapper must bind the detached source identity externally. Four restore/support Python helpers, control binding, and actual stock proof/source seal are byte-identical copies of closed preparation; only load_manifest changes among seven existing entrypoint functions. The new pure coherent_bundle_inventory.py is a fifth helper.

CLI and result ABI remain inherited: python3 install_native_house_supplement.py --bundle PATH --install or --rollback; default is preflight. Existing main/execute/transaction/image_state/device_preflight, protection, exact model/unit, predecessor, readback/unmount, source, and atomic rollback guards remain unchanged. The restore lookup uses same-directory inputs; inherited support.operation_lock still tries an optional workspace lock and has /run fallback.

Root next copies the small members and the pinned recipe/virtual-old-v3 binding, then adds actual9af candidate.disabled and Searchv2 road payloads while recording hardlink nlink/ctime changes. After new independent review, root freshly verifies complete same-directory load_manifest (actual coherent9af -> declared inverse1f468 -> unchanged strict helper stock864d full EOF). This scope did not stat/read/link/chmod any IMG or decode the recipe. Root actual proof e44ded records success835864; first ea061f ReceiptSink.extend failure is preserved, so the inherited pipeline is two attempts.

Factory rollback96739328/SHA864d removes130637 country-v2 supplemental houses. Known-working country-v2 128356352/SHA925a recovery is a separate exact-pinned phase2; the recovery agent must rebind phase1 to these NEW activated pins before packaging. A zero-exit waiting_for_usb response is not a completed restoration. No device call occurs in this preparation. Hardware/checksum policy, renderer/rootcause, complete Taiwan refresh, and installation acceptance remain unverified. Expanded4K8749 is a separate profile and is rejected by this fixed eightK catalog.

All old sources/seals remain unchanged. Stop after source sealing; root owns packet assembly, archive/publication, and later attended map test.
'''.encode()
    additions = {'actual-host-tool-receipts.json': encode(receipts), 'proof.json': encode(proof), 'HANDOFF.md': handoff}
    for name, raw in additions.items():
        require(not (HERE / name).exists(), 'Existing output ' + name)
        (HERE / name).write_bytes(raw)
        cache[name] = raw
    for name in cache:
        (HERE / name).chmod(0o444)
    rows = []
    for name, raw in sorted(cache.items()):
        p = HERE / name
        rows.append({'path': str(p.relative_to(ROOT)), 'bytes': len(raw), 'sha256': sha(raw), 'stat': stat(p), 'mode': '0444'})
    seal = {'schema': 'coherent8K-activated-test-entrypoint-source-seal/v1',
            'all_assigned_checks_passed': True, 'files': rows,
            'total_sealed_file_bytes': sum(r['bytes'] for r in rows),
            'source_and_control_scope_closed': True, 'full_actual_packet_validation_passed': False,
            'device_IO': False, 'all_handles_closed': True}
    raw = encode(seal)
    require(sum(map(len, cache.values())) + len(raw) <= LIMIT, 'Final output budget')
    (HERE / 'sealed-files.json').write_bytes(raw)
    (HERE / 'sealed-files.json').chmod(0o444)
    print(json.dumps({'all_assigned_checks_passed': True, 'seal_sha256': sha(raw), 'seal_bytes': len(raw),
                      'proof_sha256': sha(cache['proof.json']), 'proof_bytes': len(cache['proof.json']),
                      'output_bytes_with_main_seal': sum(map(len, cache.values())) + len(raw),
                      'packaging_sha256': sha(cache['PACKAGING.json']), 'packaging_bytes': len(cache['PACKAGING.json']),
                      'entrypoint': build['entrypoint'], 'manifest': build['manifest'],
                      'source_binding': build['source_binding'], 'device_IO': False, 'STOP': True}))


if __name__ == '__main__':
    main()
