#!/usr/bin/env python3
"""Host-only complete small-packet fixtures plus injected subprocess spies.

Approved digest constants are rebound IN TEST RAM to synthetic small metadata.
No actual installer import/execution, IMG, real device, or subprocess call.
The production source/binding files are never changed by these controls.
"""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import recovery_entrypoint as w

OUT = Path(__file__).resolve().parent
STUB = b'#fixture only\n'

def raw(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

def pin(path, data):
    return {'path': path, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

def manifest(phase):
    c = w.COHERENT_8K if phase == 1 else w.WORKING_V2
    value = {'device': {'part_number': '006-B1352-00', 'software_version': '800',
                        'unit_id_sha256': 'synthetic-not-a-device'},
        'preserved_stock_files': [{'device_path': '.System/gmapprom.img', 'bytes': 1, 'sha256': 'synthetic'}],
        'required_files': [w.SEARCH_V2], 'target': {'device_path': w.TARGET,
            'bundle_path': 'candidate/coherent8K-end-mirror.img.disabled' if phase == 1 else 'candidate/gmapprom1.img',
            'bytes': c['bytes'], 'candidate_sha256': c['sha256'], 'original_bytes': w.STOCK['bytes'],
            'original_sha256': w.STOCK['sha256'], 'accepted_predecessors': [{'state': 'original', **w.STOCK}]},
        'schema': 'synthetic-manifest-one' if phase == 1 else 'synthetic-manifest-two',
        'rollback': {'stock_recipe': {'synthetic': True}, 'virtual_old_v3_binding': {'virtual_candidate_sha256': w.VIRTUAL_V3}}
            if phase == 1 else {'synthetic': True}}
    if phase == 1:
        value.update(allowed_operation='controlled_physical_test', entrypoint_source_binding={
            'bundle_path':'entrypoint-source-binding.json', 'schema':'synthetic-owner-source-binding/v1'})
    return value

def make_fixture(root, mutate=None):
    # A mini complete inventory exercises the same schema/closure/hash logic.
    # Production's immutable approved binding contains all 18 real small files.
    phase1 = ['install_native_house_supplement.py', 'device_support.py', 'coherent_bundle_inventory.py',
              'manifest.json', 'entrypoint-source-binding.json']
    phase2 = ['install_native_house_supplement.py', 'device_support.py', 'manifest.json']
    files = {p + n: STUB for p, ns in [('coherent8k/', phase1), ('working-v2/', phase2)] for n in ns}
    m1, m2 = manifest(1), manifest(2)
    declared = {n: {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'role':'portable_helper'}
                for p,data in files.items() if p.startswith('coherent8k/')
                for n in [p.removeprefix('coherent8k/')]
                if n not in ('install_native_house_supplement.py','manifest.json','entrypoint-source-binding.json')}
    declared.update({'candidate/coherent8K-end-mirror.img.disabled':{**w.COHERENT_8K,'role':'candidate'},
                    'roadmap/Taiwan_OSM_SearchRepair_v2.img':{'bytes':w.SEARCH_V2['bytes'],
                    'sha256':w.SEARCH_V2['sha256'],'role':'road'}})
    m1['bundle_input_inventory'] = declared
    if mutate:
        mutate(m1, m2)
    files['coherent8k/manifest.json'] = raw(m1)
    files['working-v2/manifest.json'] = raw(m2)
    owner = {'schema': 'synthetic-owner-source-binding/v1', 'bundle_input_inventory':declared,
             'entrypoint': {'bundle_path':'install_native_house_supplement.py','bytes':len(STUB),
                           'sha256':hashlib.sha256(STUB).hexdigest()},
             'manifest': {'bundle_path':'manifest.json','bytes':len(files['coherent8k/manifest.json']),
                          'sha256':hashlib.sha256(files['coherent8k/manifest.json']).hexdigest()}}
    files['coherent8k/entrypoint-source-binding.json'] = raw(owner)
    inventory = [pin(p, data) for p, data in sorted(files.items())]
    index = {r['path']: r for r in inventory}
    binding = {'schema': 'garmin-working-v2-recovery-source-binding/v2', 'phase1_activated': True,
        'roles': {'phase1_input': w.COHERENT_8K, 'phase1_output': w.STOCK,
                  'phase2_input': w.STOCK, 'phase2_output': w.WORKING_V2},
        'small_inventory': inventory, 'required_small_paths': sorted(files),
        'phase1_manifest': index['coherent8k/manifest.json'], 'phase2_manifest': index['working-v2/manifest.json'],
        'phase1_entrypoint': index['coherent8k/install_native_house_supplement.py'],
        'phase2_entrypoint': index['working-v2/install_native_house_supplement.py'],
        'phase1_source_binding_path': 'coherent8k/entrypoint-source-binding.json',
        'phase1_source_binding_schema':owner['schema'], 'phase1_manifest_schema':m1['schema'],
        'phase2_manifest_schema':m2['schema'],
        'phase1_source_binding_links': [{'json_path': ['entrypoint','sha256'], 'expected': owner['entrypoint']['sha256']},
                                       {'json_path': ['manifest','sha256'], 'expected': owner['manifest']['sha256']}]}
    for relative, data in files.items():
        p = root / relative
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    b = raw(binding)
    (root / w.BINDING_NAME).write_bytes(b)
    w.APPROVED_BINDING_SHA = hashlib.sha256(b).hexdigest()
    w.V2_MANIFEST_SHA = binding['phase2_manifest']['sha256']
    w.V2_ENTRYPOINT_SHA = binding['phase2_entrypoint']['sha256']
    return binding, sum(map(len, files.values())) + len(b)

def reply(phase, binding, already=False):
    rollback = phase == 1
    mode = 'rollback' if rollback else 'install'
    state = 'original' if rollback else 'candidate'
    size = w.STOCK['bytes'] if rollback else w.WORKING_V2['bytes']
    r = {'mode': mode, 'state': ('already_original_verified' if rollback else 'already_installed_verified')
        if already else ('rolled_back_exact_original_verified' if rollback else 'installed_readback_verified'),
        'manifest_sha256': binding['phase1_manifest' if rollback else 'phase2_manifest']['sha256'],
        'physical_device_present': True, 'unmounted': True, 'bundle_candidate_and_rollback_verified': True,
        'device_path': w.TARGET, 'image_committed': not already, 'device_files_written': not already,
        'preflight': {'preserved_file_hashes_verified': True, 'xml_unit_verified': True,
                      'image_state': state, 'image_bytes': size}}
    if already:
        r['preflight']['image_sha256'] = w.STOCK['sha256'] if rollback else w.WORKING_V2['sha256']
    if not already:
        r['transaction'] = {'mode': mode, 'changed': True, 'committed': True, 'image_state': state,
            'destination_bytes': size, 'readback_verified': True, 'preserved_file_hashes_verified': True}
    return r

def main():
    saved = (w.APPROVED_BINDING_SHA, w.V2_MANIFEST_SHA, w.V2_ENTRYPOINT_SHA, w.standard_runner)
    results = []
    peak_fixture = 0
    peak_with_reply = 0
    def forbidden_runner(argv):
        raise AssertionError('Real subprocess runner must never be invoked')
    w.standard_runner = forbidden_runner
    try:
        with tempfile.TemporaryDirectory(prefix='synthetic-packet-', dir=OUT) as temporary:
            base = Path(temporary)
            def case(name, change_files=None, change_metadata=None, change_reply=None, runner_error=None,
                     expected_calls=0, success=False, already=False, cwd_change=False):
                nonlocal peak_fixture, peak_with_reply
                root = base / str(len(results))
                root.mkdir()
                binding, size = make_fixture(root, change_metadata)
                peak_fixture = max(peak_fixture, size)
                if change_files:
                    change_files(root, binding)
                calls = []
                def spy(argv):
                    nonlocal peak_with_reply
                    calls.append(argv)
                    if runner_error:
                        raise runner_error
                    value = reply(len(calls), binding, already)
                    if change_reply:
                        value = change_reply(value, len(calls))
                    text = value if type(value) is str else raw(value).decode()
                    peak_with_reply = max(peak_with_reply, size + len(text.encode()))
                    return 0, text
                previous = Path.cwd()
                try:
                    if cwd_change:
                        os.chdir(base)
                    value = w.execute(root, runner=spy)
                finally:
                    os.chdir(previous)
                ok = value['state'] == 'working_v2_recovery_verified'
                if ok != success or len(calls) != expected_calls:
                    raise ValueError(name + ': wrong success or calls')
                if calls and calls[0] != w.commands(root)[0]:
                    raise ValueError(name + ': wrong rollback argv')
                if len(calls) == 2 and calls[1] != w.commands(root)[1]:
                    raise ValueError(name + ': wrong install argv')
                if not ok and value['phase2_executed'] != (len(calls) == 2):
                    raise ValueError(name + ': false phase2 status')
                results.append({'name': name, 'passed': True, 'spy_calls': len(calls), 'successful_reply': ok})
            case('exact portable argv and complete inventory then two stages', expected_calls=2, success=True)
            case('same packet works from unrelated cwd', expected_calls=2, success=True, cwd_change=True)
            case('already stock then already working-v2 replies', expected_calls=2, success=True, already=True)
            case('missing helper blocks all subprocesses', change_files=lambda p,b: (p/'coherent8k/coherent_bundle_inventory.py').unlink())
            case('wrong helper bytes block all subprocesses', change_files=lambda p,b: (p/'working-v2/device_support.py').write_bytes(b'corrupt'))
            case('wrong recovery-binding pin blocks all subprocesses', change_files=lambda p,b: (p/w.BINDING_NAME).write_bytes(b'{}'))
            case('preparation manifest is refused even when fixture hash matches',
                 change_metadata=lambda a,b:a.update(integration_preparation_only=True))
            case('device parity mismatch is refused before subprocess',
                 change_metadata=lambda a,b:b['device'].update(software_version='799'))
            case('protected map parity mismatch is refused before subprocess',
                 change_metadata=lambda a,b:b['preserved_stock_files'][0].update(bytes=2))
            case('Search v2 mismatch is refused before subprocess',
                 change_metadata=lambda a,b:b.update(required_files=[]))
            def wrong_link(root, binding):
                binding['phase1_source_binding_links'][0]['expected'] = 'wrong-source-pin'
                data = raw(binding)
                (root/w.BINDING_NAME).write_bytes(data)
                w.APPROVED_BINDING_SHA = hashlib.sha256(data).hexdigest()
            case('owner source-binding link cannot name another source', change_files=wrong_link)
            def waiting(r, n):
                r.update(state='waiting_for_usb', physical_device_present=False)
                return r
            case('zero-exit waiting for USB halts after one call', change_reply=waiting, expected_calls=1)
            case('unsafe unmount halts after one call', change_reply=lambda r,n:{**r,'unmounted':False}, expected_calls=1)
            case('unverified stock readback halts after one call',
                 change_reply=lambda r,n:{**r,'transaction':{**r['transaction'],'readback_verified':False}}, expected_calls=1)
            case('wrong result manifest role halts after one call',
                 change_reply=lambda r,n:{**r,'manifest_sha256':'0'*64}, expected_calls=1)
            case('postcommit recovery-required halts after one call',
                 change_reply=lambda r,n:{**r,'recovery_required':True}, expected_calls=1)
            case('malformed stdout halts after one call', change_reply=lambda r,n:'{', expected_calls=1)
            case('runner exception halts after one call', runner_error=OSError('synthetic runner failure'), expected_calls=1)
            case('runner timeout halts after one call', runner_error=subprocess.TimeoutExpired('synthetic',1), expected_calls=1)
            case('second-stage waiting never reports recovery success',
                 change_reply=lambda r,n:waiting(r,n) if n==2 else r, expected_calls=2)
            def duplicate_json(r, n):
                return '{"state":"rolled_back_exact_original_verified","state":"waiting_for_usb"}'
            case('duplicate result keys halt instead of picking a state', change_reply=duplicate_json, expected_calls=1)
            def changed_after_first(r, n):
                if n == 1:
                    # Current fixture folder number is the current result count.
                    (base/str(len(results))/'working-v2/device_support.py').write_bytes(b'changed-after-stock')
                return r
            case('packet changed after verified stock prevents phase-two subprocess',
                 change_reply=changed_after_first, expected_calls=1)
            # No inventory open, source import or runner in the default mode.
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                rc = w.main(['--packet', str(base/'nonexistent')])
            if rc != 0 or json.loads(captured.getvalue())['default_is_plan_only'] is not True:
                raise ValueError('default metadata plan')
            results.append({'name':'default plan works with missing packet and no reads', 'passed':True, 'spy_calls':0})
            value = w.execute(base/'missing', runner=forbidden_runner)
            if value['state'] != 'halted' or value['installer_calls'] != 0:
                raise ValueError('missing packet')
            results.append({'name':'execute with missing packet halts before runner', 'passed':True, 'spy_calls':0})
        if peak_fixture > 8192 or peak_with_reply > 8192:
            raise ValueError('Synthetic live fixture budget')
    finally:
        w.APPROVED_BINDING_SHA, w.V2_MANIFEST_SHA, w.V2_ENTRYPOINT_SHA, w.standard_runner = saved
    proof = {'schema':'working-v2-recovery-entrypoint-host-controls/v2','all_controls_passed':True,
        'controls':results,'peak_small_fixture_bytes':peak_fixture,'peak_fixture_plus_reply_bytes':peak_with_reply,
        'fixture_cap':8192,'fixture_scope':'many independent tiny controls; cap bounds one complete synthetic packet and one live reply, not aggregate repeated reads',
        'approved_source_digests_rebound_only_in_test_RAM':True,'production_source_or_binding_modified':False,
        'real_subprocess_calls':0,'real_installer_imports':0,'real_IMG_operations':0,'device_operations':0,
        'temp_fixture_handles_closed_and_files_removed':True}
    (OUT/'host-control-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'passed':len(results),'peak_fixture_bytes':peak_fixture,'peak_with_reply':peak_with_reply,'real_subprocess_calls':0}))

if __name__ == '__main__':
    main()
