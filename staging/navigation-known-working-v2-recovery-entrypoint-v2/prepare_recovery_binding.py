#!/usr/bin/env python3
"""Bind exact closed activation metadata, without reading IMG or recipe files."""
from pathlib import Path
import hashlib
import json
import stat

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
OWNER = ROOT / 'staging/navigation-AP-coherent8K-activated-test-entrypoint-v1'
OLD = ROOT / 'staging/navigation-country-address-package-v2'

def need(ok, message):
    if not ok:
        raise ValueError(message)

def main():
    packaging = json.loads((OUT / 'captured-activated-PACKAGING.json').read_text())
    owner = json.loads((OUT / 'captured-activated-entrypoint-source-binding.json').read_text())
    old_capture = json.loads((OUT / 'old-v2-binding-capture.json').read_text())
    source_receipts = []
    def capture(path, expected=None):
        need('.img' not in str(path).lower() and not str(path).endswith(('.gz', '.zip')), 'No payload or recipe access')
        before = path.lstat()
        raw = path.read_bytes()
        after = path.lstat()
        key = lambda s: [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode & 0o777, s.st_nlink]
        need(stat.S_ISREG(before.st_mode) and key(before) == key(after), 'Closed small input changed')
        digest = hashlib.sha256(raw).hexdigest()
        if expected:
            need(len(raw) == expected['bytes'] and digest == expected['sha256'], 'Owner source pin')
        source_receipts.append({'path': str(path.relative_to(ROOT)), 'bytes': len(raw), 'sha256': digest,
                                'stat_before': key(before), 'stat_after': key(after)})
        return raw
    m1 = json.loads(capture(OWNER / 'manifest.json', owner['manifest']))
    m2 = json.loads(capture(OLD / 'manifest.json', {'bytes':5342,
        'sha256':'71258a290bce559b0f882282bf2ce3c6cd8e690d49fd5ef5756e454b3fde97f7'}))
    for row in packaging['files']:
        if row['bundle_path'].endswith('.py') and row['role'] == 'portable_helper':
            capture(ROOT / row['source_path'], row)
    # Recheck actual role parity independently before emitting the immutable binding.
    need(m1.get('allowed_operation') == 'controlled_physical_test'
         and not m1.get('integration_preparation_only', False), 'Actual activation required')
    need(m1['device'] == m2['device'] and m1['preserved_stock_files'] == m2['preserved_stock_files']
         and m1['required_files'] == m2['required_files'], 'Exact device/protected/search parity')
    need(m1['bundle_input_inventory'] == owner['bundle_input_inventory'], 'Actual owner inventory')
    inventory = []
    for row in packaging['files']:
        if row['role'] not in ('candidate', 'road'):
            inventory.append({'path':'coherent8k/' + row['bundle_path'], 'bytes':row['bytes'], 'sha256':row['sha256']})
    for row in old_capture['old_runtime_inventory']:
        inventory.append({'path':'working-v2/' + row['path'], 'bytes':row['bytes'], 'sha256':row['sha256']})
    inventory.sort(key=lambda x:x['path'])
    indexed = {row['path']:row for row in inventory}
    need(len(inventory) == len(indexed) == 18, 'All thirteen new and five old runtime small inputs')
    binding = {'schema':'garmin-working-v2-recovery-source-binding/v2', 'phase1_activated':True,
        'roles':{'phase1_input':{'bytes':153346048,'sha256':'9af1e68e1308bf28deeb7f7d4c7cfab88efd0063c38f4f2df77fcde352990dd3'},
                 'phase1_output':{'bytes':96739328,'sha256':'864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'},
                 'phase2_input':{'bytes':96739328,'sha256':'864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'},
                 'phase2_output':{'bytes':128356352,'sha256':'925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'}},
        'small_inventory':inventory, 'required_small_paths':sorted(indexed),
        'phase1_entrypoint':indexed['coherent8k/install_native_house_supplement.py'],
        'phase2_entrypoint':indexed['working-v2/install_native_house_supplement.py'],
        'phase1_manifest':indexed['coherent8k/manifest.json'], 'phase2_manifest':indexed['working-v2/manifest.json'],
        'phase1_manifest_schema':m1['schema'], 'phase2_manifest_schema':m2['schema'],
        'phase1_source_binding_path':'coherent8k/entrypoint-source-binding.json',
        'phase1_source_binding_schema':owner['schema'],
        'phase1_source_binding_links':[
            {'json_path':['entrypoint','sha256'],'expected':owner['entrypoint']['sha256']},
            {'json_path':['manifest','sha256'],'expected':owner['manifest']['sha256']},
            {'json_path':['actual_stock_proof_sha256'],'expected':'e44ded4324705fc9482b60898edda790e6155a646a5d9e5d7b4a139e5f41aa8e'},
            {'json_path':['old_preparation_seal_sha256'],'expected':'dc59af5ef52cee72d7a7b936f276e895ceaf28c280428beef73b86b39a125008'}],
        'activated_owner_seal_sha256':'54bdfcd2aa434d99d2d141f23e405870958218fc6e9052f402b7015bcbbefb9d',
        'runtime_payload_roles_pinned_but_not_opened':True,
        'source_review_and_root_full_packet_positive_validation_not_claimed_completed_by_this_scope':True,
        'Garmin_UI_renderer_verified':False, 'full_goal_complete':False}
    raw = (json.dumps(binding, ensure_ascii=False, indent=2) + '\n').encode()
    digest = hashlib.sha256(raw).hexdigest()
    need(len(raw) + sum(row['bytes'] for row in inventory) < 3*1024*1024, 'Complete runtime small read budget')
    (OUT / 'recovery-source-binding.json').write_bytes(raw)
    source_path = OUT / 'recovery_entrypoint.py'
    src = source_path.read_text()
    need(src.count('APPROVED_BINDING_SHA = None') == 1, 'Single explicit source rebind')
    source_path.write_text(src.replace('APPROVED_BINDING_SHA = None', "APPROVED_BINDING_SHA = '" + digest + "'"))
    receipt = {'schema':'recovery-activation-binding-preparation/v2','rows':source_receipts,
        'raw_external_input_bytes':sum(row['bytes'] for row in source_receipts),
        'real_IMG_stat_open_read_write_link':0,'recipe_raw_or_decode_bytes':0,
        'binding_sha256':digest,'binding_bytes':len(raw),'runtime_small_inventory_files':len(inventory),
        'runtime_inventory_bytes_plus_binding':len(raw)+sum(row['bytes'] for row in inventory),
        'activated_manifest_actual_field':'allowed_operation=controlled_physical_test; preparation-only fields absent',
        'device_protected_Search_parity_checked_from_actual_pinned_manifests':True,
        'owner_independent_source_review_pending_no_success_claim':True}
    (OUT / 'binding-preparation-read-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({k:receipt[k] for k in ('binding_sha256','binding_bytes','runtime_small_inventory_files',
        'runtime_inventory_bytes_plus_binding','raw_external_input_bytes')}))

if __name__ == '__main__':
    main()
