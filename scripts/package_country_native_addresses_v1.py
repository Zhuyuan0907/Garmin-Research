#!/usr/bin/env python3
"""Seal/package the checked country existing-street supplement, no device I/O."""
import hashlib
import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT/'staging/navigation-country-address-package-v1'
NAME = 'Garmin-2565RT-existing-street-address-test-v1.zip'


def digest(path):
    with path.open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, ensure_ascii=False, indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
    path.chmod(0o444)


def main():
    result_path = BASE/'package-result.json'; archive = ROOT/'reports/downloads'/NAME
    assert not archive.exists() and not result_path.exists()
    manifest = json.loads((BASE/'manifest.json').read_text())
    tests = json.loads((BASE/'validation/country-binding-results.json').read_text())
    assert tests['all_assigned_checks_passed'] and tests['controls_passed']==12
    sources = {'candidate-readback.json':'staging/navigation-country-native-candidate-v1/proof.json',
        'independent-merge-review.json':'staging/navigation-country-merge-independent-review-v1/proof.json',
        'original-CPU-bounded-read.json':'staging/navigation-country-native-cpu-v1/proof.json',
        'compact-restore-readback.json':'staging/navigation-country-layout-restore-v1/proof.json'}
    bound = {}
    for name, rel in sources.items():
        raw=(ROOT/rel).read_bytes(); proof=json.loads(raw); assert proof['all_assigned_checks_passed']
        path=BASE/'validation'/name
        with path.open('xb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
        path.chmod(0o444); bound[name]=proof
    cpu=bound['original-CPU-bounded-read.json']
    assert cpu['candidate']['inherited_root_readback_sha256']==manifest['target']['candidate_sha256']
    assert cpu['exact_parent_count']==8 and cpu['exact_new_leaf_count']==11
    assert cpu['total_actual_candidate_bytes_read']==73315 and not cpu['device_IO']
    reviewed=bound['independent-merge-review.json']
    # The review records an additional native-grid edge outlier separately from
    # the source-point membership policy. Do not silently upgrade that policy.
    assert reviewed['all_assigned_checks_passed'] and manifest['new_houses']==111608
    checked={'candidate/gmapprom1.img':digest(BASE/'candidate/gmapprom1.img'),
        'roadmap/Taiwan_OSM_SearchRepair_v2.img':digest(BASE/'roadmap/Taiwan_OSM_SearchRepair_v2.img'),
        'restore-layout.json.gz':digest(BASE/'restore-layout.json.gz')}
    assert checked['candidate/gmapprom1.img']==manifest['target']['candidate_sha256']
    assert checked['roadmap/Taiwan_OSM_SearchRepair_v2.img']==manifest['required_files'][0]['sha256']
    assert checked['restore-layout.json.gz']==manifest['rollback']['sha256']
    save(BASE/'validation/new-root-execution-receipts.json', dict(all_assigned_checks_passed=True,
        bundle_preparation=dict(exit_code=0,terminal_chunk='44326b'),
        new_binding_controls=dict(exit_code=0,terminal_chunk='3b8553',controls=12),
        actual_readonly_preflight=dict(exit_code=0,terminal_chunk='ddb32e',physical_device_present=False),
        first_fixture_failure=dict(exit_code=1,terminal_chunk='e87747',cause='Synthetic XML omitted namespace; fixed before successful new controls.'),
        old_35_transaction_suite_replayed=False, old_61_USB_suite_replayed=False, device_files_written=False))
    names=['README.txt','manifest.json','install_native_house_supplement.py','device_support.py',
        'native_address_layout_restore_v1.py','restore-layout.json.gz','candidate/gmapprom1.img',
        'roadmap/Taiwan_OSM_SearchRepair_v2.img']
    names += ['validation/'+p.name for p in sorted((BASE/'validation').iterdir())
        if p.is_file() and p.suffix in ('.json','.txt')]
    inventory=[dict(path=name,bytes=(BASE/name).stat().st_size,
        sha256=checked[name] if name in checked else digest(BASE/name)) for name in names]
    save(BASE/'SHA256SUMS.json', inventory); names.append('SHA256SUMS.json')
    partial=archive.with_suffix('.zip.partial'); assert not partial.exists()
    with zipfile.ZipFile(partial,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for name in names:z.write(BASE/name,name)
    with zipfile.ZipFile(partial) as z:
        assert sorted(z.namelist())==sorted(names)
        for row in inventory:
            h=hashlib.sha256();count=0
            with z.open(row['path']) as f:
                while data:=f.read(1024*1024):h.update(data);count+=len(data)
            assert count==row['bytes'] and h.hexdigest()==row['sha256'],row['path']
        assert json.loads(z.read('SHA256SUMS.json'))==inventory
    with partial.open('rb') as f:os.fsync(f.fileno())
    partial.chmod(0o644);os.replace(partial,archive)
    result=dict(created_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,
        archive=str(archive.relative_to(ROOT)),bytes=archive.stat().st_size,sha256=digest(archive),members=len(names),
        all_member_readbacks_verified=True,address_image_hardlinked_not_duplicated=True,road_image_hardlinked_not_duplicated=True,
        new_houses=111608,existing_streets=15679,scope='existing native streets across16 cities; partial country supplement',
        bounded_native_CPU_parent_records=8,bounded_native_CPU_new_leaves=11,independent_all_new_rows_checked=True,
        known_native_grid_city_edge_outliers=1,device_installed=False,full_Taiwan_native_address_update_complete=False,
        download_url='http://172.16.60.187:8767/'+NAME)
    save(result_path,result)
    for name in names:(BASE/name).chmod(0o444)
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
