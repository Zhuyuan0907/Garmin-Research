#!/usr/bin/env python3
"""Package only validated v3 native/restore/portable bindings; no device I/O."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'staging/navigation-country-address-package-v3'
NAME = 'Garmin-2565RT-lane-address-test-v3.zip'
CANDIDATE_SHA = '1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
PROOFS = {
    'candidate-readback-v3.json': ('staging/navigation-country-native-lane-candidate-v3/proof.json', 'b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0'),
    'independent-tree-source-readback-v3.json': ('staging/navigation-country-native-lane-independent-review-v3/proof.json', '9b2ba5d69d26939911fdfe2c311736d22244e80afc6850668716075ee8e5e01d'),
    'original-CPU-bounded-read-v3.json': ('staging/navigation-country-native-lane-cpu-v3/proof.json', 'eb8440ce02e1faa79b0bc8e3b561866bae8714c85c9d7677ade402802efbab81'),
    'compact-restore-readback-v3.json': ('staging/navigation-country-native-lane-restore-v3/proof.json', 'bebeb18b29fd934d048111f5a0c05c7dd5a9c93f8d7899159f3fe69b8c5dea9a'),
}


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write('\n'); f.flush(); os.fsync(f.fileno())
    path.chmod(0o444)


def main():
    archive = ROOT / 'reports/downloads' / NAME
    assert not archive.exists() and not (BASE / 'package-result.json').exists()
    manifest = json.loads((BASE / 'manifest.json').read_text())
    assert manifest['target']['candidate_sha256'] == CANDIDATE_SHA
    assert manifest['new_houses'] == 188870 and manifest['updated_existing_streets'] == 20107
    focused = json.loads((BASE / 'validation/portable-v3-focused-proof.json').read_text())
    production = json.loads((BASE / 'validation/production-load-manifest-proof.json').read_text())
    assert focused['all_assigned_checks_passed'] and production['all_assigned_checks_passed']
    bound = {}
    for name, (relative, expected_sha) in PROOFS.items():
        raw = (ROOT / relative).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected_sha
        proof = json.loads(raw)
        assert proof['all_assigned_checks_passed']
        destination = BASE / 'validation' / name
        if destination.exists():
            assert destination.read_bytes() == raw
        else:
            with destination.open('xb') as f:
                f.write(raw); f.flush(); os.fsync(f.fileno())
            destination.chmod(0o444)
        bound[name] = proof
    cpu = bound['original-CPU-bounded-read-v3.json']
    independent = bound['independent-tree-source-readback-v3.json']
    assert cpu['candidate']['sha256_inherited_from_completed_actual_builder_readback'] == CANDIDATE_SHA
    assert cpu['exact_record_prefix_count'] == 23 and cpu['exact_new_leaf_count'] == 7
    assert cpu['total_actual_candidate_bytes_read'] == 77237 and not cpu['device_IO']
    assert independent['candidate_sha256'] == CANDIDATE_SHA
    assert independent['counts']['actual_new_house_leaves'] == 58233
    assert independent['counts']['actual_complete_house_parent_paths'] == 20613
    assert independent['counts']['actual_prior_copied_houses'] == 51332
    checked = {name: digest(BASE / name) for name in ['candidate/gmapprom1.img',
        'roadmap/Taiwan_OSM_SearchRepair_v2.img', 'restore-layout.json.gz', 'actual-stock-restore-binding.json']}
    assert checked['candidate/gmapprom1.img'] == CANDIDATE_SHA
    assert checked['roadmap/Taiwan_OSM_SearchRepair_v2.img'] == manifest['required_files'][0]['sha256']
    assert checked['restore-layout.json.gz'] == manifest['rollback']['stock_recipe']['sha256']
    assert checked['actual-stock-restore-binding.json'] == manifest['rollback']['actual_binding']['sha256']
    names = ['README-release.txt', 'manifest.json', 'install_native_house_supplement.py',
        'device_support.py', 'native_8k_stock_restore.py', 'restore-layout.json.gz',
        'actual-stock-restore-binding.json', 'candidate/gmapprom1.img',
        'roadmap/Taiwan_OSM_SearchRepair_v2.img']
    names += ['validation/' + p.name for p in sorted((BASE / 'validation').iterdir())
              if p.is_file() and p.suffix in ('.json', '.txt')]
    inventory = [dict(path=name, bytes=(BASE/name).stat().st_size,
        sha256=checked[name] if name in checked else digest(BASE/name)) for name in names]
    save(BASE/'SHA256SUMS.json', inventory)
    names.append('SHA256SUMS.json')
    partial = archive.with_suffix('.zip.partial')
    assert not partial.exists()
    with zipfile.ZipFile(partial, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for name in names:
            z.write(BASE/name, name)
    with zipfile.ZipFile(partial) as z:
        assert sorted(z.namelist()) == sorted(names)
        for row in inventory:
            h = hashlib.sha256(); count = 0
            with z.open(row['path']) as f:
                while data := f.read(1048576):
                    h.update(data); count += len(data)
            assert count == row['bytes'] and h.hexdigest() == row['sha256'], row['path']
        assert json.loads(z.read('SHA256SUMS.json')) == inventory
    with partial.open('rb') as f:
        os.fsync(f.fileno())
    partial.chmod(0o644)
    os.replace(partial, archive)
    result = dict(all_passed=True, created_utc=datetime.now(timezone.utc).isoformat(),
        archive=str(archive.relative_to(ROOT)), bytes=archive.stat().st_size, sha256=digest(archive),
        members=len(names), all_member_CRC_size_SHA_readbacks_verified=True,
        new_houses=188870, new_lane_houses=58233, existing_streets=20107,
        bounded_native_CPU_records=23, bounded_native_CPU_new_leaves=7,
        independent_all_new_lane_rows_checked=True, exact_original_stock_restore_verified=True,
        image_and_road_hardlinked_not_duplicated=True, portable_production_binding_verified=True,
        container_block_bytes=8192, header_checksum_rule_known=False,
        device_installed=False, physical8K_acceptance_verified=False,
        full_Taiwan_native_address_update_complete=False,
        download_url='http://172.16.60.187:8767/' + NAME)
    save(BASE/'package-result.json', result)
    # Sealed source IMG was already immutable. Avoid another chmod/ctime change.
    for name in names:
        path = BASE/name
        if path.stat().st_mode & 0o222:
            path.chmod(0o444)
    print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
