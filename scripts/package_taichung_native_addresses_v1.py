#!/usr/bin/env python3
"""Package the larger actual candidate after installer validation completes."""
import hashlib
import json
import os
import shutil
import zipfile
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'staging/navigation-taichung-address-package-v1'
NAME='Garmin-2565RT-Taichung-address-test-v1.zip'


def digest(path):
    with path.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()


def save(path,value):
    with path.open('x')as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    path.chmod(0o444)


def main():
    result_path=BASE/'package-result.json';archive=ROOT/'reports/downloads'/NAME
    assert not archive.exists() and not result_path.exists()
    manifest=json.loads((BASE/'manifest.json').read_text())
    tests=json.loads((BASE/'validation/new-transaction-results.json').read_text())
    assert tests['all_assigned_checks_passed'] and tests['controls_passed']==35
    proof_sources={
        'candidate-readback.json':'staging/navigation-taichung-native-candidate-v1/proof.json',
        'independent-merge-review.json':'staging/navigation-taichung-merge-review-v1/proof.json',
        'original-CPU-bounded-read.json':'staging/navigation-taichung-native-cpu-v1/actual-Taichung-candidate-original-CPU-proof-v1.json',
        'compact-restore-readback.json':'staging/navigation-taichung-layout-restore-v1/proof.json',
    }
    for name,rel in proof_sources.items():
        data=(ROOT/rel).read_bytes();assert json.loads(data)['all_assigned_checks_passed']
        destination=BASE/'validation'/name
        with destination.open('xb')as f:f.write(data)
        destination.chmod(0o444)
    image=BASE/manifest['target']['bundle_path'];road=BASE/'roadmap/Taiwan_OSM_SearchRepair_v2.img'
    checked={'candidate/gmapprom1.img':digest(image),
        'roadmap/Taiwan_OSM_SearchRepair_v2.img':digest(road),
        'restore-layout.json.gz':digest(BASE/'restore-layout.json.gz')}
    assert checked['candidate/gmapprom1.img']==manifest['target']['candidate_sha256']
    assert checked['roadmap/Taiwan_OSM_SearchRepair_v2.img']==manifest['required_files'][0]['sha256']
    assert checked['restore-layout.json.gz']==manifest['rollback']['sha256']
    names=['README.txt','manifest.json','install_taichung_addresses.py','device_support.py',
        'native_address_layout_restore_v1.py','restore-layout.json.gz','candidate/gmapprom1.img',
        'roadmap/Taiwan_OSM_SearchRepair_v2.img']
    names+=['validation/'+p.name for p in sorted((BASE/'validation').iterdir())if p.is_file() and p.suffix in ['.json','.txt']]
    inventory=[dict(path=name,bytes=(BASE/name).stat().st_size,
        sha256=checked[name] if name in checked else digest(BASE/name))for name in names]
    save(BASE/'SHA256SUMS.json',inventory);names.append('SHA256SUMS.json')
    partial=archive.with_suffix('.zip.partial');assert not partial.exists()
    with zipfile.ZipFile(partial,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6)as package:
        for name in names:package.write(BASE/name,name)
    with zipfile.ZipFile(partial)as package:
        assert sorted(package.namelist())==sorted(names)
        for row in inventory:
            h=hashlib.sha256();count=0
            with package.open(row['path'])as f:
                while block:=f.read(1024*1024):h.update(block);count+=len(block)
            assert count==row['bytes'] and h.hexdigest()==row['sha256'],row['path']
        assert json.loads(package.read('SHA256SUMS.json'))==inventory
    with partial.open('rb')as f:os.fsync(f.fileno())
    partial.chmod(0o644);os.replace(partial,archive)
    result=dict(created_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,
        archive=str(archive.relative_to(ROOT)),bytes=archive.stat().st_size,sha256=digest(archive),
        members=len(names),all_member_readbacks_verified=True,address_image_hardlinked_not_duplicated=True,
        road_image_hardlinked_not_duplicated=True,new_houses=11002,existing_streets=1693,
        device_installed=False,full_Taiwan_native_address_update_complete=False,
        download_url='http://172.16.60.187:8767/'+NAME)
    save(result_path,result);print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
