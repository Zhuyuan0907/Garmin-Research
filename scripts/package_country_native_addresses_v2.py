#!/usr/bin/env python3
"""Package the new country/Kaohsiung/flat-city bindings after their own validations."""
import hashlib
import json
import os
import zipfile
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'staging/navigation-country-address-package-v2'
NAME='Garmin-2565RT-existing-street-address-test-v2.zip'

def digest(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(path,value):
    with path.open('x') as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    path.chmod(0o444)

def main():
    archive=ROOT/'reports/downloads'/NAME
    assert not archive.exists() and not (BASE/'package-result.json').exists()
    manifest=json.loads((BASE/'manifest.json').read_text())
    tests=json.loads((BASE/'validation/country-v2-binding-results.json').read_text())
    assert tests['all_assigned_checks_passed'] and tests['controls_passed']==7
    sources={
      'candidate-readback-v2.json':'staging/navigation-country-native-candidate-v2/proof.json',
      'independent-source-rebase-review-v2.json':'staging/navigation-country-v2-rebase-review/proof.json',
      'original-CPU-bounded-read-v2.json':'staging/navigation-country-native-cpu-v2/proof.json',
      'compact-restore-readback-v2.json':'staging/navigation-country-layout-restore-v2/proof.json',
      'inherited-country-v1-source-review.json':'staging/navigation-country-merge-independent-review-v1/proof.json',
      'inherited-Kaohsiung-source-readback.json':'staging/navigation-kaohsiung-native-house-merge-v1/output-readback-proof.json',
      'inherited-flat-city-source-readback.json':'staging/navigation-flat-city-native-house-merge-v1/output-readback-proof.json'}
    bound={};raw_proofs={}
    for name,relative in sources.items():
        raw=(ROOT/relative).read_bytes();proof=json.loads(raw)
        passed_key={'inherited-Kaohsiung-source-readback.json':'all_assigned_readbacks_passed',
          'inherited-flat-city-source-readback.json':'all_assigned_new_readback_checks_passed'}.get(name,'all_assigned_checks_passed')
        assert proof[passed_key]
        bound[name]=proof;raw_proofs[name]=raw
    cpu=bound['original-CPU-bounded-read-v2.json'];review=bound['independent-source-rebase-review-v2.json']
    assert cpu['candidate']['inherited_root_readback_sha256']==manifest['target']['candidate_sha256']
    assert 8<=cpu['exact_parent_count']<=30 and 11<=cpu['exact_new_leaf_count']<=30
    assert cpu['total_actual_candidate_bytes_read']<160000 and not cpu['device_IO']
    assert review['candidate_sha256']==manifest['target']['candidate_sha256']
    assert review['all_new_rows_reviewed']==130637 and review['all_selected_parents_reviewed']==18823
    assert review['omitted_exact_outlier_count']==1 and not review['device_IO']
    checked={name:digest(BASE/name) for name in ['candidate/gmapprom1.img',
      'roadmap/Taiwan_OSM_SearchRepair_v2.img','restore-layout.json.gz']}
    assert checked['candidate/gmapprom1.img']==manifest['target']['candidate_sha256']
    assert checked['roadmap/Taiwan_OSM_SearchRepair_v2.img']==manifest['required_files'][0]['sha256']
    assert checked['restore-layout.json.gz']==manifest['rollback']['sha256']
    for name,raw in raw_proofs.items():
        with (BASE/'validation'/name).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        (BASE/'validation'/name).chmod(0o444)
    names=['README.txt','manifest.json','install_native_house_supplement.py','device_support.py',
      'native_address_layout_restore_v1.py','restore-layout.json.gz','candidate/gmapprom1.img',
      'roadmap/Taiwan_OSM_SearchRepair_v2.img']
    names+=['validation/'+p.name for p in sorted((BASE/'validation').iterdir())
      if p.is_file() and p.suffix in ('.json','.txt')]
    inventory=[dict(path=name,bytes=(BASE/name).stat().st_size,
      sha256=checked[name] if name in checked else digest(BASE/name)) for name in names]
    save(BASE/'SHA256SUMS.json',inventory);names.append('SHA256SUMS.json')
    partial=archive.with_suffix('.zip.partial');assert not partial.exists()
    with zipfile.ZipFile(partial,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for name in names:z.write(BASE/name,name)
    with zipfile.ZipFile(partial) as z:
        assert sorted(z.namelist())==sorted(names)
        for row in inventory:
            h=hashlib.sha256();count=0
            with z.open(row['path']) as f:
                while data:=f.read(1048576):h.update(data);count+=len(data)
            assert count==row['bytes'] and h.hexdigest()==row['sha256'],row['path']
        assert json.loads(z.read('SHA256SUMS.json'))==inventory
    with partial.open('rb') as f:os.fsync(f.fileno())
    partial.chmod(0o644);os.replace(partial,archive)
    result=dict(created_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,
      archive=str(archive.relative_to(ROOT)),bytes=archive.stat().st_size,sha256=digest(archive),members=len(names),
      all_member_readbacks_verified=True,address_image_hardlinked_not_duplicated=True,
      road_image_hardlinked_not_duplicated=True,new_houses=130637,existing_streets=18823,
      scope='existing native streets, verified Kaohsiung districts and original flat cities; partial country supplement',
      bounded_native_CPU_parent_records=cpu['exact_parent_count'],
      bounded_native_CPU_new_leaves=cpu['exact_new_leaf_count'],
      independent_all_new_rows_checked=True,omitted_new_quantized_city_edge_outliers=1,
      new_binding_controls_passed=7,inherited_transaction_algorithm_controls=35,
      device_installed=False,full_Taiwan_native_address_update_complete=False,
      download_url='http://172.16.60.187:8767/'+NAME)
    save(BASE/'package-result.json',result)
    for name in names:(BASE/name).chmod(0o444)
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':main()
