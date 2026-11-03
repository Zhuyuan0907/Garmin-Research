#!/usr/bin/env python3
"""Seal the completed v2 navigation candidate; never operate a USB or service.

Preparation of this source is not packaging. Invocation requires successful
terminal build, new v2 sort/MDR/road proofs and frozen source bindings first.
Writes only v2 staging/package/result and the new v2 download ZIP. No state
publisher/canonical report or v1 result is changed here.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-repair-v2'
LAYER = ROOT / 'staging/navigation-map-layers-v2'
V1_LAYER = ROOT / 'staging/navigation-map-layers-v1'
PAYLOAD = 'Map/Taiwan_OSM_SearchRepair_v2.img'
NAME = 'Garmin-2565RT-navigation-repair-v2.zip'
EXPECTED = {'family_id': 7053, 'map_id_start': 70530001, 'tile_count': 36,
            'sort_id1': 19, 'sort_id2': 7053, 'code_page': 65001}
FORBIDDEN_SUFFIXES = {'.gcd', '.bin', '.vpm', '.gmp', '.gma', '.unl', '.jcv',
                      '.sid', '.g2s', '.gpi', '.db', '.sqlite', '.class', '.jar'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def read(path):
    need(path.is_file() and not path.is_symlink(), 'Required regular input missing: ' + str(path.relative_to(ROOT)))
    return json.loads(path.read_text())


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()


def root_path(value):
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    need(not path.is_symlink(), 'Input symlink refused')
    path = path.resolve()
    need(path.is_relative_to(ROOT), 'Input outside project root')
    return path


def relative(path):
    return str(Path(path).resolve().relative_to(ROOT))


def write_new(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def image_binding(record, image, build, sha_key='sha256'):
    need(root_path(record['path']) == image, 'Proof refers to a different candidate IMG')
    need(record['bytes'] == build['image_bytes'] and record[sha_key] == build['image_sha256'],
         'Proof has a different candidate image size/hash')


def sort_image_binding(sort, build):
    allocation = sort.get('allocation', {})
    need(allocation.get('image_bytes') == build['image_bytes'] and
         allocation.get('image_sha256') == build['image_sha256'],
         'V2 sort proof image size/hash mismatch')


def required_inputs(road_path):
    build_path = OUT / 'build-manifest.json'
    build = read(build_path)
    # This check precedes even an IMG stat/open; never read an in-progress build.
    need(build.get('state') == 'compiled_candidate_not_device_verified' and
         build.get('exit_code') == 0 and build.get('finished_utc'), 'V2 build is not terminal and successful')
    need(all(build.get(key) == value for key, value in EXPECTED.items()), 'V2 build identity is unexpected')
    need(build.get('candidate') is True and all(build.get(key) is False for key in (
        'device_installed', 'device_search_verified', 'device_routing_verified',
        'stock_maps_modified', 'GarminOS_recompiled')), 'Build is not a declared offline candidate')
    image = root_path(build['image'])
    need(image == OUT / 'compiled/gmapsupp.img', 'Unexpected v2 compiler output path')
    need(isinstance(build.get('image_bytes'), int) and build['image_bytes'] > 1024,
         'Missing terminal image size')
    need(isinstance(build.get('image_sha256'), str) and len(build['image_sha256']) == 64,
         'Missing terminal image digest')
    sort_path = OUT / 'sort-verification.json'
    query_path = ROOT / 'staging/navigation-mdr-query-v2/candidate-mdr-query-proof-v3.json'
    sort, query, road = (read(path) for path in (sort_path, query_path, road_path))
    need(all(proof.get('all_passed') is True for proof in (sort, query, road)), 'New v2 proof failed')
    sort_expected = {'family_id': 7053, 'code_page': 65001, 'sort_id1': 19, 'sort_id2': 7053,
                     'expected_tiles': 36, 'map_id_start': 70530001}
    need(root_path(sort['image']) == image and all(
        sort.get('expected', {}).get(key) == value for key, value in sort_expected.items()),
        'V2 sort proof identity mismatch')
    sort_image_binding(sort, build)
    image_binding(query['candidate'], image, build, 'ROOT_terminal_build_sha256')
    image_binding(road['candidate'], image, build)
    need(query['build_manifest']['sha256'] == sha(build_path), 'MDR query proof is not bound to final build metadata')
    for proof in (sort, query, road):
        need(proof.get('device_search_verified') is not True and
             proof.get('device_routing_verified') is not True, 'Unexpected claimed device proof')

    finite = root_path(build['finite_prototype_validation'])
    need(finite == ROOT / 'staging/navigation-firmware-sort-v1/packed-shadow-alignment-proof-v2.json',
         'A prior failed/unpacked finite sort proof cannot qualify v2')
    need(sha(finite) == build['finite_prototype_validation_sha256'] and read(finite).get('all_passed') is True,
         'Frozen native/host finite proof binding changed')
    sort_source, writer_source = (root_path(build[key]) for key in ('native_sort_source', 'native_packed_writer_source'))
    need(sha(sort_source) == build['native_sort_source_sha256'] and
         sha(writer_source) == build['native_packed_writer_source_sha256'], 'Frozen Java producer sources changed')
    resource = OUT / 'sort-resource/sort/cp65001.txt'
    need(sha(resource) == build['sort_resource_sha256'], 'V2 sort resource changed')
    style = root_path(build['style_path'])
    need(sha(style / 'inc/address') == build['style_address_sha256'], 'Address style changed')
    controls = root_path(build['producer_controls'])
    need(sha(controls) == build['producer_controls_sha256'], 'Final Java producer controls changed')
    for path, checksum in build['pinned_compiler_classes'].items():
        need(sha(root_path(path)) == checksum, 'Pinned compiler class changed')
    guarded = ROOT / 'staging/navigation-firmware-sort-v1/packed-hard-guard-proof-v2.json'
    need(read(guarded).get('all_passed') is True, 'Writer hard guards did not pass')
    layout = ROOT / 'staging/navigation-native-srt-layout-v1/srt-layout-evidence.json'
    need(read(layout).get('all_passed') is True, 'Independent exact-stock field layout proof failed')
    adapted = LAYER / 'installer-test-results.json'
    adaptation = read(adapted)
    need(adaptation.get('all_passed') is True and adaptation.get('tests_run') == 6 and
         adaptation.get('v1_prior_19_tests_inherited_not_rerun') is True,
         'Installer v2 path adaptation proof failed')
    need(sha(LAYER / 'install_navigation_bundle.py') == adaptation['source_sha256']['install_navigation_bundle.py'],
         'Adapted installer differs from verified code')
    prior = read(V1_LAYER / 'installer-test-results.json')
    need(prior.get('all_passed') is True and prior.get('tests_run') == 19 and
         sha(V1_LAYER / 'install_navigation_bundle.py') == prior['source_files']['install_navigation_bundle.py']['sha256'],
         'Frozen original installer proof binding changed')
    need(sha(V1_LAYER / 'installer-test-results.json') == adaptation['prior_proof_sha256'],
         'Adaptation does not reference the frozen v1 proof')

    proofs = [build_path, sort_path, query_path, road_path, finite, guarded, layout, adapted,
              V1_LAYER / 'installer-test-results.json']
    binding = [{'path': relative(path), 'bytes': path.stat().st_size, 'sha256': sha(path)} for path in proofs]
    return build, image, style, sort_source, writer_source, resource, controls, binding


def make_manifest(build, image, bindings):
    proposal = read(V1_LAYER / 'package-manifest-proposal.json')
    inventory = {item['path']: item for item in read(ROOT / 'backups/20261002T154458Z/files-manifest.json')}
    kept = []
    for item in proposal['retain_on_device_references']:
        path = item['device_path']
        if path.startswith(('POI/', '.System/SQLite/')) and path not in {
            '.System/SQLite/HWM/TWNHWM.db', '.System/SQLite/Prefecture/TWNJAI.db'}:
            continue
        entry = inventory[path]
        kept.append({'device_path': path, 'bytes': entry['size'], 'sha256': entry['sha256']})
    backup = ROOT / 'backups/20261002T154458Z'
    disk = read(backup / 'sda.json')
    xml = ET.fromstring((backup / 'files/Garmin/GarminDevice.xml').read_bytes())
    ns = {'g': xml.tag.split('}')[0][1:]}
    unit = xml.findtext('g:Id', namespaces=ns).strip()
    usb = disk['disk']['usb']
    return {'format_version': 1, 'candidate': True, 'candidate_version': 2,
        'created_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'new_map': {'bundle_path': PAYLOAD, 'device_path': PAYLOAD, 'bytes': build['image_bytes'],
                    'sha256': build['image_sha256'], 'family_id': 7053, 'product_id': 1, 'sort_ids': [19, 7053]},
        'previous_project_map': {'device_path': 'Map/Taiwan_OSM_20261001.img',
            'disabled_path': 'Map/Taiwan_OSM_20261001.img.disabled', 'bytes': 134852608,
            'sha256': '2801d07dfa4f3ae8d69fcdaea616e88499da6a6ed4a6d773b378253b9ebcb600'},
        'device': {'part_number': '006-B1352-00', 'software_version': '800',
            'unit_id_sha256': hashlib.sha256(unit.encode()).hexdigest(), 'disk_bytes': disk['size'],
            'usb': {'vendor': usb['idVendor'], 'product': usb['idProduct'],
                    'serial_sha256': hashlib.sha256(usb['serial'].encode()).hexdigest()}},
        'preserved_stock_files': kept, 'compiled_image_reference': relative(image),
        'validation_bindings': bindings, 'device_installed': False, 'device_search_verified': False,
        'device_routing_verified': False, 'osm_data_timestamp': build['osm_data_timestamp'],
        'installer_modes': ['preflight (default)', '--install', '--rollback'], 'only_img_payload': PAYLOAD,
        'not_in_payload': ['GarminOS firmware', 'original NT IMG', 'original address DB',
                           'JCV/SID/G2S', 'original authorizations', 'native App', 'Bluetooth music software'],
        'physical_ab_matrix': proposal['physical_ab_matrix'],
        'limitations': build['limitations'] + [
            'Original-instruction finite sort agreement and producer-order checks do not verify native address UI caller or physical search.',
            'OSM does not contain every address/house number; original proprietary auxiliary data is preserved and not updated.',
            'A/B map selections may change provider conditions; no guaranteed checkbox-to-provider switching is claimed.',
            'The sealed v1 candidate was not installed; installer accepts the verified original project OSM as previous map only.']}


def checksum_tree(package, image_checksum):
    files = sorted(path for path in package.rglob('*') if path.is_file())
    need(all(not path.is_symlink() for path in files), 'Package must contain regular files, not symlinks')
    names = [str(path.relative_to(package)) for path in files]
    need([name for name in names if name.lower().endswith('.img')] == [PAYLOAD], 'Exactly one new IMG payload is allowed')
    need(not any(Path(name).suffix.lower() in FORBIDDEN_SUFFIXES for name in names),
         'Firmware/proprietary/binary payload is forbidden')
    # The payload shares the already verified compiler inode and is sealed 0444.
    # ZIP readback below checks its actual encoded contents; do not repeat a
    # whole-image hash between the verified input and that readback.
    return {str(path.relative_to(package)): image_checksum
            if str(path.relative_to(package)) == PAYLOAD else sha(path) for path in files}


def verify_zip(package, archive, build):
    rows = (package / 'SHA256SUMS').read_text().splitlines()
    hashes = {name: checksum for checksum, name in (row.split('  ', 1) for row in rows)}
    need(hashes.get(PAYLOAD) == build['image_sha256'], 'ZIP image digest declaration mismatch')
    m = read(package / 'manifest.json')
    need(m['new_map']['device_path'] == PAYLOAD and m['new_map']['sha256'] == build['image_sha256'],
         'ZIP manifest image mismatch')
    hashes['SHA256SUMS'] = sha(package / 'SHA256SUMS')
    names = {str(path.relative_to(package)) for path in package.rglob('*') if path.is_file()}
    need(set(hashes) == names, 'Package manifest does not cover every file')
    with zipfile.ZipFile(archive) as z:
        need(len(z.namelist()) == len(hashes) and set(z.namelist()) == set(hashes), 'ZIP member set differs')
        for name, expected in hashes.items():
            h = hashlib.sha256()
            with z.open(name) as stream:
                for data in iter(lambda: stream.read(4 * 1024 * 1024), b''):
                    h.update(data)
            need(h.hexdigest() == expected, 'ZIP member readback mismatch: ' + name)
    return len(hashes)


def finish_result(archive, image, build, bindings, members):
    result = {'all_passed': True, 'candidate': True, 'candidate_version': 2,
        'created_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'created_at_local': dt.datetime.now().astimezone().isoformat(),
        'zip': relative(archive), 'zip_bytes': archive.stat().st_size, 'zip_sha256': sha(archive),
        'map_path': relative(image), 'map_bytes': build['image_bytes'], 'map_sha256': build['image_sha256'],
        'complete_zip_member_readback': True, 'member_count': members,
        'offline_verification': bindings, 'stock_maps_modified': False,
        'device_installed': False, 'device_search_verified': False, 'device_routing_verified': False,
        'GarminOS_recompiled': False, 'canonical_state_or_report_updated': False,
        'status': 'offline_v2_candidate_packaged_waiting_for_physical_verification'}
    write_new(OUT / 'package-result.json', result)
    print(json.dumps(result, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--road-proof', type=Path, required=True,
        help='New v2 road/city regression proof, relative to ROOT or absolute within ROOT')
    parser.add_argument('--finalize-existing', action='store_true',
        help='Only verify an already sealed v2 ZIP and write a missing v2 package-result')
    args = parser.parse_args()
    road_path = root_path(args.road_proof)
    need(road_path == ROOT / 'staging/navigation-road-regression-v2/road-city-regression-proof-v2.json',
         'Only the new v2 road/city proof may qualify this package')
    build, image, style, sort_source, writer_source, resource, controls, bindings = required_inputs(road_path)
    package = OUT / 'package'
    archive = ROOT / 'reports/downloads' / NAME
    need(not (OUT / 'package-result.json').exists(), 'A completed v2 package must not be overwritten')
    if args.finalize_existing:
        count = verify_zip(package, archive, build)
        finish_result(archive, image, build, bindings, count)
        return
    need(not package.exists() and not archive.exists(), 'An existing sealed v2 package must not be overwritten')
    partial = OUT / 'package.partial'
    zip_partial = archive.with_name(NAME + '.partial')
    need(not partial.exists() and not zip_partial.exists(), 'Inspect existing v2 preparation remnants first')
    need(image.is_file() and not image.is_symlink() and image.stat().st_size == build['image_bytes'] and
         sha(image) == build['image_sha256'], 'Terminal candidate IMG size/hash changed')
    with image.open('rb') as stream:
        header = stream.read(512)
    need(len(header) == 512 and header[0] == 0 and header[16:23] == b'DSKIMG\0' and
         header[65:72] == b'GARMIN\0', 'Candidate does not have the expected IMG header')
    partial.mkdir()
    for name in ('Map', 'verification', 'sources', 'tests'):
        (partial / name).mkdir()
    image.chmod(0o444)
    os.link(image, partial / PAYLOAD)  # One shared sealed inode; no extra raw-image allocation.
    write_new(partial / 'manifest.json', make_manifest(build, image, bindings))
    copies = {
        LAYER / 'install_navigation_bundle.py': 'install.py',
        V1_LAYER / 'REPORT.txt': 'original-map-layer-notes.txt',
        V1_LAYER / 'layer-inventory.json': 'verification/original-layer-inventory.json',
        V1_LAYER / 'installer-test-results.json': 'verification/inherited-installer-v1-tests.json',
        LAYER / 'installer-test-results.json': 'verification/installer-v2-adaptation-tests.json',
        OUT / 'build-manifest.json': 'verification/build-manifest-v2.json',
        OUT / 'sort-verification.json': 'verification/map-sort-verification-v2.json',
        ROOT / 'staging/navigation-mdr-query-v2/candidate-mdr-query-proof-v3.json': 'verification/candidate-mdr-query-v3.json',
        road_path: 'verification/road-city-regression-v2.json',
        ROOT / 'staging/navigation-firmware-sort-v1/packed-shadow-alignment-proof-v2.json': 'verification/native-host-packed-sort-finite-v2.json',
        ROOT / 'staging/navigation-firmware-sort-v1/packed-hard-guard-proof-v2.json': 'verification/packed-writer-hard-guards-v2.json',
        ROOT / 'staging/navigation-firmware-sort-v1/packed-shadow-source-receipt-v2.json': 'verification/packed-source-receipt-v2.json',
        ROOT / 'staging/navigation-native-srt-layout-v1/srt-layout-evidence.json': 'verification/independent-native-SRT-layout.json',
        ROOT / 'staging/navigation-native-srt-layout-v1/REPORT.txt': 'verification/native-SRT-layout-notes.txt',
        ROOT / 'staging/navigation-road-coverage-v1/native-all-city-closure-proof.json': 'verification/admin-boundary-closure.json',
        ROOT / 'staging/navigation-search-encoding-v1/source-receipt.json': 'verification/official-r4924-source-receipt.json',
        sort_source: 'sources/Sort.java', writer_source: 'sources/SRTFile.java',
        resource: 'sources/cp65001.txt', controls: 'tests/producer-controls-v2.tsv',
        ROOT / 'sources/maps/mkgmap-r4924/LICENCE': 'sources/mkgmap-LICENCE.txt',
        OUT / 'license.txt': 'LICENSE.txt', OUT / 'copyright.txt': 'COPYRIGHT.txt',
        ROOT / 'staging/navigation-road-coverage-v1/navigation-road-anchors-test.gpx': 'tests/road-anchors.gpx',
    }
    for source in sorted(style.rglob('*')):
        if source.is_file():
            copies[source] = 'sources/style/' + str(source.relative_to(style))
    provenance = []
    for source, target in copies.items():
        need(source.is_file() and not source.is_symlink(), 'Required source missing or symlink: ' + relative(source))
        destination = partial / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        need(not destination.exists(), 'Duplicate package member')
        shutil.copyfile(source, destination)
        provenance.append({'bundle_path': target, 'source_path': relative(source),
                           'bytes': source.stat().st_size, 'sha256': sha(source)})
    write_new(partial / 'verification/package-source-provenance.json', provenance)
    (partial / 'README.txt').write_text('''Garmin nüvi 2565RT 導航搜尋修復候選 v2

這包修正編譯器的漢字排序鍵與 SRT 16/10/6 欄位封裝，保留城市／道路歸屬調整。
包內離線證據包含原始函式有限對照、實際新版 MDR 索引及道路／城市檢查。
尚未確認原機地址 UI 搜尋與導航正常，不能視為已完成修復。
OSM 資料日期為 2026-10-01；它是 OSM 地圖，不是 Garmin 官方 NT 更新。

Linux／原 Raspberry Pi 上解壓縮後：
  python3 install.py --bundle .
預設只做唯讀預檢。安裝時 Garmin 必須 USB 隨身碟模式，執行：
  python3 install.py --bundle . --install
還原：
  python3 install.py --bundle . --rollback

只新增 Map/Taiwan_OSM_SearchRepair_v2.img；原已驗證的專案 OSM 20261001 改為
.img.disabled 並保留。rollback 只刪完全符合本包雜湊的新 IMG 並還原舊專案圖。
身份、原廠圖、授權與配套檔皆需核對；檔案異動、空間不足、USB 不符時拒絕安裝。
原廠 CN 道路＋Address Point 門牌層本來互補；所有原廠檔只保留、不放進下載包。
v1 封存候選未安裝；此工具不會移除任何來歷不明或其他候選圖資。

請依 device-ab-checklist.txt 實測。排序對照與檔案讀回不等於地址搜尋成功。
OSM 可能缺門牌；高雄來源邊界缺段等限制見 manifest.json 與 verification。
tests/road-anchors.gpx 只用於位置比對，不自動匯入、也不證明地址命中。
這包未包含 GarminOS、新 App、原廠私有圖資／資料庫或藍牙音樂程式。
導航實機修復確認後才恢復其他改造研究。
''')
    (partial / 'device-ab-checklist.txt').write_text('''1. 安裝器安全卸載後，拔線、完整關機再開機，確認 Search v2 名稱可見。
2. A：只勾新版 OSM；原廠 CN 與 Address Point 暫時都取消。保留所有檔案與底圖／時區。
3. 地址入口先指定臺中市，依序測民權路、民和路一段、民和路二段；記錄完整候選、城市、
   選定後位置與搜尋秒數。每次60秒即記 timeout，不再等兩小時；此時限不是速度承諾。
   民權路不應被當成民和路。另以 POI 名稱入口輸入同樣文字，分開記錄。
4. B：取消新版 OSM、一起勾原廠 CN＋Address Point；重開再用同文字、城市、入口、时限對照。
5. 勾選可能改變地址 provider 的可用条件，但本包未證明特定組合一定切換 provider。
6. 有時間再測兩個已知門牌及室外 GPS 定位後的路線計算／短路段導引，分別記錄。
7. 問題仍在就回傳 A/B 明細；必要時 --rollback。先保留導航故障排查，不宣稱已修復。
''')
    # Older RESULTS.txt is intentionally omitted: it cannot certify this new native-compatible packing.
    hashes = checksum_tree(partial, build['image_sha256'])
    (partial / 'SHA256SUMS').write_text(''.join(checksum + '  ' + name + '\n' for name, checksum in hashes.items()))
    os.rename(partial, package)
    with zipfile.ZipFile(zip_partial, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for path in sorted(package.rglob('*')):
            if path.is_file():
                z.write(path, str(path.relative_to(package)))
    zip_partial.chmod(0o644)
    count = verify_zip(package, zip_partial, build)
    # NOREPLACE publication using a hard link; refuses if another v2 ZIP appeared.
    os.link(zip_partial, archive)
    zip_partial.unlink()
    finish_result(archive, image, build, bindings, count)


if __name__ == '__main__':
    main()
