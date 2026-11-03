#!/usr/bin/env python3
"""Assemble one verified navigation candidate, without device operations."""
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
OUT = ROOT / 'staging/navigation-repair-v1'
NAME = 'Garmin-2565RT-navigation-repair-v1.zip'


def read(path):
    return json.loads(path.read_text())


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def finish_result(archive, image, build, road_proof, member_count):
    layer_dir = ROOT / 'staging/navigation-map-layers-v1'
    result = dict(all_passed=True, created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        zip=str(archive.relative_to(ROOT)), zip_bytes=archive.stat().st_size, zip_sha256=sha(archive),
        map_path=str(image.relative_to(ROOT)), map_bytes=build['image_bytes'], map_sha256=build['image_sha256'],
        complete_zip_member_readback=True, member_count=member_count,
        offline_verification=[str(p.relative_to(ROOT)) for p in [OUT / 'sort-verification.json', road_proof, layer_dir / 'installer-test-results.json']],
        stock_maps_modified=False, device_installed=False, device_search_verified=False,
        device_routing_verified=False, candidate=True,
        download_url='http://172.16.60.187:8767/' + NAME)
    write(OUT / 'package-result.json', result)
    state_path = ROOT / 'evidence/navigation-repair-state-v1.json'
    state = read(state_path)
    state.update(updated_utc=result['created_utc'], navigation_repair_status='offline_candidate_packaged_waiting_for_device',
                 repair_estimate_percent=65, package=result, download_url=result['download_url'])
    state['completed_offline_details'].extend([
        '36 圖磚與全域索引已重編，全部 LBL／MDR／SRT 排序身份與字重核對通過。',
        '實際新地圖的臺中市道路幾何、路名與行政城市歸屬回歸檢查通過；不是車機搜尋測試。',
        '單包含地圖、圖層清單、安裝／還原工具與驗證紀錄，ZIP 全部成員讀回校驗一致。'])
    write(state_path, state)
    print(json.dumps(result, ensure_ascii=False))


def verify_existing_zip(package, archive, build):
    rows = (package / 'SHA256SUMS').read_text().splitlines()
    hashes = dict((name, checksum) for checksum, name in (row.split('  ', 1) for row in rows))
    assert hashes['Map/Taiwan_OSM_SearchRepair_v1.img'] == build['image_sha256']
    assert read(package / 'manifest.json')['new_map']['sha256'] == build['image_sha256']
    hashes['SHA256SUMS'] = sha(package / 'SHA256SUMS')
    assert set(hashes) == {str(p.relative_to(package)) for p in package.rglob('*') if p.is_file()}
    with zipfile.ZipFile(archive) as z:
        assert set(z.namelist()) == set(hashes)
        for name, expected in hashes.items():
            h = hashlib.sha256()
            with z.open(name) as f:
                for chunk in iter(lambda: f.read(4 * 1024 * 1024), b''):
                    h.update(chunk)
            assert h.hexdigest() == expected, name
    return len(hashes)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--road-proof', type=Path, required=True)
    p.add_argument('--finalize-existing', action='store_true', help='Verify the existing sealed ZIP and finish a previously failed metadata write')
    a = p.parse_args()
    a.road_proof = a.road_proof.resolve()
    build = read(OUT / 'build-manifest.json')
    assert build['state'] == 'compiled_candidate_not_device_verified'
    sort = read(OUT / 'sort-verification.json')
    road = read(a.road_proof)
    assert sort['all_passed'] and road['all_passed']
    layer_dir = ROOT / 'staging/navigation-map-layers-v1'
    install_tests = read(layer_dir / 'installer-test-results.json')
    assert install_tests['all_passed']
    package = OUT / 'package'
    if a.finalize_existing:
        assert not (OUT / 'package-result.json').exists(), 'Completed packaging must not be repeated'
        archive = ROOT / 'reports/downloads' / NAME
        count = verify_existing_zip(package, archive, build)
        finish_result(archive, Path(build['image']), build, a.road_proof, count)
        return
    package.mkdir(exist_ok=False)
    for name in ['Map', 'verification', 'sources', 'tests']:
        (package / name).mkdir()
    image = Path(build['image'])
    payload = 'Map/Taiwan_OSM_SearchRepair_v1.img'
    # One sealed inode shared with the compiled output, not an extra raw copy.
    image.chmod(0o444)
    os.link(image, package / payload)
    proposal = read(layer_dir / 'package-manifest-proposal.json')
    inventory = {v['path']: v for v in read(ROOT / 'backups/20261002T154458Z/files-manifest.json')}
    kept = []
    for row in proposal['retain_on_device_references']:
        path = row['device_path']
        if path.startswith(('POI/', '.System/SQLite/')) and path not in {
                '.System/SQLite/HWM/TWNHWM.db', '.System/SQLite/Prefecture/TWNJAI.db'}:
            continue
        entry = inventory[path]
        kept.append(dict(device_path=path, bytes=entry['size'], sha256=entry['sha256']))
    backup = ROOT / 'backups/20261002T154458Z'
    disk = read(backup / 'sda.json')
    xml = ET.fromstring((backup / 'files/Garmin/GarminDevice.xml').read_bytes())
    ns = {'g': xml.tag.split('}')[0][1:]}
    unit = xml.findtext('g:Id', namespaces=ns).strip()
    usb = disk['disk']['usb']
    manifest = dict(format_version=1, candidate=True,
        created_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        new_map=dict(bundle_path=payload, device_path=payload, bytes=build['image_bytes'],
                     sha256=build['image_sha256'], family_id=7052, product_id=1, sort_ids=[19, 7052]),
        previous_project_map=dict(device_path='Map/Taiwan_OSM_20261001.img',
            disabled_path='Map/Taiwan_OSM_20261001.img.disabled', bytes=134852608,
            sha256='2801d07dfa4f3ae8d69fcdaea616e88499da6a6ed4a6d773b378253b9ebcb600'),
        device=dict(part_number='006-B1352-00', software_version='800',
            unit_id_sha256=hashlib.sha256(unit.encode()).hexdigest(), disk_bytes=disk['size'],
            usb=dict(vendor=usb['idVendor'], product=usb['idProduct'],
                     serial_sha256=hashlib.sha256(usb['serial'].encode()).hexdigest())),
        preserved_stock_files=kept, device_installed=False, device_search_verified=False,
        device_routing_verified=False, osm_data_timestamp=build['osm_data_timestamp'],
        installer_modes=['preflight (default)', '--install', '--rollback'],
        only_img_payload=payload,
        not_in_payload=['GarminOS firmware', 'original NT maps', 'JCV', 'SID', 'G2S',
                        'original proprietary address database', 'experimental native App'],
        physical_ab_matrix=proposal['physical_ab_matrix'],
        limitations=read(ROOT / 'evidence/navigation-repair-state-v1.json')['known_limits'])
    write(package / 'manifest.json', manifest)
    copies = {
        layer_dir / 'install_navigation_bundle.py': 'install.py',
        layer_dir / 'REPORT.txt': '圖層說明.txt',
        layer_dir / 'layer-inventory.json': 'verification/original-layer-inventory.json',
        layer_dir / 'installer-test-results.json': 'verification/installer-tests.json',
        OUT / 'sort-verification.json': 'verification/map-sort-verification.json',
        a.road_proof: 'verification/city-road-regression.json',
        ROOT / 'staging/navigation-road-coverage-v1/native-all-city-closure-proof.json': 'verification/admin-boundary-closure.json',
        ROOT / 'staging/navigation-search-encoding-v1/RESULTS.txt': 'verification/sort-analysis.txt',
        ROOT / 'staging/navigation-search-encoding-v1/writer-patch-src/uk/me/parabola/imgfmt/app/srt/SRTFile.java': 'sources/SRTFile.java',
        ROOT / 'staging/navigation-search-encoding-v1/sort-id-resource/sort/cp65001.txt': 'sources/cp65001.txt',
        OUT / 'style/inc/address': 'sources/taiwan-address-style.txt',
        ROOT / 'sources/maps/mkgmap-r4924/LICENCE': 'sources/mkgmap-LICENCE.txt',
        OUT / 'license.txt': 'LICENSE.txt', OUT / 'copyright.txt': 'COPYRIGHT.txt',
        ROOT / 'staging/navigation-road-coverage-v1/navigation-road-anchors-test.gpx': 'tests/road-anchors.gpx',
    }
    for source, target in copies.items():
        shutil.copyfile(source, package / target)
    (package / 'README.txt').write_text('''Garmin nüvi 2565RT 導航搜尋修復候選 v1

這包已通過離線地圖結構、中文排序與城市／道路索引檢查。
尚未安裝到車機或確認地址搜尋正常，不能視為已完成修復。
資料日期：2026-10-01。這是 OSM 地圖，不是 Garmin 官方 NT 更新。

請由本專案在原 Raspberry Pi 上處理，車機需 USB 隨身碟模式。
解壓縮後：
  python3 install.py --bundle .
上述只做唯讀預檢；確認身份後才執行：
  python3 install.py --bundle . --install
還原：
  python3 install.py --bundle . --rollback

只新增 Map/Taiwan_OSM_SearchRepair_v1.img；上一版專案 OSM 會改為
.img.disabled 保留，以免兩版同時載入。原廠道路主圖、門牌層、底圖 DEM、
時區、授權與版本配套檔全部保留。Windows 手動複製不是此安裝流程。

實機驗證請依 device-ab-checklist.txt，記錄路名、結果及耗時。
一開始只勾新版 OSM，暫時取消 CN 與 Address Point，再測原廠配套作對照。
原廠 CN 與 Address Point 同勾本來是互補；不是兩者必然衝突。
tests/road-anchors.gpx 僅供比對道路位置，不代表地址搜尋成功，亦不自動匯入。

這包不含新 GarminOS、原生 App 或藍牙音樂程式。
導航問題實機確認修好後，才繼續原音樂／App 研究。
''')
    (package / 'device-ab-checklist.txt').write_text('''1. 安裝後安全卸載，完整關機再開機，確認新版圖名可見。
2. A 組：只勾 OSM TW 2026-10-01 Search v1；暫時取消 CN Taiwan NT 與 Address Point。
   底圖／地形／時區保留；不要刪任何原廠檔。
3. 用「地址」先選臺中市，依序搜尋民權路、民和路一段、民和路二段。
   記錄候選完整路名、城市、點下去的地圖位置與從按搜尋到結果的秒數。
   民權路不能回傳或導航成民和路；一般測試期望30秒內得到結果，超時記錄為失敗。
4. 在可找到的門牌做兩筆測試，與現地或可靠位置對照；OSM不保證每個門牌均已收錄。
5. 使用者目前只實測民權路；其他「縣市＋路名」可選擇補測，不當成已確認的故障案例。
6. B 組：取消新版 OSM，只勾原廠 CN ＋ Address Point，重做同條路作對照。
7. 在室外GPS定位後測路線計算及短路段導引；只測檔案結構不等於導航正確。
8. 問題仍在：回傳 A／B 結果，必要時執行 --rollback；不宣稱已修復，也不開始其他改造。
''')
    files = sorted(p for p in package.rglob('*') if p.is_file())
    hashes = {str(p.relative_to(package)): build['image_sha256'] if str(p.relative_to(package)) == payload else sha(p)
              for p in files}
    (package / 'SHA256SUMS').write_text(''.join(f'{h}  {name}\n' for name, h in hashes.items()))
    hashes['SHA256SUMS'] = sha(package / 'SHA256SUMS')
    archive = ROOT / 'reports/downloads' / NAME
    assert not archive.exists(), 'Do not overwrite an existing sealed package'
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for name in hashes:
            z.write(package / name, name)
    archive.chmod(0o644)
    # One readback of every member validates ZIP CRC and expected content hashes.
    with zipfile.ZipFile(archive) as z:
        assert set(z.namelist()) == set(hashes)
        for name, expected in hashes.items():
            h = hashlib.sha256()
            with z.open(name) as f:
                for chunk in iter(lambda: f.read(4 * 1024 * 1024), b''):
                    h.update(chunk)
            assert h.hexdigest() == expected, name
    finish_result(archive, image, build, a.road_proof, len(hashes))


if __name__ == '__main__':
    main()
