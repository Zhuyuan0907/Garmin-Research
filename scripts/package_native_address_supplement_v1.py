#!/usr/bin/env python3
"""Package the checked nine-address candidate, roads, exact undo and installer."""
import hashlib
import json
import os
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'staging/navigation-native-address-supplement-v1'
TOOLS = ROOT / 'staging/navigation-native-address-supplement-tools-v1'
NATIVE = ROOT / 'staging/navigation-native-address-supplement-native-v1'
NAME = 'Garmin-2565RT-address-test-v1.zip'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def json_save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o444)


def main():
    archive = ROOT / 'reports/downloads' / NAME
    assert not archive.exists()
    manifest = json.loads((BASE / 'manifest.json').read_text())
    native = json.loads((NATIVE / 'candidate-original-CPU-proof-v1.json').read_text())
    tests = json.loads((TOOLS / 'installer-test-results.json').read_text())
    assert native['all_assigned_checks_passed'] and native['exact_new_leaf_count'] == 9
    assert not native['full_reader_registry_getter_query_SQL_UI_or_route_executed']
    assert tests['all_cases_passed']
    image = BASE / manifest['target']['bundle_path']
    assert digest(image) == manifest['target']['candidate_sha256']
    assert digest(BASE / 'rollback.json.gz') == manifest['rollback']['sha256']
    installer = TOOLS / 'install_address_supplement.py'
    assert digest(installer) == '8c3a74b620ad75a452421777b53c60285510c409df66cd10602648bf3604f411'
    os.link(installer, BASE / 'install_address_supplement.py')
    road_src = ROOT / 'staging/navigation-repair-v2/package/Map/Taiwan_OSM_SearchRepair_v2.img'
    (BASE / 'roadmap').mkdir()
    road_dst = BASE / 'roadmap/Taiwan_OSM_SearchRepair_v2.img'
    os.link(road_src, road_dst)
    assert road_dst.stat().st_ino == road_src.stat().st_ino
    assert digest(road_dst) == manifest['required_files'][0]['sha256']
    (BASE / 'validation').mkdir()
    for origin in [NATIVE / 'candidate-original-CPU-proof-v1.json',
                   TOOLS / 'installer-test-results.json',
                   TOOLS / 'installer-test-terminal-receipt.json',
                   TOOLS / 'readonly-preflight.json']:
        os.link(origin, BASE / 'validation' / origin.name)
    readme = '''Garmin 台灣 nüvi 2565RT（HWID1352／SW8.00）民權路地址補充測試包 v1

這是台中市中區民權路9筆來源門牌的原廠格式補充候選。
候選實際檔案已產出；原CPU已核對新目錄、街道、9筆新記錄與184號。
原機地址UI搜尋與路線尚待實測。這不是全台2026新版Address Point。

包含：
- candidate/gmapprom1.img：原廠Address Point的補充候選，97MB。
- roadmap/Taiwan_OSM_SearchRepair_v2.img：既有新版台灣OSM道路圖。
- manifest.json、rollback.json.gz：完整校驗與精確原檔還原資料。
- install_address_supplement.py：Pi／Linux的唯讀預檢、安裝與還原工具。
- validation/：限定原CPU讀取與安裝工具驗證紀錄。

更新範圍：
新增來源門牌為6、8、138、140、142、144、146、148、150號。
原84筆每筆bytes及相對順序保持，原位置也仍保留。
原縣市／區／民權路名稱索引、其他地圖元件、韌體及授權檔保留。
圖資清單名稱仍可能顯示原廠2016，不代表這包是完整全台新版。
這9筆是目前來源有且所選原84筆primary未觀察到的地址，未聲稱2016後才新建。

安裝前：
1. 將Garmin接至Pi並選隨身碟模式，保持USB連接。
2. 原廠Address Point與Search v2已安裝；工具要求Search v2雜湊吻合。
3. 在解壓縮目錄執行：
   python3 -B install_address_supplement.py --bundle .
   此命令只預檢。真正測試安裝：
   sudo python3 -B install_address_supplement.py --bundle . --install
   成功後工具會同步並安全卸載。不要直接手動覆蓋原廠檔案。
4. 本次工具只替換Address Point；roadmap/附現有道路圖供整包保存，
   不會再次覆蓋已安裝的Search v2。

實機測試：
1. 完成安全卸載後拔USB，完整關機再開機。
2. 地圖資訊勾Address Point與Search v2，先取消原廠CN Taiwan NT道路圖。
3. 用原廠「地址」入口，指定台中市，搜尋民權路6號、150號、184號。
4. 回覆每個地址能否找到、位置是否在預期民權路、路線能否計算。
   每次最多等待60秒；逾時就取消。原184號作舊資料回歸對照。

還原：
將Garmin接回Pi隨身碟模式，在同一包目錄執行：
   sudo python3 -B install_address_supplement.py --bundle . --rollback
工具只接受本候選的精確SHA，還原後必須吻合原廠完整SHA。
回復只使用差異資料，不新增另一份完整導航機備份。

來源與授權：
新增座標來自2026-10-01T20:22:06Z台灣OpenStreetMap來源快照。
© OpenStreetMap contributors；資料依ODbL提供：
https://www.openstreetmap.org/copyright
原廠地圖及其作者／授權資訊保留。本包針對已授權的單一導航機實驗。
'''
    (BASE / 'README.txt').write_text(readme)
    (BASE / 'README.txt').chmod(0o444)
    entries = ['README.txt', 'manifest.json', 'candidate/gmapprom1.img',
               'roadmap/Taiwan_OSM_SearchRepair_v2.img', 'rollback.json.gz',
               'install_address_supplement.py', 'build-verification.json']
    entries += ['validation/' + path.name for path in sorted((BASE / 'validation').iterdir())]
    inventory = [dict(path=name, bytes=(BASE / name).stat().st_size, sha256=digest(BASE / name))
                 for name in entries]
    json_save(BASE / 'SHA256SUMS.json', inventory)
    entries.append('SHA256SUMS.json')
    temp = archive.with_suffix('.zip.partial')
    assert not temp.exists()
    with zipfile.ZipFile(temp, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as package:
        for name in entries:
            package.write(BASE / name, name)
    with zipfile.ZipFile(temp) as package:
        assert sorted(package.namelist()) == sorted(entries)
        for item in inventory:
            h = hashlib.sha256()
            with package.open(item['path']) as stream:
                for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
                    h.update(block)
            assert h.hexdigest() == item['sha256'], item['path']
    with temp.open('rb') as stream:
        os.fsync(stream.fileno())
    temp.chmod(0o644)
    os.replace(temp, archive)
    result = dict(created_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
                  archive=str(archive.relative_to(ROOT)), bytes=archive.stat().st_size,
                  sha256=digest(archive), members=len(entries), all_member_readbacks_verified=True,
                  road_image_hardlinked_not_duplicated=True,
                  address_candidate_device_verified=False, whole_Taiwan_native_update_complete=False,
                  download_url='http://172.16.60.187:8767/' + NAME)
    json_save(BASE / 'package-result.json', result)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
