#!/usr/bin/env python3
"""Repackage sealed v2 into candidate v2.1 without extracting the map.

Only the installer and its revision metadata change. No USB or service calls.
The archive is copied as streams; every inherited member and the new archive
are verified against SHA-256, and zipfile checks their CRC during readback.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sys
from datetime import datetime, timezone
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / 'reports/downloads/Garmin-2565RT-navigation-repair-v2.zip'
OUTPUT = ROOT / 'reports/downloads/Garmin-2565RT-navigation-repair-v2.1.zip'
RESULT_DIR = ROOT / 'staging/navigation-repair-v2_1'
PATCH_DIR = ROOT / 'staging/navigation-map-layers-v3'
ORIGINAL_SHA = 'f22f991f6e654290432c283b68757b827cd612d629d53890d29fb5d61fe62d3d'
ORIGINAL_BYTES = 98671846
OLD_INSTALLER_SHA = '940114eee1944b22b2bfab3dd46b7a79dc72ca8447bc6391c6812e613c2ca0f8'
NEW_INSTALLER_SHA = '26cc17d565f46147faad2a681ba8065118da070fadda5b713f502196edd61044'
MAP_NAME = 'Map/Taiwan_OSM_SearchRepair_v2.img'
MAP_SHA = '664c46c99697b61ba383b5571b0a49356336746c9bbf3f94403aae583787f117'
MAP_BYTES = 131829760
BUFFER_BYTES = 4 * 1024 * 1024


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(BUFFER_BYTES), b''):
            digest.update(block)
    return digest.hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def rel(path):
    return str(path.relative_to(ROOT))


def file_record(path, data=None):
    if data is None:
        data = path.read_bytes()
    return {'path': rel(path), 'bytes': len(data), 'sha256': sha(data)}


def stat_signature(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def safe_name(name):
    p = PurePosixPath(name)
    need(name and not p.is_absolute() and '..' not in p.parts and '\\' not in name,
         'Unsafe archive member: ' + repr(name))
    need(not name.endswith('/'), 'Directory members are not expected')


def sum_table(data):
    table = {}
    for line in data.decode('utf-8').splitlines():
        digest, name = line.split('  ', 1)
        safe_name(name)
        need(len(digest) == 64 and all(c in '0123456789abcdef' for c in digest),
             'Invalid source checksum')
        need(name not in table, 'Duplicate checksum entry')
        table[name] = digest
    return table


def privacy_safe_outcome(path):
    data = path.read_bytes()
    evidence = json.loads(data)
    # Whitelist outcomes; never copy USB identity, serial, paths, or lock details.
    summary = {'source_evidence': file_record(path, data)}
    for key in ('started_at', 'completed_at', 'mode', 'state', 'error',
                'bundle_image_sha256_verified', 'device_files_written',
                'device_search_verified', 'device_routing_verified', 'unmounted'):
        if key in evidence:
            summary[key] = evidence[key]
    if 'transaction' in evidence:
        tx = evidence['transaction']
        summary['transaction'] = {key: tx[key] for key in (
            'mode', 'events', 'new_map_present', 'previous_map_active',
            'previous_map_disabled', 'preserved_stock_hashes_verified_after_transaction')
            if key in tx}
    return summary


README = '''Garmin nüvi 2565RT 導航搜尋修復候選：下載包 v2.1／地圖 v2

v2.1 只修正安裝器：同一 Garmin 的空 SD 卡槽只有在 lsblk 與 sysfs 都回報
容量 0、未掛載、沒有子分割區時才略過。身份、非零容量與所有其他拒絕條件保留。
原 v2 ZIP 不變，舊安裝器保存在 history/install-v2.py；11 項控制證據附在 verification。
地圖仍是第二版 FID 7053，內容與原 v2 ZIP 逐 byte 相同，沒有重新編圖。

已在此機安裝讀回；地址／路由尚未通過實機驗收。
只勾新版地圖時，地址入口搜尋城市「台中」實機回報「無相符項目」。
原因調查中；本包暫緩作為推薦修復版本，不宣稱導航已修好。
2026-10-06 本次使用 v3 安裝器完成讀回校驗，舊專案地圖停用並保留，14 個原廠
檔案及裝置身份完成最後核對，已安全卸載。這只證明安裝，不表示導航已修好。
verification/physical-install-outcomes.json 是去識別的結果摘要；本包不附原始機號、
藍牙位置或 USB 序號。manifest 原 device_installed=false 是原 v2 封包當時的歷史值，
目前單機讀回狀態見 package_revision，不將結果推及其他車機。

第二版地圖修正漢字排序鍵與 SRT 16/10/6 欄位封裝，保留城市／道路歸屬調整。
離線證據包含原始函式有限對照、實際新版 MDR 索引及道路／城市檢查。
OSM 資料日期 2026-10-01；它是 OSM 地圖，並非 Garmin 官方 NT 更新。

Linux／原 Raspberry Pi 上解壓縮後：
  python3 install.py --bundle .
預設只做唯讀預檢。Garmin 在 USB 隨身碟模式時安裝：
  python3 install.py --bundle . --install
還原：
  python3 install.py --bundle . --rollback

只新增 Map/Taiwan_OSM_SearchRepair_v2.img；原已驗證的專案 OSM 20261001 改為
.img.disabled 並保留。rollback 只刪完全符合本包雜湊的新 IMG 並還原舊專案圖。
身份、原廠圖、授權與配套檔皆需核對；檔案異動、空間不足、USB 不符時拒絕安裝。
原廠 CN 道路＋Address Point 門牌層互補；原廠檔保留且不放入下載包。
工具不會移除任何來歷不明或其他候選圖資。

請依 device-ab-checklist.txt 實測。排序對照與檔案讀回不等於地址搜尋成功。
OSM 可能缺門牌；高雄來源邊界缺段等限制見 manifest.json 與 verification。
tests/road-anchors.gpx 用於位置比對，不自動匯入，也不證明地址命中。
這包未包含 GarminOS、新 App、原廠私有圖資／資料庫或藍牙音樂程式。
導航實機修復確認後才恢復其他改造研究。
'''


def main():
    started = datetime.now(timezone.utc).isoformat()
    partial = OUTPUT.with_suffix('.zip.partial')
    result_path = RESULT_DIR / 'package-result.json'
    receipt_path = RESULT_DIR / 'packaging-receipt.json'
    for path in (OUTPUT, partial, result_path, receipt_path):
        need(not path.exists(), 'Refusing to replace existing output: ' + rel(path))
    original_stat = stat_signature(ORIGINAL)
    need(ORIGINAL.stat().st_size == ORIGINAL_BYTES and file_sha(ORIGINAL) == ORIGINAL_SHA,
         'Sealed v2 ZIP mismatch')
    installer_path = PATCH_DIR / 'install_navigation_bundle.py'
    installer = installer_path.read_bytes()
    need(sha(installer) == NEW_INSTALLER_SHA, 'v3 installer mismatch')
    ast.parse(installer.decode('utf-8'))
    change_path = PATCH_DIR / 'source-change.json'
    controls_path = PATCH_DIR / 'empty-sd-selection-proof.json'
    terminal_path = PATCH_DIR / 'installation-terminal-receipt.json'
    change_bytes = change_path.read_bytes()
    controls_bytes = controls_path.read_bytes()
    terminal_bytes = terminal_path.read_bytes()
    change, controls, terminal = map(json.loads, (change_bytes, controls_bytes, terminal_bytes))
    need(change['parent_sha256'] == OLD_INSTALLER_SHA and
         change['patched_sha256'] == NEW_INSTALLER_SHA and
         change['sealed_v2_source_modified'] is False, 'Installer change lineage mismatch')
    need(controls['all_passed'] is True and len(controls['checks']) == 11 and
         all(item['passed'] is True for item in controls['checks']), '11 control proof mismatch')
    outcomes = {
        'format_version': 1, 'candidate_package_version': '2.1', 'map_candidate_version': 2,
        'map_sha256': MAP_SHA, 'installer_sha256': NEW_INSTALLER_SHA,
        'scope': 'Authorized single unit installation/readback; city lookup failed and routing UI unverified.',
        'original_v2_readonly_failure': privacy_safe_outcome(ROOT / 'evidence/navigation-bundle-20261006T005056170568+0800.json'),
        'corrected_readonly_preflight': privacy_safe_outcome(ROOT / 'evidence/navigation-bundle-20261006T005428725854+0800.json'),
        'installation': privacy_safe_outcome(ROOT / 'evidence/navigation-bundle-20261006T005739339907+0800.json'),
    }
    installed = outcomes['installation']
    need(installed['state'] == 'installed_readback_verified' and
         installed['bundle_image_sha256_verified'] is True and installed['unmounted'] is True and
         installed['device_search_verified'] is False and installed['device_routing_verified'] is False,
         'Installation evidence must show readback only, pending navigation acceptance')
    need(terminal['exit_code'] == 0 and terminal['safe_unmounted'] is True and
         terminal['installer_sha256'] == NEW_INSTALLER_SHA and
         terminal['installation_evidence'] == {
             'path': installed['source_evidence']['path'],
             'sha256': installed['source_evidence']['sha256']}, 'Terminal/evidence binding mismatch')
    frozen_inputs = [file_record(path) for path in (installer_path, change_path, controls_path, terminal_path)]
    for name in ('original_v2_readonly_failure', 'corrected_readonly_preflight', 'installation'):
        frozen_inputs.append(outcomes[name]['source_evidence'])

    with zipfile.ZipFile(ORIGINAL, 'r') as source:
        names = source.namelist()
        need(len(names) == 46 and len(names) == len(set(names)), 'Original member set mismatch')
        for name in names:
            safe_name(name)
        old_small = {name: source.read(name) for name in (
            'manifest.json', 'README.txt', 'install.py', 'SHA256SUMS',
            'verification/package-source-provenance.json')}
        expected_old = sum_table(old_small['SHA256SUMS'])
        need(set(expected_old) == set(names) - {'SHA256SUMS'}, 'Original checksum member coverage mismatch')
        need(sha(old_small['install.py']) == OLD_INSTALLER_SHA, 'Original installer mismatch')
        old_manifest = json.loads(old_small['manifest.json'])
        need(old_manifest['candidate_version'] == 2 and old_manifest['candidate'] is True,
             'Original candidate version mismatch')
        need(old_manifest['new_map']['bundle_path'] == MAP_NAME and
             old_manifest['new_map']['sha256'] == MAP_SHA and
             old_manifest['new_map']['bytes'] == MAP_BYTES and
             old_manifest['new_map']['family_id'] == 7053, 'Map identity mismatch')
        need([name for name in names if name.lower().endswith('.img')] == [MAP_NAME],
             'Only original project map may be in payload')
        need(len(old_manifest['preserved_stock_files']) == 14,
             'Expected 14 original files in final hash-check scope')
        revision = {
            'package_version': '2.1', 'map_candidate_version': 2, 'installer_revision': 3,
            'candidate': True, 'created_utc': started,
            'change_scope': 'Installer empty SD LUN selection only; v2 map/source/proofs unchanged.',
            'original_v2_archive': {'path': rel(ORIGINAL), 'bytes': ORIGINAL_BYTES, 'sha256': ORIGINAL_SHA},
            'historical_root_device_flags': 'Top-level device_installed/search/routing are original v2 packaging-time flags.',
            'current_single_unit_installed': True, 'current_single_unit_readback_verified': True,
            'current_single_unit_safe_unmounted': True, 'device_search_verified': False,
            'device_routing_verified': False,
            'installation_scope': 'This authorized unit only; no address/routing acceptance or cross-unit claim.',
            'navigation_release_status': 'hold_pending_city_lookup_investigation',
            'physical_city_lookup_observation': {
                'entry': 'Address city search', 'query': '台中',
                'selected_maps': 'SearchRepair v2 only', 'reported_result': '無相符項目',
                'source': 'User onsite feedback relayed by root during packaging preparation',
                'cause_confirmed': False, 'proves_complete_search_failure': False,
            },
            'outcomes_member': 'verification/physical-install-outcomes.json',
            'installer_change_member': 'verification/installer-v3-source-change.json',
            'installer_control_member': 'verification/installer-v3-empty-sd-controls.json',
        }
        manifest = copy.deepcopy(old_manifest)
        manifest['package_version'] = '2.1'
        manifest['package_revision'] = revision
        need(manifest['new_map'] == old_manifest['new_map'], 'Map manifest changed unexpectedly')
        additions = {
            'history/install-v2.py': old_small['install.py'],
            'history/README-v2.txt': old_small['README.txt'],
            'history/manifest-v2.json': old_small['manifest.json'],
            'history/SHA256SUMS-v2.txt': old_small['SHA256SUMS'],
            'history/package-source-provenance-v2.json': old_small['verification/package-source-provenance.json'],
            'verification/installer-v3-source-change.json': change_bytes,
            'verification/installer-v3-empty-sd-controls.json': controls_bytes,
            'verification/physical-install-outcomes.json': encoded(outcomes),
            'verification/installation-terminal-receipt-v3.json': terminal_bytes,
            'verification/package-revision-v2_1.json': encoded(revision),
        }
        provenance = json.loads(old_small['verification/package-source-provenance.json'])
        matches = [entry for entry in provenance if entry['bundle_path'] == 'install.py']
        need(len(matches) == 1 and matches[0]['sha256'] == OLD_INSTALLER_SHA,
             'Original installer provenance mismatch')
        matches[0].update(source_path=rel(installer_path), bytes=len(installer), sha256=NEW_INSTALLER_SHA)
        history_sources = {
            'history/install-v2.py': 'install.py',
            'history/README-v2.txt': 'README.txt',
            'history/manifest-v2.json': 'manifest.json',
            'history/SHA256SUMS-v2.txt': 'SHA256SUMS',
            'history/package-source-provenance-v2.json': 'verification/package-source-provenance.json',
        }
        for name, data in additions.items():
            provenance.append({'bundle_path': name, 'source_path': (
                rel(ORIGINAL) + '!' + history_sources[name]
                if name in history_sources else 'generated-by:' + rel(Path(__file__).resolve())),
                'bytes': len(data), 'sha256': sha(data)})
        # Actual source paths replace generated labels for the three verbatim v3 files.
        source_overrides = {
            'verification/installer-v3-source-change.json': change_path,
            'verification/installer-v3-empty-sd-controls.json': controls_path,
            'verification/installation-terminal-receipt-v3.json': terminal_path,
        }
        for entry in provenance:
            if entry['bundle_path'] in source_overrides:
                entry['source_path'] = rel(source_overrides[entry['bundle_path']])
        replacements = {
            'install.py': installer, 'manifest.json': encoded(manifest),
            'README.txt': README.encode('utf-8'),
            'verification/package-source-provenance.json': encoded(provenance),
        }
        need(not set(additions).intersection(names), 'Added member collides with original')
        for name in additions:
            safe_name(name)
        expected_new = {}
        records = {}
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(partial, 'x', compression=zipfile.ZIP_DEFLATED,
                                 compresslevel=6, allowZip64=True) as target:
                for name in sorted(set(names) - {'SHA256SUMS'}):
                    if name in replacements:
                        data = replacements[name]
                        need(sha(source.read(name)) == expected_old[name], 'Replaced source member mismatch: ' + name)
                        target.writestr(name, data)
                        expected_new[name] = sha(data)
                        records[name] = {'bytes': len(data), 'sha256': sha(data), 'inherited_unchanged': False}
                    else:
                        digest, count = hashlib.sha256(), 0
                        info = source.getinfo(name)
                        with source.open(name) as incoming, target.open(name, 'w', force_zip64=True) as outgoing:
                            for block in iter(lambda: incoming.read(BUFFER_BYTES), b''):
                                digest.update(block)
                                count += len(block)
                                outgoing.write(block)
                        need(digest.hexdigest() == expected_old[name] and count == info.file_size,
                             'Inherited source member mismatch: ' + name)
                        expected_new[name] = digest.hexdigest()
                        records[name] = {'bytes': count, 'sha256': digest.hexdigest(), 'inherited_unchanged': True}
                for name, data in sorted(additions.items()):
                    target.writestr(name, data)
                    expected_new[name] = sha(data)
                    records[name] = {'bytes': len(data), 'sha256': sha(data), 'inherited_unchanged': False}
                sums = ''.join(f'{expected_new[name]}  {name}\n' for name in sorted(expected_new)).encode()
                target.writestr('SHA256SUMS', sums)
                records['SHA256SUMS'] = {'bytes': len(sums), 'sha256': sha(sums), 'inherited_unchanged': False}
            with partial.open('rb') as stream:
                os.fsync(stream.fileno())
            with zipfile.ZipFile(partial, 'r') as rebuilt:
                need(len(rebuilt.namelist()) == len(records) and set(rebuilt.namelist()) == set(records),
                     'New archive member coverage mismatch')
                need(sum_table(rebuilt.read('SHA256SUMS')) == expected_new, 'New checksum table mismatch')
                for name in rebuilt.namelist():
                    digest, count = hashlib.sha256(), 0
                    with rebuilt.open(name) as stream:
                        for block in iter(lambda: stream.read(BUFFER_BYTES), b''):
                            digest.update(block)
                            count += len(block)
                    need(digest.hexdigest() == records[name]['sha256'] and count == records[name]['bytes'],
                         'New ZIP readback mismatch: ' + name)
                    records[name]['readback_sha256_and_crc_passed'] = True
            need(stat_signature(ORIGINAL) == original_stat, 'Original archive changed during packaging')
            for item in frozen_inputs:
                path = ROOT / item['path']
                need(path.stat().st_size == item['bytes'] and file_sha(path) == item['sha256'],
                     'Revision evidence changed during packaging: ' + item['path'])
            need(records[MAP_NAME]['sha256'] == MAP_SHA and records[MAP_NAME]['bytes'] == MAP_BYTES,
                 'Map content changed')
            archive_bytes, archive_sha = partial.stat().st_size, file_sha(partial)
            os.link(partial, OUTPUT)  # Atomic no-replace publication on the same filesystem.
            partial.unlink()
            directory = os.open(OUTPUT.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            if partial.exists():
                partial.unlink()
            raise
    completed = datetime.now(timezone.utc).isoformat()
    result = {
        'all_passed': True, 'candidate': True, 'package_version': '2.1', 'candidate_version': 2,
        'created_utc': completed, 'zip_path': rel(OUTPUT), 'zip_bytes': archive_bytes,
        'zip_sha256': archive_sha, 'map_bundle_path': MAP_NAME, 'map_bytes': MAP_BYTES,
        'map_sha256': MAP_SHA, 'map_payload_unchanged': True, 'original_archive_unchanged': True,
        'installer_sha256': NEW_INSTALLER_SHA, 'installer_revision': 3,
        'current_single_unit_installed': True, 'current_single_unit_readback_verified': True,
        'device_search_verified': False, 'device_routing_verified': False,
        'packaging_device_io': False, 'canonical_or_service_changed': False,
        'navigation_release_status': 'hold_pending_city_lookup_investigation',
        'source_path': rel(Path(__file__).resolve()), 'source_sha256': file_sha(Path(__file__).resolve()),
        'member_count': len(records), 'all_member_sha256_and_crc_readback_passed': True,
        'changed_original_members': sorted(list(replacements) + ['SHA256SUMS']),
        'added_members': sorted(additions), 'original_archive_sha256': ORIGINAL_SHA,
    }
    receipt = {
        'all_passed': True, 'started_utc': started, 'completed_utc': completed,
        'scope': 'Streaming v2.1 ZIP packaging and readback only; no raw IMG extraction, USB or service calls.',
        'result': result, 'frozen_revision_inputs': frozen_inputs,
        'inherited_members_unchanged': sorted(name for name, record in records.items() if record['inherited_unchanged']),
        'member_verification': records,
        'old_map_native_mdr_road_test_suites_rerun': False,
        'readback': 'Every decompressed member read to EOF: zipfile CRC and independent SHA-256; whole compressed ZIP SHA-256.',
    }
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    for path, value in ((result_path, result), (receipt_path, receipt)):
        with path.open('xb') as stream:
            stream.write(encoded(value))
            stream.flush()
            os.fsync(stream.fileno())
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
