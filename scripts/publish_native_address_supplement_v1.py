#!/usr/bin/env python3
"""Publish the downloadable and physically installed single-street candidate."""
import copy
import gzip
import html
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

BASE = ROOT / 'staging/navigation-native-address-supplement-v1'
OUT = BASE / 'publication'
FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json',
         'reports/findings.json', 'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
INSTALL = 'evidence/address-supplement-install-20261007-v1.json'


def main():
    assert not OUT.exists()
    installation = read(INSTALL)
    assert installation['state'] == 'installed_readback_verified'
    assert installation['unmounted'] and installation['transaction']['readback_verified']
    assert installation['transaction']['preserved_file_hashes_verified']
    native_path = 'staging/navigation-native-address-supplement-native-v1/candidate-original-CPU-proof-v1.json'
    native = read(native_path)
    assert native['all_assigned_checks_passed'] and native['exact_new_leaf_count'] == 9
    assert not native['full_reader_registry_getter_query_SQL_UI_or_route_executed']
    tests_path = 'staging/navigation-native-address-supplement-tools-v1/installer-test-results.json'
    assert read(tests_path)['all_cases_passed']
    package = read('staging/navigation-native-address-supplement-v1/package-result.json')
    download = read('staging/navigation-native-address-supplement-v1/download-verification.json')
    assert package['all_passed'] and download['served_sha256'] == package['sha256']
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    latest = json.loads(before[FILES[-1]])
    assert public['deep_research'] == state
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    app_before = copy.deepcopy(state['native_app_music'])
    app_progress = copy.deepcopy(public['research_progress'])
    served, _ = http(latest['url'])
    assert served == before[FILES[3]]
    report_service = service()
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    clock = f'<time datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）'
    actions = [
        '門牌補充候選已安裝、安全卸載；一般模式只勾Address Point＋Search v2，測民權路6號、150號、184號，每項最多60秒。',
        '確認新增地址與舊184號位置、路線，若異常以差異還原工具精確回到原廠AP。',
        '限定增補通過後再擴大其他街道／行政區的來源對照，完成新街道與完整地址索引產生規則。',
        '全台原廠格式地址更新仍未完成，不把此9筆補充包當成全台2026 Address Point。',
        '導航搜尋与地址更新需求驗證完成後，再恢復手機音樂／App研究。',
    ]
    details = [
        '實際候選IMG已產出，96739328bytes；補入6、8、138、140、142、144、146、148、150號。',
        '原民權路84筆完整bytes及相對順序保留，其他地圖元件與縣市／區／街道名稱資料庫保留。',
        '原CPU讀取實際候選的MDR目錄、街道、9筆新增記錄與184號、原文字流程均通過；完整實機地址UI仍待測。',
        '安裝／精確還原工具61項控制通過；還原資料能重建原廠完整SHA，不另製完整導航機備份。',
        'ZIP共12成員已全部讀回校驗；區網下載HTTP200、142881670bytes及SHA完全一致。',
        '精確實機已原子替換AP並完成讀回、其他保護檔校驗與安全卸載；新門牌搜尋及路線尚待使用者確認。',
    ]
    supplement = dict(
        version=1, updated_utc=now.isoformat(), scope='台中市中區民權路9筆來源門牌補充候選',
        package_prepared=True, estimate_percent=90,
        estimate_scope='本次9筆補充候選：封裝80、實機安裝10、地址與路線驗收10；非全台更新进度。',
        manifest='staging/navigation-native-address-supplement-v1/manifest.json',
        package=package, installation_evidence=INSTALL, installed_readback_verified=True,
        safely_unmounted=True, original_84_verbatim_preserved=True,
        native_candidate_record_and_label_fragments_verified=True,
        full_native_house_query_verified=False, source_house_numbers=[6, 8, 138, 140, 142, 144, 146, 148, 150],
        device_new_address_search_verified=False, device_new_address_route_verified=False,
        original_AP_file_replaced_with_candidate=True, firmware_or_license_or_DB_modified=False,
        whole_Taiwan_native_update_complete=False, details=details,
        pending_user_question='Search6/150/184 after complete reboot with AP+Searchv2.',
    )
    nav = state['navigation_repair']
    nav.update(updated_utc=now.isoformat(), address_supplement=supplement,
               navigation_repair_status='single_street_address_candidate_installed_UI_test_pending',
               execution_status='waiting_for_supplement_address_UI_test', next=actions[0],
               remaining_next_actions=actions, current_verification_details=details,
               remaining_physical_checks=['民權路6號、150號、184號的搜尋、位置與路線'],
               original_address_data_updated_to_2026=False, full_updated_address_search_verified=False,
               goal_complete=False, required_work_remaining=True)
    nav['original_format_research'].update(
        stage='single_street_AP_candidate_written_installed_UI_pending',
        single_street_AP_writer_implemented=True, new_candidate_native_record_fragments_verified=True,
        original_maps_or_DB_modified=True,
        modification_scope='實機.System/gmapprom1.img替換為候選；原備份、其他IMG、DB及授權檔保留。',
        latest_physical_install_evidence=INSTALL, whole_AP_MDR_JAI_writer_implemented=False,
        original_address_data_updated_to_2026=False, updated_utc=now.isoformat(),
    )
    nav['known_limits'] = [
        '本次9筆地址只屬民權路補充候選；原廠大部分地址仍是舊資料，全台原生更新尚未完成。',
        '候選已安裝及讀回，新增門牌搜尋、位置、路線仍待實機UI驗收。',
        '有限原CPU記錄與文字流程通過，尚未完整執行所有metadata/getter/query或證明全部flags語義。',
        '先前原AP＋OSM的184號成功證據適用原廠AP；本次候選仍需184號回歸測試。',
        '實機AP檔案已換成補充候選；原廠備份、其他圖資、資料庫、韌體及授權檔保留。',
    ]
    state.update(updated_utc=now.isoformat(), current_priority=actions[0], next_actions=actions,
                 required_work_remaining=True, goal_complete=False)
    state['last_goal_turn'] = dict(classification='progress', validated_utc=now.isoformat(),
                                   goal_status=state['goal_status'], device_IO=True,
                                   physical_primary_case_acceptance=None, installation_evidence=INSTALL,
                                   full_goal_complete=False, required_work_remaining=True)
    for key in ['navigation_repair', 'updated_utc', 'current_priority', 'next_actions',
                'last_goal_turn', 'required_work_remaining', 'goal_complete']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state),
                  navigation_repair=copy.deepcopy(nav), goal_complete=False, required_work_remaining=True)
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert state['native_app_music'] == app_before
    for key in ['estimate_percent', 'weighted_estimate_percent', 'phases', 'completed']:
        assert public['research_progress'][key] == app_progress[key]
    items = lambda values: ''.join('<li>' + html.escape(value) + '</li>' for value in values)
    card = '<section class="card" id="navigation-repair-checkpoint-v2"><h2>門牌補充測試包已完成，車機安裝與讀回通過</h2>'
    card += '<p>台中市中區民權路新增9筆來源門牌，原84筆完整保留。新候選已安裝並安全卸載，現在等待實機地址搜尋、位置與路線確認。</p>'
    card += f'<p><a href="{html.escape(package["download_url"])}" download>下載完整測試包（約143 MB）</a>：含候選Address Point、既有新版道路圖、校驗與精確還原工具。</p>'
    card += '<p>本次9筆補充候選估計 <strong>90%</strong>；封裝80%、實機安裝10%已完成，地址／路線驗收10%待測。這個比例只適用本次補充候選，全台原廠格式地址更新仍未完成。</p>'
    card += '<progress id="navigation-repair-progress" max="100" value="90" style="width:100%;height:18px">90%</progress><p>更新：' + clock + '</p>'
    card += '<h3>已完成</h3><ul>' + items(details) + '</ul><h3>現在需要測試</h3><ol>' + items(actions) + '</ol>'
    card += '<h3>尚未完成</h3><ul>' + items(nav['known_limits']) + '</ul></section>'
    native_card = '<aside class="card" id="navigation-native-format-progress-v1"><h2>原廠格式更新：已產生整張AP候選與可逆差異包</h2>'
    native_card += '<p>本次只變動原AP的地址記錄／目錄及對應檔案長度，文字區與其他地圖元件保留。可精確還原到原廠完整SHA；仍需實機搜尋驗收。</p>'
    native_card += '<p>搜尋新增民權路6號、150號及舊184號；若逾時，最多60秒就取消並回報。</p><p>研究更新：' + clock + '</p></aside>'
    report = before[FILES[3]].decode()
    for pattern, value in [(r'<section class="card" id="navigation-repair-checkpoint-v2">.*?</section>', card),
                           (r'<aside class="card" id="navigation-native-format-progress-v1">.*?</aside>', native_card)]:
        report, count = re.subn(pattern, lambda _: value, report, count=1, flags=re.S)
        assert count == 1
    for identifier in ['report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + identifier + r'" datetime="[^"]+">[^<]+</time>',
                                lambda _: f'<time id="{identifier}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',
                                report, count=1)
        assert count == 1
    OUT.mkdir()
    for name, raw in before.items():
        with (OUT / (name.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0))
            stream.flush()
            os.fsync(stream.fileno())
    sources = [INSTALL, native_path, tests_path,
               'staging/navigation-native-address-supplement-v1/build-verification.json',
               'staging/navigation-native-address-supplement-v1/package-result.json',
               'staging/navigation-native-address-supplement-v1/download-verification.json']
    create(OUT / 'proof-bindings.json', dict(created_utc=now.isoformat(),
           files=[dict(path=name, sha256=sha((ROOT / name).read_bytes())) for name in sources],
           whole_Taiwan_update_complete=False, full_goal_complete=False))
    for name, value in zip(FILES[:4], [state, task, public, report]):
        replace(name, value)
    served, response = http(latest['url'])
    assert served == report.encode() and service() == report_service
    latest.update(updated_utc=now.isoformat(), HTTP_status=response['status'],
                  local_report_sha256=sha(served), served_report_sha256=sha(served), report_bytes=len(served),
                  served_latest_report=True, service_not_restarted=True,
                  native_address_supplement_installed=True, native_address_supplement_UI_verified=False,
                  latest_native_address_supplement_install=INSTALL, required_work_remaining=True,
                  full_goal_complete=False)
    replace(FILES[-1], latest)
    assert read(FILES[2])['deep_research'] == read(FILES[0])
    create(OUT / 'fresh-readback.json', dict(all_passed=True, HTTP=response,
           report_sha256=sha(served), service=report_service, service_not_restarted=True,
           candidate_installation_verified=True, candidate_UI_verified=False,
           download_url=package['download_url'], full_goal_complete=False))
    print(json.dumps(dict(all_passed=True, report_url=latest['url'],
                          download_url=package['download_url'], service_PID=report_service['MainPID']), ensure_ascii=False))


if __name__ == '__main__':
    main()
