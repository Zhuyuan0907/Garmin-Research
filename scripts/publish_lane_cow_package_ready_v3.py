#!/usr/bin/env python3
"""Publish final local v3 package, preserving explicit physical/full-goal gaps."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

OUT = ROOT / 'staging/navigation-lane-cow-package-publication-v3'
FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json',
         'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']


def main():
    assert not OUT.exists()
    before = {name: (ROOT/name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[-1]])
    svc = service(); served, _ = http(web['url'])
    assert served == before[FILES[3]] and state == public['deep_research']
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    package = read('staging/navigation-country-address-package-v3/package-result.json')
    download = read('staging/navigation-lane-v3-download-publication/download-verification.json')
    production = read('staging/navigation-country-address-package-v3/validation/production-load-manifest-proof.json')
    host = read('staging/navigation-country-native-lane-candidate-v3/proof.json')
    cpu = read('staging/navigation-country-native-lane-cpu-v3/proof.json')
    review = read('staging/navigation-country-native-lane-independent-review-v3/proof.json')
    restore = read('staging/navigation-country-native-lane-restore-v3/proof.json')
    preflight = read('staging/navigation-lane-v3-readonly-preflight/actual-preflight.json')
    for proof in (production, host, cpu, review, restore):
        assert proof['all_assigned_checks_passed']
    assert package['all_passed'] and download['all_passed']
    assert download['served_bytes'] == package['bytes'] and download['served_sha256'] == package['sha256']
    assert package['new_houses'] == 188870 and package['existing_streets'] == 20107
    assert preflight['state'] == 'waiting_for_usb' and not preflight['physical_device_present']
    assert not preflight['device_files_written']
    now = datetime.now(timezone.utc); local = now.astimezone(ZoneInfo('Asia/Taipei'))
    nav = state['navigation_repair']; app = copy.deepcopy(state['native_app_music'])
    current = nav['lane_tree_cow_candidate_v3']
    current.update(status='packaged_validated_waiting_for_USB', native_CPU_pending=False,
        native_CPU_verified=True, native_CPU_records=23, native_CPU_new_leaves=7,
        native_CPU_candidate_read_bytes=77237, native_CPU_full_query_UI_verified=False,
        independent_actual_tree_review_pending=False, independent_actual_new_leaves_checked=58233,
        independent_actual_parent_paths_checked=20613, independent_actual_ancestor_links_checked=24442,
        compact_stock_restore_pending=False, exact_original_stock_restore_verified=True,
        compact_stock_recipe_bytes=879499, compact_actual_binding_bytes=292144,
        package_ready=True, package=package, portable_production_binding_verified=True,
        download_HTTP_full_readback_verified=True, device_installed=False, device_search_verified=False,
        physical8K_acceptance_verified=False, header_checksum_rule_known=False,
        device_IO_preflight=preflight, evidence=[
          'staging/navigation-country-native-lane-candidate-v3/proof.json',
          'staging/navigation-country-native-lane-independent-review-v3/proof.json',
          'staging/navigation-country-native-lane-cpu-v3/proof.json',
          'staging/navigation-country-native-lane-restore-v3/proof.json',
          'staging/navigation-country-address-package-v3/validation/production-load-manifest-proof.json',
          'staging/navigation-country-address-package-v3/package-result.json',
          'staging/navigation-lane-v3-download-publication/download-verification.json'])
    nav['country_existing_street_candidate_v2'] = copy.deepcopy(nav['country_existing_street_candidate'])
    nav['country_existing_street_candidate'] = copy.deepcopy(current)
    nav['country_existing_street_candidate'].update(bytes=host['candidate_bytes'], sha256=host['candidate_sha256'],
        new_integer_houses=188870, existing_streets_updated=20107,
        new_houses_by_leaf_level={'4': 88094, '5': 85088, '6': 15688},
        original_4K_geometry_and_other_five_components_unchanged=False,
        explicit8K_geometry_other_five_component_payloads_unchanged=True,
        install_package_ready=True, physical_device_installation_pending=True,
        full_Taiwan_update_complete=False)
    nav['native_country_address_update_progress'].update(estimate_percent=65, updated_utc=now.isoformat(), phases=[
        '全台來源規劃、既有街道及完整巷弄精確比對完成；矛盾來源、子號與未匹配項仍暫留。',
        '累計188,870新整數門牌／20,107既有街道，完整候選寫出；58,233新巷弄門牌的全部父子路徑與新葉獨立讀回核對通過。',
        '原韌體有限讀取23記錄／23標籤片段、精確原廠還原、可攜式安裝綁定、22成員ZIP及區網完整下載校驗通過。',
        '較大8K候選尚未實機安裝；容器接受度、完整中文搜尋／位置／路線、新街道與子號仍待完成。'])
    actions = ['v3巷弄擴展試驗包已完成；USB隨身碟模式接Pi後安裝讀回，完整重開機先確認8K圖資載入，再測民權控制與新巷弄地址。',
        '實機先檢查新門牌搜尋、目的地與路線；v3容器接受度尚未驗證，原韌體有限讀取不等整台導航介面。',
        '繼續新街道／行政區、子號和矛盾資料，保留原地址搜尋選單；全台完整更新尚未完成。',
        '畫面刷新效能測試依使用者指示停止；導航地址需求驗證完成後恢復手機音樂／App。']
    nav.update(updated_utc=now.isoformat(), execution_status='country_v3_package_waits_for_USB_native_full_update_continues',
        remaining_next_actions=copy.deepcopy(actions), next=actions[0],
        remaining_physical_checks=['v3安裝／讀回後的8K圖資接受度、民權路控制及新增巷弄搜尋／位置／路線；不要求行車。'])
    state.update(updated_utc=now.isoformat(), current_priority=actions[0], next_actions=actions)
    state['last_goal_turn'] = dict(classification='progress', validated_utc=now.isoformat(), goal_status=state['goal_status'],
        full_goal_complete=False, required_work_remaining=True, device_files_written=False,
        reason='Locally verified lane-COW candidate and full package published; fresh read-only preflight finds no Garmin USB; physical and full-source work remains.')
    for key in ['navigation_repair', 'updated_utc', 'current_priority', 'next_actions', 'last_goal_turn']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert state['native_app_music'] == app
    report = before[FILES[3]].decode()
    report = report.replace('跨縣市原生門牌補充候選已寫出；實機待測', '巷弄擴展整合測試包完成；實機待測', 1)
    report = report.replace('全台更新工程估計 <strong>55%</strong>', '全台更新工程估計 <strong>65%</strong>', 1)
    report = report.replace('<progress id="navigation-country-address-progress" max="100" value="55">55%</progress>',
        '<progress id="navigation-country-address-progress" max="100" value="65">65%</progress>', 1)
    report, count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>', lambda _: '<h3>已完成</h3><ul>'+
        ''.join('<li>'+p+'</li>' for p in nav['native_country_address_update_progress']['phases'])+'</ul>', report, count=1, flags=re.S)
    assert count == 1
    marker = '<h3>可用測試包與既有實測</h3>'; assert report.count(marker) == 1
    card = (f'<p><a href="{package["download_url"]}" download>下載巷弄擴展整合試驗包 v3（約167 MB）</a>：'
      'Address Point補充＋2026/10/1 Search v2道路圖＋安裝／精確還原工具。累計188,870筆新整數門牌／20,107既有街道，'
      '含58,233筆巷弄補充；22成員解壓及區網完整下載校驗一致。新8K容器接受度與完整搜尋／導航仍待實機，尚未安裝。</p>')
    report = report.replace(marker, marker+card, 1)
    report = report.replace('下載最新跨縣市門牌測試包 v2', '下載前版4K跨縣市門牌測試包 v2', 1)
    report, count = re.subn(r'<h3>巷弄完整候選：尚未實機安裝</h3><p>.*?</p>', lambda _:
      '<h3>巷弄驗證範圍</h3><p>58,233新門牌、20,613條父子路徑及24,442連結已沿實際候選獨立核對；'
      '原韌體23個實際記錄／23標籤片段通過，包括超過原22-bit位置的街道指標。較大153 MB Address Point仍可精確重建'
      '96,739,328-byte原廠檔案。這些是本機有限驗證；完整原生查詢、8K車機載入與實際路線尚未驗收。</p>',
      report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'<h3>接著處理</h3><ol>.*?</ol>', lambda _: '<h3>接著處理</h3><ol>'+''.join('<li>'+a+'</li>' for a in actions)+'</ol>', report, count=1, flags=re.S)
    assert count == 1
    for identifier in ['navigation-address-updated-time', 'report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="'+identifier+r'" datetime="[^"]+">[^<]+</time>', lambda _:
            f'<time id="{identifier}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        assert count == 1
    OUT.mkdir()
    for name, raw in before.items():
        with (OUT/(name.replace('/', '__')+'.gz')).open('xb') as f:
            f.write(gzip.compress(raw, mtime=0)); f.flush(); os.fsync(f.fileno())
    for name, value in zip(FILES[:4], [state, task, public, report]):
        replace(name, value)
    served, response = http(web['url']); assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
        served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
        latest_country_partial_package=package)
    replace(FILES[-1], web)
    assert read(FILES[0]) == read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    create(OUT/'fresh-readback.json', dict(all_passed=True, service=svc, report_sha256=sha(served), package=package,
        engineering_estimate_percent=65, device_installed=False, full_goal_complete=False, preflight=preflight))
    print(json.dumps(dict(all_passed=True, report_url=web['url'], download_url=package['download_url'],
        engineering_estimate_percent=65, device_installed=False)))


if __name__ == '__main__':
    main()
