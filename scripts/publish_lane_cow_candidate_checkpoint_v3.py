#!/usr/bin/env python3
"""Publish actual COW composition, keeping package/device acceptance separate."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

OUT = ROOT / 'staging/navigation-lane-cow-composition-publication-v3'
FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json',
         'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
HOST = 'staging/navigation-country-native-lane-candidate-v3/proof.json'
HOST_SHA = 'b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0'


def main():
    assert not OUT.exists()
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[-1]])
    svc = service()
    served, _ = http(web['url'])
    assert served == before[FILES[3]] and state == public['deep_research']
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    raw = (ROOT / HOST).read_bytes()
    assert sha(raw) == HOST_SHA
    host = json.loads(raw)
    assert host['all_assigned_checks_passed'] and host['new_lane_integer_houses'] == 58233
    assert host['total_supplemented_integer_houses'] == 188870 and not host['device_installed']
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    nav = state['navigation_repair']
    app = copy.deepcopy(state['native_app_music'])
    nav['lane_tree_cow_candidate_v3'] = dict(status='complete_actual_IMG_waiting_for_native_independent_restore_checks',
        candidate_path=host['candidate_path'], candidate_bytes=host['candidate_bytes'],
        candidate_sha256=host['candidate_sha256'], new_lane_integer_houses=58233,
        prior_v2_new_integer_houses_retained=130637, total_supplemented_integer_houses=188870,
        selected_L3_root_changes=7650, explicit_lower_parent_patches=22216,
        all_current_lower_significant_bits_preserved=True, all_actual_append_streams_verified=True,
        all_six_components_full_readback_verified=True, lower_widths_expanded=False,
        container_allocation_block_bytes=8192, header_checksum_rule_known=False,
        native_CPU_pending=True, independent_actual_tree_review_pending=True,
        compact_stock_restore_pending=True, package_ready=False, device_installed=False,
        full_Taiwan_update_complete=False, evidence=HOST, evidence_sha256=HOST_SHA)
    nav['lane_missing_house_source_join'].update(native_tree_overlay_pending=False,
        native_tree_overlay_written=True, actual_candidate_verified=True, native_write_ready=False)
    nav['native_country_address_update_progress'].update(estimate_percent=55, updated_utc=now.isoformat(),
        phases=['已完成三源v2測試包；130,637新整數門牌／18,823既有街道，原韌體有限讀取、精確還原及區網下載校驗通過；尚未實機安裝。',
          '巷弄58,233新整數門牌已接成父子樹，更新7,650街道根與22,216下層父指標；完整候選檔已實際寫出並讀回。',
          '較大候選約153 MB，累計補充188,870筆；所有現有門牌表有效位元及其他五個元件保留，8K圖資容器接受度尚待實機。',
          '新候選的獨立實際樹核對、原韌體有限讀取、精確還原和安裝包繼續驗證；新街道、子號、矛盾來源仍未完成。'])
    actions = ['最新可用的v2整合測試包已完成；接USB隨身碟模式後安裝讀回，再測控制案例及新門牌搜尋、位置與路線。',
        '完成含58,233筆巷弄補充的新候選之原韌體、獨立父子路徑與還原驗證，再封裝；8K容器接受度需另外實測。',
        '繼續新街道／行政區、子號和矛盾資料；保留原地址搜尋選單，全台完整更新尚未完成。',
        '畫面刷新效能測試依使用者指示停止；導航地址需求驗證完成後恢復手機音樂／App。']
    state['next_actions'] = actions
    nav.update(remaining_next_actions=copy.deepcopy(actions), next=actions[1], updated_utc=now.isoformat(),
        execution_status='country_v2_package_waits_for_USB_and_actual_lane_COW_candidate_validation_continues')
    state.update(updated_utc=now.isoformat(), current_priority=actions[1])
    state['last_goal_turn'] = dict(classification='progress', validated_utc=now.isoformat(),
        goal_status=state['goal_status'], full_goal_complete=False, required_work_remaining=True,
        device_files_written=False, reason='Actual8K COW lane candidate composed and completely read back; native, restore, package and device checks remain.')
    for key in ['navigation_repair', 'updated_utc', 'next_actions', 'current_priority', 'last_goal_turn']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert state['native_app_music'] == app
    report = before[FILES[3]].decode()
    report = report.replace('全台更新工程估計 <strong>50%</strong>', '全台更新工程估計 <strong>55%</strong>', 1)
    report = report.replace('<progress id="navigation-country-address-progress" max="100" value="50">50%</progress>',
        '<progress id="navigation-country-address-progress" max="100" value="55">55%</progress>', 1)
    report, count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>', lambda _: '<h3>已完成</h3><ul>' +
        ''.join('<li>'+text+'</li>' for text in nav['native_country_address_update_progress']['phases'][:3]) + '</ul>',
        report, count=1, flags=re.S)
    assert count == 1
    marker = '<h3>最新來源核對進度</h3>'
    assert report.count(marker) == 1
    card = ('<h3>巷弄完整候選：尚未實機安裝</h3><p>58,233筆巷弄整數門牌已接成原生父子索引，'
      '約153 MB的實際Address Point候選已写出，累計補充188,870筆。完整讀回核對現有門牌表的有效位元、新增資料、'
      '全部街道父記錄與其他五個元件。較大的8K圖資容器之車機接受度與校驗規則仍未知；'
      '原韌體有限讀取、獨立實際父子路徑與精確原檔還原目前另行驗證，尚未提供此版安裝包。</p>')
    report = report.replace(marker, card+marker, 1)
    old = '來源位置均在指定市內；另有1筆市界附近的原生24-bit量化點跨界，已在包内独立核對記錄明列，未自動改來源坐標。實機目的地與路線仍待確認。'
    assert report.count(old) == 1
    report = report.replace(old, '前版v1有1筆新門牌的原生座標量化點跨市界；最新v2與巷弄候選已排除此新增記錄，保留原廠資料。這些較大候選的實機目的地與路線仍待確認。', 1)
    report, count = re.subn(r'<h3>接著處理</h3><ol>.*?</ol>', lambda _:
        '<h3>接著處理</h3><ol>'+''.join('<li>'+a+'</li>' for a in actions)+'</ol>', report, count=1, flags=re.S)
    assert count == 1
    for identifier in ['navigation-address-updated-time', 'report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="'+identifier+r'" datetime="[^"]+">[^<]+</time>', lambda _:
            f'<time id="{identifier}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',
            report, count=1)
        assert count == 1
    OUT.mkdir()
    for name, raw in before.items():
        with (OUT/(name.replace('/', '__')+'.gz')).open('xb') as f:
            f.write(gzip.compress(raw, mtime=0)); f.flush(); os.fsync(f.fileno())
    for name, value in zip(FILES[:4], [state, task, public, report]):
        replace(name, value)
    served, response = http(web['url'])
    assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
        served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True)
    replace(FILES[-1], web)
    assert read(FILES[0]) == read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    create(OUT/'fresh-readback.json', dict(all_passed=True, service=svc, report_sha256=sha(served),
        engineering_estimate_percent=55, candidate_sha256=host['candidate_sha256'], device_installed=False,
        full_goal_complete=False, native_restore_review_package_checks_pending=True))
    print(json.dumps(dict(all_passed=True, engineering_estimate_percent=55, report_url=web['url'], device_installed=False)))


if __name__ == '__main__':
    main()
