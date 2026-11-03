"""Publish the verified USB installation and scoped user observations for v3."""
import argparse
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json',
         'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
IMAGE_SHA = '1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
IMAGE_BYTES = 153346048


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--installation', required=True)
    parser.add_argument('--observations')
    parser.add_argument('--rollback')
    parser.add_argument('--comparison-installation')
    args = parser.parse_args()
    installation_path = ROOT / args.installation
    data = installation_path.read_bytes()
    operation = json.loads(data)
    assert operation['state'] == 'installed_readback_verified' and operation['mode'] == 'install'
    assert operation['physical_device_present'] and operation['image_committed'] and operation['unmounted']
    tx = operation['transaction']
    assert tx['readback_verified'] and tx['preserved_file_hashes_verified'] and tx['destination_bytes'] == IMAGE_BYTES
    assert not tx['original_full_backup_created']
    rollback = None
    if args.rollback:
        rollback = read(args.rollback)
        assert rollback['mode'] == 'rollback' and rollback['state'] == 'rolled_back_exact_original_verified'
        assert rollback['physical_device_present'] and rollback['image_committed'] and rollback['unmounted']
        rtx = rollback['transaction']
        assert rtx['readback_verified'] and rtx['preserved_file_hashes_verified']
        assert rtx['destination_bytes'] == 96739328 and not rtx['original_full_backup_created']
    comparison = None
    if args.comparison_installation:
        assert rollback is not None
        comparison = read(args.comparison_installation)
        assert comparison['mode'] == 'install' and comparison['state'] == 'installed_readback_verified'
        assert comparison['manifest_sha256'] == '71258a290bce559b0f882282bf2ce3c6cd8e690d49fd5ef5756e454b3fde97f7'
        assert comparison['physical_device_present'] and comparison['image_committed'] and comparison['unmounted']
        ctx = comparison['transaction']
        assert ctx['readback_verified'] and ctx['preserved_file_hashes_verified']
        assert ctx['destination_bytes'] == 128356352 and not ctx['original_full_backup_created']
        assert comparison['preflight']['image_state'] == 'original'
    observations = dict(schema='navigation-v3-user-observations/v1', installation_evidence=args.installation,
                        boot_items_visible=False, map_load_without_error=False, search_cases=[], route_cases=[])
    if args.observations:
        observations = read(args.observations)
        assert observations['schema'] == 'navigation-v3-user-observations/v1'
        assert observations['installation_evidence'] == args.installation
    loaded = observations.get('boot_items_visible') is True and observations.get('map_load_without_error') is True
    complete = observations.get('limited_search_destination_route_samples_passed') is True
    display_failure = observations.get('user_reported_map_display_failure') is True
    recovered_with_cn = observations.get('map_display_recovery_with_original_cn') is True
    comparison_display_ok = comparison is not None and observations.get('v2_AP_Search_v2_road_display_user_confirmed') is True
    comparison_primary_ok = comparison_display_ok and observations.get('v2_primary_controls_all_search_destination_routes_user_confirmed') is True
    assert not complete or not display_failure
    assert not complete or loaded
    estimate = 70 + 5 * loaded + 5 * complete
    if comparison_display_ok:
        estimate = 75
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    out = ROOT / 'staging' / ('navigation-v3-physical-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[-1]])
    svc = service()
    served, _ = http(web['url'])
    assert served == before[FILES[3]] and state == public['deep_research']
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    app = copy.deepcopy(state['native_app_music'])
    nav = state['navigation_repair']
    status = 'installed_readback_waiting_normal_mode_map_load'
    if loaded:
        status = 'normal_mode_items_and_map_visible_waiting_address_route_tests'
    if complete:
        status = 'limited_normal_mode_samples_passed_full_country_work_remaining'
    if display_failure:
        status = ('map_display_recovered_with_original_cn_two_layer_failure_unresolved' if recovered_with_cn
                  else 'user_reported_road_map_missing_prioritize_display_recovery')
    if rollback:
        status = 'exact_stock_AP_restored_readback_verified_waiting_two_layer_display_control'
        if observations.get('stock_AP_Search_v2_road_display_user_confirmed'):
            status = 'exact_stock_AP_two_layer_display_passed_v3_regression_confirmed'
    if comparison:
        status = 'v2_original_4K_profile_comparison_installed_waiting_normal_mode_display'
        if comparison_display_ok:
            status = 'v2_original_4K_profile_two_layer_display_passed_waiting_primary_address_routes'
        if comparison_primary_ok:
            status = 'v2_display_and_three_Minquan_primary_search_destination_routes_passed_larger_update_remaining'
    checkpoint = dict(updated_utc=now.isoformat(), installation_evidence=args.installation,
        installation_evidence_sha256=sha(data), installation_completed_at=operation['completed_at'],
        device_installed=True, installed_candidate_bytes=IMAGE_BYTES, installed_candidate_sha256=IMAGE_SHA,
        complete_USB_readback_verified=True, preserved_files_verified=True, safely_unmounted=True,
        original_full_backup_created=False, observations_evidence=args.observations,
        observations=observations, boot_items_visible=observations.get('boot_items_visible',False),
        map_load_without_error=observations.get('map_load_without_error',False),
        user_reported_map_display_failure=display_failure,
        map_display_recovery_with_original_cn=observations.get('map_display_recovery_with_original_cn'),
        physical8K_container_enumeration_user_confirmed=loaded, physical8K_acceptance_verified=complete,
        limited_search_destination_route_samples_passed=complete,
        full_Taiwan_native_address_update_complete=False, full_goal_complete=False)
    checkpoint.update(current_v3_candidate_installed=not bool(rollback),
                      exact_stock_AP_rollback_evidence=args.rollback,
                      exact_stock_AP_rollback_verified=bool(rollback))
    checkpoint['v2_comparison_installation_evidence'] = args.comparison_installation
    nav['latest_country_v3_physical_checkpoint'] = checkpoint
    if comparison:
        v2checkpoint = dict(installation_evidence=args.comparison_installation, candidate_version='country_AP_v2_4K',
            candidate_bytes=128356352, candidate_sha256='925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb',
            new_integer_houses=130637, current_device_installed=True, complete_USB_readback_verified=True,
            preserved_files_verified=True, safely_unmounted=True, normal_mode_map_display_verified=comparison_display_ok,
            limited_Minquan_primary_search_destination_routes_verified=comparison_primary_ok,
            address_search_verified=False, destination_route_verified=False, observations_evidence=args.observations, status=status)
        nav['latest_country_v2_comparison_checkpoint'] = v2checkpoint
        nav['country_existing_street_candidate_v2'].update(device_installed=True, installation_evidence=args.comparison_installation,
            status=status, normal_mode_map_display_verified=comparison_display_ok, device_search_verified=False,
            limited_Minquan_primary_search_destination_routes_verified=comparison_primary_ok)
    for key in ['lane_tree_cow_candidate_v3', 'country_existing_street_candidate']:
        item = nav[key]
        item.update(status=status, device_installed=not bool(rollback), physical_device_installation_pending=False,
                    installation_evidence=args.installation, physical8K_acceptance_verified=complete,
                    physical8K_container_enumeration_user_confirmed=loaded,
                    USB_complete_readback_verified=True, safely_unmounted=True,
                    limited_physical_samples_passed=complete, device_search_verified=False,
                    full_Taiwan_update_complete=False)
        if rollback:
            item.update(historical_v3_installation_verified=True, currently_restored_exact_stock_AP=True,
                        rollback_evidence=args.rollback, normal_mode_display_control_pending=True)
        if comparison:
            item['currently_restored_exact_stock_AP'] = False
            item['current_installed_comparison_version'] = 'country_AP_v2_4K'
    phases = nav['native_country_address_update_progress']['phases']
    phases = [p for p in phases if not p.startswith(('較大8K候選', '實機v3安裝', 'v3現場顯示問題', '原廠道路圖恢復對照', 'v3暫時還原', '原廠AP兩圖層對照', 'v2對照安裝', 'v2兩圖層顯示', 'v2民權路限定'))]
    phases.append('實機v3安裝完成：153,346,048-byte圖資完整讀回、原廠保護檔校驗及安全卸載通過；一般模式載入／搜尋／位置／路線另作現場驗證。')
    if loaded:
        phases.append('使用者確認Address Point及Search v2清單可見，正常模式地圖載入無錯誤；此為初步8K接受觀察，不等完整地址／行車驗收。')
    if display_failure:
        phases.append('v3現場顯示問題：使用者回報只勾Address Point＋Search v2時可搜尋地址，但道路底圖消失；兩圖層顯示驗收未通過，原因尚未確認。')
        if recovered_with_cn:
            phases.append('原廠道路圖恢復對照：勾回CN Taiwan NT後使用者確認地圖恢復；這僅確認三圖層可顯示，兩圖層問題仍待排查。')
    if observations.get('adding_v3_Address_Point_hides_road_display_user_confirmed'):
        phases.append('v3現場顯示問題A/B：Search v2單獨道路正常，加入v3 Address Point後消失；原廠CN道路三圖層可恢復。尚未區分容器、索引與原圖層相容性。')
    if rollback:
        phases.append('v3暫時還原：原廠96,739,328-byte Address Point已精確重建、完整讀回並安全卸載；Search v2與其他保護檔保持一致，原廠AP＋Search v2對照另列。')
    if observations.get('stock_AP_Search_v2_road_display_user_confirmed'):
        phases.append('原廠AP兩圖層對照：精確還原後，原廠Address Point＋Search v2正常顯示道路；v3新增更新造成的回歸已確認，8K封裝與MDR內容因素尚未分離。')
    if comparison:
        phases.append('v2對照安裝：130,637筆新增門牌、原4K配置的128,356,352-byte AP已安裝、完整讀回並安全卸載；道路圖不變，一般模式顯示結果另列。')
    if comparison_display_ok:
        phases.append('v2兩圖層顯示：使用者確認Address Point＋Search v2道路正常顯示；可先保留v2對照版，完整全台門牌／新街道與v3修復仍未完成。')
    if comparison_primary_ok:
        phases.append('v2民權路限定回歸：使用者確認6號／150號／184號均可搜尋、目的地合理且路線計算完成；只涵蓋三筆台中測試，非全台驗收。')
    nav['native_country_address_update_progress'].update(estimate_percent=estimate, updated_utc=now.isoformat(), phases=phases)
    next_action = '請在一般模式確認Address Point與Search v2可見、地圖能正常載入；接著測民權路控制與三組新增巷弄地址。'
    if loaded:
        next_action = '維持Address Point＋Search v2，測民權路控制與新增巷弄地址的搜尋、目的地及路線；每例最多60秒，不要求行車。'
    if complete:
        next_action = '有限新增巷弄地址樣本已通過；继续補齊新街道prefix／segment與完整圖資整合、子號及未匹配來源。'
    if display_failure:
        next_action = ('目前三項圖層勾選可顯示；先定位v3 Address Point與Search v2單獨搭配的道路消失原因，再完成新增地址與路線驗收。' if recovered_with_cn
                       else '先勾回原廠CN Taiwan NT道路圖，確認地圖是否恢復；暫停新增地址驗收，排查v3兩圖層道路消失問題。')
    if rollback:
        next_action = '原廠Address Point已還原；在一般模式取消CN道路圖、只勾原廠AP＋Search v2，確認同區域道路顯示，測完恢復三項。'
    if comparison:
        next_action = '較小v2門牌補充版已安裝；完整重開後只勾Address Point＋Search v2、取消CN道路，看同區域道路是否顯示，測完恢復三項。'
        if comparison_display_ok:
            next_action = '維持門牌v2 Address Point＋Search v2，驗證台中民權路6號／150號／184號的搜尋、目的地與路線，不要求行車。'
        if comparison_primary_ok:
            next_action = '先保留已通過道路與三筆民權路回歸的v2；繼續定位v3封裝／索引顯示回歸、擴大地址樣本與新街道／之號更新。'
    actions = [next_action,
        '全台完整更新仍未完成；新街道／子號離線前置原型尚未合併到已安裝v3，不把工程估計當地址覆蓋率。',
        '畫面刷新效能測試依使用者指示停止；導航更新需求驗證完成後恢復手機音樂／App。']
    nav.update(updated_utc=now.isoformat(), execution_status=status, navigation_repair_status=status,
        remaining_next_actions=copy.deepcopy(actions), next=next_action,
        remaining_physical_checks=[] if complete or comparison_primary_ok else [next_action],
        device_search_verified=False, device_routing_verified=False, goal_complete=False)
    state.update(updated_utc=now.isoformat(), current_priority=next_action, next_actions=actions,
        current_navigation_installation_checkpoint=args.installation, physical_usb_blocker_resolved=True,
        device_state='Latest verified operation: v3 USB installation and safe unmount; normal-mode observations are recorded separately.',
        required_work_remaining=True, goal_complete=False)
    if rollback:
        state['current_navigation_installation_checkpoint'] = args.rollback
        state['device_state'] = 'Exact stock Address Point restored with complete USB readback and safe unmount; v3 is retained locally and display regression diagnosis continues.'
    if comparison:
        state['current_navigation_installation_checkpoint'] = args.comparison_installation
        state['device_state'] = ('Original-4K-profile country AP v2 comparison installed, readback/unmount verified; two-layer road display confirmed; primary address/route observations separately scoped.' if comparison_display_ok else
                               'Original-4K-profile country AP v2 comparison installed with complete readback and safe unmount; normal-mode display test pending, v3 regression unresolved.')
    state['last_goal_turn'] = dict(classification='progress', validated_utc=now.isoformat(), goal_status=state['goal_status'],
        full_goal_complete=False, required_work_remaining=True, device_files_written=True,
        device_files_written_evidence=args.comparison_installation or args.rollback or args.installation,
        reason=('Country AP v2 4K comparison installation verified; normal-mode display pending.' if comparison else
               ('Exact stock AP rollback verified; normal-mode two-layer display A/B recorded separately.' if rollback else
                'Verified v3 USB install/readback/unmount; normal-mode acceptance remains separately scoped.')))
    for key in ['navigation_repair','updated_utc','current_priority','next_actions','current_navigation_installation_checkpoint',
                'physical_usb_blocker_resolved','device_state','required_work_remaining','goal_complete','last_goal_turn']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav),
                  native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert state['native_app_music'] == app
    report = before[FILES[3]].decode()
    report, count = re.subn(r'(<section class="card" id="navigation-repair-checkpoint-v2"><h2>).*?(</h2>)',
        lambda m: m[1] + (('v2道路正常；限定地址回歸驗證中' if not comparison_primary_ok else 'v2道路與民權路回歸通過；擴大更新仍進行中') if comparison_display_ok else ('較小4K門牌版已安裝；道路顯示對照中' if comparison else
                         ('已還原原廠門牌圖；排查道路顯示問題' if rollback else ('v3實機發現道路顯示問題；修復與驗證中' if display_failure else
                         ('v3已安裝；地址與路線實機驗證中' if not complete else 'v3限定樣本通過；全台更新仍進行中'))))) + m[2], report, count=1)
    assert count == 1
    report, count = re.subn(r'全台更新工程估計 <strong>\d+%</strong>', f'全台更新工程估計 <strong>{estimate}%</strong>', report, count=1)
    assert count == 1
    report, count = re.subn(r'<progress id="navigation-country-address-progress" max="100" value="\d+">\d+%</progress>',
        f'<progress id="navigation-country-address-progress" max="100" value="{estimate}">{estimate}%</progress>', report, count=1)
    assert count == 1
    report, count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>', lambda _: '<h3>已完成</h3><ul>' + ''.join('<li>'+p+'</li>' for p in phases) + '</ul>', report, count=1, flags=re.S)
    assert count == 1
    report = report.replace('新8K容器接受度與完整搜尋／導航仍待實機，尚未安裝。',
        'v3已實機安裝、完整讀回校驗及安全卸載；一般模式載入、完整搜尋／導航結果另列。',1)
    marker = '<h3>可用測試包與既有實測</h3>'
    if '<p id="v3-live-install-status">' not in report:
        report = report.replace(marker, marker+'<p id="v3-live-install-status"></p>',1)
    install_time = datetime.fromisoformat(operation['completed_at']).astimezone(ZoneInfo('Asia/Taipei')).strftime('%Y/%m/%d %H:%M')
    summary = install_time + '完成v3安裝，從先前9筆版升級，完整讀回和原廠地圖／JAI／授權保護核對通過；未另建完整備份。'
    if display_failure:
        summary += '使用者回報「可以搜尋地址，但是地圖沒有了，底層的地圖不見了」；兩圖層顯示尚未通過。'
        summary += '勾回原廠CN道路圖後已恢復顯示，仍在排查。' if recovered_with_cn else '正確認勾回原廠CN道路圖能否恢復。'
    else:
        summary += '使用者已確認兩項圖資可見、地圖正常載入；地址／路線試驗另列。' if loaded else 'Address Point顯示名稱仍可含2016；目前等待一般模式圖資清單與載入回覆。'
    if rollback:
        rollback_time = datetime.fromisoformat(rollback['completed_at']).astimezone(ZoneInfo('Asia/Taipei')).strftime('%Y/%m/%d %H:%M')
        summary += rollback_time + '已暫時精確還原原廠Address Point並完成讀回／安全卸載；目前車機不再使用v3，v3測試包保留，原AP＋Search v2對照另列。'
    if observations.get('stock_AP_Search_v2_road_display_user_confirmed'):
        summary += '還原後使用者已確認原AP＋Search v2道路顯示正常。'
    if comparison:
        comparison_time = datetime.fromisoformat(comparison['completed_at']).astimezone(ZoneInfo('Asia/Taipei')).strftime('%Y/%m/%d %H:%M')
        summary += comparison_time + '已安裝較小原4K門牌v2對照版（130,637新增），完整讀回校驗、安全卸載完成；現在車機是v2，道路顯示結果另列。'
        if comparison_display_ok:
            summary += '使用者已確認v2搭配Search v2道路正常顯示。'
        if comparison_primary_ok:
            summary += '民權路6／150／184號限定搜尋、位置與路線回歸亦通過，其他地址仍待驗證。'
        summary += 'v3測試包已確認兩圖層道路顯示回歸，暫停安裝使用，保留作離線分析。'
    report, count = re.subn(r'<p id="v3-live-install-status">.*?</p>', '<p id="v3-live-install-status">'+summary+'</p>', report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'<h3>接著處理</h3><ol>.*?</ol>', lambda _: '<h3>接著處理</h3><ol>' + ''.join('<li>'+p+'</li>' for p in actions) + '</ol>', report, count=1, flags=re.S)
    assert count == 1
    for identifier in ['navigation-address-updated-time','report-updated-time','research-updated-time']:
        report, count = re.subn(r'<time id="'+identifier+r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{identifier}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        assert count == 1
    out.mkdir()
    for name, raw in before.items():
        with (out/(name.replace('/','__')+'.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw,mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for name, value in zip(FILES[:4],[state,task,public,report]):
        replace(name,value)
    served, response = http(web['url'])
    assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
        served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
        native_country_address_estimate_percent=estimate, latest_country_v3_physical_checkpoint=checkpoint,
        current_navigation_installation_checkpoint=args.comparison_installation or args.rollback or args.installation, physical_usb_blocker_resolved=True)
    replace(FILES[-1],web)
    assert read(FILES[0]) == read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    assert read(FILES[2])['native_country_address_update_progress'] == read(FILES[0])['navigation_repair']['native_country_address_update_progress']
    create(out/'fresh-readback.json',dict(all_passed=True,service=svc,report_sha256=sha(served),
        engineering_estimate_percent=estimate,installed=not bool(rollback),historical_installation_verified=True,
        exact_stock_AP_rollback_verified=bool(rollback),normal_mode_load_observed=loaded,
        current_v2_comparison_installed=bool(comparison),
        current_v2_map_display_user_confirmed=comparison_display_ok,
        current_v2_limited_primary_controls_verified=comparison_primary_ok,
        physical_samples_passed=complete,full_goal_complete=False,installation_evidence=args.installation))
    print(json.dumps(dict(all_passed=True,report_url=web['url'],checkpoint=str(out.relative_to(ROOT)),
        engineering_estimate_percent=estimate,installed=not bool(rollback),normal_mode_load_observed=loaded)))


if __name__ == '__main__':
    main()
