"""Keep completed ABI continuations separate from real UI/device acceptance."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json',
         'reports/findings.json', 'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
PINS = {
    'staging/navigation-native-query-provider-full-getter-v1/proof.json': '8f973df914e7de2fe2df73d94736a703ac897808b74baeb224b7ab9e924ebcbc',
    'staging/navigation-native-getter-postprocess-v1/proof.json': 'a31f0114a0612cf3871b0ce9bcb80debd9ea8b83fa87230bd78f127ecf975760',
    'staging/navigation-native-ap-registry-node-semantics-v1/proof.json': 'ee1d27ceb8ef7807805aaa103b6ccac3cf3357083925da4ae5f60cddeacc1f0c',
    'staging/navigation-v3-gmp-first-metadata-control-v1/proof.json': 'f5fa0022f3744e3e7bd8427661e945fc9a879baab004497294efbe6a99b9863f',
    'staging/navigation-Dunfu6-compiled-road-linkage-v1/proof.json': '297a95d94169d8066446fe72743f9cc77a9bec85e0ae23ba65097f0bc7baeee6',
}


def main():
    inputs = []
    for name, expected in PINS.items():
        raw = (ROOT / name).read_bytes()
        assert len(raw) < 30000 and sha(raw) == expected
        inputs.append(json.loads(raw))
    getter, tail, registry, geometry, road = inputs
    assert getter['all_assigned_checks_passed'] and getter['street']['actual_CP950_text'] == '敦富六街'
    assert getter['house']['actual_CP950_text'] == '368號'
    assert getter['actual_native_metadata_mapordinal_registry_cached_GMP_chain_executed']
    assert tail['all_assigned_checks_passed'] and tail['native_public_getter_tail_return0_under_reconstructed_frame_fixture']
    assert tail['callframe_ABI_reconstruction_is_explicit_fixture'] and not tail['same_original_guest_resumed']
    assert not tail['actual_uninterrupted_query_vector_to_MDR_to_full_getter']
    assert not tail['original_MAIN_or_code_patched'] and not tail['unknown_native_callee_return_faked']
    assert registry['all_assigned_bounded_checks_passed'] and registry['completed_original_CPU_cases'] == 7
    assert not registry['v3_road_regression_rootcause_proved']
    assert geometry['all_assigned_checks_passed'] and geometry['actual_IMG_bytes_read'] == 90112
    assert not geometry['complete_relocated_IMG_created'] and not geometry['installable']
    assert road['analysis_complete'] and road['ordinary_reader_returncode'] == 0
    assert road['compiled_road_present'] and road['geometric_correspondence_within_30m']
    assert not road['physical_device_search_or_route_verified']
    now = datetime.now(timezone.utc); local = now.astimezone(ZoneInfo('Asia/Taipei'))
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    assert state == public['deep_research']
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    assert state['goal_status'] == 'active' and not state['goal_complete']
    assert not state['attended_testing']['user_present'] and state['attended_testing']['no_pending_question']
    assert not state['audio']['audible_tests_allowed']
    svc = service(); served, _ = http(web['url']); assert served == before[FILES[3]]
    nav = state['navigation_repair']
    old_v2 = copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
    old_app = copy.deepcopy(state['native_app_music'])
    phases_before = copy.deepcopy(public['research_progress']['phases'])
    checkpoint = dict(updated_utc=now.isoformat(), prerequisite_pins=PINS,
        original_metadata_registry_cached_GMP_LBL_frontier_executed=True,
        actual_new_IMG_street='敦富六街', actual_new_IMG_house='368號',
        actual_frontier_MAIN_bytes=getter['actual_NEW_MAIN_bytes_read'],
        actual_frontier_IMG_bytes=getter['actual_NEW_IMG_bytes_read'],
        original_postprocess_and_public_getter_tails_return0=True,
        getter_tail_requires_reconstructed_callframes=True,
        same_original_guest_resumed=False, uninterrupted_query_provider_getter_UI_verified=False,
        native_SQLite_or_cold_registry_GMP_verified=False,
        registry_date_and_status_cases=7, registry_completed_original_instructions=3402,
        registry_week_arithmetic_base='2001-01-01', registry_record_plus6_producer_identified=False,
        live_clock_or_expiry_or_draw_priority_semantics_verified=False,
        GMP_first_metadata_control_created=True, complete_GMP_first_IMG_created=False,
        GMP_physical_start_control=[149417984, 90112],
        geometry_header_checksum_CHS_capacity_directory_identity_unchanged=True,
        geometry_only_FAT_block_vectors_changed=True,
        selected_Searchv2_tile_has_same_exact_street_road=True,
        source_and_quantized_housepoint_within30m_of_same_road=True,
        selected_tile_city_region_is_Taichung=True,
        actual_native_route_solver_or_official_house_attachment_verified=False,
        original_renderer_or_128MiB_guard_or_v3_fix_verified=False,
        device_IO=False, installable=False, current_device_v2_unchanged=True,
        full_Taiwan_update_complete=False, full_goal_complete=False)
    nav['offline_getter_geometry_checkpoint_v1'] = copy.deepcopy(checkpoint)
    nav['next'] = '接通原query結果向量到MDR context／取名函式，追Map記錄日期欄位來源；保留v2正常配置，繼續新街道道路幾何核對與v3回歸診斷，現在不要求現場操作。'
    nav['remaining_next_actions'][0] = nav['next']
    phases = nav['native_country_address_update_progress']['phases']
    phases.append('新街／門牌原metadata→registry→cached GMP→LBL解碼讀出敦富六街／368號；另明示重建呼叫框架的407／329指令續行，文字後處理及公共getter尾段均原return0。尚非連續query或UI驗收。')
    phases.append('七個新Map日期／status案例通過，條件用2001-01-01起週數，欄位來源及與v3回歸的關係未證；另完成只改FAT資料區排列的GMP-first小型封裝資訊對照，未建完整新IMG。')
    phases.append('單一Search v2圖塊70530020解出敦富六街三筆NET／三條RGN道路，市／區域均臺中市；來源門牌點距同名道路約7.55公尺、量化點約7.74公尺。這是道路幾何對應，未跑門牌插值或路由solver。')
    nav['updated_utc'] = now.isoformat(); nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    work = state['offline_24h_work_order']
    work['latest_completed_getter_geometry_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['navigation'] = 'active query-vector/MDR constructor, registry date producer and compiled road geometry'
    state['updated_utc'] = now.isoformat()
    for key in ['updated_utc', 'navigation_repair', 'offline_24h_work_order']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state),
        navigation_repair=copy.deepcopy(nav), offline_24h_work_order=copy.deepcopy(work),
        native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert nav['latest_country_v2_comparison_checkpoint'] == old_v2
    assert state['native_app_music'] == old_app
    assert nav['native_country_address_update_progress']['estimate_percent'] == 75
    assert public['research_progress']['phases'] == phases_before
    report = before[FILES[3]].decode()
    report, count = re.subn(r'(<div id="new-street-full-offline-result-v1"><h3>).*?(</h3><p>).*?(</p>)',
        lambda m: m[1] + '新增道路：路名／門牌讀取與getter尾段驗證通過' + m[2] +
        '132 MB原4K圖資完整封裝、讀回與精確還原v2已通過。原韌體沿metadata、registry、cached GMP及LBL讀出「敦富六街」「368號」；最後文字處理與取名函式尾段也已返回成功。尾段使用明示重建的呼叫框架，這是分段驗證；連續地址查詢、冷啟動、搜尋畫面與原機接受仍待驗證。' + m[3],
        report, count=1, flags=re.S)
    assert count == 1
    marker = '<p>道路消失：三種封裝的原共用檔案系統parser'
    assert report.count(marker) == 1
    report = report.replace(marker,
        '<p>Search v2的一個實際道路圖塊確有敦富六街，路段所屬市／區域均為臺中市；368號來源點及量化點距同名道路約8公尺。這支持地理對應，未驗證正式門牌、路由計算或全台覆盖。</p>'
        '<p>新增七項原Map日期／狀態案例通過：條件使用自2001年起的整數週數；欄位寫入来源及與顯示回歸的關係仍在追。另完成只改資料區排列的封裝資訊對照，將顯示元件移到檔案前端；尚未產生完整對照圖資，未證128 MiB限制或修復。</p>' + marker, 1)
    assert '<h3>最新本機驗證</h3>' in report
    report = report.replace('<h3>最新本機驗證</h3>', '<h3>較早階段紀錄（2026/10/07 12:54）</h3>', 1)
    report = report.replace('最新離線結果：已把v3六個元件', '12:37階段紀錄：已把v3六個元件', 1)
    report, count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>',
        lambda _: '<h3>已完成</h3><ul>' + ''.join('<li>' + item + '</li>' for item in phases) + '</ul>',
        report, count=1, flags=re.S); assert count == 1
    for ident in ['navigation-address-updated-time', 'report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + ident + r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',
            report, count=1); assert count == 1
    out = ROOT / 'staging' / ('offline-getter-geometry-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir()
    for name, raw in before.items():
        with (out / (name.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for name, value in zip(FILES[:4], [state, task, public, report]): replace(name, value)
    served, response = http(web['url']); assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
        served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
        offline_getter_geometry_checkpoint_v1=checkpoint, offline_24h_work_order=copy.deepcopy(work))
    replace(FILES[4], web)
    assert read(FILES[0]) == read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    assert read(FILES[0])['native_app_music'] == read(FILES[1])['native_app_music'] == old_app
    create(out / 'fresh-readback.json', dict(all_passed=True, prerequisite_pins=PINS, service=svc,
        report_sha256=sha(served), nav_estimate=75, app_estimate=40, overall_estimate=37,
        original_getter_tails_returned_in_ABI_fixture=True, uninterrupted_query_verified=False,
        actual_goal_status='active', no_pending_presence_question=True, device_IO=False, full_goal_complete=False))
    print(json.dumps(dict(all_passed=True, checkpoint=str(out.relative_to(ROOT)),
                          report_url=web['url'], device_IO=False)))


if __name__ == '__main__':
    main()
