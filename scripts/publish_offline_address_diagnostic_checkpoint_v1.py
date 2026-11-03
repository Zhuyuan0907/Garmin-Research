"""Publish completed ordinary map-data checks; retain the physical v2 setup."""
import copy
import gzip
import json
import os
import re
import sys
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json',
         'reports/findings.json', 'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
PINS = {
    'staging/navigation-actual-AP-profile-regression-matrix-v1/proof.json': '877d98d8d2a953a53fba77c8bb3100994421d428727afd03fcc8aa4e0949234a',
    'staging/navigation-actual-AP-profile-regression-matrix-v1/execution-seal.json': '6e828f36fde678ae544d26bc74df8ed045cdd957c939b6a417580d56486dfd85',
    'staging/navigation-beitun-lossless-name-branch-plan-v1/proof.json': 'ec773b9f9029e0b18e590ab1403442f5d45b0453acc66ea2344ad1d1464635c1',
    'staging/navigation-beitun-held-road-geometry-contrast-v1/proof.json': '81a5d02a3829511c17ab18f8a260c544ea3bbe2e720217765e48036f20f0e195',
    'staging/navigation-native-L3-width-policy-static-v1/proof.json': '75b981e629bb2aabb9525cb365f30f99c340760263dda077c82936c54ff8e6b1',
    'staging/navigation-source172188-floor-node-provenance-v1/proof.json': '9cce85f5f9569b7a303c3fa27cd30e9313cf29af8846b4281f3a7961ef12e54f',
    'staging/navigation-source172188-floor-node-provenance-v1/sealed-files.json': '1892be197217ef05707d24ef6596d13c7e873f2cb5dbe7346320180b183d84ff',
    'staging/navigation-country-v2-v3-address-path-diagnostic-v1/SEAL.json': '3aa369860c62c8c9f5bdae88e2c2b957044715b50211c1e80dcbb17a7e0d2bc3',
}


def main():
    # The diagnostic summary hash is supplied only after its actual sealer ends.
    assert len(sys.argv) == 2 and re.fullmatch('[0-9a-f]{64}', sys.argv[1])
    summary_path = 'staging/navigation-country-v2-v3-address-path-diagnostic-v1/scope-summary.json'
    pins = dict(PINS, **{summary_path: sys.argv[1]})
    proofs = {}
    for path, expected in pins.items():
        raw = (ROOT / path).read_bytes()
        assert len(raw) <= 100000 and sha(raw) == expected
        proofs[path] = json.loads(raw)
    matrix = proofs['staging/navigation-actual-AP-profile-regression-matrix-v1/proof.json']
    names = proofs['staging/navigation-beitun-lossless-name-branch-plan-v1/proof.json']
    floors = proofs['staging/navigation-source172188-floor-node-provenance-v1/proof.json']
    diagnostic = proofs[summary_path]
    assert matrix['all_assigned_checks_passed'] and matrix['same_six_directory_stride_and_parameter_profiles_v2_v3']
    assert not matrix['v3_rootcause_proven'] and not matrix['device_IO']
    assert names['literal_count'] == 28 and names['literal_and_house_reconstruction_checks'] == 102
    assert floors['all_assigned_checks_passed'] and floors['actual_nodes'] == 21
    assert floors['actual_floor_unit_nodes'] == 20 and floors['original_group_floor_hold_not_released']
    # Bind to the finite, separately sealed diagnostic without depending on its
    # detailed private record/label cache schema.
    raw_diagnostic = (ROOT / 'staging/navigation-country-v2-v3-address-path-diagnostic-v1/proof.json').read_bytes()
    assert len(raw_diagnostic) <= 2000000
    assert sha(raw_diagnostic) == '9fa188d7800204c936427365e116c1c0f86bcded6d07daee3be04b267b0a6ccf'
    original = json.loads(raw_diagnostic)
    pins['staging/navigation-country-v2-v3-address-path-diagnostic-v1/proof.json'] = sha(raw_diagnostic)
    rows = original['results']
    expected_labels = ['昌平路二段', '50之6巷', '2弄', '39號']
    for version in ('v2', 'v3'):
        row = rows[version]
        assert row['status'] == 'existing_exact_terminal_leaf_found'
        assert row['exact_path_labels_reached'] == expected_labels
        assert all(step['group']['exact_match_count'] == 1 for step in row['steps'])
        leaf = row['path_records_with_full_rawbits'][-1]
        assert leaf['record'] == 1611333657
        assert [leaf['raw_location_a'], leaf['raw_location_b']] == [1127428, 5624276]
    assert floors['captured_raw24'] == [1127428, 5624288]
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    before = {path: (ROOT / path).read_bytes() for path in FILES}
    state, task, public = [json.loads(before[path]) for path in FILES[:3]]
    web = json.loads(before[FILES[4]])
    assert state == public['deep_research']
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    assert state['goal_status'] == 'active' and not state['goal_complete']
    assert not state['attended_testing']['user_present'] and state['attended_testing']['no_pending_question']
    assert not state['audio']['audible_tests_allowed']
    svc = service()
    served, _ = http(web['url'])
    assert served == before[FILES[3]]
    nav = state['navigation_repair']
    old_device = copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
    old_app = copy.deepcopy(state['native_app_music'])
    checkpoint = dict(updated_utc=now.isoformat(), prerequisite_pins=pins,
        actual_image_metadata_profiles_compared=5, actual_metadata_IMG_bytes=373336,
        stock_L3_stride=111, actual_country_v2_and_v3_L3_stride=112,
        actual_v2_v3_all_six_directory_profiles_equal=True,
        prior_root_width22_country_v2_assumption_corrected=True,
        rootcause_proven=False, road_regression_fixed=False,
        saved_name_literals_losslessly_classified=28, saved_groups_losslessly_reconstructed=102,
        section_locality_and_lane_views_do_not_release_alias_holds=True,
        new_source_node_provenance=dict(requested=21, found=21, with_floor_unit=20,
            without_explicit_floor_unit=1, original_first_node_had_floor_unit=True,
            raw_tags_private=True, group_and_floor_holds_retained=True,
            source_only_partition=True, actual_single_PBF_read_bytes=327206226,
            PBF_SHA_inherited_not_rehashed=True),
        existing_address_diagnostic=dict(labels=expected_labels,
            actual_v2_and_v3_unique_full_path_found=True, terminal_record=1611333657,
            original_leaf_raw24=[1127428,5624276], source_raw24=[1127428,5624288],
            coordinate_delta_raw24=[0,-12], approximate_difference_metres=26.117,
            missing_new_address=False, automatic_coordinate_overwrite=False,
            actual_UI_search_route_or_device_verified=False),
        geometric_contrast_does_not_prove_景賢六街_alias=True,
        current_device_v2_unchanged=True, device_IO=False, installable=False,
        full_Taiwan_update_complete=False, native_App_complete=False, full_goal_complete=False)
    nav['offline_address_diagnostic_checkpoint_v1'] = copy.deepcopy(checkpoint)
    nav['next'] = '以已驗v3真正新增的巷弄門牌準備較小v2格式對照；保持4K與既有112bit欄位，避免重複既有39號或自動改座標。原機v2保留，實機顯示等待使用者自行通知返回。'
    phases = nav['native_country_address_update_progress']['phases']
    phases.extend([
        '實讀5份AP載體的小metadata與MDR目錄：正常country v2及失敗v3六層欄位格式相同，L3皆23-bit first-child／112-bit record；22／111只屬原廠stock。格式差異不是這次回歸的變動軸，尺寸／封裝／配置／原機繪圖政策仍待隔離。',
        '28個缺名路名與102組來源完成段名、里名前綴、巷弄等可逆分類；保留原街名與門牌，不把近字或前綴直接當alias。景賢六街來源靠近景賢六路的幾何關係不證同一路名。',
        '單次定點抽取21個OSM節點，查明20筆帶樓層／單元，另1筆無該標籤；原第一筆實為4樓／之1。原群組與20筆樓層資料完整保留，僅提出來源層分組，不自動新增20個門牌。',
        '實際v2／v3檔案皆讀到唯一完整昌平路二段→50之6巷→2弄→39號與同一原leaf；來源座標約差26.1公尺。因此這筆屬既有地址的座標差異，不能當缺漏新增；未覆寫或實測介面／路線。',
    ])
    nav['updated_utc'] = now.isoformat()
    nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    work = state['offline_24h_work_order']
    work['latest_completed_address_diagnostic_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['navigation'] = nav['next']
    state['updated_utc'] = now.isoformat()
    for key in ['updated_utc', 'navigation_repair', 'offline_24h_work_order']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state),
                  navigation_repair=copy.deepcopy(nav), offline_24h_work_order=copy.deepcopy(work),
                  native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    report = before[FILES[3]].decode()
    paragraph = '<p id="offline-frontier-latest-v1">最新：正常v2与道路消失v3的地址欄位格式相同，已排除這項變動差異；封裝／尺寸等繪圖回歸原因仍待隔離。28種路名／102來源組可逆分類完成，另定點核對21個來源節點，識別20筆樓層資料。昌平路二段50之6巷2弄39號在兩版已有完整唯一地址鏈，來源位置約差26.1公尺，因此沒有重複新增或覆寫。下一步用真正新增門牌準備較小對照版；保留實機正常v2。全臺更新及原機App仍未完成。</p>'
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: paragraph, report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>',
        lambda _: '<h3>已完成</h3><ul>' + ''.join('<li>' + item + '</li>' for item in phases) + '</ul>', report, count=1, flags=re.S)
    assert count == 1
    for ident in ['navigation-address-updated-time', 'report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + ident + r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        assert count == 1
    assert nav['latest_country_v2_comparison_checkpoint'] == old_device and state['native_app_music'] == old_app
    assert nav['native_country_address_update_progress']['estimate_percent'] == 75
    out = ROOT / 'staging' / ('offline-address-diagnostic-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, raw in before.items():
        with (out / (path.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for path, value in zip(FILES[:4], [state, task, public, report]):
        replace(path, value)
    served, response = http(web['url'])
    assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'],
               local_report_sha256=sha(served), served_report_sha256=sha(served),
               report_bytes=len(served), service_not_restarted=True,
               offline_address_diagnostic_checkpoint_v1=checkpoint, offline_24h_work_order=copy.deepcopy(work))
    replace(FILES[4], web)
    assert read(FILES[0]) == read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    assert read(FILES[0])['native_app_music'] == read(FILES[1])['native_app_music'] == old_app
    create(out / 'fresh-readback.json', dict(all_passed=True, prerequisite_pins=pins,
        service=svc, report_sha256=sha(served), nav_estimate=75, app_estimate=40, overall_estimate=37,
        actual_goal_status='active', user_away=True, no_pending_presence_question=True,
        device_IO=False, full_goal_complete=False))
    print(json.dumps(dict(all_passed=True, checkpoint=str(out.relative_to(ROOT)), report_url=web['url'], device_IO=False)))


if __name__ == '__main__':
    main()
