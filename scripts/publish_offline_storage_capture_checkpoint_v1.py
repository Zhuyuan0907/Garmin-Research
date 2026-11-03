"""Publish real file-verification milestones, retaining the tested device setup."""
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
    'staging/navigation-v3-gmp-first-virtual-image-verification-v1/proof.json': 'cc4f07d774f8d679268b8cd2517ed5c6f10a0863c6b03f2819bd93964b2baac9',
    'staging/navigation-v3-gmp-first-virtual-image-verification-v1/execution-seal.json': '62b9b356d5a4f2c7e9dd6e2859243bdaa3f919a533a697f501113e4d9d3975be',
    'staging/navigation-native-query-cold-allocator-abi-v1/proof.json': '72fab0f728699658818b45d95df1bbb8f727147b3b21748605a155093fa712b9',
    'staging/navigation-native-query-cold-allocator-abi-v1/sealed-files.json': '6d154cf6a1dd5161fc97c86dee828ccd79a7e36bb796d0fb44aa5eaf54ea3838',
    'staging/navigation-native-AP-opener-drive-lineage-v1/proof.json': '97829b32857916e86a510012d5dedc8942b5c10f08ee5e21abf1df398742ae1a',
    'staging/navigation-native-AP-opener-drive-lineage-v1/sealed-files.json': '06ed7b675042a75a0d3e32ecb42a519f5a9fb0f54b49d51ba81ffb3ecca70781',
    'staging/navigation-beitun-held-name-review-v1/review.json': 'a8d502cc510d6201a19397b0e0e171ab35322c0f00de3fc9db670074a490c097',
    'staging/navigation-native-production-block-read-binding-v1/proof.json': '7b42a83081a1defbdcc1b530098da9380db3f1740a53d1320e7e8aa02629c221',
    'staging/navigation-native-query-dir-constructor-v1/proof.json': '8f2ac26515a4d932c5ab889cb36d9ff0f3ab1526a53763bfda3cded2b66b7560',
    'staging/navigation-beitun-new-street-bounded-source-v1/proof.json': 'd9845efe398ef510201f3ce4aabe9a2502c85ede38a0f9506986a5803ba7ca1b',
    'staging/navigation-beitun-source-capture-corrected-v1/proof.json': '7333ab592eecdd21e3f02207ba6d3be21c7c491687a9f6fc3a84a1364b650a25',
    'staging/navigation-beitun-source-capture-corrected-v1/SEAL.json': '5ba09fac307f25d569cb46fd60a2f948659dc4bb04fcc1cbafeaa3296c24ae3e',
    'staging/navigation-beitun-capture-output-readback-v1/proof.json': '5df3280f9e4c3c6a499c66521d6273eb07d9ad23f836ba93da90b55a1522d3e3',
    'staging/navigation-native-AP-path-producer-v1/proof.json': '1f002a85f69a0e4a8e2ad2fb385bbdb945a95c8b96b1587f5ba6a309b3cd73e3',
}


def main():
    proofs = {}
    for path, expected in PINS.items():
        raw = (ROOT / path).read_bytes()
        assert len(raw) < 60000 and sha(raw) == expected
        proofs[path] = json.loads(raw)
    virtual = proofs[next(p for p in PINS if 'virtual-image' in p and p.endswith('proof.json'))]
    cold = proofs[next(p for p in PINS if 'cold-allocator' in p and p.endswith('proof.json'))]
    driver = proofs[next(p for p in PINS if 'opener-drive' in p and p.endswith('proof.json'))]
    assert virtual['all_assigned_checks_passed'] and not virtual['new_full_IMG_created']
    assert cold['established']['native_uncontended_mutex_executed'] and not cold['held']['actual_new_handle_or_DIR_created']
    assert driver['all_assigned_checks_passed'] and not driver['actual_lineage_closed']
    captured = proofs['staging/navigation-beitun-source-capture-corrected-v1/proof.json']
    output = proofs['staging/navigation-beitun-capture-output-readback-v1/proof.json']
    assert captured['all_exact_missing_groups_captured'] and captured['missing_group_count'] == 102
    assert captured['missing_literal_count'] == 28 and captured['planning_example_count'] == 2
    assert not captured['formal_address_route_official_alias_or_install_acceptance']
    assert output['all_assigned_checks_passed'] and output['valid_single_gzip_member_CRC_and_footer']
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
    checkpoint = dict(updated_utc=now.isoformat(), prerequisite_pins=PINS,
        complete_virtual_GMP_first_stream_bytes=virtual['complete_projected_stream_bytes'],
        complete_virtual_GMP_first_SHA256=virtual['projected_stream_sha256'],
        six_components_actual_source_bytes_reverified=True,
        duplicate_large_IMG_created=False, native_renderer_or_device_acceptance=False,
        v3_regression_fixed=False, original_cold_mutex_executed=True,
        cold_constructor_stopped_at_heap_core='0x003881BC', new_DIR_handle_created=False,
        AP_selector_FILE_and_generic_drive_fields_statically_linked=True,
        true_AP_filename_to_live_drive_connection_closed=False,
        held_name_capture_and_section_name_filter_defects_identified=True,
        original_bounded_prefix_complete_rows=198103, original_missing_literal_count=28,
        saved_missing_literal_roster_in_original_scope=False,
        corrected_source_capture_complete=True, corrected_complete_source_groups=102,
        corrected_complete_name_roster=28, captured_gzip_footer_and_mapping_links_verified=True,
        source_raw24_district_inclusion_planning_examples=2,
        sectioned_planning_names=['崇德路2段', '崇德路3段'],
        official_alias_or_install_acceptance_for_planning_examples=False,
        AP_basename_metadata_producer_identified=True,
        AP_specific_METADATA_is_not_a_proven_FILE_opener=True,
        primary_name_crosscheck=dict(
            url='https://www.traffic.taichung.gov.tw/form/index.asp?Parser=3,8,485,358,383,484,,,,,25,,,,,u,0',
            observed_document_road_literal='景賢六路', observed_document_year=113,
            observed_page_update='2026-09-04 16:59:00',
            browser_open_observed=True, raw_HTTP_response_frozen=False,
            candidate_景賢六街_alias_or_formal_address_proved=False,
            source_not_an_exhaustive_official_street_registry=True),
        next='Classify the saved28 names and lossless lane/alley data; trace actual MDR context producer and AP mapping setup using bounded static witnesses.',
        current_device_v2_unchanged=True, device_IO=False, installable=False,
        full_Taiwan_update_complete=False, native_App_complete=False, full_goal_complete=False)
    nav['offline_storage_capture_checkpoint_v1'] = copy.deepcopy(checkpoint)
    nav['next'] = '接續已保存28個路名的段名／巷弄分類與可逆完整門牌表示；核對MDR context及AP實際mapping來源。保留正常v2配置，現在不要求實機操作。'
    phases = nav['native_country_address_update_progress']['phases']
    phases.extend([
        'GMP前置排列的153,337,856-byte完整虛擬圖資已串流雜湊；六個logical元件全部來源內容雜湊、FAT跨block／尾端與配置padding通過，不另存大型IMG。尚未驗原機renderer或修復v3。',
        '原地址DIR冷初始化的mutex實際執行並返回0；停在heap core首指令前、handle仍0，未完成配置／constructor／連續地址query。',
        'AP selector4D→FILE欄位與通用FILE路徑→64-byte drive表已各自定位；真AP檔名／live drive來源尚缺，不把slot2當partition2。',
        '段名與保存規則修正後，同一有界198,103組前綴的28種缺名路名／102完整groups全部保留，18,867-byte新capture的gzip footer與全部名冊／group連結已獨立讀回核對。崇德路2段51號／3段199號兩例來源與raw24均在北屯polygon內，但與原廠二段／三段的寫法關係仍held，沒有新街或正式地址驗收。',
        '找到selector4D產生/.System/與gmapprom1.img兩個metadata欄位的原碼，也找到通用filename→mapping caller；metadata欄位輸出不是physical FILE opener，真AP檔案→live drive連結仍未完成。',
        '官方<a href="https://www.traffic.taichung.gov.tw/form/index.asp?Parser=3,8,485,358,383,484,,,,,25,,,,,u,0" target="_blank" rel="noopener">交通調查資料</a>使用「景賢六路」；這不能證明來源「景賢六街」與其為同一路名／地址，也不以搜尋無結果推論路名不存在。',
    ])
    nav['updated_utc'] = now.isoformat()
    nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    work = state['offline_24h_work_order']
    work['latest_completed_storage_capture_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['navigation'] = checkpoint['next']
    state['updated_utc'] = now.isoformat()
    for key in ['updated_utc', 'navigation_repair', 'offline_24h_work_order']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state),
                  navigation_repair=copy.deepcopy(nav), offline_24h_work_order=copy.deepcopy(work),
                  native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    report = before[FILES[3]].decode()
    text = '<p id="offline-frontier-latest-v1">最新：段名篩選及缺名保存規則已修正，同一有界前綴的28種缺名／102完整來源groups全部保存，新gzip與名冊連結已讀回校驗；兩個崇德路分段門牌的來源／raw24範圍檢查通過，仍待核對與原廠段名的關係。另完成153 MB地圖前置排列的虛擬串流及六個元件內容核對，沒有再存一份IMG；原機顯示根因仍未知。地址冷constructor停在heap core，DIR／全臺更新／連續原機搜尋尚未完成。</p>'
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: text, report, count=1, flags=re.S)
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
    out = ROOT / 'staging' / ('offline-storage-capture-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir()
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
               offline_storage_capture_checkpoint_v1=checkpoint, offline_24h_work_order=copy.deepcopy(work))
    replace(FILES[4], web)
    assert read(FILES[0]) == read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    assert read(FILES[0])['native_app_music'] == read(FILES[1])['native_app_music'] == old_app
    create(out / 'fresh-readback.json', dict(all_passed=True, prerequisite_pins=PINS,
        service=svc, report_sha256=sha(served), nav_estimate=75, app_estimate=40, overall_estimate=37,
        actual_goal_status='active', user_away=True, no_pending_presence_question=True,
        device_IO=False, full_goal_complete=False))
    print(json.dumps(dict(all_passed=True, checkpoint=str(out.relative_to(ROOT)), report_url=web['url'], device_IO=False)))


if __name__ == '__main__':
    main()
