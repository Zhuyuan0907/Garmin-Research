#!/usr/bin/env python3
"""Publish the AP+OSM physical result and bounded native-address writer progress."""
import copy
import gzip
import html
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from publish_navigation_native_basis_checkpoint_v1 import (
    ROOT, create, http, read, replace, service, sha,
)

OUT = ROOT / 'staging/navigation-address-update-checkpoint-v1'
CANONICALS = [
    'evidence/deep-research-state.json', 'evidence/task-state.json',
    'reports/findings.json', 'reports/nuvi2565RT.html', 'evidence/report-web-latest.json',
]
PHYSICAL = 'evidence/navigation-AP-OSM-destination-route-20261006-v1.json'


def main():
    assert not OUT.exists()
    proofs = {PHYSICAL: sha((ROOT / PHYSICAL).read_bytes())}
    manifests = [
        'staging/navigation-native-AP-packed-records-v1/sealed-record-reader-manifest-v2.json',
        'staging/navigation-native-AP-child-range-v1/sealed-child-range-manifest-v1.json',
        'staging/navigation-native-AP-rescale-suffix-v1/sealed-rescale-suffix-manifest-v1.json',
        'staging/navigation-stock-AP-LBL-labels-v1/original-AP-LBL-fragments-file-seal-v1.json',
        'staging/navigation-AP-MinQuan184-witness-v1/source-file-seal.json',
        'staging/navigation-native-record-writer-v1/native-record-writer-file-seal-v1.json',
        'staging/navigation-native-record-house184-prototype-v1/house184-prototype-file-seal-v1.json',
        'staging/navigation-native-record-writer-cpu-v1/new-payload-CPU-file-seal-v1.json',
    ]
    # File-only registration of previously completed proofs, with no probe replay.
    for name in manifests:
        raw = (ROOT / name).read_bytes()
        proofs[name] = sha(raw)
        manifest = json.loads(raw)
        entries = manifest.get('files', manifest.get('sealed_files'))
        if isinstance(entries, dict):
            entries = [dict(path=p, sha256=h) for p, h in entries.items()]
        for entry in entries:
            raw = (ROOT / entry['path']).read_bytes()
            assert sha(raw) == entry['sha256'], entry['path']
            expected_size = entry.get('bytes', entry.get('size_bytes'))
            assert expected_size is None or len(raw) == expected_size
            proofs[entry['path']] = entry['sha256']
        if 'ledger' in manifest:
            raw = (ROOT / manifest['ledger']).read_bytes()
            assert sha(raw) == manifest['ledger_sha256']
            proofs[manifest['ledger']] = sha(raw)
    for name in [
        'staging/navigation-stock-AP-LBL-labels-v1/original-AP-LBL-sealer-terminal-tool-receipt-v1.json',
        'staging/navigation-native-record-writer-v1/writer-file-sealer-terminal-tool-receipt-v1.json',
        'staging/navigation-native-record-house184-prototype-v1/house184-FILE-sealer-terminal-tool-receipt-v1.json',
    ]:
        receipt = read(name)
        assert receipt['terminal'] and receipt['actual_exit_code'] == 0
        proofs[name] = sha((ROOT / name).read_bytes())
    physical = read(PHYSICAL)
    assert physical['primary_destination_correct_user_confirmed']
    assert physical['primary_route_calculation_user_confirmed']
    assert not physical['original_CN_road_layer_needed_for_primary_case']
    witness_name = 'staging/navigation-AP-MinQuan184-witness-v1/stock-MinQuan184-bounded-source-proof-v1.json'
    witness = read(witness_name)
    assert witness['all_bounded_source_and_host_decode_checks_passed']
    assert witness['strict_184_match_count'] == 1
    writer = read('staging/navigation-native-record-writer-v1/native-record-writer-source-crosscheck-proof-v1.json')
    assert writer['all_bounded_host_checks_passed']
    assert writer['totals']['original_source_used_bit_crosschecks'] == 5
    assert writer['totals']['rejected_invalid_inputs'] == 12
    cpu_base = 'staging/navigation-native-record-writer-cpu-v1/'
    cpu_post = read(cpu_base + 'post-seal-review-receipt-v1.json')
    assert cpu_post['all_sealed_files_sha256_match'] and not cpu_post['metadata_success_hook']
    assert proofs[cpu_post['seal_path']] == cpu_post['seal_sha256']
    proofs[cpu_base + 'post-seal-review-receipt-v1.json'] = sha((ROOT / (cpu_base + 'post-seal-review-receipt-v1.json')).read_bytes())
    cpu = read(cpu_base + 'new-selected184-and-writer-payloads-partial-CPU-proof-v1.json')
    assert cpu['all_assigned_case_checks_passed'] and cpu['exact_new_case_count'] == 3
    assert not cpu['complete_reader_return_or_SQL_or_UI_or_registry_executed']
    assert not cpu['result_or_metadata_success_or_sort_or_policy_hooks']
    assert cpu['actual_house184_raw24_delta'] == [3, 3]
    for case, prototype in zip(cpu['cases'][1:], [
        'staging/navigation-native-record-writer-v1/modern-Minquan-street-point-prototype-v1.json',
        'staging/navigation-native-record-house184-prototype-v1/modern-source-native-house184-point-prototype-v1.json',
    ]):
        assert case['actual_original_prefix_output_hex'] == read(prototype)['expected_native_output_32bytes_hex']

    before = {p: (ROOT / p).read_bytes() for p in CANONICALS}
    state, task, public = [json.loads(before[p]) for p in CANONICALS[:3]]
    latest = json.loads(before[CANONICALS[-1]])
    assert public['deep_research'] == state
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    app_before = copy.deepcopy(state['native_app_music'])
    progress_before = copy.deepcopy(public['research_progress'])
    service_before = service()
    served, _ = http(latest['url'])
    assert served == before[CANONICALS[3]]
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    timestamp = local.isoformat(timespec='seconds')
    next_actions = [
        '實測Address Point＋Search v2可搜尋民權路184號並計算路線；先保留目前已測通的設定，原廠CN道路圖留作對照。其他地址尚未全面驗證。',
        '完成原廠格式地址記錄與搜尋索引的配套產生規則，讓新版道路、門牌、縣市及街道名稱保持一致。',
        '比對新版來源和舊地址記錄，挑選有實際更新價值的地址；資料缺漏與行政區歧義須保留。',
        '可安裝更新包完成後，再驗證新地址搜尋與路線；目前沒有額外USB操作需求。',
        '導航搜尋與地址更新需求驗證完成後，恢復手機音樂／App研究。',
    ]
    details = [
        '最新實機對照：只勾原廠Address Point＋Search v2、取消原廠CN道路圖，使用者確認民權路184號位置正確，路線也算出。',
        '此前三層一起啟用也能快速搜尋並計算路線；Search v2單獨查街道仍無相符項目。兩層結果只涵蓋這一個測試地址。',
        '目前道路圖已更新，實際門牌搜尋仍沿用原廠2016地址資料；新增或變更的地址尚未取得完整更新。',
        '原備份中已找到台中市→中區→民權路→184號的名稱、階層與座標記錄，並核對原程式的有限讀取片段。',
        '離線工具已能產生單筆原格式記錄，五筆舊記錄的有效位元完全一致；這還不是完整Address Point地圖或索引更新包。',
    ]
    native_details = [
        '原廠中文名稱編碼與三個名稱讀取片段已核對；原DB階層可以區分不同行政區的同名民權路與民和路。',
        '縣市、區、街道記錄的子表起點、筆數、名稱引用與座標格式已核對；民權路下一層共84筆，包含交叉路口等記錄，不能全部當成門牌。',
        '在這84筆中找到唯一完整「184號」：level4 ID904780、名稱引用808；來源文字與座標已唯讀核對。',
        '原格式單筆writer完成五筆611個有效位元的來源比對及12個輸入拒絕案例；已產出街道和184號各16bytes的座標原型。',
        '原CPU有限讀取片段已分別核對舊184號及兩筆新原型；完整MDR、地圖、縣市／街道索引與新門牌串接尚未產出，原廠檔案沒有修改。',
    ]
    nav = state['navigation_repair']
    native = nav['original_format_research']
    native.update(
        updated_utc=now.isoformat(), stage='selected_native_address_chain_and_record_writer_proven',
        selected_record_fields_and_child_ranges_verified=True,
        selected_source_backed_coordinate_transform_verified=True,
        selected_LBL_name_fragments_verified=True,
        original_house184_source_record_identified=True,
        original_house184_low_ID=904780, original_house184_label_reference=808,
        native_packed_record_writer_implemented=True,
        native_record_writer_source_cases=5, native_record_writer_source_bits=611,
        native_record_writer_rejection_controls=12,
        fresh_street_and_house_point_payloads_bytes=32,
        fresh_payloads_independent_native_CPU_verified=True,
        fresh_payload_native_CPU_scope='Two record-prefix and explicit source-backed rescale fragments; no complete reader/registry/SQL/UI.',
        original_house184_native_record_prefix_verified=True,
        original_format_writer_implemented=False, whole_AP_MDR_JAI_writer_implemented=False,
        original_address_data_updated_to_2026=False,
        selected_AP_position_and_route_relationship_verified=False,
        details=native_details, latest_evidence=list(proofs),
    )
    nav.update(
        updated_utc=now.isoformat(), latest_physical_test=PHYSICAL,
        latest_physical_test_result=copy.deepcopy(physical),
        latest_AP_OSM_destination_route_test=PHYSICAL,
        AP_OSM_primary_destination_correct_user_confirmed=True,
        AP_OSM_primary_route_calculation_user_confirmed=True,
        original_CN_road_layer_needed_for_primary_case=False,
        latest_successful_minimal_layer_configuration=['original Address Point', 'Search v2'],
        daily_selection_recommendation=['original Address Point', 'Search v2'],
        daily_selection_scope='Primary-case-only evidence; original CN retained, other roads not broadly validated.',
        navigation_repair_status='AP_OSM_primary_case_passed_native_address_update_in_progress',
        execution_status='building_original_format_address_and_index_update_rules',
        current_verification_details=details, remaining_next_actions=next_actions,
        next=next_actions[1], candidate_accepted=False, candidate_recommendation_held=True,
        original_address_data_updated_to_2026=False, full_updated_address_search_verified=False,
        goal_complete=False, required_work_remaining=True,
    )
    nav['known_limits'] = [
        '兩層及三層的民權路184號搜尋與路線計算已實測通過；實際查詢／路由來源未逐段觀察，且原廠地址資料仍為2016年。',
        '新版OSM單獨的原生街道搜尋未通過，現有成功組合仍需原廠Address Point。',
        '其他道路、新增門牌、搜尋秒數及實際行車導引尚未全面驗證。',
        '離線writer目前只產出單筆二進位記錄；完整地圖與搜尋索引更新尚未完成，沒有將原型安裝到車機。',
        '有限原CPU片段驗證不等於完整GarminOS模擬或實機搜尋，原廠地圖、授權檔、資料庫及韌體保持原檔。',
    ]
    nav['sources'].update(AP_OSM_destination_route=PHYSICAL, original_house184=witness_name,
                          native_record_writer='scripts/native_address_records.py')
    state.update(updated_utc=now.isoformat(), current_priority=next_actions[1],
                 next_actions=next_actions, goal_complete=False, required_work_remaining=True)
    state['last_goal_turn'] = dict(
        classification='progress', validated_utc=now.isoformat(), goal_status=state['goal_status'],
        physical_primary_case_acceptance=PHYSICAL, previous_blocking_condition_resolved=True,
        reason='AP+OSM physical primary case passed; native-address binary writer is a bounded prototype.',
        device_IO=False, full_goal_complete=False, required_work_remaining=True,
    )
    for key in ['navigation_repair', 'updated_utc', 'current_priority', 'next_actions',
                'last_goal_turn', 'required_work_remaining', 'goal_complete']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state),
                  navigation_repair=copy.deepcopy(nav), goal_complete=False, required_work_remaining=True)
    public['navigation_repair_progress']['AP_OSM_primary_case_passed'] = True
    public['navigation_repair_progress']['native_address_update_complete'] = False
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert state['native_app_music'] == app_before
    for key in ['estimate_percent', 'weighted_estimate_percent', 'phases', 'completed']:
        assert public['research_progress'][key] == progress_before[key]

    def items(values):
        return ''.join('<li>' + html.escape(value) + '</li>' for value in values)

    clock = f'<time datetime="{timestamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）'
    card = '<section class="card" id="navigation-repair-checkpoint-v2"><h2>導航搜尋：Address Point＋新版道路圖已通過民權路測試</h2>'
    card += '<p id="navigation-AP-OSM-route-acceptance-v1"><strong>最新確認：Address Point＋Search v2兩項就能找到民權路184號，並算出路線。</strong>原廠CN道路圖已保留，可供其他地址對照；新版單獨搜尋街道仍失敗。</p>'
    card += '<p><strong>地址更新仍在處理：</strong>目前Address Point及配套搜尋索引仍是原廠舊資料。完整更新須讓新道路、門牌、縣市與街道索引互相對應。</p>'
    card += '<p>既有候選準備與安裝里程碑估計 <strong>75%</strong>；原廠格式地址更新仍在研究，此比例不代表所有地址的修復成功率。</p><progress id="navigation-repair-progress" max="100" value="75" style="width:100%;height:18px">75%</progress>'
    card += '<p>更新：' + clock + '</p><h3>最新完成的確認</h3><ul>' + items(details) + '</ul>'
    card += '<h3>後續處理順序</h3><ol>' + items(next_actions) + '</ol>'
    card += '<details><summary>既有候選編圖及安裝紀錄</summary><ul>' + items(nav['completed_physical_details'] + nav['completed_offline_details']) + '</ul>'
    card += '<p><a href="' + html.escape(nav['download_url']) + '" download>第二版研究候選包</a>：保留編圖與安裝紀錄，並未包含新版原廠格式Address Point。</p></details>'
    card += '<h3>尚未完成</h3><ul>' + items(nav['known_limits']) + '</ul></section>'
    native_card = '<aside class="card" id="navigation-native-format-progress-v1"><h2>原廠格式地址更新：找到184號記錄，單筆產生工具完成</h2>'
    native_card += '<p>以下為備份檔與有限原指令的研究成果；完整新版Address Point尚未完成，也未安裝單筆原型。</p><ul>' + items(native_details) + '</ul>'
    native_card += '<p><strong>下一步：</strong>' + html.escape(next_actions[1]) + '</p><p>研究更新：' + clock + '</p></aside>'
    report = before[CANONICALS[3]].decode()
    for pattern, replacement in [
        (r'<section class="card" id="navigation-repair-checkpoint-v2">.*?</section>', card),
        (r'<aside class="card" id="navigation-native-format-progress-v1">.*?</aside>', native_card),
    ]:
        report, count = re.subn(pattern, lambda _: replacement, report, count=1, flags=re.S)
        assert count == 1
    for identifier in ['report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + identifier + r'" datetime="[^"]+">[^<]+</time>',
                                lambda _: f'<time id="{identifier}" datetime="{timestamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',
                                report, count=1)
        assert count == 1
    OUT.mkdir()
    for name, raw in before.items():
        path = OUT / (name.replace('/', '__') + '.gz')
        with path.open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0))
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o444)
    create(OUT / 'root-reviewed-proof-bindings.json', dict(
        created_utc=now.isoformat(), verified_sha256=proofs,
        proof_checks='File-only; no old CPU/codec/map suite replay, no device IO.',
        updated_native_AP_complete=False, full_goal_complete=False,
    ))
    for name, value in zip(CANONICALS[:4], [state, task, public, report]):
        replace(name, value)
    served, response = http(latest['url'])
    assert served == report.encode() and service() == service_before
    latest.update(updated_utc=now.isoformat(), HTTP_status=response['status'],
                  cache_control=response['cache_control'], report_bytes=len(served),
                  local_report_sha256=sha(served), served_report_sha256=sha(served),
                  served_latest_report=True, service_not_restarted=True,
                  latest_navigation_AP_OSM_destination_route_test=PHYSICAL,
                  latest_original_format_research=str(OUT.relative_to(ROOT)) + '/root-reviewed-proof-bindings.json',
                  native_address_update_complete=False, required_work_remaining=True, full_goal_complete=False)
    replace(CANONICALS[-1], latest)
    assert read(CANONICALS[2])['deep_research'] == read(CANONICALS[0])
    assert read(CANONICALS[0])['navigation_repair'] == read(CANONICALS[1])['navigation_repair']
    create(OUT / 'fresh-readback.json', dict(
        all_passed=True, checked_utc=datetime.now(timezone.utc).isoformat(), HTTP=response,
        report_sha256=sha(served), service=service_before, service_not_restarted=True,
        primary_AP_OSM_case_user_confirmed=True, native_address_update_complete=False,
        fresh_payload_native_CPU_pending=False, full_goal_complete=False,
    ))
    print(json.dumps(dict(all_passed=True, report_url=latest['url'],
                          service_PID=service_before['MainPID'], native_address_update_complete=False), ensure_ascii=False))


if __name__ == '__main__':
    main()
