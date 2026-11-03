"""Publish source/caller frontiers without upgrading any device claims."""
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
    'staging/navigation-native-ap-registry-date-producer-v1/proof.json': '47a3faadad8a614323358b4a2a8d21ae09fc11ecd7752e226f3f5fb451266abe',
    'staging/navigation-native-query-vector-provider-binding-v1/proof.json': 'bf28f343d2d44c7042e6c434c3706f9225428df96e4eb6fb7e7528128b042a17',
    'staging/navigation-Dunfu-road-family-source-plan-v1/proof.json': '147c28621bafb8ac96f5211392c4f79ed76f7dd3d601b87aa9c717cfe6998249',
}


def main():
    values = []
    for name, expected in PINS.items():
        raw = (ROOT / name).read_bytes()
        assert len(raw) < 20000 and sha(raw) == expected
        values.append(json.loads(raw))
    producer, query, source = values
    assert producer['all_assigned_bounded_checks_passed'] and producer['completed_original_CPU_cases'] == 1
    assert producer['completed_original_instructions'] == 31 and not producer['real_expiry_reason_proved']
    assert not producer['authorization_bypass_tested'] and not producer['v3_fixed']
    assert query['all_assigned_checks_passed'] and query['guest_cases_executed'] == 0
    assert source['ordinary_file_analysis_complete'] and source['new_distinct_street_example_count'] == 0
    assert source['status'] == 'held_no_additional_Dunfu_source_in_authorized_prefix'
    now = datetime.now(timezone.utc); local = now.astimezone(ZoneInfo('Asia/Taipei'))
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    assert state == public['deep_research'] and state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    assert state['goal_status'] == 'active' and not state['goal_complete']
    assert not state['attended_testing']['user_present'] and state['attended_testing']['no_pending_question']
    assert not state['audio']['audible_tests_allowed']
    svc = service(); served, _ = http(web['url']); assert served == before[FILES[3]]
    nav = state['navigation_repair']; old_v2 = copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
    old_app = copy.deepcopy(state['native_app_music'])
    checkpoint = dict(updated_utc=now.isoformat(), prerequisite_pins=PINS,
        original_registry_payload_plus6_write_producer_identified=True,
        actual_bounded_synthetic_producer_case=True, actual_producer_instructions=31,
        original_registration_stopped_at_entry=True,
        real_provider_value_expiry_or_v3_rootcause_verified=False,
        real_tokens_unlock_or_serial_read_or_published=False,
        static_query_vector_DIR_handle_and_context_store_identified=True,
        actual_query_vector_constructor_guest_executed=False,
        uninterrupted_query_to_getter_UI_verified=False,
        bounded_Dunfu_source_search_additional_candidates=0,
        bounded_prefix_scope_only=True, whole_source_absence_proved=False,
        next='query DIR constructor, production block-read callback, other Beitun road-name source examples',
        current_device_v2_unchanged=True, device_IO=False, installable=False,
        full_Taiwan_update_complete=False, full_goal_complete=False)
    nav['offline_frontier_checkpoint_v1'] = copy.deepcopy(checkpoint)
    phases = nav['native_country_address_update_progress']['phases']
    phases.append('Map狀態欄位+6原寫入點與數值選取鏈已找到，1個合成producer／31原指令通過並停註冊入口；實機值、到期語意與v3回歸原因未證。')
    phases.append('原query tuple consumer、DIR handle取得與MDR context寫入點已靜態定位，下一cold constructor尚待執行；有界來源前綴46,470組只有敦富六街，其他同系列新街未取得，不代表全來源不存在。')
    nav['updated_utc'] = now.isoformat(); nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    work = state['offline_24h_work_order']; work['latest_completed_frontier_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['navigation'] = checkpoint['next']
    state['updated_utc'] = now.isoformat()
    for key in ['updated_utc', 'navigation_repair', 'offline_24h_work_order']: task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav),
        native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']),
        offline_24h_work_order=copy.deepcopy(work))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    report = before[FILES[3]].decode()
    old = '欄位寫入来源及與顯示回歸的關係仍在追。'
    assert report.count(old) == 1
    report = report.replace(old, '欄位原寫入點與數值選取鏈已找到，合成producer停在註冊入口；實機值與顯示回歸的關係仍在追。', 1)
    marker = '<div id="new-street-full-offline-result-v1">'
    assert report.count(marker) == 1
    report = report.replace(marker, marker +
        '<p id="offline-frontier-latest-v1">目前接續原地址結果向量到DIR／MDR context建立；另追實際儲存讀取callback。新增來源檢查在有界46,470組前綴只取得敦富六街，沒有其他同系列新街樣本；接著檢查北屯其他路名。未到來源結尾，不推論整份資料沒有其他新街。</p>', 1)
    report, count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>',
        lambda _: '<h3>已完成</h3><ul>' + ''.join('<li>' + item + '</li>' for item in phases) + '</ul>',
        report, count=1, flags=re.S); assert count == 1
    for ident in ['navigation-address-updated-time', 'report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + ident + r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',
            report, count=1); assert count == 1
    assert nav['latest_country_v2_comparison_checkpoint'] == old_v2 and state['native_app_music'] == old_app
    assert nav['native_country_address_update_progress']['estimate_percent'] == 75
    out = ROOT / 'staging' / ('offline-frontier-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ')); out.mkdir()
    for name, raw in before.items():
        with (out / (name.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for name, value in zip(FILES[:4], [state, task, public, report]): replace(name, value)
    served, response = http(web['url']); assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
        served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
        offline_frontier_checkpoint_v1=checkpoint, offline_24h_work_order=copy.deepcopy(work))
    replace(FILES[4], web)
    assert read(FILES[0]) == read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    assert read(FILES[0])['native_app_music'] == read(FILES[1])['native_app_music'] == old_app
    create(out / 'fresh-readback.json', dict(all_passed=True, prerequisite_pins=PINS, service=svc,
        report_sha256=sha(served), nav_estimate=75, app_estimate=40, overall_estimate=37,
        actual_goal_status='active', user_away=True, no_pending_presence_question=True,
        device_IO=False, full_goal_complete=False))
    print(json.dumps(dict(all_passed=True, checkpoint=str(out.relative_to(ROOT)), report_url=web['url'], device_IO=False)))


if __name__ == '__main__':
    main()
