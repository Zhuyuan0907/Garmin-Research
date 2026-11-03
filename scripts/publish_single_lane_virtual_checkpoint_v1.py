"""Publish the finite map-data delta and review; preserve physical acceptance."""
import copy
import gzip
import json
import os
import re
import sys
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json',
         'reports/findings.json', 'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
PINS = {
    'staging/navigation-single-lane-v2-4k-virtual-delta-v1/scope-summary.json':
        'd18486d5cfd9434477f2499452066b93d03a346ec89a52962fcdd09b20ac79f3',
    'staging/navigation-single-lane-v2-4k-virtual-delta-v1/sealed-files.json':
        'e70643bf37de5edd1dc4a4701da9df0f54e8ea03580040034f23b360ade0cde0',
    'staging/navigation-v3-reachable-suffix-compaction-root-observed-v3/actual-failure.json':
        '9c2e22b5ccfe05c5b3667e621a3475a8e9f154a689878dabadfaa08fea62fbd4',
}


def main():
    assert len(sys.argv) == 3 and all(re.fullmatch('[0-9a-f]{64}', x) for x in sys.argv[1:])
    review_dir = 'staging/navigation-single-lane-virtual-delta-independent-review-v1/'
    pins = dict(PINS)
    pins[review_dir + 'proof.json'] = sys.argv[1]
    pins[review_dir + 'sealed-files.json'] = sys.argv[2]
    docs = {}
    for path, pin in pins.items():
        raw = (ROOT / path).read_bytes()
        assert len(raw) <= 100000 and sha(raw) == pin
        docs[path] = json.loads(raw)
    summary = docs[next(iter(PINS))]
    review = docs[review_dir + 'proof.json']
    assert review['all_assigned_checks_passed']
    assert review['producer_seal_SHA256'] == PINS['staging/navigation-single-lane-v2-4k-virtual-delta-v1/sealed-files.json']
    assert summary['exact_path'] == ['四川路二段', '4巷', '2號']
    assert summary['all_oldfour_bits_lowerptr_order_preserved']
    assert summary['whole_container_blockbytes'] == 4096
    assert summary['wholeheader_capacity_bytes'] == 134217728
    assert summary['actual_inverse_from_emitted_transformed_bytes_SHA256'] == '925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'
    assert not review['independent_full_inverse_SHA256_recomputed']
    assert review['artifact_bytes_read_total'] <= 1048576
    assert not review['install_ready'] and not review['renderer_UI_native_lookup_route_and_device_verified']
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
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    nav = state['navigation_repair']
    old_device = copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
    old_app = copy.deepcopy(state['native_app_music'])
    old_audio = copy.deepcopy(state['audio'])
    checkpoint = dict(updated_utc=now.isoformat(), prerequisite_pins=pins,
        source_address='新北市板橋區四川路二段4巷2號', source_node=12084620255,
        virtual_stream_completed=True, actual_terminal='ab0374 EXIT0',
        virtual_IMG_bytes=summary['virtual_IMG_bytes'], virtual_IMG_sha256=summary['virtual_IMG_SHA256'],
        image_growth_bytes=4096, MDR_growth_bytes=4351, original_4K_header_and_capacity_preserved=True,
        original_267_siblings_and_4_house_flags_pointers_order_preserved=True,
        inverse_whole_hash_from_emitted_bytes_matches_original_v2=True,
        independent_review_passed=True, independent_full_whole_hash_recomputed=False,
        independent_captured_bytes=88047, independent_artifact_bytes=review['artifact_bytes_read_total'],
        Minquan_6_150_184_raw_record_controls_preserved=True,
        full_output_IMG_created=False, device_IO=False, installable=False,
        UI_renderer_and_route_verified=False, v3_road_loss_rootcause_proven=False,
        full_Taiwan_update_complete=False, native_App_complete=False, full_goal_complete=False,
        compaction=dict(status='actual_memory_measurement_correction_pending',
            root_actual_terminal='19798a EXIT1', actual_IMG_bytes_read=0,
            historical_ru_maxrss_KiB=424240, actual_post_exec_VmRSS_and_VmHWM_KiB=17824,
            original_budget_KiB=393216, source_stream_not_executed=True,
            failure_is_own_Python_resource_guard=True, platform_rejection=False))
    nav['single_lane_virtual_checkpoint_v1'] = copy.deepcopy(checkpoint)
    nav['next'] = ('已完成單筆新增巷弄的4K虛擬差異與獨立核對；接著修正主機記憶體觀測，'
                   '計算完整v3未引用索引能否回收並保留全台新增門牌。道路消失根因與新候選實機顯示仍未確認；原機正常v2保留。')
    phases = nav['native_country_address_update_progress']['phases']
    phases.append('四川路二段4巷2號的單筆新增4K虛擬串流完成，保留267筆兄弟與原4筆門牌的未知旗標、下層指標及順序；差異僅增加4096 bytes。實際輸出串流逆向核對可回到原v2雜湊，獨立審閱確認有限擷取資料與逆向資料來源；未產生整份可安裝IMG，未驗證車機繪圖或搜尋。')
    phases.append('全台v3索引回收分析尚未讀取MDR：主機歷史記憶體峰值424240KiB觸發自訂384MiB上限，而本次程序VmRSS與VmHWM皆17824KiB。失敗紀錄保留，正在校正資源觀測；尚不能宣稱完整更新版已縮小或道路消失已修復。')
    nav['updated_utc'] = now.isoformat()
    nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    work = state['offline_24h_work_order']
    work['latest_completed_single_lane_virtual_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['navigation'] = nav['next']
    state['updated_utc'] = now.isoformat()
    for key in ['updated_utc', 'navigation_repair', 'offline_24h_work_order', 'goal_status', 'goal_complete']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), goal_status='active', goal_complete=False,
        deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav),
        offline_24h_work_order=copy.deepcopy(work),
        native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    report = before[FILES[3]].decode()
    paragraph = ('<p id="offline-frontier-latest-v1">最新：已完成四川路二段4巷2號的單筆4K虛擬差異與獨立核對，'
        '保留原有地址欄位與民權路三筆控制，輸出串流可逆向回到原v2。這是隔離道路消失問題的小型離線對照，'
        '尚未在車機顯示或搜尋。完整全台版仍在研究索引容量回收；v3道路消失根因、原機App與手機直接藍牙音樂未完成。'
        '實機保持已通過道路與民權路6、150、184號搜尋／路線的Address Point v2＋Search v2。</p>')
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: paragraph, report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>',
        lambda _: '<h3>已完成</h3><ul>' + ''.join('<li>' + x + '</li>' for x in phases) + '</ul>', report, count=1, flags=re.S)
    assert count == 1
    report = report.replace('依使用者最新指示列為主線，goal 保持 active。',
        '依目前優先序排在導航、藍牙音樂與原機 App 之後，goal 保持 active。')
    for ident in ['navigation-address-updated-time', 'report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + ident + r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        assert count == 1
    assert nav['latest_country_v2_comparison_checkpoint'] == old_device
    assert state['native_app_music'] == old_app and state['audio'] == old_audio
    assert nav['native_country_address_update_progress']['estimate_percent'] == 75
    out = ROOT / 'staging' / ('single-lane-virtual-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, raw in before.items():
        with (out / (path.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for path, value in zip(FILES[:4], [state, task, public, report]):
        replace(path, value)
    served, response = http(web['url'])
    assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), goal_status='active', goal_complete=False,
        HTTP_status=response['status'], local_report_sha256=sha(served), served_report_sha256=sha(served),
        report_bytes=len(served), service_not_restarted=True,
        single_lane_virtual_checkpoint_v1=checkpoint, offline_24h_work_order=copy.deepcopy(work))
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / p).read_bytes()) for p in [FILES[0], FILES[1], FILES[2], FILES[4]]]
    assert all(x['goal_status'] == 'active' and not x['goal_complete'] for x in fresh)
    assert fresh[0] == fresh[2]['deep_research']
    assert fresh[0]['navigation_repair'] == fresh[1]['navigation_repair'] == fresh[2]['navigation_repair']
    assert fresh[0]['native_app_music'] == fresh[1]['native_app_music'] == old_app
    create(out / 'fresh-readback.json', dict(all_passed=True, prerequisite_pins=pins,
        service=svc, report_sha256=sha(served), nav_estimate=75, app_estimate=40, overall_estimate=37,
        goal_status='active', user_away=True, no_pending_presence_question=True,
        device_IO=False, full_goal_complete=False))
    print(json.dumps(dict(all_passed=True, checkpoint=str(out.relative_to(ROOT)), report_url=web['url'],
        updated_at_Taiwan=local.isoformat(timespec='seconds'), device_IO=False)))


if __name__ == '__main__':
    main()
