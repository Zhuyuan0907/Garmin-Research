"""Publish the closed L4 data comparison; keep hardware validation separate."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json',
         'reports/findings.json', 'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
BASE = 'staging/navigation-v3-exclusive-stock-L4-reuse-feasibility-v1/'
PINS = {
    BASE + 'scope-summary.json': '31ff1e560798e9c772cb5cdb01682aa049ba161b80c82d071e0715751e116ec9',
    BASE + 'sealed-files.json': '4de5e8108e4760f34451c75654eac76d81184f2f1aaab87d71855c2e6c9d1246',
    BASE + 'actual-exec-terminal-receipt.json': '2d5498f266c6369a2655a6b4afebdfb977490f1e69829ad73eb7df43d2c6cc88',
}


def main():
    docs = {}
    for path, pin in PINS.items():
        raw = (ROOT/path).read_bytes()
        assert len(raw) <= 10000 and sha(raw) == pin
        docs[path] = json.loads(raw)
    summary = docs[BASE+'scope-summary.json']
    assert summary['actual_terminal'] == dict(session=48330, chunk='d1a040', exit_code=0)
    assert summary['candidate_roots'] == 1251 and summary['actual_L4_rows_compared'] == 108235
    assert summary['outside_mask_rejected_groups'] == 0
    assert summary['arithmetic']['projected_IMG_bytes'] == 135438336
    assert summary['arithmetic']['excess_bytes'] == 1220608 and not summary['arithmetic']['fits']
    assert not any(summary['falseflags'].values())
    before = {path:(ROOT/path).read_bytes() for path in FILES}
    state, task, public = [json.loads(before[path]) for path in FILES[:3]]
    web = json.loads(before[FILES[4]])
    assert state == public['deep_research']
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    assert all(x['goal_status'] == 'active' and not x['goal_complete'] for x in [state,task,public,web])
    assert not state['attended_testing']['user_present'] and state['attended_testing']['no_pending_question']
    assert not state['audio']['audible_tests_allowed']
    svc = service()
    assert http(web['url'])[0] == before[FILES[3]]
    old_app, old_audio = copy.deepcopy(state['native_app_music']), copy.deepcopy(state['audio'])
    nav = state['navigation_repair']
    old_device = copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    checkpoint = dict(updated_utc=now.isoformat(), prerequisite_pins=PINS,
        actual_terminal='d1a040 EXIT0', compared_L4_rows=108235, reusable_original_groups=1251,
        changed_fields_only='Known first/count child pointer fields; other 128-bit row fields identical.',
        projected_original_4K_IMG_bytes=135438336, original_declared_capacity_bytes=134217728,
        remaining_excess_bytes=1220608, fits_declared_capacity=False,
        actual_IMG_read_bytes=4945952, current_mm_peak_KiB=52704,
        L5_followup_status='active_data_comparison_not_yet_completed',
        independent_L4_plan_review_status='pending',
        original_capacity_is_not_proven_device_maximum=True,
        unknown_external_references_and_cache_semantics_held=True,
        device_IO=False, IMG_created=False, installable=False, road_loss_rootcause_proven=False,
        full_Taiwan_update_complete=False, native_App_complete=False, full_goal_complete=False)
    nav['exclusive_stock_L4_reuse_checkpoint_v1'] = copy.deepcopy(checkpoint)
    nav['reachable_suffix_capacity_checkpoint_v1']['stock_root_pointer_only_reuse_feasibility_status'] = 'L4_actual_data_comparison_completed_still_over_capacity'
    nav['next'] = ('已完成1251組原廠L4索引沿用核對，可省108235筆重複記錄，但完整新版仍超原封裝容量1220608 bytes；'
                   '繼續核對L5索引沿用與獨立容量門檻，保留新增門牌。全台更新包與道路消失修復仍未完成；正常v2保留，等使用者自行通知返回。')
    phases = nav['native_country_address_update_progress']['phases']
    phases.append('原廠L4群組沿用的實際資料核對完成：1251組、108235筆記錄在子項指標以外的全部位元相同，並通過已知地址樹的獨占範圍檢查。重用計畫預估135438336 bytes，仍超原封裝容量1220608 bytes；未知外部引用仍待確認，未產生或安裝新IMG。')
    nav['updated_utc'] = now.isoformat()
    nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    work = state['offline_24h_work_order']
    work['latest_completed_stock_L4_reuse_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['navigation'] = nav['next']
    turn = dict(classification='progress', validated_utc=now.isoformat(), goal_status='active',
                full_goal_complete=False, required_work_remaining=True, device_files_written=False,
                reason='Closed L4 data comparison; further L5 capacity and full update validation remain.')
    state.update(updated_utc=now.isoformat(), last_goal_turn=copy.deepcopy(turn))
    for key in ['updated_utc','navigation_repair','offline_24h_work_order','last_goal_turn']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav),
                  offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn),
                  native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    report = before[FILES[3]].decode()
    paragraph = ('<p id="offline-frontier-latest-v1">最新：1251組原廠索引沿用的離線資料核對完成，'
        '可省下108235筆重複記錄，但完整新版仍超原封裝容量約1.22MB。正核對下一層索引，保留新增門牌。'
        '全台更新包與新版道路消失問題尚未完成修復。車機保留已實測正常的門牌v2＋Search v2；'
        '民權路6、150、184號已由使用者確認可找到、位置合理並算出路線。'
        '原機App與手機直接藍牙音樂仍未完成，Pi轉送音樂是先前已實測的另一條路徑。</p>')
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _:paragraph, report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>',
        lambda _:'<h3>已完成</h3><ul>'+''.join('<li>'+x+'</li>' for x in phases)+'</ul>', report, count=1, flags=re.S)
    assert count == 1
    for ident in ['navigation-address-updated-time','report-updated-time','research-updated-time']:
        report, count = re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>',
            lambda _:f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        assert count == 1
    assert nav['latest_country_v2_comparison_checkpoint'] == old_device
    assert state['native_app_music'] == old_app and state['audio'] == old_audio
    assert nav['native_country_address_update_progress']['estimate_percent'] == 75
    out = ROOT/'staging'/('stock-L4-reuse-publication-'+now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, raw in before.items():
        with (out/(path.replace('/','__')+'.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw,mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for path,value in zip(FILES[:4],[state,task,public,report]):
        replace(path,value)
    served,response = http(web['url'])
    assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
               served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
               exclusive_stock_L4_reuse_checkpoint_v1=copy.deepcopy(checkpoint),
               offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    display = web['progress_display_verified']
    display.update(navigation_repair_estimate_percent=75, App_estimate_percent=40, estimate_percent=37,
                   report_updated_time=local.isoformat(timespec='seconds'), research_updated_time=local.isoformat(timespec='seconds'))
    replace(FILES[4],web)
    fresh = [json.loads((ROOT/p).read_bytes()) for p in [FILES[0],FILES[1],FILES[2],FILES[4]]]
    assert all(x['goal_status']=='active' and not x['goal_complete'] for x in fresh)
    assert fresh[0] == fresh[2]['deep_research']
    assert fresh[0]['navigation_repair'] == fresh[1]['navigation_repair'] == fresh[2]['navigation_repair']
    assert fresh[0]['native_app_music'] == fresh[1]['native_app_music'] == old_app
    create(out/'fresh-readback.json', dict(all_passed=True, prerequisite_pins=PINS, service=svc,
        report_sha256=sha(served), nav_estimate=75, app_estimate=40, overall_estimate=37,
        goal_status='active', user_away=True, device_IO=False, full_goal_complete=False))
    print(json.dumps(dict(all_passed=True, checkpoint=str(out.relative_to(ROOT)), report_url=web['url'],
        updated_at_Taiwan=local.isoformat(timespec='seconds'), device_IO=False)))


if __name__ == '__main__':
    main()
