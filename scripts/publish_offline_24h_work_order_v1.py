"""Reconcile actual active goal and user-away offline work order into the report."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json',
         'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
GOAL_EVIDENCE = 'evidence/offline-24h-goal-live-status-20261007.json'
ANCHOR = datetime.fromisoformat('2026-10-07T04:28:33+00:00')


def main():
    goal = read(GOAL_EVIDENCE)
    assert goal['goal']['status'] == 'active'
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    deadline = (ANCHOR + timedelta(hours=24)).astimezone(ZoneInfo('Asia/Taipei'))
    before = {name: (ROOT/name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    assert state == public['deep_research']
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    svc = service()
    served, _ = http(web['url'])
    assert served == before[FILES[3]]
    nav = state['navigation_repair']
    assert nav['latest_country_v2_comparison_checkpoint']['limited_Minquan_primary_search_destination_routes_verified']
    app = copy.deepcopy(state['native_app_music'])
    plan = dict(requested_utc=ANCHOR.isoformat(), target_deadline=deadline.isoformat(),
        deadline_is_requested_research_target_not_verified_completion=True,
        user_away=True, user_will_notify_return=True, unsolicited_presence_questions=False,
        physical_USB_or_Bluetooth_not_required_for_current_work=True,
        native_device_audio_tests_allowed=False, current_device_address_candidate='country_AP_v2_original_4K',
        current_daily_layers=['Address Point v2','Search v2'],
        limited_device_controls='Road display and Minquan 6/150/184 search/destination/route user confirmed.',
        priorities=['Identify v3 AP road-display regression with exact original code and bounded offline controls.',
                    'Complete original JAI prefix/segment and safely scoped new-street index preparation.',
                    'Connect original OS20 resident music worker to typed FIFO/source/mixer offline.'],
        parallel_tasks=['native_address_candidate_check','taiwan_address_ingestion_plan','continuous_music_binding'],
        later_work=['Direct phone A2DP and native menu/App integration','Android Auto','Native offline Google Maps'],
        full_Taiwan_map_update_complete=False, native_App_direct_phone_music_complete=False,
        whole_goal_complete=False, actual_goal_status_read='active', actual_goal_evidence=GOAL_EVIDENCE)
    state.update(updated_utc=now.isoformat(), goal_status='active', research_goal_status='active_offline',
        native_app_research_status='active_offline_parallel_after_primary_navigation_controls',
        latest_user_instruction='使用者外出暫無車機，回來會通知；不要詢問人在不在。繼續離線研究與本機驗證，希望一天內有研究結果。',
        offline_24h_work_order=plan, user_resting=False, goal_complete=False, required_work_remaining=True)
    state['attended_testing'].update(user_present=False, waiting_for_user_return=True, recorded_utc=now.isoformat(),
        user_instruction=state['latest_user_instruction'], no_pending_question=True,
        physical_test_availability_question_pending=False, user_available_for_future_physical_tests=False,
        current_attended_test=None, next_attended_test_not_requested_yet=True,
        automatic_calls_or_sound_allowed_while_away=False, USB_or_Bluetooth_required_for_current_offline_work=False,
        current_real_USB_volume_observed=False)
    state['audio']['audible_tests_allowed'] = False
    nav.update(goal_status='active', research_goal_status='active_offline',
        native_app_research_status=state['native_app_research_status'], remaining_physical_checks=[],
        offline_24h_work_order=copy.deepcopy(plan))
    for key in ['updated_utc','goal_status','research_goal_status','native_app_research_status','latest_user_instruction',
                'offline_24h_work_order','attended_testing','navigation_repair','user_resting','goal_complete','required_work_remaining']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav),
        offline_24h_work_order=copy.deepcopy(plan))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert state['native_app_music'] == app
    report = before[FILES[3]].decode()
    card = ('<section class="card" id="offline-research-24h"><h2>外出期間：離線研究與本機驗證</h2>'
            '<p>研究目標時限：'+deadline.strftime('%Y/%m/%d %H:%M')+'（台灣時間）。使用者回來時會主動通知；目前不要求接車機或配對。</p>'
            '<ol><li>優先定位v3新版門牌图的道路顯示回歸，使用精確原指令與有限離線對照。</li>'
            '<li>補齊新街道JAI前綴／片段查詢路徑，以及保留其他索引的局部更新。</li>'
            '<li>平行連接原生音樂工作程序與音訊FIFO／來源／混音器；App及手機直接藍牙仍待完整整合。</li></ol>'
            '<p>車機先保留已實測道路正常、民權路6／150／184號搜尋／位置／路線通過的門牌v2＋Search v2。'
            '全台完整更新、v3修復與原生App尚未完成；24小時是工作目標，離線通過不代替實機喇叭、畫面及手机連線。</p></section>')
    if 'id="offline-research-24h"' in report:
        report, count = re.subn(r'<section class="card" id="offline-research-24h">.*?</section>', card, report, count=1, flags=re.S)
        assert count == 1
    else:
        marker = '<section class="card" id="navigation-repair-checkpoint-v2">'
        assert report.count(marker) == 1
        report = report.replace(marker,card+marker,1)
    for identifier in ['navigation-address-updated-time','report-updated-time','research-updated-time']:
        report, count = re.subn(r'<time id="'+identifier+r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{identifier}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        assert count == 1
    out = ROOT/'staging'/('offline-24h-work-order-publication-'+now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir()
    for name,raw in before.items():
        with (out/(name.replace('/','__')+'.gz')).open('xb') as f:
            f.write(gzip.compress(raw,mtime=0)); f.flush(); os.fsync(f.fileno())
    for name,value in zip(FILES[:4],[state,task,public,report]):
        replace(name,value)
    served,response = http(web['url'])
    assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'],local_report_sha256=sha(served),
        served_report_sha256=sha(served),report_bytes=len(served),service_not_restarted=True,
        offline_24h_work_order=copy.deepcopy(plan),actual_goal_status_read='active')
    replace(FILES[4],web)
    assert read(FILES[0]) == read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    create(out/'fresh-readback.json',dict(all_passed=True,service=svc,report_sha256=sha(served),
        deadline=deadline.isoformat(),actual_goal_status_read='active',native_country_engineering_estimate_percent=75,
        device_IO=False,full_goal_complete=False,waiting_for_unsolicited_user_return=True))
    print(json.dumps(dict(all_passed=True,checkpoint=str(out.relative_to(ROOT)),deadline=deadline.isoformat(),report_url=web['url'])))


if __name__ == '__main__':
    main()
