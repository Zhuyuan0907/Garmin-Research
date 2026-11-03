#!/usr/bin/env python3
"""Publish accepted single-street cases and the separate rendering investigation."""
import copy
import gzip
import html
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

OUT = ROOT / 'staging/navigation-physical-followup-publication-v1'
EV = 'evidence/navigation-supplement-position-route-rendering-20261007-v1.json'
FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json',
         'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
REVIEW = 'staging/navigation-rendering-review-v1/review.json'


def main():
    assert not OUT.exists() and not (ROOT / EV).exists()
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    latest = json.loads(before[FILES[-1]])
    assert public['deep_research'] == state
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    old_app = copy.deepcopy(state['native_app_music'])
    old_progress = copy.deepcopy(public['research_progress'])
    served, _ = http(latest['url']); assert served == before[FILES[3]]
    svc = service()
    now = datetime.now(timezone.utc); local = now.astimezone(ZoneInfo('Asia/Taipei'))
    ev = dict(recorded_utc=now.isoformat(), evidence_kind='physical user observation',
        previous_search_evidence='evidence/address-supplement-search-20261007-v1.json',
        configuration_as_prompted=['candidate Address Point', 'Search v2'],
        original_CN_road_unchecked_as_prompted=True, configuration_independently_read_back=False,
        observations=[
            dict(test='民權路6號及150號目的地位置', user_quote='合理'),
            dict(test='民權路6號及150號路線計算', user_quote='兩個都算出路線'),
            dict(test='地圖刷新問題與原廠比較', user_quote='實際移動時；原廠圖也會'),
            dict(test='固定圖層／視角、地圖詳細度改簡略', user_quote='稍微改善')],
        new_destination_positions_reasonable_user_confirmed=True,
        new_destination_routes_calculated_user_confirmed=True, tested_new_house_numbers=[6, 150],
        previous_search_numbers=[6, 150, 184], all_nine_addresses_device_tested=False,
        route_data_source_instrumented=False, turn_by_turn_driving_verified=False,
        rendering_issue_also_on_stock_user_confirmed=True, less_detail_improvement='slight',
        exact_frame_rate_or_latency_measured=False, CPU_bottleneck_confirmed=False,
        north_up_comparison_pending=True, rendering_fixed=False,
        whole_Taiwan_native_update_complete=False, full_goal_complete=False)
    create(ROOT / EV, ev)
    nav = state['navigation_repair']; supp = nav['address_supplement']
    actions = ['保持簡略，將地圖畫面改北方向上，固定圖層以相同方式比較刷新；等待使用者回覆。',
        '完成全台地址來源與原生街道對照，擴大地址更新writer；新增街道／行政區索引仍需處理。',
        '準備保留道路與地址處理的建物顯示減量候選，先驗證再安排實機比較。',
        '整體導航搜尋、地址更新及刷新需求驗證完成後，再恢復手機音樂／App研究。']
    supp.update(updated_utc=now.isoformat(), estimate_percent=100,
        estimate_scope='本次民權路補充試驗：封裝80、安裝10、6/150/184搜尋5、6/150位置與路線5。全台更新另行進行。',
        device_new_address_search_verified=True, device_new_address_positions_reasonable=True,
        device_new_address_route_verified=True, device_position_route_tested_numbers=[6, 150],
        controlled_trial_accepted=True, latest_position_route_evidence=EV,
        all_nine_device_tested=False, pending_user_question=None)
    supp['details'] += ['使用者確認6號、150號位置合理，兩個目的地都成功計算路線；本輪抽測通過。']
    nav.update(updated_utc=now.isoformat(),
        navigation_repair_status='single_street_trial_accepted_full_update_and_rendering_in_progress',
        latest_physical_test=EV, latest_physical_test_result='6/150位置合理且路線計算成功；原廠也會刷新慢，簡略稍微改善。',
        execution_status='expanding_native_addresses_and_investigating_rendering',
        next=actions[0], remaining_next_actions=actions,
        remaining_physical_checks=['簡略＋北方向上的刷新比較', '後續較大範圍地址候選實機驗證'],
        current_verification_details=supp['details'])
    nav['original_format_research'].update(stage='single_street_native_address_trial_accepted_full_update_in_progress',
        latest_candidate_position_route_evidence=EV, updated_utc=now.isoformat())
    nav['rendering_issue'].update(latest_physical_evidence=EV,
        also_on_original_CN_AP_user_confirmed=True, actual_movement_user_confirmed=True,
        stock_map_comparison_pending=False, movement_or_simulator_comparison_pending=False,
        less_detail_improvement='slight', north_up_comparison_pending=True,
        latest_readonly_analysis=REVIEW, corrected=False)
    nav['known_limits'] = ['本次新增6號、150號的位置與路線已確認，尚未測全部9筆或所有道路。',
        '原廠大部分地址仍是舊資料，完整全台原生地址更新尚未完成。',
        '刷新慢與短暫破圖在原廠圖也會，簡略只稍微改善；根因與修復尚未完成。',
        '未量測刷新率、精確搜尋秒數或查詢／路由來源，也未驗證實際轉彎導引。']
    state.update(updated_utc=now.isoformat(), current_priority=actions[0], next_actions=actions)
    state['last_goal_turn'] = dict(classification='progress', validated_utc=now.isoformat(),
        goal_status=state['goal_status'], device_IO=False, user_physical_evidence=EV,
        full_goal_complete=False, required_work_remaining=True)
    for key in ['navigation_repair','updated_utc','current_priority','next_actions','last_goal_turn']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(),deep_research=copy.deepcopy(state),navigation_repair=copy.deepcopy(nav))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert state['native_app_music'] == old_app
    for key in ['estimate_percent','weighted_estimate_percent','phases','completed']:
        assert public['research_progress'][key] == old_progress[key]
    stamp = local.isoformat(timespec='seconds')
    clock = f'<time datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）'
    items = lambda values: ''.join('<li>'+html.escape(v)+'</li>' for v in values)
    card = '<section class="card" id="navigation-repair-checkpoint-v2"><h2>民權路補充抽測已驗收；全台更新與刷新改善繼續</h2>'
    card += '<p>6號、150號、184號皆找到且無逾時；6號、150號位置合理，路線都計算成功。</p>'
    card += f'<p><a href="{html.escape(supp["package"]["download_url"])}" download>下載完整測試包（約143 MB）</a>，含AP補充、Search v2道路與精確還原工具。</p>'
    card += '<p>本次民權路補充試驗里程碑 <strong>100%</strong>，範圍為封裝、安裝及上述抽測。全台原生地址更新仍在進行。</p>'
    card += '<progress id="navigation-repair-progress" max="100" value="100" style="width:100%;height:18px">100%</progress><p>更新：'+clock+'</p>'
    card += '<h3>圖面刷新排查</h3><p>使用者確認原廠圖也會在移動時刷新慢、短暫破圖；改簡略稍微改善。CPU原因尚未確認，正在比較北方向上與圖資顯示量。</p>'
    card += '<p>唯讀統計：民權路所在分區最細層有16,638個多邊形，其中11,851為建物。這是整個分區數量，未量測同畫面或實機負荷。</p>'
    card += '<h3>已完成</h3><ul>'+items(supp['details'])+'</ul><h3>接著處理</h3><ol>'+items(actions)+'</ol>'
    card += '<h3>仍待完成</h3><ul>'+items(nav['known_limits'])+'</ul></section>'
    aside = '<aside class="card" id="navigation-native-format-progress-v1"><h2>原廠格式地址補充已有實機搜尋及路線證據</h2>'
    aside += '<p>原84筆保留並補入9筆民權路門牌。本輪測6號、150號及184號搜尋，並驗證兩個新增門牌的位置與路線。完整全台MDR／JAI產生與新街道處理繼續研究。</p><p>研究更新：'+clock+'</p></aside>'
    report = before[FILES[3]].decode()
    for pattern,value in [(r'<section class="card" id="navigation-repair-checkpoint-v2">.*?</section>',card),
                          (r'<aside class="card" id="navigation-native-format-progress-v1">.*?</aside>',aside)]:
        report,count = re.subn(pattern,lambda _:value,report,count=1,flags=re.S); assert count == 1
    for identifier in ['report-updated-time','research-updated-time']:
        report,count = re.subn(r'<time id="'+identifier+r'" datetime="[^"]+">[^<]+</time>',
            lambda _:f'<time id="{identifier}" datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',report,count=1)
        assert count == 1
    OUT.mkdir()
    for name,raw in before.items():
        with (OUT/(name.replace('/','__')+'.gz')).open('xb') as f:
            f.write(gzip.compress(raw,mtime=0)); f.flush(); os.fsync(f.fileno())
    create(OUT/'proof-bindings.json',dict(evidence=[dict(path=n,sha256=sha((ROOT/n).read_bytes())) for n in [EV,REVIEW]],full_goal_complete=False))
    for name,value in zip(FILES[:4],[state,task,public,report]): replace(name,value)
    served,response = http(latest['url']); assert served == report.encode() and service() == svc
    latest.update(updated_utc=now.isoformat(),HTTP_status=response['status'],local_report_sha256=sha(served),
        served_report_sha256=sha(served),report_bytes=len(served),served_latest_report=True,service_not_restarted=True,
        native_address_supplement_position_route_verified=True,latest_native_address_position_route_evidence=EV)
    replace(FILES[-1],latest)
    assert read(FILES[2])['deep_research'] == read(FILES[0])
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    create(OUT/'fresh-readback.json',dict(all_passed=True,HTTP=response,report_sha256=sha(served),service=svc,
        route_scope=[6,150],rendering_fixed=False,full_goal_complete=False))
    print(json.dumps(dict(all_passed=True,report_url=latest['url'],route_scope=[6,150],rendering_fixed=False),ensure_ascii=False))


if __name__ == '__main__': main()
