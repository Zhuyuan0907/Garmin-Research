#!/usr/bin/env python3
"""Record the user's scoped address search result and new rendering issue."""
import copy
import gzip
import html
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

OUT = ROOT / 'staging/navigation-address-supplement-search-publication-v1'
EVIDENCE = 'evidence/address-supplement-search-20261007-v1.json'
FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json',
         'reports/findings.json', 'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
QUOTE = '都找到，無逾時，不過可能是這台CPU本來就緩慢的原因，在導航的時候地圖跑得比較久 然後如果有車子往前開時 有新的地圖產生 那麼圖就會稍微破圖再回來這樣 然後圖都很緩慢'


def main():
    assert not OUT.exists() and not (ROOT / EVIDENCE).exists()
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    latest = json.loads(before[FILES[-1]])
    assert public['deep_research'] == state
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    nav = state['navigation_repair']
    assert nav['address_supplement']['installed_readback_verified']
    served, _ = http(latest['url'])
    assert served == before[FILES[3]]
    svc = service()
    app = copy.deepcopy(state['native_app_music'])
    progress = copy.deepcopy(public['research_progress'])
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    ev = dict(recorded_utc=now.isoformat(), evidence_kind='physical user observation',
              user_quote=QUOTE, configuration_as_prompted=['candidate Address Point', 'Search v2'],
              original_CN_road_unchecked_as_prompted=True, complete_reboot_requested=True,
              tested_house_numbers=[6, 150, 184], all_three_found_user_confirmed=True,
              timed_out_user_confirmed=False, exact_search_seconds=None,
              checkbox_selection_independently_read_back=False,
              actual_query_source_instrumented=False,
              candidate_installation='evidence/address-supplement-install-20261007-v1.json',
              new_destination_positions_confirmed=False, new_routes_confirmed=False,
              rendering_issue_user_reported=True, rendering_root_cause_confirmed=False,
              all_nine_supplement_addresses_tested=False,
              whole_Taiwan_native_update_complete=False, full_goal_complete=False)
    create(ROOT / EVIDENCE, ev)
    actions = [
        '保持候選Address Point＋Search v2，確認民權路6號、150號目的地位置與路線計算；不必開車。',
        '確認刷新慢／短暫破圖發生於實際行車還是模擬導航，再與原廠CN＋AP及較低地圖細節比較。',
        '繼續全台地址來源與原生縣市／區／街道對照，完成較大範圍地址補充及新街道索引規則。',
        '完整導航搜尋與地址更新驗證完成後，再恢復手機音樂／App研究。',
    ]
    supp = nav['address_supplement']
    supp.update(updated_utc=now.isoformat(), estimate_percent=95,
                estimate_scope='本次9筆補充候選：封裝80、安裝10、6/150/184搜尋5已完成；位置與路線5待驗。非全台更新進度。',
                device_new_address_search_verified=True, tested_house_numbers=[6, 150, 184],
                latest_search_evidence=EVIDENCE, all_nine_device_tested=False,
                device_new_address_route_verified=False,
                pending_user_question='Confirm destination positions and routes for 6/150; clarify rendering conditions.')
    supp['details'] = supp['details'][:5] + [
        '候選AP已原子安裝、完整讀回校驗，其他保護檔不變並安全卸載。',
        '使用者實機確認民權路6號、150號、184號皆找到，沒有逾時；尚未確認新增目的地位置與路線。',
    ]
    nav.update(updated_utc=now.isoformat(),
               navigation_repair_status='supplement_search_passed_destination_route_and_rendering_pending',
               execution_status='investigating_rendering_and_expanding_addresses',
               latest_physical_test=EVIDENCE, latest_physical_test_result='6/150/184 found without timeout',
               next=actions[0], remaining_next_actions=actions,
               remaining_physical_checks=['民權路6號、150號目的地位置與路線', '地圖重繪問題的原廠／新版比較'],
               current_verification_details=supp['details'])
    nav['original_format_research'].update(stage='single_street_AP_candidate_device_search_passed_route_pending',
        updated_utc=now.isoformat(), latest_candidate_UI_evidence=EVIDENCE)
    nav['rendering_issue'] = dict(user_reported=True, evidence=EVIDENCE,
        description='導航地圖更新慢，移動至新區域時短暫破圖後恢復。',
        root_cause_confirmed=False, CPU_cause_confirmed=False,
        movement_or_simulator_comparison_pending=True, stock_map_comparison_pending=True,
        corrected=False)
    nav['known_limits'] = [
        '本次只補民權路9筆；全台原廠地址仍未完整更新。',
        '實機測了6號、150號、184號搜尋，沒有測全部9筆或所有街道。',
        '新增門牌的目的地位置、路線仍待確認；行車圖面刷新問題尚未定位及修復。',
        '搜尋無逾時由使用者確認，未量測精確秒數或查詢與路由資料來源。',
        '原廠備份、其他IMG、資料庫、韌體及授權檔保持。',
    ]
    state.update(updated_utc=now.isoformat(), current_priority=actions[0], next_actions=actions)
    state['last_goal_turn'] = dict(classification='progress', validated_utc=now.isoformat(),
        goal_status=state['goal_status'], device_IO=False, user_physical_search_evidence=EVIDENCE,
        full_goal_complete=False, required_work_remaining=True)
    for key in ['navigation_repair', 'updated_utc', 'current_priority', 'next_actions', 'last_goal_turn']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert app == state['native_app_music']
    for key in ['estimate_percent', 'weighted_estimate_percent', 'phases', 'completed']:
        assert progress[key] == public['research_progress'][key]
    timestamp = local.isoformat(timespec='seconds')
    clock = f'<time datetime="{timestamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）'
    items = lambda vals: ''.join('<li>' + html.escape(v) + '</li>' for v in vals)
    card = '<section class="card" id="navigation-repair-checkpoint-v2"><h2>門牌補充：6號、150號、184號實機搜尋通過</h2>'
    card += '<p>三個測試門牌皆找到、沒有逾時。新增門牌的位置與路線待確認；使用者另回報地圖刷新慢、短暫破圖，原因仍在排查。</p>'
    card += f'<p><a href="{html.escape(supp["package"]["download_url"])}" download>下載完整測試包（約143 MB）</a>：候選AP、Search v2道路圖、校驗與精確還原工具。</p>'
    card += '<p>本次9筆補充候選估計 <strong>95%</strong>；封裝80%、安裝10%、限定搜尋5%完成，位置與路線5%待驗。全台原生地址更新仍未完成；刷新問題另行排查。</p>'
    card += '<progress id="navigation-repair-progress" max="100" value="95" style="width:100%;height:18px">95%</progress><p>更新：' + clock + '</p>'
    card += '<h3>已完成</h3><ul>' + items(supp['details']) + '</ul><h3>接著處理</h3><ol>' + items(actions) + '</ol>'
    card += '<h3>尚未完成</h3><ul>' + items(nav['known_limits']) + '</ul></section>'
    aside = '<aside class="card" id="navigation-native-format-progress-v1"><h2>原廠格式地址補充已通過限定實機搜尋</h2>'
    aside += '<p>已在原AP地址架構補入9筆民權路來源門牌，原84筆保留。6號、150號及184號搜尋皆通過；新門牌位置與路線待驗，尚非全台更新。</p><p>研究更新：' + clock + '</p></aside>'
    report = before[FILES[3]].decode()
    for pattern, value in [(r'<section class="card" id="navigation-repair-checkpoint-v2">.*?</section>', card),
                           (r'<aside class="card" id="navigation-native-format-progress-v1">.*?</aside>', aside)]:
        report, count = re.subn(pattern, lambda _: value, report, count=1, flags=re.S)
        assert count == 1
    for identifier in ['report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + identifier + r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{identifier}" datetime="{timestamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        assert count == 1
    OUT.mkdir()
    for name, raw in before.items():
        with (OUT / (name.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0))
            stream.flush()
            os.fsync(stream.fileno())
    create(OUT / 'proof-bindings.json', dict(evidence=EVIDENCE, sha256=sha((ROOT / EVIDENCE).read_bytes()),
        scope='three physical address searches only', goal_complete=False))
    for name, value in zip(FILES[:4], [state, task, public, report]):
        replace(name, value)
    served, response = http(latest['url'])
    assert served == report.encode() and service() == svc
    latest.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
        served_report_sha256=sha(served), report_bytes=len(served), served_latest_report=True,
        service_not_restarted=True, native_address_supplement_UI_verified=True,
        native_address_supplement_UI_scope='6/150/184 searches only',
        latest_native_address_search_evidence=EVIDENCE)
    replace(FILES[-1], latest)
    assert read(FILES[2])['deep_research'] == read(FILES[0])
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    create(OUT / 'fresh-readback.json', dict(all_passed=True, HTTP=response, report_sha256=sha(served),
        service=svc, search_scope=[6, 150, 184], route_verified=False, full_goal_complete=False))
    print(json.dumps(dict(all_passed=True, search_scope=[6, 150, 184], report_url=latest['url'], service_PID=svc['MainPID']), ensure_ascii=False))


if __name__ == '__main__':
    main()
