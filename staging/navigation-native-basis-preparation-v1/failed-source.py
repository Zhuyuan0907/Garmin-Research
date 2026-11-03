#!/usr/bin/env python3
"""Record the scoped physical acceptance and the original-format update work."""
import copy
import gzip
import hashlib
import html
import json
import os
import re
import subprocess
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'staging/navigation-native-basis-checkpoint-v1'
EVIDENCE = 'evidence/navigation-combined-layer-destination-route-20261006-v1.json'
CANONICALS = [
    'evidence/deep-research-state.json', 'evidence/task-state.json',
    'reports/findings.json', 'reports/nuvi2565RT.html',
    'evidence/report-web-latest.json',
]


def read(name):
    return json.loads((ROOT / name).read_text())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    if isinstance(value, str):
        return value.encode()
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def create(path, value):
    with path.open('xb') as stream:
        stream.write(encoded(value))
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o444)


def replace(name, value):
    path = ROOT / name
    temporary = path.with_name('.native-basis-v1-' + path.name)
    with temporary.open('xb') as stream:
        stream.write(encoded(value))
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o644)
    os.replace(temporary, path)


def service():
    process = subprocess.run(
        ['systemctl', 'show', 'garmin-report-web.service',
         '--property=MainPID,ActiveState,SubState'],
        text=True, capture_output=True, check=True,
    )
    result = dict(line.split('=', 1) for line in process.stdout.splitlines())
    assert result['ActiveState'] == 'active' and result['SubState'] == 'running'
    os.kill(int(result['MainPID']), 0)
    return result


def http(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={'Cache-Control': 'no-cache'})
    with opener.open(request, timeout=15) as response:
        assert response.status == 200
        return response.read(), dict(status=response.status,
                                     cache_control=response.headers.get('Cache-Control'))


def main():
    assert not OUT.exists()
    before = {name: (ROOT / name).read_bytes() for name in CANONICALS}
    state, task, public = [json.loads(before[name]) for name in CANONICALS[:3]]
    latest = json.loads(before[CANONICALS[4]])
    assert public['deep_research'] == state
    assert public['navigation_repair'] == task['navigation_repair'] == state['navigation_repair']
    app_before = copy.deepcopy(state['native_app_music'])
    app_progress = copy.deepcopy(public['research_progress'])
    served_before, _ = http(latest['url'])
    assert served_before == before[CANONICALS[3]]
    service_before = service()
    physical = read(EVIDENCE)
    assert physical['combined_primary_destination_correct_user_confirmed']
    assert physical['combined_primary_route_calculation_user_confirmed']
    assert not physical['original_native_address_data_updated_to_2026']

    bindings = read('staging/navigation-original-layer-baseline-v1/root-reviewed-proof-bindings.json')
    sources = [item['path'] for item in bindings['proofs']]
    parser_manifest = read('staging/navigation-native-MDR-provider-fields-v1/sealed-parser-manifest-v1.json')
    assert parser_manifest['actual_v1_exit_code'] == parser_manifest['actual_v2_exit_code'] == 0
    for item in parser_manifest['files']:
        data = (ROOT / item['path']).read_bytes()
        assert len(data) == item['bytes'] and sha(data) == item['sha256']
    for item in bindings['proofs']:
        data = (ROOT / item['path']).read_bytes()
        assert len(data) == item['bytes'] and sha(data) == item['sha256']
    parser = read('staging/navigation-native-MDR-provider-fields-v1/native-MDR-header-fields-proof-v1.json')
    controls = read('staging/navigation-native-MDR-provider-fields-v1/native-MDR-header-negative-controls-proof-v2.json')
    assert parser['all_cases_reached_stop'] and controls['all_negative_controls_passed']
    sources.extend([
        EVIDENCE,
        'staging/navigation-native-MDR-provider-fields-v1/sealed-parser-manifest-v1.json',
        'staging/navigation-native-MDR-provider-fields-v1/native-MDR-header-fields-proof-v1.json',
        'staging/navigation-native-MDR-provider-fields-v1/native-MDR-header-negative-controls-proof-v2.json',
    ])
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    timestamp = local.isoformat(timespec='seconds')
    next_actions = [
        '日常保留原廠CN道路圖、Address Point、Search v2三項勾選；民權路184號位置與路線計算已由使用者確認。',
        '解析原廠TWNJAI搜尋詞、地址層級及AP載體位置的連結，先建立唯讀解析與可逆的離線重建規則。',
        '以新版OSM補充新道路／地址時，保留縣市與門牌搜尋；尚未完成原廠格式更新，不把2016原廠索引算作2026資料。',
        '新資料包完成後，再驗證新增地址搜尋及路線來源；目前沒有額外USB操作需求。',
        '導航搜尋與更新需求驗證完成後，依原先指示恢復手機音樂／App研究。',
    ]
    details = [
        '實機三層對照完成：新版单獨找不到街道，原廠CN＋Address Point可正確查找；三層一起啟用後搜尋非常快速，縣市與門牌選單保留。',
        '使用者確認三層啟用時「民權路184號」位置正確，並已算出路線；未測行車導引，亦未量測確切搜尋秒數。',
        '原廠地址搜尋的台灣分流讀取實際MDR碼頁，並檢查額外資料欄位；原廠Address Point有該描述與六筆載體記錄，新版OSM沒有。單改碼頁不能補齊它。',
        '原廠TWNJAI包含22個縣市搜尋分區與地址階層；HWM資料庫主要為交流道／道路標誌連結，不能直接當成門牌庫。',
        '新版實際NET數字串可解析到民權路偶數184至178的範圍，LBL指標連到臺中市；有資料不等同原生地址介面已能搜尋。',
    ]
    nav = state['navigation_repair']
    nav.update(
        updated_utc=now.isoformat(),
        navigation_repair_status='combined_primary_address_and_route_accepted_native_update_in_progress',
        execution_status='investigating_original_layer_based_update',
        latest_combined_destination_route_test=EVIDENCE,
        combined_primary_destination_correct_user_confirmed=True,
        combined_primary_route_calculation_user_confirmed=True,
        physical_AB_comparison_completed=True,
        actual_road_guidance_tested=False,
        full_updated_address_search_verified=False,
        original_address_data_updated_to_2026=False,
        device_search_verified=False,
        device_routing_verified=False,
        broad_device_verification_flags_scope='Acceptance of updated-map native search/routing; the scoped three-layer primary case passed separately.',
        candidate_accepted=False,
        candidate_recommendation_held=True,
        required_work_remaining=True,
        goal_complete=False,
        remaining_physical_checks=['新原廠格式更新候選完成後，驗證新增地址與路線來源；目前無待操作項目。'],
        remaining_next_actions=next_actions,
        next=next_actions[1],
        current_verification_details=details,
    )
    nav['combined_test_result'].update(
        route_calculation_user_acceptance='passed',
        destination_user_acceptance='correct_position',
        destination_route_evidence=EVIDENCE,
    )
    nav['known_limits'] = [
        '三層組合的民權路184號搜尋、位置及路線計算已由使用者確認；原廠地址索引仍為舊版，新版資料是否參與查詢或路由尚未觀察。',
        '新版OSM單獨的原生街道搜尋未通過；保留原廠縣市／門牌架構後再更新，不推薦單獨取代。',
        '原指令探針使用明示的合成記憶體與有限函式；主機解析不等同完整GarminOS或實機UI。',
        '確切搜尋耗時、其他道路及實際行車導引尚未量測；沒有宣稱全部台灣地址已驗證。',
        '原廠NT/AP载體與TWNJAI引用尚未完整解析，未修改原廠地圖、授權檔、資料庫或韌體。',
    ]
    nav['sources'].update(
        combined_destination_route=EVIDENCE,
        native_provider_fields='staging/navigation-native-MDR-provider-fields-v1/native-MDR-header-fields-proof-v1.json',
        native_provider_negative_controls='staging/navigation-native-MDR-provider-fields-v1/native-MDR-header-negative-controls-proof-v2.json',
        original_schema='staging/navigation-stock-address-schema-v1/stock-address-schema-evidence.json',
        compiled_house184='staging/navigation-house184-query-v1/house184-compiled-NET-inspection-v1.json',
    )
    state.update(updated_utc=now.isoformat(), current_priority=next_actions[1], next_actions=next_actions,
                 required_work_remaining=True, goal_complete=False)
    state['last_goal_turn'] = dict(
        classification='progress', validated_utc=now.isoformat(), goal_status=state['goal_status'],
        required_work_remaining=True, full_goal_complete=False,
        physical_primary_case_acceptance=EVIDENCE,
        reason='User confirmed the three-layer primary destination and route; original-format address update research continues.',
        device_IO=False, previous_blocking_condition_resolved=True,
    )
    for key in ['updated_utc', 'navigation_repair', 'current_priority', 'next_actions',
                'last_goal_turn', 'required_work_remaining', 'goal_complete']:
        task[key] = copy.deepcopy(state[key])
    task['pending'] = []
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav),
                  required_work_remaining=True, goal_complete=False)
    public['research_progress'].update(research_updated_utc=now.isoformat(), next=next_actions[1])
    public['navigation_repair_progress'].update(
        estimate_percent=75, goal_complete=False,
        scope='Existing OSM candidate preparation/install milestones; native original-format update is an additional incomplete workstream.',
        combined_primary_case_passed=True,
    )
    assert state['native_app_music'] == app_before
    for key in ['estimate_percent', 'weighted_estimate_percent', 'phases', 'completed']:
        assert public['research_progress'][key] == app_progress[key]
    e = html.escape
    card = '<section class="card" id="navigation-repair-checkpoint-v2"><h2>導航搜尋：民權路184號與路線已實測通過</h2>'
    card += '<p id="navigation-combined-route-acceptance-v1"><strong>日常請勾選：原廠CN道路圖＋Address Point＋Search v2。</strong>使用者確認搜尋非常快速，民權路184號的位置正確，路線已算出。新版單獨搜尋街道仍失敗；原廠地址索引尚未更新到2026年，這次查詢及路線使用哪張地圖尚未確認。</p>'
    card += '<p>既有候選準備與安裝里程碑估計 <strong>75%</strong>；原廠格式圖資更新仍在研究，百分比不代表完整修復成功率。</p><progress id="navigation-repair-progress" max="100" value="75" style="width:100%;height:18px">75%</progress>'
    card += f'<p>更新：<time datetime="{timestamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
    card += '<h3>最新完成的確認</h3><ul>' + ''.join('<li>' + e(item) + '</li>' for item in details) + '</ul>'
    card += '<h3>後續處理順序</h3><ol>' + ''.join('<li>' + e(item) + '</li>' for item in next_actions) + '</ol>'
    card += '<details><summary>既有候選編圖及安裝紀錄</summary><ul>' + ''.join('<li>' + e(item) + '</li>' for item in nav['completed_physical_details'] + nav['completed_offline_details']) + '</ul>'
    card += f'<p><a href="{e(nav["download_url"])}" download>第二版研究候選包</a>：新版單獨街道查詢未通過，保留作研究紀錄。</p></details>'
    card += '<h3>尚未完成</h3><ul>' + ''.join('<li>' + e(item) + '</li>' for item in nav['known_limits']) + '</ul></section>'
    report, count = re.subn(r'<section class="card" id="navigation-repair-checkpoint-v2">.*?</section>', lambda _: card,
                            before[CANONICALS[3]].decode(), count=1, flags=re.S)
    assert count == 1
    for identifier in ['report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + identifier + r'" datetime="[^"]+">[^<]+</time>',
                                lambda _: f'<time id="{identifier}" datetime="{timestamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',
                                report, count=1)
        assert count == 1
    report, count = re.subn(r'<p><strong>下一步：</strong>.*?</p>', lambda _: '<p><strong>下一步：</strong>' + e(next_actions[1]) + '</p>',
                            report, count=1, flags=re.S)
    assert count == 1
    OUT.mkdir()
    for name, data in before.items():
        path = OUT / (name.replace('/', '__') + '.gz')
        with path.open('xb') as stream:
            stream.write(gzip.compress(data, mtime=0))
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o444)
    create(OUT / 'reviewed-proof-bindings.json', dict(
        created_utc=now.isoformat(), device_IO=False, stock_originals_unmodified=True,
        original_format_update_implemented=False, full_goal_complete=False,
        files=[dict(path=name, bytes=(ROOT / name).stat().st_size,
                    sha256=sha((ROOT / name).read_bytes())) for name in sources],
    ))
    for name, value in zip(CANONICALS[:4], [state, task, public, report]):
        replace(name, value)
    served_after, response = http(latest['url'])
    assert served_after == report.encode()
    service_after = service()
    assert service_after == service_before
    latest.update(updated_utc=now.isoformat(), HTTP_status=response['status'], report_bytes=len(served_after),
                  cache_control=response['cache_control'], local_report_sha256=sha(served_after),
                  served_report_sha256=sha(served_after), served_latest_report=True,
                  service=service_after, service_not_restarted=True,
                  latest_navigation_combined_destination_route_test=EVIDENCE,
                  combined_primary_destination_and_route_user_confirmed=True,
                  navigation_execution_status=nav['execution_status'], required_work_remaining=True,
                  full_goal_complete=False)
    replace(CANONICALS[4], latest)
    assert read(CANONICALS[2])['deep_research'] == read(CANONICALS[0])
    create(OUT / 'fresh-readback.json', dict(
        checked_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
        HTTP=response, service=service_after, service_not_restarted=True,
        report_sha256=sha(served_after), report_bytes=len(served_after),
        physical_acceptance_scope='Three-layer Taichung Minquan184 destination and route calculation',
        original_native_address_update_complete=False, goal_complete=False,
        canonical_files=[dict(path=name, bytes=(ROOT / name).stat().st_size,
                              mode=oct((ROOT / name).stat().st_mode & 0o777),
                              sha256=sha((ROOT / name).read_bytes())) for name in CANONICALS],
    ))
    print(json.dumps({'all_passed': True, 'report_url': latest['url'],
                      'combined_primary_case_passed': True, 'original_format_update_complete': False,
                      'report_service_PID': service_after['MainPID']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
