#!/usr/bin/env python3
"""Publish closed, scoped native-format proofs without accepting a new map."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
from publish_navigation_native_basis_checkpoint_v1 import ROOT, read, sha, create, replace, service, http

OUT = ROOT / 'staging/navigation-native-format-progress-v1'
CANONICALS = ['evidence/deep-research-state.json', 'evidence/task-state.json',
              'reports/findings.json', 'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']


def verify_file(path, expected_sha, expected_bytes=None):
    raw = (ROOT / path).read_bytes()
    assert sha(raw) == expected_sha, path
    if expected_bytes is not None:
        assert len(raw) == expected_bytes, path


def main():
    assert not OUT.exists()
    sources = [
        'staging/navigation-native-update-contract-v1/root-reviewed-proof-bindings-v1.json',
        'staging/navigation-native-update-contract-v1/native-address-update-contract-v1.json',
    ]
    native_base = 'staging/navigation-stock-fts-native-codec-v1/'
    native_seal = read(native_base + 'native-fts-codec-file-seal-v1.json')
    assert native_seal['all_selected_file_checks_passed']
    ledger_path = native_seal['ledger']
    verify_file(ledger_path, native_seal['ledger_sha256'])
    ledger = read(ledger_path)
    for field in ['source_sha256', 'output_sha256']:
        for path, expected in ledger[field].items():
            verify_file(path, expected)
    post_path = native_base + 'native-fts-codec-sealer-terminal-tool-receipt-v1.json'
    post = read(post_path)
    assert post['actual_exit_code'] == 0 and post['terminal']
    for path, expected in post['source_output_sha256'].items():
        verify_file(path, expected)
    codec_path = native_base + 'native-fts-token-codec-proof-v2.json'
    codec = read(codec_path)
    assert codec['all_passed']
    assert not codec['scope']['conversion_hooks'] and not codec['scope']['copy_or_string_hooks']
    sources.extend([codec_path, native_base + 'native-fts-codec-file-seal-v1.json', post_path])
    for directory in ['navigation-JAI-AP-link-samples-v1', 'navigation-AP-target-packed-bytes-v1']:
        manifest_path = 'staging/' + directory + '/analysis-file-seal.json'
        manifest = read(manifest_path)
        for item in manifest['files']:
            verify_file(item['path'], item['sha256'], item['bytes'])
        sources.append(manifest_path)
    plan_manifest_path = 'staging/navigation-native-AP-packed-reader-v1/sealed-plan-manifest-v1.json'
    plan_manifest = read(plan_manifest_path)
    for item in plan_manifest['files']:
        verify_file(item['path'], item['sha256'], item['bytes'])
    plan_path = 'staging/navigation-native-AP-packed-reader-v1/original-packed-reader-plan-proof-v1.json'
    plan = read(plan_path)
    assert plan['all_cases_passed']
    sources.extend([plan_manifest_path, plan_path])

    before = {name: (ROOT / name).read_bytes() for name in CANONICALS}
    state, task, public = [json.loads(before[name]) for name in CANONICALS[:3]]
    latest = json.loads(before[CANONICALS[4]])
    assert public['deep_research'] == state
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    app_before = copy.deepcopy(state['native_app_music'])
    original_progress = copy.deepcopy(public['research_progress'])
    body, _ = http(latest['url'])
    assert body == before[CANONICALS[3]]
    service_before = service()
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    details = [
        '原廠台中市、中區、民權路的中文編碼與解码函式已實際執行；三個名稱共8個漢字，輸出與原DB逐位元組一致，沒有替換轉碼函式。',
        '原DB階層定位到台中市→中區→民權路，能區分六個不同行政區的同名民權路與民和路；資料列PK、地址ID、地圖ID是不同數字空間。',
        '原廠資料讀取程式確認：縣市／區／街道分別選擇對應資料表，地址ID由1起算；三筆原資料共48bytes已唯讀取得，交由原bitreader解析。',
        '原廠地址資料包含六組packed記錄，前三組容量與縣市／區／街道ID範圍吻合；不是六個城市。門牌與路由關係尚未解析完成。',
    ]
    progress = dict(
        updated_utc=now.isoformat(), stage='native_labels_and_record_addressing_proven_selected_payload_in_progress',
        selected_native_UTF8_codec_verified=True, selected_names=['台中市', '中區', '民權路'],
        complete_address_UI_query_verified=False, native_provider_SQLite_constructor_verified=False,
        record_reader_one_based_addressing_verified=True, selected_original_body_bytes=48,
        selected_AP_position_and_route_relationship_verified=False,
        original_format_writer_implemented=False, original_address_data_updated_to_2026=False,
        original_maps_or_DB_modified=False, device_IO=False,
        details=details, evidence=sources,
    )
    state['navigation_repair'].update(updated_utc=now.isoformat(), original_format_research=progress,
                                     goal_complete=False, required_work_remaining=True)
    state.update(updated_utc=now.isoformat(), required_work_remaining=True, goal_complete=False)
    for key in ['navigation_repair', 'updated_utc', 'required_work_remaining', 'goal_complete']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state),
                  navigation_repair=copy.deepcopy(state['navigation_repair']),
                  goal_complete=False, required_work_remaining=True)
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert state['native_app_music'] == app_before
    for key in ['estimate_percent', 'weighted_estimate_percent', 'phases', 'completed']:
        assert public['research_progress'][key] == original_progress[key]
    card = '<aside class="card" id="navigation-native-format-progress-v1"><h2>原廠格式圖資更新：中文編碼與記錄定位已核對</h2>'
    card += '<p>正在保留完整縣市、街道與門牌搜尋架構的前提下，研究更新道路和地址資料。以下是原備份與有限原指令核對，仍不是已安裝的新地址包。</p><ul>'
    import html
    card += ''.join('<li>' + html.escape(item) + '</li>' for item in details) + '</ul>'
    card += '<p><strong>下一步：</strong>解析原地址記錄的位置、門牌及路由引用，建立可逆的資料產生規則；目前不需額外USB操作。</p>'
    card += f'<p>研究更新：<time datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p></aside>'
    report = before[CANONICALS[3]].decode()
    assert 'id="navigation-native-format-progress-v1"' not in report
    report, count = re.subn(r'(<section class="card" id="navigation-repair-checkpoint-v2">.*?</section>)',
                            lambda match: match.group(1) + card, report, count=1, flags=re.S)
    assert count == 1
    for identifier in ['report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + identifier + r'" datetime="[^"]+">[^<]+</time>',
                                lambda _: f'<time id="{identifier}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',
                                report, count=1)
        assert count == 1
    OUT.mkdir()
    for name, data in before.items():
        path = OUT / (name.replace('/', '__') + '.gz')
        with path.open('xb') as stream:
            stream.write(gzip.compress(data, mtime=0))
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o444)
    create(OUT / 'root-reviewed-proof-bindings.json', dict(
        created_utc=now.isoformat(), all_selected_source_hashes_verified=True,
        actual_native_probe_receipt=native_seal['native_helper_execution_receipt'],
        stock_or_device_writes=False, complete_UI_or_navigation_proof=False,
        proofs=[dict(path=name, bytes=(ROOT / name).stat().st_size,
                     sha256=sha((ROOT / name).read_bytes())) for name in sources],
    ))
    for name, value in zip(CANONICALS[:4], [state, task, public, report]):
        replace(name, value)
    served, response = http(latest['url'])
    assert served == report.encode()
    assert service_before == service()
    latest.update(updated_utc=now.isoformat(), HTTP_status=response['status'], cache_control=response['cache_control'],
                  local_report_sha256=sha(served), served_report_sha256=sha(served), report_bytes=len(served),
                  served_latest_report=True, service_not_restarted=True,
                  latest_original_format_research='staging/navigation-native-format-progress-v1/root-reviewed-proof-bindings.json',
                  required_work_remaining=True, full_goal_complete=False)
    replace(CANONICALS[4], latest)
    assert read(CANONICALS[2])['deep_research'] == read(CANONICALS[0])
    create(OUT / 'fresh-readback.json', dict(
        all_passed=True, checked_utc=datetime.now(timezone.utc).isoformat(), HTTP=response,
        report_sha256=sha(served), service=service_before, service_not_restarted=True,
        native_codec_verified_scope='Three stock Chinese names, eight Unicode units',
        original_format_map_writer_implemented=False, full_goal_complete=False,
    ))
    print(json.dumps({'all_passed': True, 'report_url': latest['url'],
                      'native_format_writer_implemented': False, 'service_PID': service_before['MainPID']}))


if __name__ == '__main__':
    main()
