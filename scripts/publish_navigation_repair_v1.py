#!/usr/bin/env python3
"""One-shot navigation candidate checkpoint; prepare/review before ROOT executes.

No guest, device, installation, service restart or old-suite revalidation.
Large IMG/ZIP digests are ROOT's completed package results, not rehashed here.
"""
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
SOURCE = 'scripts/publish_navigation_repair_v1.py'
STATE = 'evidence/navigation-repair-state-v1.json'
PACKAGE = 'staging/navigation-repair-v1/package-result.json'
OLD = 'evidence/firmware-analysis/garminos-media-compaction-checkpoint-audit.json'
OUT = 'evidence/navigation-repair-checkpoint-v1.json'
B = 'staging/navigation-repair-checkpoint-v1/'
WEB = 'evidence/report-web-latest.json'
CANONICAL = ['evidence/deep-research-state.json', 'evidence/task-state.json',
             'reports/findings.json', 'reports/nuvi2565RT.html']
DOWNLOAD = 'http://172.16.60.187:8767/Garmin-2565RT-navigation-repair-v1.zip'


def path(name):
    value = Path(name)
    assert not value.is_absolute() and '..' not in value.parts, name
    return ROOT / value


def decode(data):
    return json.loads(data.decode('utf-8'))


def read(name):
    return decode(path(name).read_bytes())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fresh_sha(name):
    # Deliberately uncached: canonical readbacks must see the bytes just written.
    return digest(path(name).read_bytes())


def encoded(payload):
    return payload.encode('utf-8') if isinstance(payload, str) else (
        json.dumps(payload, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def create(name, payload):
    with path(name).open('xb') as stream:
        stream.write(encoded(payload))
        stream.flush()
        os.fsync(stream.fileno())


def replace(name, payload):
    target = path(name)
    temporary = target.with_name('.navigation-publication-v1-' + target.name)
    assert not temporary.exists(), temporary
    with temporary.open('xb') as stream:
        stream.write(encoded(payload))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, target)


def service_now():
    result = subprocess.run(['systemctl', 'show', 'garmin-report-web.service',
        '--property=MainPID,ActiveState,SubState,UnitFileState'],
        capture_output=True, text=True, check=True)
    value = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    assert value == dict(MainPID='357833', ActiveState='active', SubState='running', UnitFileState='enabled')
    os.kill(int(value['MainPID']), 0)
    return value


def served(url):
    request = urllib.request.Request(url, headers={'Cache-Control': 'no-cache'})
    with urllib.request.urlopen(request, timeout=15) as response:
        assert response.status == 200 and 'no-store' in response.headers.get('Cache-Control', '')
        return response.read(), dict(status=response.status, cache_control=response.headers.get('Cache-Control'))


def download_head(expected_bytes):
    request = urllib.request.Request(DOWNLOAD, method='HEAD', headers={'Cache-Control': 'no-cache'})
    with urllib.request.urlopen(request, timeout=15) as response:
        assert response.status == 200 and int(response.headers['Content-Length']) == expected_bytes
        return dict(url=DOWNLOAD, HTTP_status=response.status,
                    content_length=int(response.headers['Content-Length']), method='HEAD',
                    full_ZIP_GET_or_digest_repeated_by_publisher=False)


def substitute(report, pattern, replacement, flags=0):
    report, count = re.subn(pattern, replacement, report, count=1, flags=flags)
    assert count == 1, pattern
    return report


def main():
    assert not path(B).exists() and not path(OUT).exists(), 'One-shot namespace already exists; do not rerun.'
    old, nav, package, latest = [read(name) for name in [OLD, STATE, PACKAGE, WEB]]
    assert old['all_passed'] and package['all_passed']
    assert len(old['protected_sources']) == 4882
    assert nav['goal_status'] == 'active' and not nav['goal_complete']
    assert nav['research_goal_status'] == 'paused'
    assert nav['native_app_research_status'] == 'deferred_until_navigation_verified'
    assert nav['current_goal_priority'] == 'navigation_search_repair' and nav['candidate']
    assert all(nav[key] is False for key in ['device_installed', 'device_search_verified',
        'device_routing_verified', 'stock_maps_modified', 'physical_ab_test_success'])
    estimate = nav['repair_estimate_percent']
    assert isinstance(estimate, int) and 0 < estimate <= 65
    assert nav['estimate_is_planning_not_verified_success']
    assert nav['completed_offline_details'] and nav['remaining_physical_checks']
    assert nav['download_url'] == DOWNLOAD and nav['package']
    assert package['zip'] == 'reports/downloads/Garmin-2565RT-navigation-repair-v1.zip'
    assert package['offline_verification'], 'Completed offline results are required.'
    large = {}
    for label, name, byte_count, expected in [
        ('candidate_map', package['map_path'], package['map_bytes'], package['map_sha256']),
        ('download_ZIP', package['zip'], package['zip_bytes'], package['zip_sha256'])]:
        assert re.fullmatch('[0-9a-f]{64}', expected) and byte_count > 0
        assert path(name).is_file() and path(name).stat().st_size == byte_count
        large[name] = dict(sha256=expected, bytes=byte_count, verification_owner='ROOT package result',
                          size_checked_by_publisher=True, digest_repeated_by_publisher=False, role=label)

    before_bytes = {name: path(name).read_bytes() for name in CANONICAL}
    before_sha = {name: digest(data) for name, data in before_bytes.items()}
    state, task, public = [decode(before_bytes[name]) for name in CANONICAL[:3]]
    assert public['deep_research'] == state
    progress, app = public['research_progress'], state['native_app_music']
    estimates = [progress['estimate_percent'], progress['weighted_estimate_percent'],
                 [phase['estimate_percent'] for phase in progress['phases']]]
    assert estimates[:2] == [37, 37] and progress['phases'][4]['estimate_percent'] == 40
    old_findings = copy.deepcopy(app['static_findings'])
    old_details = list(progress['completed'])
    service = service_now()
    original_served, pre_http = served(latest['url'])
    assert original_served == before_bytes[CANONICAL[3]]
    head = download_head(package['zip_bytes'])

    protected, focused = dict(old['protected_sources']), {}

    def register(name):
        if name in focused:
            return focused[name]
        assert name not in large and path(name).stat().st_size <= 4 * 1024 * 1024, name
        assert not name.lower().endswith(('.img', '.zip', '.pbf', '.squashfs')), name
        value = fresh_sha(name)
        assert name not in protected or protected[name] == value, name
        focused[name] = value
        protected[name] = value
        return value

    selected = [SOURCE, STATE, PACKAGE, OLD, 'scripts/build_navigation_repair_v1.py']
    selected.extend(nav['sources'].values())
    for row in package['offline_verification']:
        name = row if isinstance(row, str) else next(row[key] for key in ['path', 'file', 'evidence'] if key in row)
        selected.append(name)
        if name.endswith('.json'):
            result = read(name)
            if isinstance(result, dict) and 'all_passed' in result:
                assert result['all_passed'] is True, name
    for name in selected:
        register(name)
    for name, row in large.items():
        assert name not in protected or protected[name] == row['sha256'], name
        protected[name] = row['sha256']

    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    iso = local.isoformat(timespec='seconds')
    next_text = '先核對USB實機身份與空間，安裝候選並讀回；再做新版OSM單獨／原廠CN＋Address Point兩組對照，確認臺中市民權路、民和路對照、搜尋耗時與GPS路由。確認導航修復後依使用者原先指示繼續音樂／App研究。'
    priorities = ['現場藍牙配對與維持連線（有配對要求時立即優先）',
        '導航地址搜尋與路由修復：候選安裝、A/B對照與實機確認',
        '原生音樂與GarminOS App研究（導航確認前暫緩）',
        'Android Auto內建接收端（原研究恢復後再安排）',
        '原機離線Google Maps（依使用者指示延後）']
    details = list(nav['completed_offline_details'])
    details.append(f'導航修復候選已封裝，離線修復估計{estimate}%；ZIP約{package["zip_bytes"] / 1e6:.1f}MB。尚未安裝或驗證實機中文搜尋／路由；原廠CN＋Address Point保留並互補，將做兩組對照。整體研究37%、App40%保持，音樂／App暫緩。')
    repair = copy.deepcopy(nav)
    repair.update(published_utc=now.isoformat(), package=package, checkpoint=OUT,
        required_work_remaining=True, next=next_text,
        progress_components=[dict(name='離線分析、重編與封裝', weight=65, completed_points=estimate),
            dict(name='實機安裝與讀回', weight=10, completed_points=0),
            dict(name='地址搜尋、A/B與GPS路由確認', weight=25, completed_points=0)],
        findings=dict(layers='原廠CN道路主圖與Address Point是互補配套；保留底圖DEM、時區及原廠索引。',
            road_names='原始OSM的市中心民權路與沿海民和路是不同道路，尚未證明兩小時搜尋的根因。',
            sort='缺頁SRT字重序列化與新排序ID通過離線檢查；Garmin實際搜尋政策尚未測到。',
            candidate='新OSM候選與原廠產品分開；ZIP及IMG採用ROOT完成的校驗值。',
            physical='安裝、地址與門牌、耗時、其他缺路和實際路由仍待實機確認。'))
    previous_classification = state['last_goal_turn'].get('classification')
    state.update(updated_utc=now.isoformat(), goal_status='active', goal_complete=False,
        required_work_remaining=True, current_goal_priority='navigation_search_repair',
        research_goal_status='paused', native_app_research_status='deferred_until_navigation_verified',
        current_priority=next_text, next_actions=list(nav['remaining_physical_checks']),
        latest_user_instruction='原音樂／App研究暫緩，先修導航地址搜尋與路由問題；離線候選不代表實機已修好。',
        navigation_repair=repair, ordered_priorities=priorities,
        current_navigation_repair_checkpoint=OUT)
    app['research_priority'] = 'Deferred until navigation search/routing is physically verified; then continue the already authorized music/App research.'
    state['map_update']['repair_candidate'] = dict(evidence=STATE, package=PACKAGE,
        candidate=True, installed=False, device_search_verified=False, device_routing_verified=False)
    state['last_goal_turn'] = dict(classification='progress', validated_utc=now.isoformat(),
        previous_published_checkpoint_classification=previous_classification,
        reasons=['Completed scoped offline navigation candidate analysis, full-map verification and packaging.'],
        focused_evidence=PACKAGE, focused_evidence_sha256=focused[PACKAGE],
        goal_status='active', full_goal_complete=False, required_work_remaining=True,
        current_goal_priority='navigation_search_repair', research_goal_status='paused',
        native_app_research_status='deferred_until_navigation_verified', next_focus=next_text,
        device_IO=False, device_io=False, device_files_written=False,
        guest_execution=False, old_frozen_suites_rerun=False, old_sources_fresh_rehash=False,
        previous_canonical_snapshot_encoding='gzip')
    for key in ['updated_utc', 'goal_status', 'goal_complete', 'required_work_remaining',
        'current_goal_priority', 'research_goal_status', 'native_app_research_status',
        'current_priority', 'next_actions', 'latest_user_instruction', 'navigation_repair',
        'ordered_priorities', 'last_goal_turn', 'current_navigation_repair_checkpoint']:
        task[key] = copy.deepcopy(state[key])
    task['research_completed'] = False
    progress['completed'].extend(details)
    progress['phases'][0]['completed'].extend(details)
    progress['phases'][4].update(deferred=True, next='原研究暫緩；導航實機確認後依原先指示繼續音樂／App研究。')
    progress.update(research_updated_utc=now.isoformat(), ordered_priorities=priorities,
        next=next_text, original_research_status='paused', current_goal_priority='navigation_search_repair')
    public.update(updated=now.isoformat(), deep_research=state, navigation_repair=repair,
        navigation_repair_progress=dict(estimate_percent=estimate, estimate_is_milestone_assessment=True,
            goal_complete=False, components=repair['progress_components']),
        current_navigation_repair_checkpoint=OUT, goal_status='active', goal_complete=False,
        required_work_remaining=True, current_goal_priority='navigation_search_repair',
        research_goal_status='paused', native_app_research_status='deferred_until_navigation_verified')
    assert app['static_findings'] == old_findings and progress['completed'][:len(old_details)] == old_details
    assert estimates == [progress['estimate_percent'], progress['weighted_estimate_percent'],
                         [phase['estimate_percent'] for phase in progress['phases']]]

    escape = html.escape
    card = ('<section class="card" id="navigation-repair-checkpoint-v1"><h2>導航修復候選：待實機確認</h2>'
        f'<p>導航修復估計 <strong>{estimate}%</strong>，屬工作里程碑，尚未證明問題已解決。原音樂／App研究暫緩；'
        '原整體研究37%、App40%保持。</p>'
        f'<progress id="navigation-repair-progress" max="100" value="{estimate}" style="width:100%;height:18px" aria-label="導航修復工作估計">{estimate}%</progress>'
        '<p>離線分析與封裝65分；實機安裝10分、地址搜尋與GPS路由25分仍待完成。</p>'
        f'<p>更新：<time datetime="{iso}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
        f'<p><a href="{DOWNLOAD}" download>下載導航修復候選ZIP（約{package["zip_bytes"] / 1e6:.1f}MB）</a>；'
        '包內含安裝、還原、校驗與A/B測試說明。先核對實機身份與空間，再安裝讀回。</p>'
        '<table><thead><tr><th>圖層</th><th>用途與對照</th></tr></thead><tbody>'
        '<tr><td>原廠CN道路主圖＋Address Point</td><td>道路／路由與地址補充互補，B組一起啟用。</td></tr>'
        '<tr><td>新版OSM修復候選</td><td>新編道路與搜尋索引，A組單獨啟用詳圖；不替代原廠配套。</td></tr>'
        '<tr><td>底圖DEM與時區</td><td>兩組均保留；原廠JCV／SID／SQLite／POI亦保留。</td></tr>'
        '</tbody></table><h3>已完成的離線工作</h3><ul>' + ''.join('<li>' + escape(d) + '</li>' for d in details) +
        '</ul><h3>尚待實機確認</h3><ul>' + ''.join('<li>' + escape(d) + '</li>' for d in nav['remaining_physical_checks']) +
        '</ul><p>原廠CN與Address Point一起勾選本來互補；與OSM交疊是否造成問題仍待對照。'
        '使用者目前只實測民權路。各組重啟後查地址→臺中市／台中市→民權路，核對道路、門牌、位置與耗時；期望30秒內有結果，超過60秒記錄未完成並取消。</p>'
        '<h3>已知限制</h3><ul>' + ''.join('<li>' + escape(d) + '</li>' for d in nav['known_limits']) + '</ul></section>')
    report = before_bytes[CANONICAL[3]].decode('utf-8')
    assert 'id="navigation-repair-checkpoint-v1"' not in report and report.count('<main>') == 1
    report = report.replace('<main>', '<main>' + card, 1)
    report = substitute(report, r'(<span class="progress-status">)[^<]+(</span>)',
        lambda m: m[1] + '導航修復進行中；原研究暫緩' + m[2])
    report = substitute(report, r'(<ol class="research-priorities">).*?(</ol>)',
        lambda m: m[1] + ''.join('<li>' + escape(d) + '</li>' for d in priorities) + m[2], re.S)
    report = substitute(report, r'(<ul class="completed-progress">)(.*?)(</ul>)',
        lambda m: m[1] + m[2] + ''.join('<li>' + escape(d) + '</li>' for d in details) + m[3], re.S)
    report = substitute(report, r'<p><strong>下一步：</strong>.*?</p>',
        lambda m: '<p><strong>下一步：</strong>' + escape(next_text) + '</p>', re.S)
    report = substitute(report, r'(<tr><td>原生 App 入口與功能整合</td><td>40%</td><td>).*?(</td></tr>)',
        lambda m: m[1] + escape(progress['phases'][4]['next']) + m[2], re.S)
    for name in ['report-updated-time', 'research-updated-time']:
        report = substitute(report, r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
            lambda m: '<time id="' + name + '" datetime="' + iso + '">' + local.strftime('%Y/%m/%d %H:%M:%S') + '</time>')
    assert 'id="research-progress" max="100" value="37"' in report
    assert 'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', report)

    # Freeze four current canonicals once; no backup image or historical proof reads.
    assert all(fresh_sha(name) == expected for name, expected in before_sha.items())
    path(B).mkdir()
    snapshots = []
    for index, name in enumerate(CANONICAL):
        target = B + 'previous-' + ['state.json', 'task.json', 'public.json', 'report.html'][index] + '.gz'
        with path(target).open('xb') as stream:
            with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0, compresslevel=6) as zipped:
                zipped.write(before_bytes[name])
        assert gzip.decompress(path(target).read_bytes()) == before_bytes[name]
        register(target)
        snapshots.append(dict(original=name, snapshot=target, encoding='gzip', decoded_sha256=before_sha[name]))
    inputs = dict(all_passed=True, prepared_utc=now.isoformat(), navigation_state=STATE,
        package_result=PACKAGE, snapshots=snapshots, focused_sources_sha256=dict(focused),
        ROOT_verified_large_files=large, inherited_protected_source_count=4882,
        inherited_selected_frozen_suites=old['selected_frozen_suites'],
        inherited_native_unique_exact_dependencies=old['native_unique_exact_dependencies'],
        old_registry_hashes_inherited_without_revalidation=True, full_prior_rehash_repeated=False,
        full_backup_rehash_repeated=False, old_suites_rerun=False, guest_execution=False,
        device_IO=False, device_installation=False, download_HEAD=head, prepublication_HTTP=pre_http,
        goal_status='active', original_research_status='paused', overall_percent=37, App_percent=40,
        navigation_repair_estimate_percent=estimate, physical_navigation_repair_verified=False)
    create(B + 'publication-inputs.json', inputs)
    register(B + 'publication-inputs.json')
    for name, payload in zip(CANONICAL, [state, task, public, report]):
        replace(name, payload)
    after = {name: fresh_sha(name) for name in CANONICAL}
    assert [read(name) for name in CANONICAL[:3]] == [state, task, public]
    body, post_http = served(latest['url'])
    assert body == report.encode('utf-8') and digest(body) == fresh_sha(CANONICAL[3])
    assert service_now() == service
    audit = dict(old, all_passed=True, updated_utc=now.isoformat(), previous_checkpoint=OLD,
        protected_sources=protected, current_focused_sources_sha256=focused,
        previous_canonical_snapshots=snapshots, canonical_after_sha256=after,
        current_state_sha256=after[CANONICAL[0]], report_sha256=after[CANONICAL[3]],
        local_report_sha256=after[CANONICAL[3]], served_report_sha256=digest(body),
        canonical_readback_uncached=True, current_findings=len(app['static_findings']),
        current_public_details=len(progress['completed']), navigation_finding_count=len(repair['findings']),
        navigation_repair=repair, ROOT_verified_navigation_large_files=large,
        goal_status='active', full_goal_complete=False, required_work_remaining=True,
        current_goal_priority='navigation_search_repair', research_goal_status='paused',
        native_app_research_status='deferred_until_navigation_verified',
        estimate_percent=37, weighted_estimate_percent=37, App_estimate_percent=40,
        prior_full_source_rehash_repeated_this_turn=False,
        publisher_second_full_source_rehash_claimed=False,
        source_dependency_union_revalidated_once_before_write=False,
        full_backup_image_rehash_repeated_by_compactor=False,
        historical_preservation_scope='4882 old protected sources and all prior suites/dependencies inherited; only new focused small files and current canonicals checked.',
        device_IO_this_turn=False, scope_checks=dict(old['scope_checks'],
            navigation_offline_candidate_package_complete=True, physical_navigation_search_verified=False,
            physical_navigation_routing_verified=False, device_installation_this_publication=False,
            original_CN_and_Address_Point_complementary=True, original_App_percent_unchanged=True,
            old_protected_sources_freshly_rehashed_this_publication=False))
    create(OUT, audit)
    latest.setdefault('checkpoint_sha256', {})[OUT] = fresh_sha(OUT)
    latest.update(updated_utc=now.isoformat(), current_navigation_repair_checkpoint=OUT,
        HTTP_status=post_http['status'], cache_control=post_http['cache_control'],
        local_report_sha256=after[CANONICAL[3]], served_report_sha256=digest(body),
        report_bytes=len(body), service=service, service_not_restarted=True,
        served_latest_report=True, canonical_hash_readback_uncached=True,
        current_goal_priority='navigation_search_repair', native_app_research_status='deferred_until_navigation_verified',
        goal_status='active', full_goal_complete=False, navigation_download=head)
    latest['progress_display_verified'].update(completed_items=len(progress['completed']),
        report_updated_time=iso, research_updated_time=iso, navigation_repair_visible=True,
        navigation_repair_estimate_percent=estimate, original_overall_percent=37, original_App_percent=40)
    replace(WEB, latest)
    create(B + 'fresh-readback.json', dict(all_passed=True, checked_utc=datetime.now(timezone.utc).isoformat(),
        canonical_sha256=after, report_HTTP=post_http, local_report_sha256=fresh_sha(CANONICAL[3]),
        served_report_sha256=digest(body), service=service_now(), service_not_restarted=True,
        checkpoint_sha256=fresh_sha(OUT), report_web_sha256=fresh_sha(WEB), download_HEAD=head,
        full_prior_rehash_repeated=False, device_IO=False))
    print(json.dumps(dict(all_passed=True, checkpoint=OUT, findings=len(app['static_findings']),
        details=len(progress['completed']), inherited_protected_sources=4882,
        protected_sources=len(protected), report_sha256=after[CANONICAL[3]], report_bytes=len(body),
        navigation_repair_estimate_percent=estimate, overall_percent=37, App_percent=40,
        goal_status='active', research_goal_status='paused', physical_navigation_verified=False,
        device_IO=False)), flush=True)


if __name__ == '__main__':
    main()
