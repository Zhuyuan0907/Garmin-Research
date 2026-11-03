#!/usr/bin/env python3
"""Publish reviewed Android Auto *host-layer* results without device execution.

Default mode only validates the inputs and proposed changes.  --publish is the
separate, explicit publication step.  No builder, guest, pairing, audio, service
restart, whitelist change, or goal transition is performed by this script.

Required run-metadata schema (all paths are relative to the workspace):
  schema: "android-auto-host-checkpoint-v1"
  goal_receipt: {path, sha256, status_path: "status", objective_path: "objective"}
  tls / wire: {
    proof_sha256, claims: {"dot.path.in.proof": expected_value, ...},
    pass_claim: "dot.path", device_io_claim: "dot.path",
    native_guest_claim: "dot.path", case_count_claim: "dot.path",
    case_count: integer, source_pins_claim: "dot.path",
    source_pins: {path: sha256, ...},
    scope: string, completed: [string, ...]
  }
  terminal_receipts: [{path, sha256, result_path: "actual_terminal_result",
                       chunk_id: "actual finished tool chunk"}, ...]

The caller supplies reviewed exact claims, rather than this publisher guessing
different producer schemas.  In particular both proofs must explicitly record
zero device I/O and zero native guest execution; an omitted field is not proof.
Terminal receipts must be final EXIT0 tool results, without a live session ID.
The goal receipt must contain the actual active goal-tool result, not a cached
research state.  Only a bounded proof summary is placed in the public HTML.
"""
import argparse
import copy
import gzip
import hashlib
import html
import json
import os
import re
import stat
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
FILES = ('evidence/deep-research-state.json', 'evidence/task-state.json',
         'reports/findings.json', 'reports/nuvi2565RT.html',
         'evidence/report-web-latest.json')
FIELD = 'latest_android_auto_host_checkpoint'
CARD_ID = 'android-auto-host-current-checkpoint-v1'
SCHEMA = 'android-auto-host-checkpoint-v1'
OBJECTIVE = ('resume please help me continue work, for about the deep research '
             'this garminOS, i really want to have something like android auto, '
             'google map or what, so please help me to rerearch')
PRIORITIES = [
    '現場配對與維持連線：使用者主動開始藍牙實測時立即優先；目前不發來電或播放音源。',
    'GarminOS 原機 Android Auto：先完成可攜式封包／TLS／控制通道，再接真正 USB 主機與手機傳輸。',
    'H.264 解碼、記憶體與效能、螢幕顯示、觸控及音訊整合；原機接收端與菜單入口尚未完成。',
    'Google Maps／離線地圖能力接續驗證；保留原生藍牙音樂與 App 研究，導航修復及麥克風維持停止。',
]
NEXT_ACTIONS = [
    '把主機端已驗證的TLS與封包流程串成控制通道與媒體佇列，再接真正USB主機／VBUS／AOA傳輸；目前不接裝置。',
    '建立H.264解碼、保守記憶體配置及畫面／觸控／音訊介面；原機速度、可用heap、載入、菜單與導航共存仍須驗證。',
    'Android Auto接收端與Google Maps／離線使用均未在Garmin運行成功。藍牙音樂歷史成果保留；導航修復、麥克風停止，不自動配對、發來電或播音。',
]
GAPS = [
    'Garmin 實體 USB 主機／VBUS、enumeration 與 AOA bulk 傳輸未驗證。',
    '手機投影協商、控制／媒體通道、可靠取消與流量控制尚未完成端到端整合。',
    '原機亂數、時間、配置與平台介面未驗證；主機 TLS 成功不等於 Garmin 可用。',
    'H.264 原機解碼效能／記憶體、螢幕顯示與觸控回傳尚未實測。',
    '原機 App 載入／菜單、音訊所有權、停止重啟與導航共存尚未完成。',
    'Android Auto／Google Maps／原機離線使用尚未成功，沒有可安裝接收端。',
]
PRIVATE = re.compile(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b|REDACTED_PRIVATE_ID|-----BEGIN .*PRIVATE KEY')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def resolve(name):
    require(isinstance(name, str), 'Path must be text')
    path = (ROOT / name).resolve()
    require(path.is_relative_to(ROOT) and path.is_file(), 'Existing workspace file: ' + name)
    return path


def pinned_json(name, pin):
    path = resolve(name)
    require(path.suffix == '.json' and path.stat().st_size <= 1024 * 1024,
            'Bounded JSON proof/receipt: ' + name)
    raw = path.read_bytes()
    require(re.fullmatch(r'[0-9a-f]{64}', pin or '') and digest(raw) == pin,
            'Reviewed JSON SHA-256: ' + name)
    return json.loads(raw), {'path': str(path.relative_to(ROOT)), 'sha256': pin}


def field(document, dotted):
    require(isinstance(dotted, str) and dotted != '', 'Nonempty proof field')
    value = document
    for part in dotted.split('.'):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def validate_proof(name, spec):
    proof, reference = pinned_json(name, spec['proof_sha256'])
    require(isinstance(spec['claims'], dict) and spec['claims'], 'Exact reviewed proof claims')
    for dotted, expected in spec['claims'].items():
        observed = field(proof, dotted)
        require(type(observed) is type(expected) and observed == expected,
                'Exact claim ' + name + ':' + dotted)
    for item, wanted in (('pass_claim', True), ('device_io_claim', False),
                         ('native_guest_claim', False)):
        dotted = spec[item]
        require(dotted in spec['claims'] and field(proof, dotted) is wanted,
                'Explicit host-only scope: ' + item)
    count = spec['case_count']
    require(type(count) is int and count > 0 and
            spec['case_count_claim'] in spec['claims'] and
            type(field(proof, spec['case_count_claim'])) is int and
            field(proof, spec['case_count_claim']) == count, 'Verified host case count')
    require(isinstance(spec['source_pins'], dict) and spec['source_pins'], 'Compiled/tested source pins')
    recorded_sources = field(proof, spec['source_pins_claim'])
    require(isinstance(recorded_sources, dict), 'Source pins recorded as a dictionary')
    recorded_pins = {name: (value['sha256'] if isinstance(value, dict) else value)
                     for name, value in recorded_sources.items()}
    require(spec['source_pins_claim'] in spec['claims'] and
            recorded_pins == spec['source_pins'],
            'Source pins are exactly the pins recorded in the reviewed test proof')
    for source, pin in spec['source_pins'].items():
        path = resolve(source)
        require((path.suffix in ('.c', '.h', '.py', '.json', '.txt', '.md', '.cmake') or path.name == 'COPYING')
                and path.stat().st_size <= 1024 * 1024, 'Bounded source-only pin: ' + source)
        require(digest(path.read_bytes()) == pin, 'Tested source remains current: ' + source)
    require(isinstance(spec['scope'], str) and 0 < len(spec['scope']) <= 2000,
            'Explicit evidence scope')
    require(isinstance(spec['completed'], list) and spec['completed'] and
            all(isinstance(x, str) and 0 < len(x) <= 2000 for x in spec['completed']),
            'Reviewed completed details')
    require(not PRIVATE.search(spec['scope'] + '\n'.join(spec['completed'])),
            'Do not publish unit identifiers or keys')
    return dict(reference, case_count=count, scope=spec['scope'],
                completed=copy.deepcopy(spec['completed']),
                source_pins=copy.deepcopy(spec['source_pins']),
                verified_claims=copy.deepcopy(spec['claims']),
                host_layer_only=True, native_guest_execution=False, device_IO=False,
                actual_phone_or_Garmin_session_verified=False)


def replace(name, data):
    target = ROOT / name
    fd, temporary = tempfile.mkstemp(prefix=target.name + '.aa-host.', dir=target.parent)
    try:
        os.fchmod(fd, stat.S_IMODE(target.stat().st_mode))
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def substitute(text, pattern, value, label):
    result, count = re.subn(pattern, lambda _: value, text, count=1, flags=re.S)
    require(count == 1, 'Existing unique report element: ' + label)
    return result


def prepare(before, checkpoint, now):
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'], 'Prior canonical equality')
    require(not any(doc.get('goal_complete') for doc in (state, task, public, web)), 'Goal remains incomplete')
    require(state['navigation_repair']['status'] == 'stopped_by_user' and
            state['microphone_amplifier']['status'] == 'cancelled_by_user', 'User cancellations preserved')
    require(task['user_away'] and not state['audio']['audible_tests_allowed'] and
            not web['current_physical_test_requested'], 'No unattended physical tests')
    require(not state['native_android_auto']['native_receiver_running'] and
            not state['native_android_auto']['phone_session_verified'] and
            not state['native_app_music']['native_app_running'] and
            not state['native_app_music']['direct_phone_music_verified'], 'No unsupported target success')
    old_audio, old_nav, old_mic, old_app = [copy.deepcopy(state[k]) for k in
                                         ('audio', 'navigation_repair', 'microphone_amplifier', 'native_app_music')]
    old_maps = copy.deepcopy(state['google_maps'])
    old_progress = copy.deepcopy(public['research_progress'])
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp, display = local.isoformat(timespec='seconds'), local.strftime('%Y/%m/%d %H:%M:%S')
    checkpoint['updated_utc'], checkpoint['updated_Taiwan'] = now.isoformat(), stamp
    history = state.setdefault('research_goal_status_history', [])
    history.append({'recorded_utc': now.isoformat(), 'prior_goal_status': state['goal_status'],
                    'prior_priority': state.get('current_goal_priority'),
                    'prior_requested_goal': state.get('requested_goal'),
                    'prior_latest_user_instruction': state.get('latest_user_instruction'),
                    'prior_current_priority': state.get('current_priority'),
                    'prior_ordered_priorities': copy.deepcopy(state.get('ordered_priorities')),
                    'prior_goal_turn': copy.deepcopy(state.get('last_goal_turn')),
                    'prior_blocked_reason': state.get('goal_blocked_reason'),
                    'bluetooth_music_blocking_audit': copy.deepcopy(state.get('bluetooth_music_blocking_audit')),
                    'reason': 'User resumed Android Auto/Google Maps; writable host development restored. Prior native execution boundary remains.'})
    state.pop('goal_blocked_reason', None)
    turn = {'classification': 'progress', 'previous_goal_turn_assessment': 'no_progress',
            'validated_utc': now.isoformat(), 'goal_status': 'active',
            'required_work_remaining': True, 'full_goal_complete': False,
            'host_layer_implementation_and_verification': True,
            'native_guest_execution': False, 'device_IO': False,
            'device_files_written': False, 'device_calls_or_sound': False,
            'focused_evidence': copy.deepcopy(checkpoint['proofs']),
            'reason': 'Reviewed new TLS and wire host implementation/test evidence; no guest, hardware, phone or install claim.'}
    state.update(updated_utc=now.isoformat(), requested_goal=OBJECTIVE,
                 latest_user_instruction=OBJECTIVE, current_goal_priority='android_auto_google_maps',
                 current_priority='GarminOS 原機 Android Auto／Google Maps；本輪完成主機層程式與驗證。',
                 research_goal_status='active_android_auto_google_maps', goal_status='active',
                 goal_complete=False, required_work_remaining=True,
                 ordered_priorities=copy.deepcopy(PRIORITIES), next_actions=copy.deepcopy(NEXT_ACTIONS),
                 last_goal_turn=turn)
    state['android_auto_host_development_status'] = 'active_writable_host_implementation_and_verification'
    state['android_auto_blocking_audit'] = {'updated_utc': now.isoformat(), 'condition': None,
        'consecutive_no_progress_goal_turns': 0, 'blocked_threshold': 3,
        'current_goal_turn_classification': 'progress', 'goal_status': 'active',
        'prior_bluetooth_counter_not_reused': True, 'full_goal_complete': False}
    state['execution_environment']['host_development_filesystem_writable'] = True
    state['execution_environment']['host_permission_change_recorded_utc'] = now.isoformat()
    state['execution_environment']['user_present_for_assistance'] = False
    state['execution_environment']['pending'] = 'Offline host-layer development; user will notify before target testing. No pairing/call/audio action requested.'
    state[FIELD] = copy.deepcopy(checkpoint)
    maps = state['google_maps']
    maps['prior_user_deferral'] = {'research_deferred_by_user': old_maps.get('research_deferred_by_user'),
                                 'deferral_reason': old_maps.get('deferral_reason')}
    maps.update(research_deferred_by_user=False, deferral_reason=None,
                current_research_priority='Resumed with Android Auto; native/offline Google Maps still unverified',
                latest_resume_utc=now.isoformat())
    aa = state['native_android_auto']
    aa.update(research_priority='Current main goal: native GarminOS Android Auto and Google Maps',
              Maps_still_deferred=False, remaining_work=copy.deepcopy(GAPS))
    aa[FIELD] = copy.deepcopy(checkpoint)
    work = state['offline_24h_work_order']
    work.update(goal_status='active', actual_goal_status_read='active', current_blocking_reason=None,
                current_priority='android_auto_google_maps', latest_user_priority_decision=OBJECTIVE,
                priorities=copy.deepcopy(PRIORITIES), whole_goal_complete=False)
    work[FIELD] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['android_auto'] = 'Host TLS/wire implementation verified; real USB, phone, native decoder/display/UI and speaker unverified'
    work['current_offline_line_status']['google_maps'] = 'Research resumed; native/offline execution unverified'
    # Keep the dated BT blocked audit itself byte-for-byte in semantic terms.
    # It is history and must never be relabelled as the resumed AA audit.
    state['prior_bluetooth_audit_is_historical'] = True
    for document in (task, public, web):
        for key in ('updated_utc', 'requested_goal', 'latest_user_instruction', 'current_goal_priority',
                    'current_priority', 'research_goal_status', 'goal_status', 'goal_complete',
                    'required_work_remaining', 'ordered_priorities', 'next_actions', 'last_goal_turn',
                    'offline_24h_work_order', FIELD, 'research_goal_status_history',
                    'prior_bluetooth_audit_is_historical', 'android_auto_host_development_status'):
            document[key] = copy.deepcopy(state[key])
        document['android_auto_blocking_audit'] = copy.deepcopy(state['android_auto_blocking_audit'])
        document.pop('goal_blocked_reason', None)
    task['native_android_auto'] = copy.deepcopy(aa)
    task['google_maps'] = copy.deepcopy(maps)
    task['execution_environment'] = copy.deepcopy(state['execution_environment'])
    task['current_device_connection_verified'] = False
    public['updated'], public['deep_research'] = now.isoformat(), copy.deepcopy(state)
    progress = public['research_progress']
    completed = checkpoint['proofs']['tls']['completed'] + checkpoint['proofs']['wire']['completed']
    progress['completed'].extend(completed)
    progress.update(research_updated_utc=now.isoformat(), ordered_priorities=copy.deepcopy(PRIORITIES),
                    current_goal_priority='android_auto_google_maps', original_research_status='active',
                    includes_deferred_Google_Maps=False, goal_completed=False, next=NEXT_ACTIONS[0],
                    method='沿用完整研究計畫的歷史工程估計；Android Auto／Google Maps已恢復主線。本輪主機檢查不提高原機實作百分比；導航修復及麥克風已停止。')
    phase_next = {'USB 主機與手機連線': NEXT_ACTIONS[0],
                  '畫面、影片與觸控投影': NEXT_ACTIONS[1],
                  '原生 App 入口與功能整合': '完成Android Auto原機載入／菜單、平台介面與控制／影音整合；保留藍牙App歷史原型及生命週期缺口。',
                  '原機離線 Google Maps': '研究已恢復；須分別驗證投影Google Maps與原機離線使用，OSM IMG不代表此目標完成。'}
    for phase in progress['phases']:
        if phase['name'] in phase_next:
            phase['next'], phase['deferred'] = phase_next[phase['name']], False
            if phase.get('status') == 'deferred_while_bluetooth_music_is_priority':
                phase['status'] = 'active_host_research_native_target_unverified'
    require(progress['estimate_percent'] == old_progress['estimate_percent'] and
            progress['weighted_estimate_percent'] == old_progress['weighted_estimate_percent'] and
            [(p['name'], p['weight'], p['estimate_percent']) for p in progress['phases']] ==
            [(p['name'], p['weight'], p['estimate_percent']) for p in old_progress['phases']],
            'Historical milestone estimates unchanged')
    require(all(state[k] == old for k, old in zip(('audio', 'navigation_repair', 'microphone_amplifier', 'native_app_music'),
                                                 (old_audio, old_nav, old_mic, old_app))), 'Native/audio/navigation history unchanged')
    report = before[FILES[3]].decode()
    require(CARD_ID not in report, 'v1 checkpoint not already published')
    archived = re.search(r'<section class="card" id="bluetooth-music-goal-blocked-v1">.*?</section>', report, re.S)
    require(archived is not None, 'Historical BT blocked section')
    prior_card = archived.group()
    history_card = ('<details class="card" id="bluetooth-music-goal-blocked-history-v1"><summary>'
                    '歷史紀錄：2026/10/07 藍牙音樂目標受阻（目前已恢復 Android Auto／Google Maps）'
                    '</summary>' + prior_card + '</details>')
    report = report.replace(prior_card, history_card, 1)
    e = html.escape
    steps = ''.join('<li>' + e(x) + '</li>' for x in completed)
    gaps = ''.join('<li>' + e(x) + '</li>' for x in GAPS)
    scopes = ''.join('<li><strong>' + title + '：</strong>' + e(checkpoint['proofs'][key]['scope']) +
                     '；' + str(checkpoint['proofs'][key]['case_count']) + '項主機檢查。</li>'
                     for title, key in (('TLS', 'tls'), ('封包', 'wire')))
    card = (f'<section class="card" id="{CARD_ID}"><h2>目前主線：GarminOS Android Auto／Google Maps</h2>'
            f'<p>目標 active／尚未完成。更新：<time datetime="{stamp}">{display}</time>（台灣時間）</p>'
            '<p>開發環境已恢復可寫；這輪完成可攜式接收端主機層實作與驗證，原機執行分支先前受系統限制的界線仍保留。</p>'
            '<p><strong>藍牙音樂現況：</strong>Pixel → Pi → Garmin 持續60秒有聲是使用者確認的歷史實測；'
            '第四版Android APK已完成API35編譯／DEX／API28簽章及18項gate＋12項lease主機檢查，'
            '尚未在Pixel驗證本機通話、實際SCO路由或Garmin出聲。原機直接A2DP與GarminOS菜單App仍未完成。'
            '<a href="/garmin-hfp-prototype.apk" download="garmin-hfp-prototype.apk">保留的Android第四版實驗APK</a>。</p>'
            '<h3>本輪已完成</h3><ul>' + steps + '</ul><h3>驗證範圍</h3><ul>' + scopes + '</ul>'
            '<p>上述結果在主機測試環境取得，沒有執行原廠／自製原機guest、接手機、寫車機、發來電或播放音訊。</p>'
            '<h3>仍待完成</h3><ul>' + gaps + '</ul>'
            '<p>整體工程估計維持' + str(progress['estimate_percent']) + '%，不是Android Auto的完成率。'
            '原機Android Auto／Google Maps及可安裝接收端尚未達成。導航修復與麥克風維持停止；藍牙音樂歷史證據保留。</p></section>')
    report = report.replace('<main>', '<main>' + card, 1)
    report = substitute(report, r'<span class="progress-status">.*?</span>',
                        '<span class="progress-status">Android Auto／Google Maps 研究中</span>', 'current progress status')
    report = substitute(report, r'<p id="progress-method"[^>]*>.*?</p>',
                        '<p id="progress-method" class="progress-note">' + e(progress['method']) + '</p>', 'method')
    report = substitute(report, r'<ol class="research-priorities">.*?</ol>',
                        '<ol class="research-priorities">' + ''.join('<li>' + e(x) + '</li>' for x in PRIORITIES) + '</ol>', 'priorities')
    report = substitute(report, r'<p id="offline-frontier-latest-v1">.*?</p>',
                        '<p id="offline-frontier-latest-v1">最新：Android Auto／Google Maps研究已恢復，TLS與封包主機層有新實作／驗證；原機USB、手機投影、畫面、觸控和喇叭尚未驗收，無可安裝包。</p>', 'frontier')
    report = substitute(report, r'<p><strong>下一步：</strong>.*?</p>',
                        '<p><strong>下一步：</strong>' + e(NEXT_ACTIONS[0]) + '</p>', 'next')
    report = substitute(report, r'(<ul class="completed-progress">)(.*?)(</ul>)',
                        re.search(r'<ul class="completed-progress">.*?</ul>', report, re.S).group()[:-5] + steps + '</ul>', 'completed history')
    for phase in progress['phases']:
        if phase['name'] in phase_next:
            report = substitute(report, r'<tr><td>' + re.escape(e(phase['name'])) + r'</td><td>.*?</td><td>.*?</td></tr>',
                                '<tr><td>' + e(phase['name']) + '</td><td>' + str(phase['estimate_percent']) +
                                '%</td><td>' + e(phase['next']) + '</td></tr>', 'phase ' + phase['name'])
    for element in ('report-updated-time', 'research-updated-time'):
        report = substitute(report, r'<time id="' + element + r'" datetime="[^"]+">[^<]+</time>',
                            f'<time id="{element}" datetime="{stamp}">{display}</time>', element)
    report = report.replace('<h2>目前主線：原生藍牙音樂與 GarminOS 播放器 App</h2>',
                            '<h2>歷史主線：原生藍牙音樂與 GarminOS 播放器 App</h2>', 1)
    report = report.replace('<h2>外出期間：藍牙音樂離線研究</h2>',
                            '<h2>歷史紀錄：外出期間的藍牙音樂研究</h2>', 1)
    report = report.replace('<h2>離線 Google Maps：依使用者要求延後</h2>',
                            '<h2>離線 Google Maps：已恢復研究，原機執行仍未完成</h2>', 1)
    report = report.replace('使用者已要求先延後此研究，優先更新台灣離線圖資。仍未達成。',
                            '使用者已恢復Android Auto／Google Maps研究；原機離線Google Maps仍未達成。', 1)
    report = report.replace('依目前優先序排在導航、藍牙音樂與原機 App 之後，goal 保持 active。',
                            '目前主線為GarminOS Android Auto／Google Maps，goal active；主機層新結果列在報告頂端，原機仍未運行。', 1)
    report = report.replace('目前依使用者指示，主線是原生藍牙音樂與 GarminOS 播放器 App；Android Auto 排在後續。',
                            '目前依使用者新指示，主線已恢復GarminOS Android Auto／Google Maps；原生藍牙音樂與播放器App證據保留。', 1)
    require(not PRIVATE.search(report), 'No unit identifier, phone address or private key in public HTML')
    require(report.index('id="' + CARD_ID + '"') < report.index('bluetooth-music-goal-blocked-v1'), 'Current card precedes historical blockage')
    web.update(full_goal_complete=False, actual_goal_status_read='active', current_physical_test_requested=False)
    web['progress_display_verified'].update(estimate_percent=progress['estimate_percent'], completed_items=len(progress['completed']),
        report_updated_time=stamp, research_updated_time=stamp, current_priority_order_visible=True,
        android_auto_host_checkpoint_visible=True, historical_BT_blocked_status_not_current=True,
        HTML_structure_checked=False, visual_browser_render_not_performed=True)
    return {FILES[0]: encoded(state), FILES[1]: encoded(task), FILES[2]: encoded(public),
            FILES[3]: report.encode(), FILES[4]: encoded(web)}, checkpoint


def live_server(web):
    pid = int(web['service']['MainPID'])
    process = Path('/proc') / str(pid)
    require(b'garmin-report-web/server.py' in (process / 'cmdline').read_bytes(), 'Existing report server PID')
    return pid, (process / 'stat').read_bytes().split()[21]


def fetch(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(url, headers={'Cache-Control': 'no-cache'}), timeout=10) as response:
        require(response.status == 200, 'Report HTTP 200')
        return response.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tls-proof', required=True)
    parser.add_argument('--wire-proof', required=True)
    parser.add_argument('--run-metadata', required=True)
    parser.add_argument('--publish', action='store_true', help='Write canonical/report files after all input/preflight checks')
    args = parser.parse_args()
    meta_path = resolve(args.run_metadata)
    require(meta_path.suffix == '.json' and meta_path.stat().st_size <= 128 * 1024, 'Bounded run metadata')
    meta_raw = meta_path.read_bytes()
    metadata = json.loads(meta_raw)
    require(metadata['schema'] == SCHEMA, 'Reviewed metadata schema')
    goal, goal_ref = pinned_json(metadata['goal_receipt']['path'], metadata['goal_receipt']['sha256'])
    require(field(goal, metadata['goal_receipt'].get('status_path', 'status')) == 'active', 'Actual active goal-tool receipt')
    require(field(goal, metadata['goal_receipt'].get('objective_path', 'objective')) == OBJECTIVE,
            'Goal receipt corresponds to the resumed full objective')
    proofs = {key: validate_proof(name, metadata[key]) for key, name in
              (('tls', args.tls_proof), ('wire', args.wire_proof))}
    receipts = []
    require(isinstance(metadata['terminal_receipts'], list) and len(metadata['terminal_receipts']) >= 2, 'TLS/wire final terminal receipts')
    for row in metadata['terminal_receipts']:
        receipt, reference = pinned_json(row['path'], row['sha256'])
        result = field(receipt, row['result_path']) if row.get('result_path') else receipt
        require(result['exit_code'] == 0 and 'session_id' not in result and
                result['chunk_id'] == row['chunk_id'], 'Actual terminal EXIT0, no active session')
        receipts.append(dict(reference, chunk_id=row['chunk_id'], exit_code=0))
    checkpoint = {'schema': SCHEMA, 'goal_status': 'active', 'full_goal_complete': False,
                  'required_work_remaining': True, 'goal_receipt': goal_ref, 'proofs': proofs,
                  'terminal_receipts': receipts, 'run_metadata': {'path': str(meta_path.relative_to(ROOT)), 'sha256': digest(meta_raw)},
                  'source_and_test_scope': 'Host-layer TLS/wire implementation only; no native guest, firmware, phone, device or install execution',
                  'device_IO': False, 'native_guest_execution': False,
                  'Garmin_native_receiver_or_Google_Maps_running': False, 'device_install_candidate': False,
                  'remaining_work': copy.deepcopy(GAPS), 'historical_progress_estimates_not_increased': True}
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    web_before = json.loads(before[FILES[4]])
    pid, start = live_server(web_before)
    require(fetch(web_before['url']) == before[FILES[3]], 'Before HTTP matches existing local report')
    now = datetime.now(timezone.utc)
    after, checkpoint = prepare(before, checkpoint, now)
    for name, raw in before.items():
        require((ROOT / name).read_bytes() == raw, 'No concurrent canonical changes: ' + name)
    if not args.publish:
        print(json.dumps({'all_input_and_preflight_checks_passed': True, 'publication_performed': False,
                          'planned_checkpoint': checkpoint, 'report_PID': pid,
                          'host_cases': {k: p['case_count'] for k, p in proofs.items()},
                          'device_IO': False, 'native_guest_execution': False, 'full_goal_complete': False}, ensure_ascii=False))
        return
    out = ROOT / 'staging' / ('android-auto-host-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    (out / 'canonical-before.json.gz').write_bytes(gzip.compress(encoded({k: v.decode() for k, v in before.items()}), mtime=0))
    (out / 'publication-inputs.json').write_bytes(encoded(checkpoint))
    written = []
    try:
        for name in FILES[:4]:
            replace(name, after[name])
            written.append(name)
        served = fetch(web_before['url'])
        require(served == after[FILES[3]], 'Published HTML exact HTTP readback')
        require(live_server(web_before) == (pid, start), 'Server identity unchanged, no restart')
        web = json.loads(after[FILES[4]])
        web.update(HTTP_status=200, local_report_sha256=digest(served), served_report_sha256=digest(served),
                   report_bytes=len(served), served_latest_report=True, service_not_restarted=True,
                   canonical_hash_readback_uncached=True)
        after[FILES[4]] = encoded(web)
        replace(FILES[4], after[FILES[4]])
        written.append(FILES[4])
        require(all((ROOT / name).read_bytes() == raw for name, raw in after.items()), 'Exact canonical readback')
        documents = [json.loads(after[name]) for name in (FILES[0], FILES[1], FILES[2], FILES[4])]
        require(documents[0] == documents[2]['deep_research'] and all(
            d['goal_status'] == 'active' and not d['goal_complete'] and d[FIELD] == checkpoint for d in documents), 'Active incomplete canonical equality')
        receipt = {'all_publication_checks_passed': True, 'updated_at_Taiwan': checkpoint['updated_Taiwan'],
                   'report_url': web_before['url'], 'report_PID': pid, 'service_not_restarted': True,
                   'report_HTTP_exact_bytes': True, 'canonical_after_sha256': {k: digest(v) for k, v in after.items()},
                   'host_cases': {k: p['case_count'] for k, p in proofs.items()},
                   'native_guest_execution': False, 'device_IO': False, 'full_goal_complete': False}
        (out / 'fresh-readback.json').write_bytes(encoded(receipt))
        print(json.dumps(dict(receipt, snapshot=str(out.relative_to(ROOT))), ensure_ascii=False))
    except Exception as error:
        rolled_back, conflicts = [], []
        for name in reversed(written):
            if (ROOT / name).read_bytes() == after[name]:
                replace(name, before[name])
                rolled_back.append(name)
            else:
                conflicts.append(name)
        (out / 'publication-failure.json').write_bytes(encoded({'error': str(error), 'own_changes_rolled_back': rolled_back,
                                                              'concurrent_conflicts_left_untouched': conflicts,
                                                              'native_guest_execution': False, 'device_IO': False}))
        raise


if __name__ == '__main__':
    main()
