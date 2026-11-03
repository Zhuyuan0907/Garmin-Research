#!/usr/bin/env python3
"""Publish completed static platform/portability review; no runtime/device work.

Default is a read-only preflight. --publish updates the same five existing
canonical/report files, checks exact HTTP bytes and unchanged service identity,
and rolls back only its own changes on failure. No goal transition is issued.
"""
import argparse
import copy
import datetime
import gzip
import html
import json
from pathlib import Path
import re
from zoneinfo import ZoneInfo

import publish_android_auto_host_checkpoint_v1 as P

ROOT, FILES = P.ROOT, P.FILES
FIELD = 'latest_android_auto_platform_gate_review'
CARD = 'android-auto-platform-gate-review-v1'
INPUTS = {
    'usb_board': ('evidence/android-auto-usb-board-primary-review-v1.json',
                  'ce9a9e9fbcf5dbe6b8fac3e0942ebb858140acfd316bc265c148aab6d8d3b853'),
    'host_artifacts': ('evidence/android-auto-host-portability-v1.json',
                       '2839110643a4ddb69df760fe4f628d6d48e48fc97faaf4e488a9724e09963895'),
    'port_contracts': ('evidence/android-auto-native-port-contract-review-v1.json',
                       '62cbdefa02dc48e86b067b546019ea6284c00a6b1d26da7b5268669ba1f8826d'),
    'official_sdk_list': ('staging/android-auto-platform-gates-review-v1/official-connect-iq-retrieval.json',
                         'd763c815f359c40dc134b1df82ffc058478d195e4a9f5d0f3971de6239db86f2'),
}
COMPLETED = [
    '核對精確台灣2565RT官方手冊與有限官方服務圖搜尋：已知USB隨身碟／車架電源輸入／GDR10專用連接，仍無板級USB host／VBUS／Hub／AOA驗證。',
    '核對官方Connect IQ支援清單，沒有此nüvi的SDK目標；保留歷史2.10→WFFF→2.10診斷執行證據，不推論所有自製程式皆不可載入。',
    '靜態核對六個既有host程式的實際byte hash／ELF／DT_NEEDED／imports；全為64位AArch64共享程式，尚非Garmin安裝模組。',
    '核對21份公開OpenH264來源與官方commit封裝一致，列明零threads下的配置／CPU查詢／時鐘／logging移植需求與條件thread分支；runtime案例為0，未實作移植。',
]
NEXT = [
    '取得精確原機USB host／VBUS／AOA與可用程式載入／平台API證據；公開資料與host測試尚未補齊這兩個條件。等使用者主動通知可實測，不詢問在場或要求配對。',
    '平台入口成立後才驗證受限單執行緒H264與32位ABI／配置／時鐘／CRT／清理合約，並接真正顯示／觸控／音訊所有權與current phone。原受中斷native分支不重試／繞過。',
    '原機Android Auto／Google Maps、直接A2DP與菜單播放器仍未完成；Pi音樂轉送保留為另一條已實機成功的路徑。導航／麥克風研究停止。',
]


def verify_inputs():
    docs, refs = {}, {}
    for key, (name, pin) in INPUTS.items():
        docs[key], refs[key] = P.pinned_json(name, pin)
    board = docs['usb_board']
    P.require(board['scope']['runtime_tests'] == 0 and not board['scope']['device_io'] and
              not board['conclusion']['exact_board_generic_usb_host_verified'] and
              not board['conclusion']['capability_absent_proved'], 'Exact-board review has no unsupported success/absence')
    for name, pin in board['source_sha256'].items():
        P.require(P.digest(P.resolve(name).read_bytes()) == pin, 'Current saved hardware source: ' + name)
    artifacts = docs['host_artifacts']
    P.require(artifacts['pass'] and artifacts['artifact_count'] == 6 and not artifacts['device_IO'] and
              not artifacts['native_guest_executed'] and not artifacts['install_candidate'], 'Static own-artifact scope')
    for row in artifacts['objects'].values():
        for key in ('proof', 'artifact'):
            p = row[key]
            P.require(P.digest(P.resolve(p['path']).read_bytes()) == p['sha256'], 'Actual unchanged tested artifact/evidence')
        P.require(row['header']['Class'] == 'ELF64' and row['header']['Machine'] == 'AArch64' and
                  not row['runtime_call_reachability_verified'], 'Host ABI, no runtime call inference')
    contract = docs['port_contracts']
    P.require(contract['public_source_files_archive_verified'] == 21 and contract['runtime_tests'] == 0 and
              not contract['port_implemented'] and not contract['compile_or_link_performed'] and
              not contract['install_candidate'], 'Public source contract review only')
    for document in (artifacts, contract):
        for name, pin in document['source_sha256'].items():
            P.require(P.digest(P.resolve(name).read_bytes()) == pin, 'Current own/public source pin')
    sdk = docs['official_sdk_list']
    snap = P.resolve(sdk['snapshot'])
    raw = gzip.decompress(snap.read_bytes())
    P.require(P.digest(snap.read_bytes()) == sdk['snapshot_sha256'] and P.digest(raw) == sdk['raw_sha256'] and
              sdk['HTTP_status'] == 200 and not any(sdk['exact_model_or_HWID_strings_found'].values()), 'Exact official support snapshot')
    historical = {}
    for key, name, claim in (
        ('modified_diagnostic', 'evidence/native-warm-probe-physical-positive-20261005T045004Z.json',
         'physical_modified_diagnostic_code_execution_observed'),
        ('diagnostic_restore', 'evidence/native-warm-probe-physical-final-control-20261005T045419Z.json',
         'physical_A_B_A_sequence_complete'),
    ):
        d = json.loads(P.resolve(name).read_text())
        P.require(d[claim] is True, 'Historical diagnostic positive/restore preserved')
        historical[key] = {'path': name, 'sha256': P.digest(P.resolve(name).read_bytes()),
                           'historical_not_rerun': True}
    return refs, historical


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--goal-receipt', required=True)
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    goal_path = P.resolve(args.goal_receipt)
    goal = json.loads(goal_path.read_text())
    P.require(goal['goal']['status'] == 'active' and goal['goal']['objective'] == P.OBJECTIVE, 'Actual full-objective active receipt')
    refs, historical = verify_inputs()
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public, web = [json.loads(before[name]) for name in (FILES[0], FILES[1], FILES[2], FILES[4])]
    P.require(public['deep_research'] == state and all(d['goal_status'] == 'active' and not d['goal_complete']
              for d in (state, task, public, web)), 'Canonical active, incomplete equality')
    P.require(state['last_goal_turn']['classification'] == 'progress' and
              state['latest_android_auto_interactive_checkpoint']['proofs']['integration']['case_count'] == 13,
              'Prior actual interactive13 publication')
    P.require(task['user_away'] and not state['audio']['audible_tests_allowed'] and
              state['navigation_repair']['status'] == 'stopped_by_user' and
              state['microphone_amplifier']['status'] == 'cancelled_by_user', 'Authorized unattended scope')
    P.require(not state['native_android_auto']['native_receiver_running'] and not state['google_maps']['native_running'] and
              not state['native_app_music']['direct_phone_music_verified'], 'No native success inferred')
    preserved = {key: copy.deepcopy(value) for key, value in state.items() if
                 key.startswith('latest_android_auto_') or key in ('audio', 'google_maps', 'native_app_music',
                 'navigation_repair', 'microphone_amplifier', 'bluetooth_music_blocking_audit', 'research_goal_status_history')}
    progress_before = copy.deepcopy(public['research_progress'])
    now = datetime.datetime.now(datetime.timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp, display = local.isoformat(timespec='seconds'), local.strftime('%Y/%m/%d %H:%M:%S')
    checkpoint = {'schema': 'android-auto-platform-gate-review-v1', 'updated_utc': now.isoformat(),
                  'updated_Taiwan': stamp, 'goal_status': 'active', 'full_goal_complete': False,
                  'goal_receipt': {'path': str(goal_path.relative_to(ROOT)), 'sha256': P.digest(goal_path.read_bytes())},
                  'evidence': refs, 'historical_diagnostic_execution': historical,
                  'static_artifact_count': 6, 'public_codec_source_files_verified': 21, 'runtime_tests': 0,
                  'device_IO': False, 'native_guest_execution': False, 'crosscompile': False,
                  'native_port_implemented': False, 'exact_board_host_VBUS_AOA_verified': False,
                  'device_install_candidate': False, 'current_phone_or_hardware_or_Maps_verified': False,
                  'prior_pipeline_and_percent_preserved': True, 'next_actions': NEXT}
    turn = {'classification': 'progress', 'previous_goal_turn_assessment': 'progress',
            'reason': 'New actual static artifact ABI/dependency inventory and exact-model primary-source review establish concrete native port/platform requirements; no device/runtime success.',
            'validated_utc': now.isoformat(), 'goal_status': 'active', 'required_work_remaining': True,
            'full_goal_complete': False, 'focused_evidence': refs, 'device_IO': False,
            'native_guest_execution': False, 'hardware_display_touch_or_speaker_verified': False,
            'runtime_tests_this_turn': 0, 'software_binaries_changed': False}
    state.update(updated_utc=now.isoformat(), current_priority='原機Android Auto／Google Maps：USB角色／可達載入入口與非Linux移植條件查證。',
                 next_actions=copy.deepcopy(NEXT), last_goal_turn=turn)
    state[FIELD] = checkpoint
    state['native_android_auto'][FIELD] = copy.deepcopy(checkpoint)
    state['offline_24h_work_order'][FIELD] = copy.deepcopy(checkpoint)
    state['offline_24h_work_order']['current_offline_line_status']['android_auto'] = (
        'Exact-board primary-source and own-host ABI/port-contract review complete; real transport/loading, phone and hardware remain unverified')
    state['android_auto_blocking_audit'].update(updated_utc=now.isoformat(), condition=None,
        consecutive_no_progress_goal_turns=0, current_goal_turn_classification='progress', goal_status='active')
    P.require(all(state[key] == old for key, old in preserved.items()), 'All prior evidence and user cancellations retained')
    for d in (task, public, web):
        for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', 'android_auto_blocking_audit', 'offline_24h_work_order', FIELD):
            d[key] = copy.deepcopy(state[key])
        d.update(required_work_remaining=True, goal_status='active', goal_complete=False)
    task['native_android_auto'] = copy.deepcopy(state['native_android_auto'])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state))
    progress = public['research_progress']
    progress['completed'].extend(COMPLETED)
    progress.update(research_updated_utc=now.isoformat(), next=NEXT[0], goal_completed=False)
    P.require(progress['estimate_percent'] == progress_before['estimate_percent'] == 37 and
              progress['weighted_estimate_percent'] == progress_before['weighted_estimate_percent'] and
              progress['phases'] == progress_before['phases'], 'Engineering estimates and phases unchanged')
    e = html.escape
    steps = ''.join('<li>' + e(s) + '</li>' for s in COMPLETED)
    card = (f'<section class="card" id="{CARD}"><h2>原機安裝條件查證：USB、程式載入與非Linux移植</h2>'
        f'<p>更新：<time datetime="{stamp}">{display}</time>（台灣時間）；完整目標仍未完成。</p>'
        '<p>本輪只查官方資料、既有host程式與公開codec來源，新增runtime案例為0，沒有車機操作或新安裝。</p><ul>' + steps + '</ul>'
        '<p><strong>結論：</strong>USB主機與板級供電、可用App／平台入口仍未驗證。零threads不能讓現有H264 binary成為freestanding；CPU查詢、時鐘、配置及部分logging仍需移植。尚未實作或編譯該移植。</p>'
        '<p>官方Connect IQ清單沒有此nüvi；歷史WFFF診斷成功仍保留，這不等於原機播放器已運行。沒有找到服務圖不代表硬體功能不存在。</p>'
        '<p>來源：<a href="https://download.garmin.com/tw/download/manuals/nuvi2555_2565T_2565RT_TW_0B.pdf">Garmin台灣手冊</a>、'
        '<a href="https://developer.garmin.com/connect-iq/compatible-devices/">Connect IQ支援裝置</a>、'
        '<a href="https://developer.android.com/develop/connectivity/usb/accessory">Android USB accessory角色</a>。</p>'
        '<p>前輪主機互動13／video20／H26476測試完整保留，未重跑；工程估計37%不變。實際手機、Garmin螢幕／喇叭、原機AA／Google Maps與直接A2DP未完成。</p></section>')
    report = before[FILES[3]].decode()
    P.require(CARD not in report and report.count('<main>') == 1, 'New one-time card, single main')
    report = report.replace('<main>', '<main>' + card, 1)
    report = P.substitute(report, r'<span class="progress-status">.*?</span>',
        '<span class="progress-status">Android Auto／Google Maps：原機安裝條件查證</span>', 'status')
    report = P.substitute(report, r'<p><strong>下一步：</strong>.*?</p>',
        '<p><strong>下一步：</strong>' + e(NEXT[0]) + '</p>', 'next')
    old_list = re.search(r'<ul class="completed-progress">.*?</ul>', report, re.S)
    P.require(old_list is not None, 'Existing detailed completed list')
    report = report.replace(old_list.group(), old_list.group()[:-5] + steps + '</ul>', 1)
    for element in ('report-updated-time', 'research-updated-time'):
        report = P.substitute(report, r'<time id="' + element + r'" datetime="[^"]+">[^<]+</time>',
            f'<time id="{element}" datetime="{stamp}">{display}</time>', element)
    P.require(not P.PRIVATE.search(report), 'No private identifiers')
    web.update(full_goal_complete=False, actual_goal_status_read='active', current_physical_test_requested=False)
    web['progress_display_verified'].update(completed_items=len(progress['completed']), report_updated_time=stamp,
        research_updated_time=stamp, platform_gate_static_review_visible=True,
        source_or_ELF_inventory_not_runtime_verified_visible=True, native_install_not_claimed=True)
    after = {FILES[0]: P.encoded(state), FILES[1]: P.encoded(task), FILES[2]: P.encoded(public),
             FILES[3]: report.encode(), FILES[4]: P.encoded(web)}
    web_before = json.loads(before[FILES[4]])
    pid, started = P.live_server(web_before)
    P.require(P.fetch(web_before['url']) == before[FILES[3]], 'Exact HTTP before')
    P.require(all((ROOT / name).read_bytes() == raw for name, raw in before.items()), 'No concurrent canonical edit')
    summary = {'all_review_checks_passed': True, 'goal_status': 'active', 'full_goal_complete': False,
               'runtime_tests': 0, 'host_artifacts': 6, 'public_source_files': 21,
               'exact_board_host_VBUS_AOA_verified': False, 'native_port_implemented': False,
               'device_IO': False, 'install_candidate': False, 'report_PID': pid,
               'updated_at_Taiwan': stamp, 'report_url': web_before['url']}
    if not args.publish:
        print(json.dumps(dict(summary, publication_performed=False), ensure_ascii=False))
        return
    snap = ROOT / 'staging' / ('aa-platform-review-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    snap.mkdir(mode=0o700)
    (snap / 'canonical-before.json.gz').write_bytes(gzip.compress(P.encoded({n: b.decode() for n, b in before.items()}), mtime=0))
    (snap / 'review-checkpoint.json').write_bytes(P.encoded(checkpoint))
    written = []
    try:
        for name in FILES[:4]:
            P.replace(name, after[name]); written.append(name)
        served = P.fetch(web_before['url'])
        P.require(served == after[FILES[3]] and P.live_server(web_before) == (pid, started), 'Exact served bytes, no restart')
        web.update(HTTP_status=200, served_latest_report=True, local_report_sha256=P.digest(served),
                   served_report_sha256=P.digest(served), report_bytes=len(served), service_not_restarted=True)
        after[FILES[4]] = P.encoded(web)
        P.replace(FILES[4], after[FILES[4]]); written.append(FILES[4])
        P.require(all((ROOT / n).read_bytes() == b for n, b in after.items()), 'Five exact canonical readbacks')
        print(json.dumps(dict(summary, publication_performed=True, report_HTTP_exact_bytes=True,
            service_not_restarted=True, canonical_after_sha256={n:P.digest(b) for n,b in after.items()},
            snapshot=str(snap.relative_to(ROOT))), ensure_ascii=False))
    except BaseException:
        for name in reversed(written):
            P.require((ROOT / name).read_bytes() == after[name], 'Only own writes may be rolled back')
            P.replace(name, before[name])
        raise


if __name__ == '__main__':
    main()
