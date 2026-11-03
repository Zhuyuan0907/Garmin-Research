#!/usr/bin/env python3
"""Prepare/publish the reviewed TLS + wire + message-assembler host checkpoint.

The default is read-only preflight.  --publish updates only the four canonical
research/report files and evidence/report-web-latest.json, with snapshots and
HTTP readback.  It never executes builders, tests, guest code, service controls,
device access, pairing, calls, audio, or a goal transition.

Run metadata schema:
  schema: "android-auto-pipeline-checkpoint-v1"
  publisher_helper_sha256: hash of publish_android_auto_host_checkpoint_v1.py
  goal_receipt: {path, sha256, status_path, objective_path}
  pipeline: the previous publisher's validate_proof specification, namely
    proof_sha256, claims (dotpath -> exact expected value), pass_claim,
    device_io_claim, native_guest_claim, case_count_claim, case_count,
    source_pins_claim, source_pins, scope, completed.
  prerequisite_reference_paths: {tls: "proof.dotpath", wire: "proof.dotpath"}
    Each referenced pipeline-proof value must be {path, sha256}, exactly equal
    to the matching previous TLS/wire checkpoint proof reference.
  terminal_receipts: [{path, sha256, result_path, chunk_id}, ...]

Prerequisites and all their recorded claims/current source hashes are rechecked
as files only.  The prior TLS15/wire25 checkpoint remains unchanged history;
it is not relabelled as today's pipeline test.  Reviewed text supplied by root
must describe the actual host integration scope and separate it from the phone,
Garmin, real USB, native execution, installation and screen/speaker gaps.
"""
import argparse
import copy
import gzip
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

# This imports only our previous metadata publisher's pure functions/constants.
# Its __main__ block is not run, and none of its prepare/publish code is called.
import publish_android_auto_host_checkpoint_v1 as P

ROOT, FILES = P.ROOT, P.FILES
FIELD = 'latest_android_auto_pipeline_checkpoint'
SCHEMA = 'android-auto-pipeline-checkpoint-v1'
CARD_ID = 'android-auto-pipeline-current-checkpoint-v1'
NEXT_ACTIONS = [
    '接續完成Android Auto控制協商／通道與有界影音佇列；主機端TLS、外層封包及完整訊息組裝已串接驗證，尚未接真正USB主機／VBUS／AOA與Pixel。',
    '建立H.264解碼、保守記憶體配置、螢幕／觸控與音訊介面；原機亂數、時間、配置、載入／菜單、速度、停止重啟和導航共存仍待驗證。',
    'Google Maps及離線使用尚未在Garmin運行成功；藍牙音樂歷史、Android第四版APK及原生App缺口保留。導航修復與麥克風停止，現在不要求裝置／配對，不發來電或播音。',
]
GAPS = [
    'Garmin 實體 USB 主機／VBUS、enumeration 與 AOA bulk 傳輸未驗證。',
    'Android Auto 控制協商、Protobuf／影音通道、媒體佇列與端到端停止／重連仍待整合。',
    '主機 TLS 平台回呼不是 Garmin 的亂數、時間、配置／ABI，手機憑證與實際 Pixel session 未驗證。',
    'H.264 原機解碼效能／記憶體、螢幕顯示及觸控回傳尚未實測。',
    '原機 App 載入／菜單、音訊所有權與導航共存仍未完成；受中斷 native 執行途徑不重試。',
    'Android Auto／Google Maps／原機離線使用尚未成功，沒有可安裝接收端。',
]


def validate_prerequisites(proof, metadata, state):
    prior = state[P.FIELD]
    P.require(prior['goal_status'] == 'active' and not prior['full_goal_complete'], 'Prior limited active host checkpoint')
    references = metadata['prerequisite_reference_paths']
    P.require(set(references) == {'tls', 'wire'}, 'Exactly TLS/wire prerequisite references')
    result = {}
    for key, expected_count in (('tls', 15), ('wire', 25)):
        summary = prior['proofs'][key]
        expected = {k: summary[k] for k in ('path', 'sha256')}
        P.require(P.field(proof, references[key]) == expected, 'Pipeline proof references actual previous ' + key)
        document, reference = P.pinned_json(expected['path'], expected['sha256'])
        P.require(summary['case_count'] == expected_count and summary['host_layer_only'] and
                  not summary['device_IO'] and not summary['native_guest_execution'], 'Previous exact host scope: ' + key)
        for dotted, wanted in summary['verified_claims'].items():
            observed = P.field(document, dotted)
            P.require(type(observed) is type(wanted) and observed == wanted, 'Prerequisite claim: ' + key + ':' + dotted)
        for name, pin in summary['source_pins'].items():
            source = P.resolve(name)
            P.require((source.suffix in ('.c', '.h', '.py', '.json', '.txt', '.md', '.cmake') or source.name == 'COPYING')
                      and source.stat().st_size <= 1024 * 1024 and P.digest(source.read_bytes()) == pin,
                      'Prerequisite tested source remains current: ' + name)
        result[key] = dict(reference, case_count=expected_count,
                           historical_prerequisite_not_new_test=True,
                           current_source_pins_verified=True, device_IO=False, native_guest_execution=False)
    return result


def prepare(before, checkpoint, now):
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    P.require(state == public['deep_research'], 'Prior canonical equality')
    P.require(all(d['goal_status'] == 'active' and not d['goal_complete'] and
                  d['current_goal_priority'] == 'android_auto_google_maps' for d in (state, task, public, web)),
              'Full resumed objective remains active and incomplete')
    P.require(state['requested_goal'] == P.OBJECTIVE and state['last_goal_turn']['classification'] == 'progress',
              'Previous actual TLS/wire goal turn was progress')
    P.require(state['navigation_repair']['status'] == 'stopped_by_user' and
              state['microphone_amplifier']['status'] == 'cancelled_by_user', 'Cancellations preserved')
    P.require(task['user_away'] and not state['audio']['audible_tests_allowed'] and
              not web['current_physical_test_requested'], 'No unattended device or audio test')
    P.require(not state['native_android_auto']['native_receiver_running'] and
              not state['native_android_auto']['phone_session_verified'] and
              not state['native_app_music']['native_app_running'] and
              not state['native_app_music']['direct_phone_music_verified'] and
              not state['google_maps']['native_running'], 'Target running/audio/install goals still unproven')
    preserved_keys = ('audio', 'navigation_repair', 'microphone_amplifier', 'native_app_music', 'google_maps',
                      P.FIELD, 'bluetooth_music_blocking_audit', 'research_goal_status_history')
    preserved = {k: copy.deepcopy(state[k]) for k in preserved_keys}
    old_progress = copy.deepcopy(public['research_progress'])
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp, display = local.isoformat(timespec='seconds'), local.strftime('%Y/%m/%d %H:%M:%S')
    checkpoint.update(updated_utc=now.isoformat(), updated_Taiwan=stamp)
    turn = {'classification': 'progress', 'previous_goal_turn_assessment': 'progress',
            'validated_utc': now.isoformat(), 'goal_status': 'active', 'required_work_remaining': True,
            'full_goal_complete': False, 'focused_evidence': copy.deepcopy(checkpoint['pipeline']),
            'prerequisite_evidence': copy.deepcopy(checkpoint['prerequisites']),
            'host_layer_implementation_and_verification': True, 'native_guest_execution': False,
            'device_IO': False, 'device_files_written': False, 'device_calls_or_sound': False,
            'reason': 'Actual host TLS/wire/message-assembler integration verified; previous TLS15/wire25 retained as prerequisites, no phone/native/install success.'}
    state.update(updated_utc=now.isoformat(), goal_status='active', goal_complete=False,
                 current_priority='GarminOS Android Auto／Google Maps；主機端TLS、外層封包與完整訊息組裝整合。',
                 next_actions=copy.deepcopy(NEXT_ACTIONS), last_goal_turn=turn)
    state[FIELD] = copy.deepcopy(checkpoint)
    state['android_auto_blocking_audit'].update(updated_utc=now.isoformat(), condition=None,
        consecutive_no_progress_goal_turns=0, current_goal_turn_classification='progress',
        goal_status='active', full_goal_complete=False)
    aa = state['native_android_auto']
    aa[FIELD] = copy.deepcopy(checkpoint)
    aa['remaining_work'] = copy.deepcopy(GAPS)
    work = state['offline_24h_work_order']
    work[FIELD] = copy.deepcopy(checkpoint)
    work.update(goal_status='active', actual_goal_status_read='active', current_blocking_reason=None,
                current_priority='android_auto_google_maps', whole_goal_complete=False)
    work['current_offline_line_status']['android_auto'] = 'Host TLS/wire/message assembly integration verified; real USB, phone, native video/UI/audio and install unverified'
    for document in (task, public, web):
        for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', FIELD,
                    'offline_24h_work_order', 'android_auto_blocking_audit'):
            document[key] = copy.deepcopy(state[key])
        document.update(goal_status='active', goal_complete=False, required_work_remaining=True)
        document.pop('goal_blocked_reason', None)
    task['native_android_auto'] = copy.deepcopy(aa)
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state))
    completed = checkpoint['pipeline']['completed']
    progress = public['research_progress']
    progress['completed'].extend(completed)
    progress.update(research_updated_utc=now.isoformat(), next=NEXT_ACTIONS[0], goal_completed=False,
        method='沿用完整研究計畫的歷史工程估計；本輪TLS、外層封包及完整訊息組裝僅主機端驗證，不提高原機百分比。Android Auto／Google Maps主線繼續，導航修復及麥克風停止。')
    phase_next = {'USB 主機與手機連線': NEXT_ACTIONS[0],
                  '畫面、影片與觸控投影': NEXT_ACTIONS[1],
                  '原生 App 入口與功能整合': '完成Android Auto原機載入／菜單、平台介面、控制／影音整合及停止／重連；主機pipeline不是可安裝App。'}
    for phase in progress['phases']:
        if phase['name'] in phase_next:
            phase['next'] = phase_next[phase['name']]
    P.require(progress['estimate_percent'] == old_progress['estimate_percent'] and
              progress['weighted_estimate_percent'] == old_progress['weighted_estimate_percent'] and
              [(p['name'], p['weight'], p['estimate_percent'], p['deferred']) for p in progress['phases']] ==
              [(p['name'], p['weight'], p['estimate_percent'], p['deferred']) for p in old_progress['phases']],
              'No estimate, weight or deferred milestone changes')
    P.require(all(state[k] == old for k, old in preserved.items()), 'Historical host/BT/native/audio/navigation/maps objects preserved')
    report = before[FILES[3]].decode()
    P.require(CARD_ID not in report, 'Pipeline v1 not already published')
    previous = re.search(r'<section class="card" id="' + P.CARD_ID + r'">.*?</section>', report, re.S)
    P.require(previous is not None, 'Previous TLS15/wire25 HTML checkpoint')
    prior_card = previous.group()
    report = report.replace(prior_card, '<details class="card" id="android-auto-host-checkpoint-history-v1">'
        '<summary>前一輪主機層紀錄：TLS 15 類／外層封包 25 類（2026/10/08 07:38）</summary>' + prior_card + '</details>', 1)
    e = html.escape
    steps = ''.join('<li>' + e(text) + '</li>' for text in completed)
    gaps = ''.join('<li>' + e(text) + '</li>' for text in GAPS)
    card = (f'<section class="card" id="{CARD_ID}"><h2>目前主線：Android Auto 主機資料流程整合</h2>'
        f'<p>目標 active／尚未完成。更新：<time datetime="{stamp}">{display}</time>（台灣時間）</p>'
        '<p>本輪把主機端TLS、外層封包及完整訊息組裝接在一起驗證；GarminOS Android Auto／Google Maps仍是完整目標。</p>'
        '<h3>本輪已完成</h3><ul>' + steps + '</ul>'
        '<p><strong>驗證範圍：</strong>' + e(checkpoint['pipeline']['scope']) + '；'
        + str(checkpoint['pipeline']['case_count']) + '項主機檢查。前輪TLS15／wire25是獨立已驗證前置，沒有把它們算作本輪重測或原機成果。</p>'
        '<p><strong>藍牙音樂現況：</strong>Pixel → Pi → Garmin 持續60秒有聲屬使用者確認的歷史實測；'
        'Android第四版APK只有編譯／DEX／API28簽章及18項gate＋12項lease主機檢查，'
        'Pixel本機通話、SCO與Garmin出聲仍未驗證。原機直接A2DP與GarminOS菜單App仍未完成。'
        '<a href="/garmin-hfp-prototype.apk" download="garmin-hfp-prototype.apk">保留的第四版實驗APK</a>。</p>'
        '<h3>仍待完成</h3><ul>' + gaps + '</ul>'
        '<p>這輪沒有接手機或車機、執行原native guest、修改原機callsite、配對、發來電或播音；原機執行中斷界線保留。'
        '工程估計維持' + str(progress['estimate_percent']) + '%，不是Android Auto完成率。導航修復與麥克風停止，沒有可安裝接收端。</p></section>')
    P.require(report.count('<main>') == 1, 'Single report main')
    report = report.replace('<main>', '<main>' + card, 1)
    report = P.substitute(report, r'<span class="progress-status">.*?</span>',
        '<span class="progress-status">Android Auto／Google Maps：主機資料流程整合中</span>', 'current progress status')
    report = P.substitute(report, r'<p id="progress-method"[^>]*>.*?</p>',
        '<p id="progress-method" class="progress-note">' + e(progress['method']) + '</p>', 'method')
    report = P.substitute(report, r'<p id="offline-frontier-latest-v1">.*?</p>',
        '<p id="offline-frontier-latest-v1">最新：TLS、外層封包與完整訊息組裝主機整合已驗證；原機USB、Pixel投影、H.264／螢幕、觸控、音訊與安裝仍未驗收。Android Auto／Google Maps目標active／尚未完成。</p>', 'frontier')
    report = P.substitute(report, r'<p><strong>下一步：</strong>.*?</p>',
        '<p><strong>下一步：</strong>' + e(NEXT_ACTIONS[0]) + '</p>', 'next')
    old_list = re.search(r'<ul class="completed-progress">.*?</ul>', report, re.S)
    P.require(old_list is not None, 'Historical completed progress list')
    report = report.replace(old_list.group(), old_list.group()[:-5] + steps + '</ul>', 1)
    for phase in progress['phases']:
        if phase['name'] in phase_next:
            report = P.substitute(report, r'<tr><td>' + re.escape(e(phase['name'])) + r'</td><td>.*?</td><td>.*?</td></tr>',
                '<tr><td>' + e(phase['name']) + '</td><td>' + str(phase['estimate_percent']) + '%</td><td>'
                + e(phase['next']) + '</td></tr>', 'phase ' + phase['name'])
    for element in ('report-updated-time', 'research-updated-time'):
        report = P.substitute(report, r'<time id="' + element + r'" datetime="[^"]+">[^<]+</time>',
            f'<time id="{element}" datetime="{stamp}">{display}</time>', element)
    P.require(not P.PRIVATE.search(report), 'No unit identifiers, phone addresses or private key in public report')
    P.require(report.index('id="' + CARD_ID + '"') < report.index('id="' + P.CARD_ID + '"'), 'New pipeline checkpoint is first')
    web.update(full_goal_complete=False, actual_goal_status_read='active', current_physical_test_requested=False)
    web['progress_display_verified'].update(estimate_percent=progress['estimate_percent'], completed_items=len(progress['completed']),
        report_updated_time=stamp, research_updated_time=stamp, android_auto_pipeline_checkpoint_visible=True,
        prior_TLS_wire_checkpoint_preserved_as_history=True, HTML_structure_checked=False,
        visual_browser_render_not_performed=True)
    return {FILES[0]: P.encoded(state), FILES[1]: P.encoded(task), FILES[2]: P.encoded(public),
            FILES[3]: report.encode(), FILES[4]: P.encoded(web)}, checkpoint


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proof', required=True)
    parser.add_argument('--run-metadata', required=True)
    parser.add_argument('--publish', action='store_true', help='Write canonical/report files after preflight; default only checks')
    args = parser.parse_args()
    meta_path = P.resolve(args.run_metadata)
    P.require(meta_path.suffix == '.json' and meta_path.stat().st_size <= 128 * 1024, 'Bounded run metadata')
    meta_raw = meta_path.read_bytes()
    metadata = json.loads(meta_raw)
    P.require(metadata['schema'] == SCHEMA, 'Pipeline run metadata schema')
    P.require(P.digest(Path(P.__file__).read_bytes()) == metadata['publisher_helper_sha256'], 'Reviewed shared publisher implementation')
    goal, goal_ref = P.pinned_json(metadata['goal_receipt']['path'], metadata['goal_receipt']['sha256'])
    P.require(P.field(goal, metadata['goal_receipt'].get('status_path', 'status')) == 'active' and
              P.field(goal, metadata['goal_receipt'].get('objective_path', 'objective')) == P.OBJECTIVE,
              'Actual active goal tool receipt for full resumed objective')
    pipeline = P.validate_proof(args.proof, metadata['pipeline'])
    proof, unused = P.pinned_json(args.proof, metadata['pipeline']['proof_sha256'])
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    prerequisites = validate_prerequisites(proof, metadata, json.loads(before[FILES[0]]))
    P.require(isinstance(metadata['terminal_receipts'], list) and metadata['terminal_receipts'], 'Actual finished pipeline test receipts')
    receipts = []
    for row in metadata['terminal_receipts']:
        receipt, reference = P.pinned_json(row['path'], row['sha256'])
        result = P.field(receipt, row['result_path']) if row.get('result_path') else receipt
        P.require(result['exit_code'] == 0 and 'session_id' not in result and result['chunk_id'] == row['chunk_id'],
                  'Actual final EXIT0 tool receipt, no running session')
        receipts.append(dict(reference, chunk_id=row['chunk_id'], exit_code=0))
    checkpoint = {'schema': SCHEMA, 'goal_status': 'active', 'full_goal_complete': False,
        'required_work_remaining': True, 'goal_receipt': goal_ref, 'pipeline': pipeline, 'prerequisites': prerequisites,
        'terminal_receipts': receipts, 'run_metadata': {'path': str(meta_path.relative_to(ROOT)), 'sha256': P.digest(meta_raw)},
        'source_and_test_scope': 'Host TLS/wire/message assembly integration only; no native guest, phone, real USB, installation or screen/speaker success',
        'device_IO': False, 'native_guest_execution': False,
        'Garmin_native_receiver_or_Google_Maps_running': False, 'device_install_candidate': False,
        'remaining_work': copy.deepcopy(GAPS), 'historical_progress_estimates_not_increased': True}
    web_before = json.loads(before[FILES[4]])
    pid, start = P.live_server(web_before)
    P.require(P.fetch(web_before['url']) == before[FILES[3]], 'Before HTTP equals current local report')
    now = datetime.now(timezone.utc)
    after, checkpoint = prepare(before, checkpoint, now)
    P.require(all((ROOT / name).read_bytes() == raw for name, raw in before.items()), 'No concurrent canonical changes')
    if not args.publish:
        print(json.dumps({'all_input_and_preflight_checks_passed': True, 'publication_performed': False,
            'planned_checkpoint': checkpoint, 'report_PID': pid, 'host_pipeline_cases': pipeline['case_count'],
            'native_guest_execution': False, 'device_IO': False, 'full_goal_complete': False}, ensure_ascii=False))
        return
    out = ROOT / 'staging' / ('android-auto-pipeline-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    (out / 'canonical-before.json.gz').write_bytes(gzip.compress(P.encoded({k: v.decode() for k, v in before.items()}), mtime=0))
    (out / 'publication-inputs.json').write_bytes(P.encoded(checkpoint))
    written = []
    try:
        for name in FILES[:4]:
            P.replace(name, after[name])
            written.append(name)
        served = P.fetch(web_before['url'])
        P.require(served == after[FILES[3]], 'Published HTML exact HTTP readback')
        P.require(P.live_server(web_before) == (pid, start), 'Same report PID/start ticks; no service restart')
        web = json.loads(after[FILES[4]])
        web.update(HTTP_status=200, local_report_sha256=P.digest(served), served_report_sha256=P.digest(served),
                   report_bytes=len(served), served_latest_report=True, service_not_restarted=True,
                   canonical_hash_readback_uncached=True)
        after[FILES[4]] = P.encoded(web)
        P.replace(FILES[4], after[FILES[4]])
        written.append(FILES[4])
        P.require(all((ROOT / name).read_bytes() == raw for name, raw in after.items()), 'Exact canonical file readback')
        docs = [json.loads(after[name]) for name in (FILES[0], FILES[1], FILES[2], FILES[4])]
        P.require(docs[0] == docs[2]['deep_research'] and all(d['goal_status'] == 'active' and
                  not d['goal_complete'] and d[FIELD] == checkpoint for d in docs), 'Active/incomplete canonical equality')
        receipt = {'all_publication_checks_passed': True, 'updated_at_Taiwan': checkpoint['updated_Taiwan'],
            'report_url': web_before['url'], 'report_PID': pid, 'service_not_restarted': True, 'report_HTTP_exact_bytes': True,
            'canonical_after_sha256': {k: P.digest(v) for k, v in after.items()}, 'host_pipeline_cases': pipeline['case_count'],
            'prerequisite_host_cases': {'tls': 15, 'wire': 25}, 'prior_checkpoint_preserved': True,
            'native_guest_execution': False, 'device_IO': False, 'full_goal_complete': False}
        (out / 'fresh-readback.json').write_bytes(P.encoded(receipt))
        print(json.dumps(dict(receipt, snapshot=str(out.relative_to(ROOT))), ensure_ascii=False))
    except Exception as error:
        rolled_back, conflicts = [], []
        for name in reversed(written):
            if (ROOT / name).read_bytes() == after[name]:
                P.replace(name, before[name])
                rolled_back.append(name)
            else:
                conflicts.append(name)
        (out / 'publication-failure.json').write_bytes(P.encoded({'error': str(error),
            'own_changes_rolled_back': rolled_back, 'concurrent_conflicts_left_untouched': conflicts,
            'native_guest_execution': False, 'device_IO': False}))
        raise


if __name__ == '__main__':
    main()
