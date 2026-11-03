#!/usr/bin/env python3
"""Preflight/publish reviewed AA control and independent protobuf host proofs.

Default is read-only preflight. --publish atomically replaces each of the four
JSON/HTML research files plus report-web-latest.json, with snapshots, rollback of
our changes on failure, exact HTTP readback and unchanged report process identity.
No build, test, guest, device, service restart, pairing, call or sound is executed.

Metadata schema: android-auto-control-checkpoint-v1
  publisher_helper_sha256: hash of publish_android_auto_host_checkpoint_v1.py
  goal_receipt: {path, sha256, status_path, objective_path}
  previous_goal_turn_assessment: "no_progress"
  previous_goal_turn_reason: truthful description of the status-only goal turn
  control / proto: {proof_sha256, claims (dotpath -> exact expected value),
    pass_claim, device_io_claim, native_guest_claim, case_count_claim, case_count,
    source_pins_claim, source_pins, scope, completed}
  terminal_receipts: [{path, sha256, result_path, chunk_id,
                       covers: ["control", "proto"]}, ...]
    One actual EXIT0 tool result may cover both proofs if it ran both producers;
    separate results may cover each. No invented or active-session receipt.
  control_proto_reference_path: optional dotpath for {path,sha256} in control proof

Control proof schema: android-auto-control-host-v1; prerequisite.startup must pin
the previous startup29 proof. Proto schema: android-auto-proto-host-v1. All claims,
source hashes (including .proto), final tool results and the actual active goal
receipt are checked as files. The separate proto proof is not implicitly relabelled
as a current-phone protocol test or as proof of the whole native receiver.
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

import publish_android_auto_host_checkpoint_v1 as P

ROOT, FILES = P.ROOT, P.FILES
FIELD = 'latest_android_auto_control_checkpoint'
SCHEMA = 'android-auto-control-checkpoint-v1'
CARD_ID = 'android-auto-control-current-checkpoint-v1'
PRIOR_FIELD = 'latest_android_auto_startup_checkpoint'
PRIOR_CARD_ID = 'android-auto-startup-current-checkpoint-v1'
NEXT_ACTIONS = [
    '接續整合可取消的影音資料佇列、media傳送／接收與流量控制，並核對真正USB主機／VBUS／AOA與current phone介面；本輪控制與Protobuf結果僅Linux-host。',
    '完成H.264解碼與保守記憶體／效能驗證、螢幕／觸控／音訊與原機App／菜單平台介面；原native執行中斷分支不重試或繞過。',
    'Android Auto／Google Maps／原機離線使用與可安裝接收端仍未完成；BT及Android第四版歷史保留，導航修復／麥克風停止。使用者會主動通知可實測，現在不查裝置、要求配對、發來電或播音。',
]
GAPS = [
    '本地peer及固定legacy service／channel／media模型未證current Pixel／Google接受。',
    '真正USB主機／VBUS、enumeration與AOA bulk傳輸尚未在Garmin驗證。',
    '完整影音串流、媒體佇列／ACK生命週期、可靠停止／重連與現行手機協定仍待整合。',
    'H.264原機解碼效能／可用記憶體、螢幕、觸控、音訊所有權及導航共存尚未驗證。',
    '原機亂數／時間／配置／ABI、App載入／菜單與安裝包未完成；原native guest界線保留。',
    'Garmin Android Auto／Google Maps／原機離線使用均未成功，phone／Google／native／installation／full-goal完成旗標仍false。',
]


def source_pin(name, pin):
    source = P.resolve(name)
    P.require((source.suffix in ('.c', '.h', '.py', '.json', '.txt', '.md', '.cmake', '.proto', '.options') or source.name in ('COPYING', 'protoc-gen-nanopb'))
              and source.stat().st_size <= 1024 * 1024, 'Bounded source-only pin: ' + name)
    P.require(P.digest(source.read_bytes()) == pin, 'Tested source remains current: ' + name)


def validate_proof(name, spec, schema):
    proof, reference = P.pinned_json(name, spec['proof_sha256'])
    P.require(proof['schema'] == schema, 'Actual proof schema: ' + schema)
    P.require(isinstance(spec['claims'], dict) and spec['claims'], 'Reviewed exact proof claims')
    for dotted, wanted in spec['claims'].items():
        observed = P.field(proof, dotted)
        P.require(type(observed) is type(wanted) and observed == wanted, 'Exact proof claim ' + name + ':' + dotted)
    for key, wanted in (('pass_claim', True), ('device_io_claim', False), ('native_guest_claim', False)):
        dotted = spec[key]
        P.require(dotted in spec['claims'] and P.field(proof, dotted) is wanted, 'Explicit host-only evidence: ' + key)
    count = spec['case_count']
    P.require(type(count) is int and count > 0 and spec['case_count_claim'] in spec['claims'] and
              type(P.field(proof, spec['case_count_claim'])) is int and
              P.field(proof, spec['case_count_claim']) == count, 'Actual host test count')
    recorded = P.field(proof, spec['source_pins_claim'])
    P.require(isinstance(recorded, dict) and spec['source_pins_claim'] in spec['claims'], 'Proof records reviewed source dictionary')
    pins = {key: (value['sha256'] if isinstance(value, dict) else value) for key, value in recorded.items()}
    P.require(pins and pins == spec['source_pins'], 'Exactly the tested source pins, not arbitrary sources')
    for source, pin in pins.items():
        source_pin(source, pin)
    P.require(isinstance(spec['scope'], str) and 0 < len(spec['scope']) <= 2000 and
              isinstance(spec['completed'], list) and spec['completed'] and
              all(isinstance(text, str) and 0 < len(text) <= 2000 for text in spec['completed']), 'Reviewed bounded summary/scope')
    P.require(not P.PRIVATE.search(spec['scope'] + '\n'.join(spec['completed'])), 'No private identifiers/credentials in public summary')
    return proof, dict(reference, case_count=count, scope=spec['scope'], completed=copy.deepcopy(spec['completed']),
        source_pins=pins, verified_claims=copy.deepcopy(spec['claims']), host_layer_only=True,
        native_guest_execution=False, device_IO=False, current_phone_or_Google_acceptance_verified=False)


def validate_startup_prerequisite(proof, state):
    prior = state[PRIOR_FIELD]
    summary = prior['startup']
    expected = {key: summary[key] for key in ('path', 'sha256')}
    P.require(proof['prerequisite']['startup'] == expected, 'Control proof pins actual startup29 prerequisite')
    document, reference = P.pinned_json(expected['path'], expected['sha256'])
    P.require(prior['goal_status'] == 'active' and not prior['full_goal_complete'] and
              summary['case_count'] == 29 and summary['host_layer_only'] and
              not summary['device_IO'] and not summary['native_guest_execution'], 'Prior startup exact host29 scope')
    for dotted, wanted in summary['verified_claims'].items():
        observed = P.field(document, dotted)
        P.require(type(observed) is type(wanted) and observed == wanted, 'Prerequisite recorded claim: ' + dotted)
    for name, pin in summary['source_pins'].items():
        source_pin(name, pin)
    return dict(reference, case_count=29, historical_prerequisite_not_new_test=True,
                current_source_pins_verified=True, device_IO=False, native_guest_execution=False)


def prepare(before, checkpoint, now, previous_reason):
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    P.require(state == public['deep_research'], 'Prior canonical equality')
    P.require(all(d['goal_status'] == 'active' and not d['goal_complete'] and
                  d['current_goal_priority'] == 'android_auto_google_maps' for d in (state, task, public, web)),
              'Full resumed objective remains active/incomplete')
    P.require(state['requested_goal'] == P.OBJECTIVE, 'Full objective preserved')
    P.require(state['navigation_repair']['status'] == 'stopped_by_user' and
              state['microphone_amplifier']['status'] == 'cancelled_by_user', 'User cancellations preserved')
    P.require(task['user_away'] and not state['audio']['audible_tests_allowed'] and
              not web['current_physical_test_requested'], 'No unattended device/audio work')
    P.require(not state['native_android_auto']['native_receiver_running'] and
              not state['native_android_auto']['phone_session_verified'] and
              not state['native_app_music']['native_app_running'] and
              not state['native_app_music']['direct_phone_music_verified'] and
              not state['google_maps']['native_running'], 'No unsupported phone/native/App/maps success')
    keys = ('audio', 'navigation_repair', 'microphone_amplifier', 'native_app_music', 'google_maps',
            P.FIELD, 'latest_android_auto_pipeline_checkpoint', PRIOR_FIELD,
            'bluetooth_music_blocking_audit', 'research_goal_status_history')
    preserved = {key: copy.deepcopy(state[key]) for key in keys}
    old_progress = copy.deepcopy(public['research_progress'])
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp, display = local.isoformat(timespec='seconds'), local.strftime('%Y/%m/%d %H:%M:%S')
    checkpoint.update(updated_utc=now.isoformat(), updated_Taiwan=stamp)
    checkpoint['prior_published_goal_turn'] = copy.deepcopy(state['last_goal_turn'])
    turn = {'classification': 'progress', 'previous_goal_turn_assessment': 'no_progress',
        'previous_goal_turn_reason': previous_reason,
        'prior_published_goal_turn_classification': state['last_goal_turn']['classification'],
        'earlier_startup29_checkpoint_is_actual_progress': True,
        'validated_utc': now.isoformat(), 'goal_status': 'active', 'required_work_remaining': True,
        'full_goal_complete': False, 'focused_evidence': copy.deepcopy(checkpoint['proofs']),
        'prerequisite_evidence': copy.deepcopy(checkpoint['prerequisite']),
        'host_layer_implementation_and_verification': True, 'native_guest_execution': False,
        'device_IO': False, 'device_files_written': False, 'device_calls_or_sound': False,
        'reason': 'Actual new host control/service discovery/channel/media and independently generated bounded protobuf proof; previous status-only turn is no_progress, earlier startup29 remains historical progress.'}
    state.update(updated_utc=now.isoformat(), goal_status='active', goal_complete=False,
        current_priority='GarminOS Android Auto／Google Maps；Linux-host服務探索、通道／媒體控制與有界Protobuf證據。',
        next_actions=copy.deepcopy(NEXT_ACTIONS), last_goal_turn=turn)
    state[FIELD] = copy.deepcopy(checkpoint)
    state['android_auto_blocking_audit'].update(updated_utc=now.isoformat(), condition=None,
        consecutive_no_progress_goal_turns=0, current_goal_turn_classification='progress',
        goal_status='active', prior_bluetooth_counter_not_reused=True, full_goal_complete=False)
    aa = state['native_android_auto']
    aa[FIELD] = copy.deepcopy(checkpoint)
    aa['remaining_work'] = copy.deepcopy(GAPS)
    work = state['offline_24h_work_order']
    work[FIELD] = copy.deepcopy(checkpoint)
    work.update(goal_status='active', actual_goal_status_read='active', current_blocking_reason=None,
                current_priority='android_auto_google_maps', whole_goal_complete=False)
    work['current_offline_line_status']['android_auto'] = 'Linux-host legacy service/channel/media control plus separate bounded generated-protobuf evidence; Pixel/Google, real USB, native video/UI/audio and install unverified'
    for document in (task, public, web):
        for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', FIELD,
                    'offline_24h_work_order', 'android_auto_blocking_audit'):
            document[key] = copy.deepcopy(state[key])
        document.update(goal_status='active', goal_complete=False, required_work_remaining=True)
        document.pop('goal_blocked_reason', None)
    task['native_android_auto'] = copy.deepcopy(aa)
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state))
    completed = checkpoint['proofs']['control']['completed'] + checkpoint['proofs']['proto']['completed']
    progress = public['research_progress']
    progress['completed'].extend(completed)
    progress.update(research_updated_utc=now.isoformat(), next=NEXT_ACTIONS[0], goal_completed=False,
        method='沿用完整研究計畫的歷史工程估計；服務／通道／媒體控制與獨立有界Protobuf僅Linux-host驗證，沒有提高原機百分比。Android Auto／Google Maps主線繼續，導航修復與麥克風停止。')
    phase_next = {'USB 主機與手機連線': NEXT_ACTIONS[0],
        '畫面、影片與觸控投影': NEXT_ACTIONS[1],
        '原生 App 入口與功能整合': '補齊完整影音／輸入與App載入、菜單和停止／重連；Linux-host控制及有界Protobuf不是current phone或原機安裝驗收。'}
    for phase in progress['phases']:
        if phase['name'] in phase_next:
            phase['next'] = phase_next[phase['name']]
    P.require(progress['estimate_percent'] == old_progress['estimate_percent'] == 37 and
        progress['weighted_estimate_percent'] == old_progress['weighted_estimate_percent'] and
        [(p['name'], p['weight'], p['estimate_percent'], p['deferred']) for p in progress['phases']] ==
        [(p['name'], p['weight'], p['estimate_percent'], p['deferred']) for p in old_progress['phases']],
        'Historical37 estimate, weights and phase scores unchanged')
    P.require(all(state[key] == old for key, old in preserved.items()), 'Previous startup29/pipeline27/TLS15/wire25/BT/App/navigation/mic history preserved')
    report = before[FILES[3]].decode()
    P.require(CARD_ID not in report, 'Control v1 not already published')
    previous = re.search(r'<section class="card" id="' + PRIOR_CARD_ID + r'">.*?</section>', report, re.S)
    P.require(previous is not None, 'Previous startup29 report card')
    prior_card = previous.group()
    report = report.replace(prior_card, '<details class="card" id="android-auto-startup-checkpoint-history-v1">'
        '<summary>前一輪啟動紀錄：legacy啟動／本地TLS peer／同session交接29類主機檢查</summary>' + prior_card + '</details>', 1)
    e = html.escape
    steps = ''.join('<li>' + e(text) + '</li>' for text in completed)
    gaps = ''.join('<li>' + e(text) + '</li>' for text in GAPS)
    scopes = ''.join('<li><strong>' + title + '：</strong>' + e(checkpoint['proofs'][key]['scope']) + '；'
        + str(checkpoint['proofs'][key]['case_count']) + '類主機檢查。</li>'
        for title, key in (('控制整合', 'control'), ('獨立生成Protobuf', 'proto')))
    card = (f'<section class="card" id="{CARD_ID}"><h2>目前主線：服務探索／通道與媒體控制（Linux-host）</h2>'
        f'<p>完整Android Auto／Google Maps目標 active／尚未完成。更新：<time datetime="{stamp}">{display}</time>（台灣時間）</p>'
        '<p><strong>本地peer、legacy模型及獨立生成的有界Protobuf結果不是current Pixel／Google或Garmin驗收。</strong>'
        '前一個只回報狀態的goal turn記為no_progress；本輪進展以新的實作及實際host test proof為依據。</p>'
        '<h3>本輪已完成</h3><ul>' + steps + '</ul><h3>驗證範圍</h3><ul>' + scopes + '</ul>'
        '<p>先前startup29／pipeline27／TLS15／wire25完整保留，不算本輪重測或車機完成。</p>'
        '<p><strong>藍牙音樂：</strong>Pixel → Pi → Garmin持續60秒有聲屬使用者確認的歷史實測；'
        'Android第四版APK只有主機編譯／DEX／API28簽章及18項gate＋12項lease檢查，'
        'Pixel本機通話、SCO與Garmin出聲未驗證。原機直接A2DP與GarminOS菜單App仍未完成。'
        '<a href="/garmin-hfp-prototype.apk" download="garmin-hfp-prototype.apk">保留的第四版實驗APK</a>。</p>'
        '<h3>仍待完成</h3><ul>' + gaps + '</ul>'
        '<p>沒有執行original Garmin／native guest、修改原機callsite、接手機／實機USB、配對、來電、播音或安裝；原native執行中斷界線保留。'
        '工程估計仍37%，不是Android Auto完成率。導航修復／麥克風停止，沒有可安裝接收端。</p></section>')
    P.require(report.count('<main>') == 1, 'Single report main')
    report = report.replace('<main>', '<main>' + card, 1)
    report = P.substitute(report, r'<span class="progress-status">.*?</span>',
        '<span class="progress-status">Android Auto／Google Maps：服務與通道主機研究中</span>', 'progress status')
    report = P.substitute(report, r'<p id="progress-method"[^>]*>.*?</p>',
        '<p id="progress-method" class="progress-note">' + e(progress['method']) + '</p>', 'method')
    report = P.substitute(report, r'<p id="offline-frontier-latest-v1">.*?</p>',
        '<p id="offline-frontier-latest-v1">最新：服務探索／通道／媒體控制與獨立有界Protobuf已有新的Linux-host證據；current Pixel／Google接受、USB／AOA、完整影音、H.264／螢幕／觸控／音訊與原機安裝仍未驗證。</p>', 'frontier')
    report = P.substitute(report, r'<p><strong>下一步：</strong>.*?</p>',
        '<p><strong>下一步：</strong>' + e(NEXT_ACTIONS[0]) + '</p>', 'next')
    old_list = re.search(r'<ul class="completed-progress">.*?</ul>', report, re.S)
    P.require(old_list is not None, 'Historical completed list')
    report = report.replace(old_list.group(), old_list.group()[:-5] + steps + '</ul>', 1)
    for phase in progress['phases']:
        if phase['name'] in phase_next:
            report = P.substitute(report, r'<tr><td>' + re.escape(e(phase['name'])) + r'</td><td>.*?</td><td>.*?</td></tr>',
                '<tr><td>' + e(phase['name']) + '</td><td>' + str(phase['estimate_percent']) + '%</td><td>'
                + e(phase['next']) + '</td></tr>', 'phase ' + phase['name'])
    for element in ('report-updated-time', 'research-updated-time'):
        report = P.substitute(report, r'<time id="' + element + r'" datetime="[^"]+">[^<]+</time>',
            f'<time id="{element}" datetime="{stamp}">{display}</time>', element)
    P.require(not P.PRIVATE.search(report), 'No unit IDs, phone addresses or private keys in public report')
    P.require(report.index('id="' + CARD_ID + '"') < report.index('id="' + PRIOR_CARD_ID + '"'), 'New control card is first')
    web.update(full_goal_complete=False, actual_goal_status_read='active', current_physical_test_requested=False)
    web['progress_display_verified'].update(estimate_percent=37, completed_items=len(progress['completed']),
        report_updated_time=stamp, research_updated_time=stamp, android_auto_control_checkpoint_visible=True,
        prior_startup29_pipeline27_TLS15_wire25_preserved_as_history=True,
        current_Pixel_Google_native_install_not_claimed=True,
        HTML_structure_checked=False, visual_browser_render_not_performed=True)
    return {FILES[0]: P.encoded(state), FILES[1]: P.encoded(task), FILES[2]: P.encoded(public),
        FILES[3]: report.encode(), FILES[4]: P.encoded(web)}, checkpoint


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proof', required=True, help='Actual control host proof JSON')
    parser.add_argument('--proto-proof', default='evidence/android-auto-proto-host-v1.json')
    parser.add_argument('--run-metadata', required=True)
    parser.add_argument('--publish', action='store_true', help='Write five canonical/report files; default read-only preflight')
    args = parser.parse_args()
    meta_path = P.resolve(args.run_metadata)
    P.require(meta_path.suffix == '.json' and meta_path.stat().st_size <= 128 * 1024, 'Bounded run metadata')
    meta_raw = meta_path.read_bytes()
    metadata = json.loads(meta_raw)
    P.require(metadata['schema'] == SCHEMA and not metadata.get('illustrative_template'), 'Actual reviewed metadata, not example')
    P.require(metadata['previous_goal_turn_assessment'] == 'no_progress' and
        isinstance(metadata['previous_goal_turn_reason'], str) and 0 < len(metadata['previous_goal_turn_reason']) <= 2000,
        'Prior status-only goal turn classified truthfully')
    P.require(P.digest(Path(P.__file__).read_bytes()) == metadata['publisher_helper_sha256'], 'Reviewed shared metadata/HTTP helpers')
    goal, goal_ref = P.pinned_json(metadata['goal_receipt']['path'], metadata['goal_receipt']['sha256'])
    P.require(P.field(goal, metadata['goal_receipt'].get('status_path', 'status')) == 'active' and
        P.field(goal, metadata['goal_receipt'].get('objective_path', 'objective')) == P.OBJECTIVE, 'Actual active goal receipt, original full objective')
    control_proof, control = validate_proof(args.proof, metadata['control'], 'android-auto-control-host-v1')
    proto_proof, proto = validate_proof(args.proto_proof, metadata['proto'], 'android-auto-proto-host-v1')
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    prerequisite = validate_startup_prerequisite(control_proof, json.loads(before[FILES[0]]))
    proto_reference = {key: proto[key] for key in ('path', 'sha256')}
    proto_link_checked = False
    if metadata.get('control_proto_reference_path'):
        P.require(P.field(control_proof, metadata['control_proto_reference_path']) == proto_reference, 'Control proof exact independent proto reference')
        proto_link_checked = True
    P.require(isinstance(metadata['terminal_receipts'], list) and metadata['terminal_receipts'], 'Actual final test receipts')
    receipts, coverage = [], set()
    for row in metadata['terminal_receipts']:
        receipt, reference = P.pinned_json(row['path'], row['sha256'])
        result = P.field(receipt, row['result_path']) if row.get('result_path') else receipt
        P.require(result['exit_code'] == 0 and 'session_id' not in result and result['chunk_id'] == row['chunk_id'], 'Actual EXIT0, no running session')
        P.require(isinstance(row['covers'], list) and row['covers'] and set(row['covers']) <= {'control', 'proto'}, 'Receipt names tested proof coverage')
        coverage.update(row['covers'])
        receipts.append(dict(reference, chunk_id=row['chunk_id'], exit_code=0, covers=copy.deepcopy(row['covers'])))
    P.require(coverage == {'control', 'proto'}, 'Actual receipts cover both independent proofs')
    checkpoint = {'schema': SCHEMA, 'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
        'goal_receipt': goal_ref, 'proofs': {'control': control, 'proto': proto}, 'prerequisite': {'startup': prerequisite},
        'control_proof_pinned_proto_reference_checked': proto_link_checked,
        'terminal_receipts': receipts, 'run_metadata': {'path': str(meta_path.relative_to(ROOT)), 'sha256': P.digest(meta_raw)},
        'source_and_test_scope': 'Linux-host legacy service discovery/channel/media control and independent bounded generated protobuf only',
        'phone_or_Pixel_or_Google_acceptance_verified': False, 'Garmin_native_receiver_or_Google_Maps_running': False,
        'device_IO': False, 'native_guest_execution': False, 'device_install_candidate': False,
        'remaining_work': copy.deepcopy(GAPS), 'historical_progress_estimates_not_increased': True}
    web_before = json.loads(before[FILES[4]])
    pid, start = P.live_server(web_before)
    P.require(pid == 885568, 'Existing authorized report PID885568, no replacement/restart')
    P.require(P.fetch(web_before['url']) == before[FILES[3]], 'Before HTTP equals local report')
    now = datetime.now(timezone.utc)
    after, checkpoint = prepare(before, checkpoint, now, metadata['previous_goal_turn_reason'])
    P.require(all((ROOT / name).read_bytes() == raw for name, raw in before.items()), 'No concurrent canonical changes')
    if not args.publish:
        print(json.dumps({'all_input_and_preflight_checks_passed': True, 'publication_performed': False,
            'planned_checkpoint': checkpoint, 'report_PID': pid, 'host_cases': {key: value['case_count'] for key, value in checkpoint['proofs'].items()},
            'native_guest_execution': False, 'device_IO': False, 'full_goal_complete': False}, ensure_ascii=False))
        return
    out = ROOT / 'staging' / ('android-auto-control-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    (out / 'canonical-before.json.gz').write_bytes(gzip.compress(P.encoded({key: raw.decode() for key, raw in before.items()}), mtime=0))
    (out / 'publication-inputs.json').write_bytes(P.encoded(checkpoint))
    written = []
    try:
        for name in FILES[:4]:
            P.replace(name, after[name])
            written.append(name)
        served = P.fetch(web_before['url'])
        P.require(served == after[FILES[3]], 'Published HTML exact HTTP readback')
        P.require(P.live_server(web_before) == (pid, start), 'Same report process, no restart')
        web = json.loads(after[FILES[4]])
        web.update(HTTP_status=200, local_report_sha256=P.digest(served), served_report_sha256=P.digest(served),
            report_bytes=len(served), served_latest_report=True, service_not_restarted=True, canonical_hash_readback_uncached=True)
        after[FILES[4]] = P.encoded(web)
        P.replace(FILES[4], after[FILES[4]])
        written.append(FILES[4])
        P.require(all((ROOT / name).read_bytes() == raw for name, raw in after.items()), 'Exact canonical file readback')
        docs = [json.loads(after[name]) for name in (FILES[0], FILES[1], FILES[2], FILES[4])]
        P.require(docs[0] == docs[2]['deep_research'] and all(document['goal_status'] == 'active' and
            not document['goal_complete'] and document[FIELD] == checkpoint for document in docs), 'Active/incomplete canonical equality')
        receipt = {'all_publication_checks_passed': True, 'updated_at_Taiwan': checkpoint['updated_Taiwan'],
            'report_url': web_before['url'], 'report_PID': pid, 'service_not_restarted': True, 'report_HTTP_exact_bytes': True,
            'canonical_after_sha256': {name: P.digest(raw) for name, raw in after.items()},
            'host_cases': {key: value['case_count'] for key, value in checkpoint['proofs'].items()},
            'prerequisite_startup_cases': 29, 'prior_checkpoints_preserved': True,
            'previous_goal_turn_assessment': 'no_progress', 'current_goal_turn_assessment': 'progress',
            'phone_or_Pixel_or_Google_acceptance_verified': False,
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
