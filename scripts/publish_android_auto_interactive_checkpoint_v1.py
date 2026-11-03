#!/usr/bin/env python3
"""Prepare/publish actual Linux-host AA video/input/audio integration evidence.

Default preflight is read-only and prints a short summary. --publish atomically
updates the existing five canonical/report files with snapshot/own-change rollback,
exact HTTP readback and unchanged report PID885568. The prior software-pattern PNG
and its exact data URI remain intact; no image copy, route change or restart occurs.
No test/build, original Garmin/native guest/callsite, device query, phone, pairing,
call, playback, installation or goal transition is executed here.

CLI: --proof INTEGRATION --input-proof INPUT --audio-proof AUDIO --run-metadata META
Run metadata schema: android-auto-interactive-checkpoint-v1
  publisher_helper_sha256, publisher_video_helper_sha256: exact reviewed pure helpers
  goal_receipt: {path,sha256,status_path,objective_path}
  previous_goal_turn_assessment: "progress"
  integration/input/audio: {proof_sha256,claims:{dotpath:expected},pass_claim,
    device_io_claim,native_guest_claim,host_function_claim,case_count_claim,case_count,
    count_label,source_pins_claim,source_pins,scope,completed}
  integration additionally: software_decode_claim (actual TRUE claim)
  integration_references: {input: actual proof dotpath,audio: actual proof dotpath}
  terminal_receipts: [{path,sha256,result_path,chunk_id,covers:[...]}]

Actual proof schemas are android-auto-interactive-host-v1 / android-auto-input-host-v1
/ android-auto-audio-host-v1. Integration must pin prerequisite.video to published20.
Counts and positive claims come from actual proofs; synthetic input and owned PCM
never establish Pixel, Google, touchscreen, display, speaker or native installation.
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
import publish_android_auto_video_checkpoint_v1 as V

ROOT, FILES = P.ROOT, P.FILES
SCHEMA = 'android-auto-interactive-checkpoint-v1'
FIELD = 'latest_android_auto_interactive_checkpoint'
CARD_ID = 'android-auto-interactive-current-checkpoint-v1'
PRIOR_FIELD = V.FIELD
PROOF_SCHEMAS = {'integration': 'android-auto-interactive-host-v1',
    'input': 'android-auto-input-host-v1', 'audio': 'android-auto-audio-host-v1'}
NEXT_ACTIONS = [
    '優先釐清精確HWID1352原機的USB host／VBUS／AOA與可達平台端點／載入入口；新增host fixtures不能取代這兩個裝機gate。現在不查裝置、不要求現場。',
    '在可用平台端點成立後，接真正current phone並驗證協商／重連；補native entropy／time／ABI、總配置與即時性能、display／touch／audio ownership／UI與安全生命週期。',
    'Google Maps／原機離線能力、可安裝接收端、直接A2DP與原機音樂App仍未完成。保留Pi轉送與Android APK歷史；導航／麥克風停止，原native中斷界線不重試／繞過。',
]
GAPS = [
    '最關鍵gate：真正USB host／VBUS／AOA及精確原機可達的執行／App載入與平台端點尚未成立；OTG線或Hub不證明能力。',
    '本地legacy peer未證current Pixel／Google接受；真正phone session／協商／影音時鐘／重連尚未驗證。',
    '原機entropy／time／ARM ABI、total heap／allocator與decode即時性能未驗證。',
    '軟體影格／合成single-pointer或key／wheel輸入不是Garmin螢幕／觸控；CANCEL／multitouch不主張。',
    'owned PCM接受／回壓不等於音訊registration／DAC／喇叭；原機音訊所有權、focus／AV同步與導航共存未完成。',
    '真正task／IRQ、停止／重連／callback quiescence／安全回收、UI及可安裝App未完成；Google Maps／原機離線Maps仍未運行。',
]


def validate_proof(name, spec, kind):
    proof, reference = P.pinned_json(name, spec['proof_sha256'])
    P.require(proof['schema'] == PROOF_SCHEMAS[kind], 'Actual ' + kind + ' proof schema')
    P.require(isinstance(spec['claims'], dict) and spec['claims'], 'Reviewed exact claims')
    for dotted, wanted in spec['claims'].items():
        observed = P.field(proof, dotted)
        P.require(type(observed) is type(wanted) and observed == wanted, 'Exact claim ' + kind + ':' + dotted)
    checks = [('pass_claim', True), ('device_io_claim', False), ('native_guest_claim', False), ('host_function_claim', True)]
    if kind == 'integration':
        checks.append(('software_decode_claim', True))
    for key, wanted in checks:
        dotted = spec[key]
        P.require(dotted in spec['claims'] and P.field(proof, dotted) is wanted, 'Explicit host evidence: ' + kind + ':' + key)
    count = spec['case_count']
    P.require(type(count) is int and count > 0 and spec['case_count_claim'] in spec['claims'] and
        type(P.field(proof, spec['case_count_claim'])) is int and P.field(proof, spec['case_count_claim']) == count,
        'Actual count with exact reviewed unit')
    P.require(isinstance(spec['count_label'], str) and 0 < len(spec['count_label']) <= 100, 'Bounded actual count label')
    recorded = P.field(proof, spec['source_pins_claim'])
    P.require(isinstance(recorded, dict) and spec['source_pins_claim'] in spec['claims'], 'Reviewed source dictionary')
    pins = {key: (value['sha256'] if isinstance(value, dict) else value) for key, value in recorded.items()}
    P.require(pins and pins == spec['source_pins'], 'Exactly tested text-only source pins')
    for name, pin in pins.items():
        V.source_pin(name, pin)
    P.require(isinstance(spec['scope'], str) and 0 < len(spec['scope']) <= 2000 and
        isinstance(spec['completed'], list) and 0 < len(spec['completed']) <= 64 and
        all(isinstance(text, str) and 0 < len(text) <= 2000 for text in spec['completed']), 'Bounded reviewed scope/completed')
    P.require(not P.PRIVATE.search(spec['scope'] + '\n'.join(spec['completed']) + spec['count_label']), 'No private identifiers/keys in public summary')
    return proof, dict(reference, case_count=count, count_label=spec['count_label'], scope=spec['scope'],
        completed=copy.deepcopy(spec['completed']), source_pins=pins, verified_claims=copy.deepcopy(spec['claims']),
        host_layer_only=True, device_IO=False, native_guest_execution=False,
        current_phone_or_Google_acceptance_verified=False, hardware_display_touch_or_speaker_verified=False)


def validate_prior_video(integration, before):
    state = json.loads(before[FILES[0]])
    prior = state[PRIOR_FIELD]
    summary = prior['proofs']['video']
    expected = {key: summary[key] for key in ('path', 'sha256')}
    P.require(integration['prerequisite']['video'] == expected and summary['case_count'] == 20 and
        prior['goal_status'] == 'active' and not prior['full_goal_complete'] and not prior['device_IO'] and
        not prior['native_guest_execution'], 'Exact historical video20 prerequisite')
    proof, reference = P.pinned_json(expected['path'], expected['sha256'])
    for dotted, wanted in summary['verified_claims'].items():
        observed = P.field(proof, dotted)
        P.require(type(observed) is type(wanted) and observed == wanted, 'Actual prior video claim: ' + dotted)
    for name, pin in summary['source_pins'].items():
        V.source_pin(name, pin)
    artifact = copy.deepcopy(prior.get('software_frame_artifact'))
    frame = None
    if artifact is not None:
        P.require(artifact['publish_target'] == V.ARTIFACT_TARGET and
            not artifact['Garmin_display_or_Google_Maps_verified'] and not artifact['standalone_PNG_HTTP_route_verified'],
            'Retained software-only pattern scope')
        recorded = P.field(proof, artifact['proof_field'])
        P.require(artifact['proof'] == expected and recorded == {'path': artifact['source_path'],
            'sha256': artifact['sha256'], 'width': artifact['width'], 'height': artifact['height'], 'source': artifact['source']},
            'Retained image metadata still pins the actual prior video proof')
        target = V.software_artifact_target()
        P.require(target.exists(), 'Existing prior report PNG remains present')
        frame = target.read_bytes()
        V.validate_png(frame)
        P.require(P.digest(frame) == artifact['sha256'], 'Exact prior report PNG hash')
        V.verify_HTTP_embedded_artifact(before[FILES[3]], artifact, frame)
    return dict(reference, case_count=20, historical_prerequisite_not_new_test=True,
        current_source_pins_verified=True, device_IO=False, native_guest_execution=False), artifact, frame


def prepare(before, checkpoint, now):
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    P.require(state == public['deep_research'], 'Prior canonical equality')
    P.require(all(d['goal_status'] == 'active' and not d['goal_complete'] and
        d['current_goal_priority'] == 'android_auto_google_maps' for d in (state, task, public, web)), 'Full objective active/incomplete')
    P.require(state['requested_goal'] == P.OBJECTIVE and state['last_goal_turn']['classification'] == 'progress', 'Prior video20 actual progress')
    P.require(state['navigation_repair']['status'] == 'stopped_by_user' and state['microphone_amplifier']['status'] == 'cancelled_by_user', 'User cancellations')
    P.require(task['user_away'] and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'], 'No unattended hardware work')
    P.require(not state['native_android_auto']['native_receiver_running'] and not state['native_android_auto']['phone_session_verified'] and
        not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'] and
        not state['google_maps']['native_running'], 'No unsupported native/App/phone/Maps success')
    keys = ('audio', 'navigation_repair', 'microphone_amplifier', 'native_app_music', 'google_maps', P.FIELD,
        'latest_android_auto_pipeline_checkpoint', 'latest_android_auto_startup_checkpoint', 'latest_android_auto_control_checkpoint', PRIOR_FIELD,
        'bluetooth_music_blocking_audit', 'research_goal_status_history')
    preserved = {key: copy.deepcopy(state[key]) for key in keys}
    old_progress = copy.deepcopy(public['research_progress'])
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp, display = local.isoformat(timespec='seconds'), local.strftime('%Y/%m/%d %H:%M:%S')
    checkpoint.update(updated_utc=now.isoformat(), updated_Taiwan=stamp,
        prior_published_goal_turn=copy.deepcopy(state['last_goal_turn']))
    turn = {'classification': 'progress', 'previous_goal_turn_assessment': 'progress',
        'previous_goal_turn_reason': 'Published video20 was actual host progress; inherited decoder76/control43/proto127 stay at their own historical scopes.',
        'validated_utc': now.isoformat(), 'goal_status': 'active', 'required_work_remaining': True, 'full_goal_complete': False,
        'focused_evidence': copy.deepcopy(checkpoint['proofs']), 'prerequisite_evidence': copy.deepcopy(checkpoint['prerequisite']),
        'host_layer_implementation_and_verification': True, 'software_decoded_frames_verified': True,
        'device_IO': False, 'native_guest_execution': False, 'device_files_written': False, 'device_calls_or_sound': False,
        'hardware_display_touch_or_speaker_verified': False, 'display_hardware_verified': False,
        'touchscreen_hardware_verified': False, 'speaker_sound_verified': False,
        'reason': 'Actual Linux-host video, outbound synthetic input and owned PCM integration proofs; no phone/native/physical endpoint/install success.'}
    state.update(updated_utc=now.isoformat(), goal_status='active', goal_complete=False,
        current_priority='GarminOS Android Auto／Google Maps：Linux-host影像／輸入／PCM互動核心，下一gate為真正原機transport／platform端點。',
        next_actions=copy.deepcopy(NEXT_ACTIONS), last_goal_turn=turn)
    state[FIELD] = copy.deepcopy(checkpoint)
    state['android_auto_blocking_audit'].update(updated_utc=now.isoformat(), condition=None, consecutive_no_progress_goal_turns=0,
        current_goal_turn_classification='progress', goal_status='active', prior_bluetooth_counter_not_reused=True, full_goal_complete=False)
    aa = state['native_android_auto']
    aa[FIELD] = copy.deepcopy(checkpoint)
    aa['remaining_work'] = copy.deepcopy(GAPS)
    work = state['offline_24h_work_order']
    work[FIELD] = copy.deepcopy(checkpoint)
    work.update(goal_status='active', actual_goal_status_read='active', current_blocking_reason=None,
        current_priority='android_auto_google_maps', whole_goal_complete=False)
    work['current_offline_line_status']['android_auto'] = 'Linux-host video/input/owned PCM core only; real USB/AOA, reachable Garmin platform/loading, current phone, hardware and native install unverified'
    for document in (task, public, web):
        for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', FIELD, 'offline_24h_work_order', 'android_auto_blocking_audit'):
            document[key] = copy.deepcopy(state[key])
        document.update(goal_status='active', goal_complete=False, required_work_remaining=True)
        document.pop('goal_blocked_reason', None)
    task['native_android_auto'] = copy.deepcopy(aa)
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state))
    completed = [text for key in ('input', 'audio', 'integration') for text in checkpoint['proofs'][key]['completed']]
    progress = public['research_progress']
    progress['completed'].extend(completed)
    progress.update(research_updated_utc=now.isoformat(), next=NEXT_ACTIONS[0], goal_completed=False,
        method='沿用完整研究計畫的歷史工程估計37%；本輪為Linux-host互動核心，未跨過真正原機transport／platform gate，不提高原機百分比。AA／Maps仍未完成；導航／麥克風停止。')
    phase_next = {'USB 主機與手機連線': NEXT_ACTIONS[0], '畫面、影片與觸控投影': NEXT_ACTIONS[1],
        '原生 App 入口與功能整合': '先成立原機可達platform／loader，再整合UI／真正影音ownership與生命週期；synthetic輸入或PCM不是硬體驗收。'}
    for phase in progress['phases']:
        if phase['name'] in phase_next:
            phase['next'] = phase_next[phase['name']]
    P.require(progress['estimate_percent'] == old_progress['estimate_percent'] == 37 and
        progress['weighted_estimate_percent'] == old_progress['weighted_estimate_percent'] and
        [(p['name'], p['weight'], p['estimate_percent'], p['deferred']) for p in progress['phases']] ==
        [(p['name'], p['weight'], p['estimate_percent'], p['deferred']) for p in old_progress['phases']], 'Historical estimates unchanged')
    P.require(all(state[key] == old for key, old in preserved.items()), 'All prior video/control/proto/startup/TLS/wire/BT/App/cancellations preserved')
    report = before[FILES[3]].decode()
    P.require(CARD_ID not in report, 'Interactive v1 not already published')
    previous = re.search(r'<section class="card" id="' + V.CARD_ID + r'">.*?</section>', report, re.S)
    P.require(previous is not None, 'Complete prior video20 card including its exact image')
    prior_card = previous.group()
    report = report.replace(prior_card, '<details class="card" id="android-auto-video-checkpoint-history-v1">'
        '<summary>前輪完整影片紀錄：video20／decoder76，保留原軟體測試圖樣</summary>' + prior_card + '</details>', 1)
    e = html.escape
    steps = ''.join('<li>' + e(text) + '</li>' for text in completed)
    scopes = ''.join('<li><strong>' + title + '：</strong>' + e(checkpoint['proofs'][key]['scope']) + '；' +
        str(checkpoint['proofs'][key]['case_count']) + e(checkpoint['proofs'][key]['count_label']) + '。</li>'
        for title, key in (('輸入編碼', 'input'), ('PCM provider', 'audio'), ('互動流程整合', 'integration')))
    gaps = ''.join('<li>' + e(text) + '</li>' for text in GAPS)
    card = (f'<section class="card" id="{CARD_ID}"><h2>目前主線：影像／輸入／PCM互動核心（Linux-host）</h2>'
        f'<p>完整Android Auto／Google Maps目標active／未完成。更新：<time datetime="{stamp}">{display}</time>（台灣時間）</p>'
        '<p><strong>本輪actual proof只有Linux-host本地TLS peer、軟體影格、合成single-pointer／key／wheel與owned PCM；沒有Pixel／Google、Garmin螢幕／觸控／喇叭或原機安裝。</strong></p>'
        '<h3>本輪已完成</h3><ul>' + steps + '</ul><h3>精確驗證範圍</h3><ul>' + scopes + '</ul>'
        '<p>PRESS／RELEASE／DRAG為自有單指模型；CANCEL與multitouch不主張。媒體ACK表示provider接受資料，不代表呈現或出聲。前輪video20／decoder76、control43／proto127、startup29／pipeline27／TLS15／wire25完整保留，各自scope不外推或當本輪重測。</p>'
        '<p><strong>優先gate：</strong>精確原機的USB host／VBUS／AOA與可達platform／loader，接著才是current phone；更多host fixtures不能替代端點與裝機證據。</p>'
        '<p><strong>藍牙音樂：</strong>Pixel → Pi → Garmin持續60秒有聲是歷史使用者確認。Android第四版APK只有host建置／DEX／API28簽章與18 gate＋12 lease檢查；Pixel本機通話／SCO／Garmin出聲未驗證。原機直接A2DP與菜單音樂App仍未完成。'
        '<a href="/garmin-hfp-prototype.apk" download="garmin-hfp-prototype.apk">第四版實驗APK</a>。</p>'
        '<h3>仍待完成</h3><ul>' + gaps + '</ul><p>工程估計仍37%，不是Android Auto完成率。導航／麥克風停止；原native中斷界線不重試／繞過。使用者會主動通知可實測，目前不查裝置、不要求配對、不發來電或播音。</p></section>')
    P.require(report.count('<main>') == 1, 'Single main')
    report = report.replace('<main>', '<main>' + card, 1)
    report = P.substitute(report, r'<span class="progress-status">.*?</span>', '<span class="progress-status">Android Auto／Google Maps：主機互動核心研究中</span>', 'status')
    report = P.substitute(report, r'<p id="progress-method"[^>]*>.*?</p>', '<p id="progress-method" class="progress-note">' + e(progress['method']) + '</p>', 'method')
    report = P.substitute(report, r'<p id="offline-frontier-latest-v1">.*?</p>', '<p id="offline-frontier-latest-v1">最新actual成果限Linux-host影像／合成輸入／PCM互動核心。下一關鍵gate是真正USBhost／VBUS／AOA及可達Garmin平台端點／載入；current phone／Google、native效能／硬體／App仍未驗證。</p>', 'frontier')
    report = P.substitute(report, r'<p><strong>下一步：</strong>.*?</p>', '<p><strong>下一步：</strong>' + e(NEXT_ACTIONS[0]) + '</p>', 'next')
    old_list = re.search(r'<ul class="completed-progress">.*?</ul>', report, re.S)
    P.require(old_list is not None, 'Previous completed list')
    report = report.replace(old_list.group(), old_list.group()[:-5] + steps + '</ul>', 1)
    for phase in progress['phases']:
        if phase['name'] in phase_next:
            report = P.substitute(report, r'<tr><td>' + re.escape(e(phase['name'])) + r'</td><td>.*?</td><td>.*?</td></tr>',
                '<tr><td>' + e(phase['name']) + '</td><td>' + str(phase['estimate_percent']) + '%</td><td>' + e(phase['next']) + '</td></tr>', 'phase ' + phase['name'])
    for element in ('report-updated-time', 'research-updated-time'):
        report = P.substitute(report, r'<time id="' + element + r'" datetime="[^"]+">[^<]+</time>', f'<time id="{element}" datetime="{stamp}">{display}</time>', element)
    P.require(not P.PRIVATE.search(report), 'No private identifiers/credentials')
    P.require(report.index('id="' + CARD_ID + '"') < report.index('id="' + V.CARD_ID + '"'), 'Latest interactive card first')
    web.update(full_goal_complete=False, actual_goal_status_read='active', current_physical_test_requested=False)
    web['progress_display_verified'].update(estimate_percent=37, completed_items=len(progress['completed']), report_updated_time=stamp,
        research_updated_time=stamp, android_auto_interactive_checkpoint_visible=True, prior_video20_and_BT_history_preserved=True,
        synthetic_input_owned_PCM_not_physical_touch_or_sound_visible=True, true_platform_endpoint_gates_visible=True,
        current_Pixel_Google_native_install_not_claimed=True, HTML_structure_checked=False, visual_browser_render_not_performed=True)
    return {FILES[0]: P.encoded(state), FILES[1]: P.encoded(task), FILES[2]: P.encoded(public), FILES[3]: report.encode(), FILES[4]: P.encoded(web)}, checkpoint


def short_summary(checkpoint, pid):
    return {'schema': SCHEMA, 'goal_status': 'active', 'report_PID': pid,
        'proofs': {key: {name: value[name] for name in ('path', 'sha256', 'case_count', 'count_label')}
            for key, value in checkpoint['proofs'].items()}, 'software_decoded_frames_verified': True,
        'synthetic_input_and_owned_PCM_only': True, 'current_phone_or_Google_acceptance_verified': False,
        'hardware_display_touch_or_speaker_verified': False, 'display_hardware_verified': False,
        'touchscreen_hardware_verified': False, 'speaker_sound_verified': False, 'device_IO': False, 'native_guest_execution': False,
        'device_install_candidate': False, 'full_goal_complete': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proof', required=True, help='Actual integrated Linux-host video/input/audio proof')
    parser.add_argument('--input-proof', required=True)
    parser.add_argument('--audio-proof', required=True)
    parser.add_argument('--run-metadata', required=True)
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    meta_path = P.resolve(args.run_metadata)
    P.require(meta_path.suffix == '.json' and meta_path.stat().st_size <= 256 * 1024, 'Bounded run metadata')
    meta_raw = meta_path.read_bytes()
    meta = json.loads(meta_raw)
    P.require(meta['schema'] == SCHEMA and not meta.get('illustrative_template') and
        meta['previous_goal_turn_assessment'] == 'progress', 'Actual reviewed metadata/prior video progress')
    P.require(P.digest(Path(P.__file__).read_bytes()) == meta['publisher_helper_sha256'] and
        P.digest(Path(V.__file__).read_bytes()) == meta['publisher_video_helper_sha256'], 'Reviewed pure publisher helpers')
    goal, goal_ref = P.pinned_json(meta['goal_receipt']['path'], meta['goal_receipt']['sha256'])
    P.require(P.field(goal, meta['goal_receipt'].get('status_path', 'status')) == 'active' and
        P.field(goal, meta['goal_receipt'].get('objective_path', 'objective')) == P.OBJECTIVE, 'Actual active full-objective goal receipt')
    proofs, documents = {}, {}
    for kind, name in (('integration', args.proof), ('input', args.input_proof), ('audio', args.audio_proof)):
        documents[kind], proofs[kind] = validate_proof(name, meta[kind], kind)
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    prior, artifact, frame = validate_prior_video(documents['integration'], before)
    P.require(set(meta['integration_references']) == {'input', 'audio'}, 'Exact input/audio integration references required')
    for kind in ('input', 'audio'):
        P.require(P.field(documents['integration'], meta['integration_references'][kind]) ==
            {key: proofs[kind][key] for key in ('path', 'sha256')}, 'Integrated proof pins actual ' + kind + ' proof')
    P.require(isinstance(meta['terminal_receipts'], list) and meta['terminal_receipts'], 'Actual final terminal receipts')
    receipts, coverage = [], set()
    for row in meta['terminal_receipts']:
        receipt, reference = P.pinned_json(row['path'], row['sha256'])
        result = P.field(receipt, row['result_path']) if row.get('result_path') else receipt
        P.require(result['exit_code'] == 0 and 'session_id' not in result and result['chunk_id'] == row['chunk_id'], 'Actual final EXIT0 result')
        P.require(isinstance(row['covers'], list) and row['covers'] and set(row['covers']) <= set(PROOF_SCHEMAS), 'Actual proof coverage')
        coverage.update(row['covers'])
        receipts.append(dict(reference, chunk_id=row['chunk_id'], exit_code=0, covers=copy.deepcopy(row['covers'])))
    P.require(coverage == set(PROOF_SCHEMAS), 'Actual receipts cover integration/input/audio')
    checkpoint = {'schema': SCHEMA, 'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
        'goal_receipt': goal_ref, 'proofs': proofs, 'prerequisite': {'video': prior}, 'terminal_receipts': receipts,
        'run_metadata': {'path': str(meta_path.relative_to(ROOT)), 'sha256': P.digest(meta_raw)},
        'software_decoded_frames_verified': True, 'synthetic_input_and_owned_PCM_only': True,
        'phone_or_Pixel_or_Google_acceptance_verified': False, 'Garmin_native_receiver_or_Google_Maps_running': False,
        'hardware_display_touch_or_speaker_verified': False, 'display_hardware_verified': False,
        'touchscreen_hardware_verified': False, 'speaker_sound_verified': False, 'device_IO': False, 'native_guest_execution': False,
        'device_install_candidate': False, 'remaining_work': copy.deepcopy(GAPS),
        'historical_progress_estimates_not_increased': True}
    if artifact is not None:
        checkpoint['retained_software_frame_artifact'] = artifact
    web_before = json.loads(before[FILES[4]])
    pid, start = P.live_server(web_before)
    P.require(pid == 885568, 'Same existing PID885568, never restart')
    P.require(P.fetch(web_before['url']) == before[FILES[3]], 'Before HTTP exact bytes')
    now = datetime.now(timezone.utc)
    after, checkpoint = prepare(before, checkpoint, now)
    if frame is not None:
        V.verify_HTTP_embedded_artifact(after[FILES[3]], artifact, frame)
    P.require(all((ROOT / name).read_bytes() == raw for name, raw in before.items()), 'No concurrent canonical changes')
    if not args.publish:
        print(json.dumps(dict(short_summary(checkpoint, pid), all_input_and_preflight_checks_passed=True, publication_performed=False), ensure_ascii=False))
        return
    out = ROOT / 'staging' / ('android-auto-interactive-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    (out / 'canonical-before.json.gz').write_bytes(gzip.compress(P.encoded({name: raw.decode() for name, raw in before.items()}), mtime=0))
    (out / 'publication-inputs.json').write_bytes(P.encoded(checkpoint))
    written = []
    try:
        for name in FILES[:4]:
            P.replace(name, after[name])
            written.append(name)
        served = P.fetch(web_before['url'])
        P.require(served == after[FILES[3]] and P.live_server(web_before) == (pid, start), 'Exact HTTP report and process identity unchanged')
        web = json.loads(after[FILES[4]])
        web.update(HTTP_status=200, local_report_sha256=P.digest(served), served_report_sha256=P.digest(served),
            report_bytes=len(served), served_latest_report=True, service_not_restarted=True, canonical_hash_readback_uncached=True)
        retained = {}
        if frame is not None:
            P.require(V.software_artifact_target().read_bytes() == frame, 'Retained prior PNG remains exact, never rewritten')
            retained = V.verify_HTTP_embedded_artifact(served, artifact, frame)
            web.update(retained)
        after[FILES[4]] = P.encoded(web)
        P.replace(FILES[4], after[FILES[4]])
        written.append(FILES[4])
        P.require(all((ROOT / name).read_bytes() == raw for name, raw in after.items()), 'Exact canonical file readback')
        docs = [json.loads(after[name]) for name in (FILES[0], FILES[1], FILES[2], FILES[4])]
        P.require(docs[0] == docs[2]['deep_research'] and all(document['goal_status'] == 'active' and
            not document['goal_complete'] and document[FIELD] == checkpoint for document in docs), 'Canonical active/incomplete equality')
        receipt = dict(short_summary(checkpoint, pid), all_publication_checks_passed=True,
            updated_at_Taiwan=checkpoint['updated_Taiwan'], report_url=web_before['url'], service_not_restarted=True,
            report_HTTP_exact_bytes=True, canonical_after_sha256={name: P.digest(raw) for name, raw in after.items()},
            prerequisite_video_cases=20, previous_goal_turn_assessment='progress', current_goal_turn_assessment='progress', **retained)
        (out / 'fresh-readback.json').write_bytes(P.encoded(receipt))
        print(json.dumps(dict(receipt, snapshot=str(out.relative_to(ROOT))), ensure_ascii=False))
    except Exception as error:
        rolled_back, conflicts, failures = [], [], []
        for name in reversed(written):
            try:
                if (ROOT / name).read_bytes() == after[name]:
                    P.replace(name, before[name])
                    rolled_back.append(name)
                else:
                    conflicts.append(name)
            except Exception as rollback_error:
                failures.append({'path': name, 'error': str(rollback_error)})
        (out / 'publication-failure.json').write_bytes(P.encoded({'error': str(error), 'own_changes_rolled_back': rolled_back,
            'concurrent_conflicts_left_untouched': conflicts, 'rollback_failures': failures, 'prior_PNG_not_modified': True,
            'native_guest_execution': False, 'device_IO': False}))
        raise


if __name__ == '__main__':
    main()
