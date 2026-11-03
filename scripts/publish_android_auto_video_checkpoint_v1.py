#!/usr/bin/env python3
"""Preflight/publish actual host H.264 decoding and AA video integration proofs.

Default is read-only preflight with a short summary, never a full checkpoint dump.
--plan-output staging/private/NAME.json optionally writes a bounded private plan.
--publish updates five canonical/report files with snapshots, atomic file replaces,
rollback of our own changes on failure, exact HTTP readback and PID885568 unchanged.
An optional proof-backed PNG is copied to one fixed report artifact and embedded as
a data URI; the existing server/CSP has no standalone image route. Default preflight
only reads/validates PNG bytes, never copies them or changes the served report.
No builder, test, guest, original Garmin instruction/callsite, device query, service
restart, pairing, call, audio or goal transition is executed by this publisher.

Run metadata schema: android-auto-video-checkpoint-v1
  publisher_helper_sha256: hash of publish_android_auto_host_checkpoint_v1.py
  goal_receipt: {path, sha256, status_path, objective_path}
  previous_goal_turn_assessment: "progress"
  video / h264: {proof_sha256, claims (dotpath -> exact expected value),
    pass_claim, device_io_claim, native_guest_claim, case_count_claim, case_count,
    source_pins_claim, source_pins, scope, completed,
    software_decode_claim: dotpath to a TRUE claim in actual proof,
    count_label: truthful label, e.g. "項主機檢查" or "筆fixture比較"}
  terminal_receipts: [{path, sha256, result_path, chunk_id,
                       covers: ["video", "h264"]}, ...]
  video_h264_reference_path: optional dotpath for {path,sha256} in video proof
  software_frame_artifact: optional {proof_field: exact dotpath in video proof,
    publish_target: "reports/android-auto-decoded-pattern.png"}
    The proof field must contain {path,sha256,width:480,height:272,source} for the
    actual staging/android-auto-video-host-v1/decoded-test-pattern.png. Publication
    verifies the PNG copied locally and the embedded PNG bytes read back via HTML
    HTTP; it never claims a standalone PNG URL, Garmin display or Google Maps.

Video schema: android-auto-video-host-v1; prerequisite.control must pin control43.
H.264 schema: android-auto-h264-host-v1. Only actual reviewed proof can establish
software_decoded_frames_verified=true. Phone/Google/native/install/Maps/hardware
display/sound/full-goal flags stay false. Prior startup29/pipeline27/TLS15/wire25,
control43 and proto127 remain history; proto127 means 63 fixture comparisons per
build plus one literal uint64 control, not127 independent categories.
"""
import argparse
import base64
import copy
import gzip
import html
import json
import os
import re
import stat
import struct
import tempfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import publish_android_auto_host_checkpoint_v1 as P

ROOT, FILES = P.ROOT, P.FILES
FIELD = 'latest_android_auto_video_checkpoint'
SCHEMA = 'android-auto-video-checkpoint-v1'
CARD_ID = 'android-auto-video-current-checkpoint-v1'
PRIOR_FIELD = 'latest_android_auto_control_checkpoint'
PRIOR_CARD_ID = 'android-auto-control-current-checkpoint-v1'
ARTIFACT_SOURCE = 'staging/android-auto-video-host-v1/decoded-test-pattern.png'
ARTIFACT_TARGET = 'reports/android-auto-decoded-pattern.png'
ARTIFACT_IMG_ID = 'android-auto-software-decoded-pattern-v1'
ARTIFACT_LABEL = '本地H264測試圖樣的軟體解碼／縮放結果；不是Garmin螢幕或GoogleMaps'
PNG_LIMIT = 512 * 1024
NEXT_ACTIONS = [
    '核對真正USB主機／VBUS／AOA與current phone介面，再整合完整影音資料生命週期；Linux-host軟體解碼不代表Garmin即時效能或螢幕呈現。',
    '完成原機H.264 allocator／保守記憶體與效能、display／縮放／觸控／音訊／App與UI平台介面；原native執行中斷分支不重試或繞過。',
    'Android Auto／Google Maps／原機離線使用與可安裝接收端仍未完成；BT／Android第四版歷史保留，導航修復與麥克風停止。使用者會主動通知可實測，現在不查裝置、要求配對、發來電或播音。',
]
GAPS = [
    '本地peer與固定legacy模型未證current phone／Pixel／Google接受。',
    '真正USB主機／VBUS、enumeration及AOA bulk傳輸尚未在Garmin驗證。',
    'H.264 native allocator／可用記憶體、ARM平台相容性與即時效能沒有實機證據。',
    '軟體decoded frames不等於硬體螢幕顯示；display／縮放／觸控／audio／UI仍待整合。',
    '完整媒體生命週期、原機音訊所有權、可靠停止／重連及導航共存未完成。',
    '原機亂數／時間／配置／ABI、App載入／菜單、可安裝接收端及原機Google Maps／離線使用未完成；原native guest界線保留。',
]


def source_pin(name, pin):
    path = P.resolve(name)
    suffixes = ('.c', '.h', '.cpp', '.cc', '.hpp', '.py', '.json', '.txt', '.md', '.cmake', '.proto', '.options', '.mk')
    P.require((path.suffix in suffixes or path.name in ('COPYING', 'protoc-gen-nanopb', 'LICENSE.openh264'))
              and path.stat().st_size <= 1024 * 1024, 'Bounded source-only pin, no binaries: ' + name)
    P.require(P.digest(path.read_bytes()) == pin, 'Tested source remains current: ' + name)


def validate_png(raw):
    """Validate bounded PNG envelope, dimensions, chunk CRCs and final IEND."""
    P.require(isinstance(raw, bytes) and 33 <= len(raw) <= PNG_LIMIT and
        raw[:8] == b'\x89PNG\r\n\x1a\n', 'Bounded actual PNG magic')
    offset, types, dimensions = 8, [], None
    while offset < len(raw):
        P.require(offset + 12 <= len(raw), 'Complete PNG chunk header and CRC')
        length = struct.unpack_from('>I', raw, offset)[0]
        kind = raw[offset + 4:offset + 8]
        end = offset + 12 + length
        P.require(length <= PNG_LIMIT and end <= len(raw) and
            re.fullmatch(rb'[A-Za-z]{4}', kind), 'Bounded complete PNG chunk')
        body = raw[offset + 8:offset + 8 + length]
        expected_crc = struct.unpack_from('>I', raw, offset + 8 + length)[0]
        P.require(zlib.crc32(kind + body) & 0xffffffff == expected_crc, 'Actual PNG chunk CRC')
        if not types:
            P.require(kind == b'IHDR' and length == 13, 'First PNG chunk is one IHDR')
            width, height, bits, colour, compression, filtering, interlace = struct.unpack('>IIBBBBB', body)
            P.require((width, height) == (480, 272) and bits in (1, 2, 4, 8, 16) and
                colour in (0, 2, 3, 4, 6) and compression == 0 and filtering == 0 and interlace in (0, 1),
                'Proof-backed 480x272 software image dimensions/PNG header')
            dimensions = (width, height)
        elif kind == b'IHDR':
            P.require(False, 'Only one PNG IHDR')
        types.append(kind)
        offset = end
        if kind == b'IEND':
            P.require(length == 0 and offset == len(raw), 'Final empty PNG IEND, no trailing bytes')
            break
    P.require(types[-1] == b'IEND' and b'IDAT' in types, 'Complete PNG image payload')
    return dimensions


def software_artifact_target():
    path = ROOT / ARTIFACT_TARGET
    P.require(path.parent.is_dir() and path.parent.resolve() == (ROOT / 'reports').resolve() and
        not path.is_symlink() and (not path.exists() or path.is_file()), 'Fixed regular report PNG artifact target')
    P.require(not path.exists() or path.stat().st_size <= PNG_LIMIT, 'Bounded previous report artifact')
    return path


def validate_software_artifact(video_proof, metadata, video_reference):
    spec = metadata.get('software_frame_artifact')
    if spec is None:
        return None, None, None
    P.require(isinstance(spec, dict) and set(spec) == {'proof_field', 'publish_target'} and
        spec['publish_target'] == ARTIFACT_TARGET, 'Optional exact proof dotpath and fixed artifact target')
    recorded = P.field(video_proof, spec['proof_field'])
    P.require(isinstance(recorded, dict) and recorded['path'] == ARTIFACT_SOURCE and
        type(recorded['width']) is int and type(recorded['height']) is int and
        (recorded['width'], recorded['height']) == (480, 272) and
        isinstance(recorded['source'], str) and 0 < len(recorded['source']) <= 1000 and
        not P.PRIVATE.search(recorded['source']), 'Actual software pattern artifact provenance/dimensions')
    source = P.resolve(recorded['path'])
    P.require(source.suffix == '.png' and source.stat().st_size <= PNG_LIMIT,
        'Only bounded generated software-test PNG is read')
    raw = source.read_bytes()
    P.require(re.fullmatch(r'[0-9a-f]{64}', recorded['sha256'] or '') and
        P.digest(raw) == recorded['sha256'], 'Exact proof-backed generated PNG SHA-256')
    validate_png(raw)
    target = software_artifact_target()
    old = target.read_bytes() if target.exists() else None
    return {'proof': {key: video_reference[key] for key in ('path', 'sha256')},
        'proof_field': spec['proof_field'], 'source_path': recorded['path'], 'sha256': recorded['sha256'],
        'width': 480, 'height': 272, 'source': recorded['source'], 'label': ARTIFACT_LABEL,
        'publish_target': ARTIFACT_TARGET, 'bytes': len(raw),
        'HTTP_transport': 'PNG bytes embedded in the existing report HTML data URI',
        'standalone_PNG_HTTP_route_verified': False, 'software_surface_only': True,
        'Garmin_display_or_Google_Maps_verified': False}, raw, old


def replace_software_artifact(raw):
    """Atomically copy exact bytes; support the first optional artifact creation."""
    path = software_artifact_target()
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def software_figure(checkpoint, raw):
    if raw is None:
        P.require('software_frame_artifact' not in checkpoint, 'No optional figure without actual proof')
        return ''
    artifact = checkpoint['software_frame_artifact']
    P.require(P.digest(raw) == artifact['sha256'], 'Exact reviewed figure bytes')
    return ('<figure id="android-auto-software-decoded-pattern-figure-v1"><img id="' + ARTIFACT_IMG_ID +
        '" width="480" height="272" style="max-width:100%;height:auto" alt="' + html.escape(ARTIFACT_LABEL) +
        '" src="data:image/png;base64,' + base64.b64encode(raw).decode('ascii') + '"><figcaption>' +
        html.escape(ARTIFACT_LABEL) + '</figcaption></figure>')


def verify_HTTP_embedded_artifact(served, artifact, raw):
    matches = re.findall(rb'<img id="' + ARTIFACT_IMG_ID.encode() +
        rb'"[^>]* src="data:image/png;base64,([A-Za-z0-9+/=]+)"', served)
    P.require(len(matches) == 1, 'Single proof-backed PNG embedded in exact HTTP report')
    observed = base64.b64decode(matches[0], validate=True)
    P.require(observed == raw and P.digest(observed) == artifact['sha256'],
        'Exact image PNG bytes/SHA-256 read back through existing HTML HTTP route')
    return {'report_artifact_exact_copy_verified': True,
        'software_frame_HTTP_embedded_readback_verified': True,
        'software_frame_HTTP_embedded_sha256': artifact['sha256'],
        'standalone_PNG_HTTP_route_verified': False}


def validate_proof(name, spec, schema):
    proof, reference = P.pinned_json(name, spec['proof_sha256'])
    P.require(proof['schema'] == schema, 'Actual proof schema: ' + schema)
    P.require(isinstance(spec['claims'], dict) and spec['claims'], 'Reviewed exact proof claims')
    for dotted, wanted in spec['claims'].items():
        observed = P.field(proof, dotted)
        P.require(type(observed) is type(wanted) and observed == wanted, 'Exact proof claim ' + name + ':' + dotted)
    for key, wanted in (('pass_claim', True), ('device_io_claim', False), ('native_guest_claim', False), ('software_decode_claim', True)):
        dotted = spec[key]
        P.require(dotted in spec['claims'] and P.field(proof, dotted) is wanted, 'Explicit actual host/decoded-frame evidence: ' + key)
    count = spec['case_count']
    P.require(type(count) is int and count > 0 and spec['case_count_claim'] in spec['claims'] and
        type(P.field(proof, spec['case_count_claim'])) is int and P.field(proof, spec['case_count_claim']) == count,
        'Actual host count, no inferred cases')
    P.require(isinstance(spec['count_label'], str) and 0 < len(spec['count_label']) <= 100, 'Truthful count label')
    recorded = P.field(proof, spec['source_pins_claim'])
    P.require(isinstance(recorded, dict) and spec['source_pins_claim'] in spec['claims'], 'Reviewed proof source dictionary')
    pins = {key: (value['sha256'] if isinstance(value, dict) else value) for key, value in recorded.items()}
    P.require(pins and pins == spec['source_pins'], 'Exactly the tested source pins')
    for source, pin in pins.items():
        source_pin(source, pin)
    P.require(isinstance(spec['scope'], str) and 0 < len(spec['scope']) <= 2000 and
        isinstance(spec['completed'], list) and 0 < len(spec['completed']) <= 64 and
        all(isinstance(text, str) and 0 < len(text) <= 2000 for text in spec['completed']), 'Bounded reviewed summary/scope')
    P.require(not P.PRIVATE.search(spec['scope'] + '\n'.join(spec['completed']) + spec['count_label']), 'No identifiers or credentials in public summary')
    return proof, dict(reference, case_count=count, count_label=spec['count_label'], scope=spec['scope'],
        completed=copy.deepcopy(spec['completed']), source_pins=pins, verified_claims=copy.deepcopy(spec['claims']),
        host_layer_only=True, software_decoded_frames_verified=True, native_guest_execution=False, device_IO=False,
        current_phone_or_Google_acceptance_verified=False, display_hardware_verified=False, speaker_sound_verified=False)


def validate_control_prerequisite(proof, state):
    prior = state[PRIOR_FIELD]
    summary = prior['proofs']['control']
    expected = {key: summary[key] for key in ('path', 'sha256')}
    P.require(proof['prerequisite']['control'] == expected, 'Video proof pins exact control43 prerequisite')
    document, reference = P.pinned_json(expected['path'], expected['sha256'])
    P.require(prior['goal_status'] == 'active' and not prior['full_goal_complete'] and
        summary['case_count'] == 43 and summary['host_layer_only'] and not summary['device_IO'] and
        not summary['native_guest_execution'] and prior['proofs']['proto']['case_count'] == 127,
        'Prior control43/proto127 exact scope')
    for dotted, wanted in summary['verified_claims'].items():
        observed = P.field(document, dotted)
        P.require(type(observed) is type(wanted) and observed == wanted, 'Prerequisite actual recorded claim: ' + dotted)
    for name, pin in summary['source_pins'].items():
        source_pin(name, pin)
    return dict(reference, case_count=43, historical_prerequisite_not_new_test=True,
        proto_comparisons_in_prior_checkpoint=127, proto127_not_independent_categories=True,
        current_source_pins_verified=True, device_IO=False, native_guest_execution=False)


def prepare(before, checkpoint, now, frame_raw=None):
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    P.require(state == public['deep_research'], 'Prior canonical equality')
    P.require(all(d['goal_status'] == 'active' and not d['goal_complete'] and
        d['current_goal_priority'] == 'android_auto_google_maps' for d in (state, task, public, web)), 'Full objective remains active/incomplete')
    P.require(state['requested_goal'] == P.OBJECTIVE and state['last_goal_turn']['classification'] == 'progress', 'Previous control43 actual progress')
    P.require(state['navigation_repair']['status'] == 'stopped_by_user' and
        state['microphone_amplifier']['status'] == 'cancelled_by_user', 'User cancellations preserved')
    P.require(task['user_away'] and not state['audio']['audible_tests_allowed'] and
        not web['current_physical_test_requested'], 'No unattended device or audio work')
    P.require(not state['native_android_auto']['native_receiver_running'] and not state['native_android_auto']['phone_session_verified'] and
        not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'] and
        not state['google_maps']['native_running'], 'No unsupported phone/native/App/maps success')
    keys = ('audio', 'navigation_repair', 'microphone_amplifier', 'native_app_music', 'google_maps', P.FIELD,
        'latest_android_auto_pipeline_checkpoint', 'latest_android_auto_startup_checkpoint', PRIOR_FIELD,
        'bluetooth_music_blocking_audit', 'research_goal_status_history')
    preserved = {key: copy.deepcopy(state[key]) for key in keys}
    old_progress = copy.deepcopy(public['research_progress'])
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp, display = local.isoformat(timespec='seconds'), local.strftime('%Y/%m/%d %H:%M:%S')
    checkpoint.update(updated_utc=now.isoformat(), updated_Taiwan=stamp)
    checkpoint['prior_published_goal_turn'] = copy.deepcopy(state['last_goal_turn'])
    turn = {'classification': 'progress', 'previous_goal_turn_assessment': 'progress',
        'previous_goal_turn_reason': 'Previous control43 host implementation/tests were actual progress; proto127 means fixture comparisons, not127 distinct categories.',
        'validated_utc': now.isoformat(), 'goal_status': 'active', 'required_work_remaining': True, 'full_goal_complete': False,
        'focused_evidence': copy.deepcopy(checkpoint['proofs']), 'prerequisite_evidence': copy.deepcopy(checkpoint['prerequisite']),
        'host_layer_implementation_and_verification': True, 'software_decoded_frames_verified': True,
        'display_hardware_verified': False, 'speaker_sound_verified': False,
        'native_guest_execution': False, 'device_IO': False, 'device_files_written': False, 'device_calls_or_sound': False,
        'reason': 'Actual independent H264 software decode proof and TLS/control-ownedqueue-decoder host integration; no phone/Google/native/display hardware/sound/install success.'}
    state.update(updated_utc=now.isoformat(), goal_status='active', goal_complete=False,
        current_priority='GarminOS Android Auto／Google Maps；Linux-host H.264軟體解碼與TLS／控制／自有佇列整合。',
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
    work['current_offline_line_status']['android_auto'] = 'Linux-host decoded software frames and video integration verified; phone/Google, real USB, native allocator/performance/display/touch/audio/UI/install unverified'
    for document in (task, public, web):
        for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', FIELD, 'offline_24h_work_order', 'android_auto_blocking_audit'):
            document[key] = copy.deepcopy(state[key])
        document.update(goal_status='active', goal_complete=False, required_work_remaining=True)
        document.pop('goal_blocked_reason', None)
    task['native_android_auto'] = copy.deepcopy(aa)
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state))
    completed = checkpoint['proofs']['h264']['completed'] + checkpoint['proofs']['video']['completed']
    progress = public['research_progress']
    progress['completed'].extend(completed)
    progress.update(research_updated_utc=now.isoformat(), next=NEXT_ACTIONS[0], goal_completed=False,
        method='沿用完整研究計畫的歷史工程估計；H.264軟體解碼及資料流程只有Linux-host驗證，不提高原機百分比。真正GarminOS Android Auto／Google Maps仍未完成，導航修復與麥克風停止。')
    phase_next = {'USB 主機與手機連線': NEXT_ACTIONS[0], '畫面、影片與觸控投影': NEXT_ACTIONS[1],
        '原生 App 入口與功能整合': '補齊原機載入／App／UI、完整影音與停止／重連；host軟體影格不是硬體顯示或current phone驗收。'}
    for phase in progress['phases']:
        if phase['name'] in phase_next:
            phase['next'] = phase_next[phase['name']]
    P.require(progress['estimate_percent'] == old_progress['estimate_percent'] == 37 and
        progress['weighted_estimate_percent'] == old_progress['weighted_estimate_percent'] and
        [(p['name'], p['weight'], p['estimate_percent'], p['deferred']) for p in progress['phases']] ==
        [(p['name'], p['weight'], p['estimate_percent'], p['deferred']) for p in old_progress['phases']], 'Historical37 estimates unchanged')
    P.require(all(state[key] == old for key, old in preserved.items()), 'Prior control/proto/startup/pipeline/TLS/wire/BT/App/cancellations preserved')
    report = before[FILES[3]].decode()
    P.require(CARD_ID not in report, 'Video v1 not already published')
    previous = re.search(r'<section class="card" id="' + PRIOR_CARD_ID + r'">.*?</section>', report, re.S)
    P.require(previous is not None, 'Previous control43 report card')
    prior_card = previous.group()
    report = report.replace(prior_card, '<details class="card" id="android-auto-control-checkpoint-history-v1">'
        '<summary>前一輪控制紀錄：control43／proto127筆比較</summary><p>Proto127是63筆fixture在兩建置各比較一次，再加1個uint64 literal控制；不是127獨立類別。前卡內容完整保留，計數以本說明及原proof為準。</p>' + prior_card + '</details>', 1)
    e = html.escape
    steps = ''.join('<li>' + e(text) + '</li>' for text in completed)
    gaps = ''.join('<li>' + e(text) + '</li>' for text in GAPS)
    scopes = ''.join('<li><strong>' + title + '：</strong>' + e(checkpoint['proofs'][key]['scope']) + '；'
        + str(checkpoint['proofs'][key]['case_count']) + e(checkpoint['proofs'][key]['count_label']) + '。</li>'
        for title, key in (('獨立H.264', 'h264'), ('影像流程整合', 'video')))
    card = (f'<section class="card" id="{CARD_ID}"><h2>目前主線：H.264軟體解碼／影像資料流程（Linux-host）</h2>'
        f'<p>完整Android Auto／Google Maps目標active／尚未完成。更新：<time datetime="{stamp}">{display}</time>（台灣時間）</p>'
        '<p><strong>本輪proof確認的是主機端軟體decoded frames，未證current phone／Google、Garmin解碼效能、硬體display或喇叭。</strong>'
        '目前仍沒有原機可安裝接收端。</p><h3>本輪已完成</h3><ul>' + steps + '</ul>' + software_figure(checkpoint, frame_raw) +
        '<h3>驗證範圍</h3><ul>' + scopes + '</ul>'
        '<p>前輪control43、startup29、pipeline27與TLS15／wire25保留；proto127是fixture比較總數，兩建置不是不同類別，未把歷史結果當本輪重測。</p>'
        '<p><strong>藍牙音樂：</strong>Pixel → Pi → Garmin持續60秒有聲屬使用者確認的歷史實測；Android第四版APK只有主機編譯／DEX／API28簽章及18項gate＋12項lease檢查，'
        'Pixel本機通話／SCO／Garmin出聲未驗證。原機直接A2DP與GarminOS菜單App仍未完成。'
        '<a href="/garmin-hfp-prototype.apk" download="garmin-hfp-prototype.apk">保留的第四版實驗APK</a>。</p>'
        '<h3>仍待完成</h3><ul>' + gaps + '</ul><p>本輪沒有original Garmin／native guest／原機callsite操作、手機或實體USB、配對、來電、播音或安裝；原native執行中斷界線保留。'
        '工程估計仍37%，不是Android Auto完成率；導航修復與麥克風停止。</p></section>')
    P.require(report.count('<main>') == 1, 'Single report main')
    report = report.replace('<main>', '<main>' + card, 1)
    report = P.substitute(report, r'<span class="progress-status">.*?</span>',
        '<span class="progress-status">Android Auto／Google Maps：主機軟體影像流程研究中</span>', 'progress status')
    report = P.substitute(report, r'<p id="progress-method"[^>]*>.*?</p>',
        '<p id="progress-method" class="progress-note">' + e(progress['method']) + '</p>', 'method')
    report = P.substitute(report, r'<p id="offline-frontier-latest-v1">.*?</p>',
        '<p id="offline-frontier-latest-v1">最新：H.264軟體解碼與TLS／控制／自有佇列影像流程有新的Linux-host證據；current phone／Google、USB／AOA、Garmin allocator／效能／display／觸控／audio／UI與安裝仍未驗證。</p>', 'frontier')
    report = P.substitute(report, r'<p><strong>下一步：</strong>.*?</p>', '<p><strong>下一步：</strong>' + e(NEXT_ACTIONS[0]) + '</p>', 'next')
    old_list = re.search(r'<ul class="completed-progress">.*?</ul>', report, re.S)
    P.require(old_list is not None, 'Historical completed list')
    report = report.replace(old_list.group(), old_list.group()[:-5] + steps + '</ul>', 1)
    for phase in progress['phases']:
        if phase['name'] in phase_next:
            report = P.substitute(report, r'<tr><td>' + re.escape(e(phase['name'])) + r'</td><td>.*?</td><td>.*?</td></tr>',
                '<tr><td>' + e(phase['name']) + '</td><td>' + str(phase['estimate_percent']) + '%</td><td>' + e(phase['next']) + '</td></tr>', 'phase ' + phase['name'])
    for element in ('report-updated-time', 'research-updated-time'):
        report = P.substitute(report, r'<time id="' + element + r'" datetime="[^"]+">[^<]+</time>',
            f'<time id="{element}" datetime="{stamp}">{display}</time>', element)
    P.require(not P.PRIVATE.search(report), 'No unit IDs, phone addresses or private keys in public report')
    P.require(report.index('id="' + CARD_ID + '"') < report.index('id="' + PRIOR_CARD_ID + '"'), 'New video card first')
    web.update(full_goal_complete=False, actual_goal_status_read='active', current_physical_test_requested=False)
    web['progress_display_verified'].update(estimate_percent=37, completed_items=len(progress['completed']), report_updated_time=stamp,
        research_updated_time=stamp, android_auto_video_checkpoint_visible=True, prior_control43_proto127_history_preserved=True,
        software_decode_not_hardware_display_or_sound_visible=True, proto127_fixture_count_limits_visible=True,
        current_Pixel_Google_native_install_not_claimed=True, HTML_structure_checked=False, visual_browser_render_not_performed=True)
    if frame_raw is not None:
        verify_HTTP_embedded_artifact(report.encode(), checkpoint['software_frame_artifact'], frame_raw)
        web['progress_display_verified'].update(software_test_pattern_figure_in_proposed_HTML=True,
            software_test_pattern_not_Garmin_display_or_Google_Maps_visible=True)
    return {FILES[0]: P.encoded(state), FILES[1]: P.encoded(task), FILES[2]: P.encoded(public), FILES[3]: report.encode(), FILES[4]: P.encoded(web)}, checkpoint


def short_summary(checkpoint, pid):
    summary = {'schema': SCHEMA, 'goal_status': 'active', 'report_PID': pid,
        'proofs': {key: {name: value[name] for name in ('path', 'sha256', 'case_count', 'count_label')}
                   for key, value in checkpoint['proofs'].items()},
        'software_decoded_frames_verified': True, 'display_hardware_verified': False, 'speaker_sound_verified': False,
        'current_phone_or_Google_acceptance_verified': False, 'native_guest_execution': False,
        'device_IO': False, 'device_install_candidate': False, 'full_goal_complete': False}
    if 'software_frame_artifact' in checkpoint:
        summary['software_frame_artifact'] = {key: checkpoint['software_frame_artifact'][key]
            for key in ('publish_target', 'sha256', 'width', 'height', 'HTTP_transport', 'standalone_PNG_HTTP_route_verified')}
    return summary


def write_private_plan(name, checkpoint, pid):
    path = (ROOT / name).resolve()
    P.require(path.is_relative_to(ROOT / 'staging' / 'private') and path.suffix == '.json' and not path.exists(), 'New private staging JSON plan only')
    document = short_summary(checkpoint, pid)
    document.update(planned_not_published=True, updated_Taiwan=checkpoint['updated_Taiwan'], remaining_work=checkpoint['remaining_work'],
        completed={key: value['completed'] for key, value in checkpoint['proofs'].items()},
        scope={key: value['scope'] for key, value in checkpoint['proofs'].items()})
    raw = P.encoded(document)
    P.require(len(raw) <= 128 * 1024, 'Private plan <=128KiB; no full source/claims dump')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return str(path.relative_to(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proof', required=True, help='Actual AA video host-integration proof')
    parser.add_argument('--h264-proof', default='evidence/android-auto-h264-host-v1.json')
    parser.add_argument('--run-metadata', required=True)
    parser.add_argument('--plan-output', help='Optional bounded new staging/private/NAME.json preflight plan')
    parser.add_argument('--publish', action='store_true', help='Write five canonical/report files and any proof-backed optional fixed PNG; default read-only short preflight')
    args = parser.parse_args()
    P.require(not (args.publish and args.plan_output), 'Private plan is a preflight option, separate from publication')
    meta_path = P.resolve(args.run_metadata)
    P.require(meta_path.suffix == '.json' and meta_path.stat().st_size <= 256 * 1024, 'Bounded run metadata')
    meta_raw = meta_path.read_bytes()
    metadata = json.loads(meta_raw)
    P.require(metadata['schema'] == SCHEMA and not metadata.get('illustrative_template'), 'Actual reviewed metadata')
    P.require(metadata['previous_goal_turn_assessment'] == 'progress', 'Previous control43 actual progress')
    P.require(P.digest(Path(P.__file__).read_bytes()) == metadata['publisher_helper_sha256'], 'Reviewed pure metadata/HTTP helpers')
    goal, goal_ref = P.pinned_json(metadata['goal_receipt']['path'], metadata['goal_receipt']['sha256'])
    P.require(P.field(goal, metadata['goal_receipt'].get('status_path', 'status')) == 'active' and
        P.field(goal, metadata['goal_receipt'].get('objective_path', 'objective')) == P.OBJECTIVE, 'Actual active goal receipt, full objective')
    video_proof, video = validate_proof(args.proof, metadata['video'], 'android-auto-video-host-v1')
    h264_proof, h264 = validate_proof(args.h264_proof, metadata['h264'], 'android-auto-h264-host-v1')
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    prerequisite = validate_control_prerequisite(video_proof, json.loads(before[FILES[0]]))
    h264_link_checked = False
    if metadata.get('video_h264_reference_path'):
        P.require(P.field(video_proof, metadata['video_h264_reference_path']) == {key: h264[key] for key in ('path', 'sha256')}, 'Video proof exact independent decoder reference')
        h264_link_checked = True
    P.require(isinstance(metadata['terminal_receipts'], list) and metadata['terminal_receipts'], 'Actual final test receipts')
    receipts, coverage = [], set()
    for row in metadata['terminal_receipts']:
        receipt, reference = P.pinned_json(row['path'], row['sha256'])
        result = P.field(receipt, row['result_path']) if row.get('result_path') else receipt
        P.require(result['exit_code'] == 0 and 'session_id' not in result and result['chunk_id'] == row['chunk_id'], 'Actual EXIT0, no running session')
        P.require(isinstance(row['covers'], list) and row['covers'] and set(row['covers']) <= {'video', 'h264'}, 'Actual tested proof coverage')
        coverage.update(row['covers'])
        receipts.append(dict(reference, chunk_id=row['chunk_id'], exit_code=0, covers=copy.deepcopy(row['covers'])))
    P.require(coverage == {'video', 'h264'}, 'Actual receipts cover both proofs')
    checkpoint = {'schema': SCHEMA, 'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
        'goal_receipt': goal_ref, 'proofs': {'video': video, 'h264': h264}, 'prerequisite': {'control': prerequisite},
        'video_proof_pinned_h264_reference_checked': h264_link_checked, 'terminal_receipts': receipts,
        'run_metadata': {'path': str(meta_path.relative_to(ROOT)), 'sha256': P.digest(meta_raw)},
        'source_and_test_scope': 'Independent H264 decoded software frames and TLS/control-ownedqueue-decoder integration, Linux host only',
        'software_decoded_frames_verified': True, 'phone_or_Pixel_or_Google_acceptance_verified': False,
        'Garmin_native_receiver_or_Google_Maps_running': False, 'display_hardware_verified': False, 'speaker_sound_verified': False,
        'device_IO': False, 'native_guest_execution': False, 'device_install_candidate': False,
        'remaining_work': copy.deepcopy(GAPS), 'historical_progress_estimates_not_increased': True}
    artifact, frame_raw, frame_before = validate_software_artifact(video_proof, metadata, video)
    if artifact is not None:
        checkpoint['software_frame_artifact'] = artifact
    web_before = json.loads(before[FILES[4]])
    pid, start = P.live_server(web_before)
    P.require(pid == 885568, 'Existing PID885568, no restart/replacement')
    P.require(P.fetch(web_before['url']) == before[FILES[3]], 'Before HTTP exact local report')
    now = datetime.now(timezone.utc)
    after, checkpoint = prepare(before, checkpoint, now, frame_raw)
    P.require(all((ROOT / name).read_bytes() == raw for name, raw in before.items()), 'No concurrent canonical changes')
    if not args.publish:
        plan = write_private_plan(args.plan_output, checkpoint, pid) if args.plan_output else None
        print(json.dumps(dict(short_summary(checkpoint, pid), all_input_and_preflight_checks_passed=True,
            publication_performed=False, private_plan=plan), ensure_ascii=False))
        return
    out = ROOT / 'staging' / ('android-auto-video-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    (out / 'canonical-before.json.gz').write_bytes(gzip.compress(P.encoded({name: raw.decode() for name, raw in before.items()}), mtime=0))
    (out / 'publication-inputs.json').write_bytes(P.encoded(checkpoint))
    if frame_raw is not None:
        (out / 'software-frame-before.json').write_bytes(P.encoded({'target': ARTIFACT_TARGET,
            'previously_present': frame_before is not None, 'previous_sha256': P.digest(frame_before) if frame_before is not None else None}))
        if frame_before is not None:
            (out / 'software-frame-before.png').write_bytes(frame_before)
    written, frame_written = [], False
    try:
        if frame_raw is not None:
            target = software_artifact_target()
            P.require((target.read_bytes() if target.exists() else None) == frame_before,
                'No concurrent optional report artifact changes')
            P.require(P.resolve(ARTIFACT_SOURCE).read_bytes() == frame_raw,
                'Proof-backed optional artifact remains exact before publication')
            frame_written = True
            replace_software_artifact(frame_raw)
            P.require(target.read_bytes() == frame_raw, 'Exact fixed PNG report artifact copy')
        for name in FILES[:4]:
            P.replace(name, after[name])
            written.append(name)
        served = P.fetch(web_before['url'])
        P.require(served == after[FILES[3]], 'Published HTML exact HTTP readback')
        P.require(P.live_server(web_before) == (pid, start), 'Same report process identity, no restart')
        web = json.loads(after[FILES[4]])
        web.update(HTTP_status=200, local_report_sha256=P.digest(served), served_report_sha256=P.digest(served),
            report_bytes=len(served), served_latest_report=True, service_not_restarted=True, canonical_hash_readback_uncached=True)
        frame_readback = verify_HTTP_embedded_artifact(served, artifact, frame_raw) if frame_raw is not None else {}
        if frame_raw is not None:
            P.require(software_artifact_target().read_bytes() == frame_raw, 'Exact copied PNG remains after HTTP readback')
            web.update(frame_readback)
        after[FILES[4]] = P.encoded(web)
        P.replace(FILES[4], after[FILES[4]])
        written.append(FILES[4])
        P.require(all((ROOT / name).read_bytes() == raw for name, raw in after.items()), 'Exact canonical file readback')
        docs = [json.loads(after[name]) for name in (FILES[0], FILES[1], FILES[2], FILES[4])]
        P.require(docs[0] == docs[2]['deep_research'] and all(document['goal_status'] == 'active' and
            not document['goal_complete'] and document[FIELD] == checkpoint for document in docs), 'Active/incomplete canonical equality')
        receipt = dict(short_summary(checkpoint, pid), all_publication_checks_passed=True, updated_at_Taiwan=checkpoint['updated_Taiwan'],
            report_url=web_before['url'], service_not_restarted=True, report_HTTP_exact_bytes=True,
            canonical_after_sha256={name: P.digest(raw) for name, raw in after.items()},
            prerequisite_control_cases=43, previous_goal_turn_assessment='progress', current_goal_turn_assessment='progress')
        receipt.update(frame_readback)
        (out / 'fresh-readback.json').write_bytes(P.encoded(receipt))
        print(json.dumps(dict(receipt, snapshot=str(out.relative_to(ROOT))), ensure_ascii=False))
    except Exception as error:
        rolled_back, conflicts, rollback_failures = [], [], []
        for name in reversed(written):
            try:
                if (ROOT / name).read_bytes() == after[name]:
                    P.replace(name, before[name])
                    rolled_back.append(name)
                else:
                    conflicts.append(name)
            except Exception as rollback_error:
                rollback_failures.append({'path': name, 'error': str(rollback_error)})
        if frame_written:
            try:
                target = software_artifact_target()
                if target.exists() and target.read_bytes() == frame_raw:
                    if frame_before is None:
                        target.unlink()
                    else:
                        replace_software_artifact(frame_before)
                    rolled_back.append(ARTIFACT_TARGET)
                else:
                    conflicts.append(ARTIFACT_TARGET)
            except Exception as rollback_error:
                rollback_failures.append({'path': ARTIFACT_TARGET, 'error': str(rollback_error)})
        (out / 'publication-failure.json').write_bytes(P.encoded({'error': str(error), 'own_changes_rolled_back': rolled_back,
            'concurrent_conflicts_left_untouched': conflicts, 'rollback_failures': rollback_failures,
            'native_guest_execution': False, 'device_IO': False}))
        raise


if __name__ == '__main__':
    main()
