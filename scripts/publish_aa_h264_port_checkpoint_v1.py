#!/usr/bin/env python3
"""Preflight/publish actual public H.264 host-port build and test evidence.

Only --publish writes the existing five canonical/report files. Default preflight
is read-only and prints a small summary. No builder/test, guest, original Garmin
code/callsite, target compile, device query, pairing, sound, install, restart or goal
transition is performed. Existing PNG bytes/data URI and all old evidence remain.

Run metadata schema: android-auto-h264-port-checkpoint-v1
  publisher_helper_sha256, publisher_video_helper_sha256: reviewed pure helpers
  goal_receipt: {path,sha256,status_path,objective_path}
  previous_goal_turn_assessment: "no_progress" (the preceding status-only turn)
  proof: {proof_sha256,claims:{dotpath:expected},pass_claim,device_io_claim,
    native_guest_claim,host_function_claim,software_decode_claim,case_count_claim,
    case_count,count_label,source_pins_claim,source_pins,scope,completed}
  suite_counts: {abi:{claim,count,label},platform:{claim,count,label}}
    Each count must be in reviewed proof.claims and match actual test evidence.
  build: {path,sha256,claims:{dotpath:expected},proof_reference_path}
    Or use proof_path_claim/proof_sha256_claim when the producer records separate
    path/hash fields. The actual proof must pin both exact values. Build schema is
    android-auto-h264-port-host-build-v1. Source dictionaries/current host .so
    hashes, ordinary zero undefined/DT_NEEDED and hosted/sanitizer scopes are checked.
  terminal_receipts: [{path,sha256,result_path,chunk_id,covers:["build","test"]},...]

Proof schema: android-auto-h264-port-host-v1. Hosted Linux C++ headers, local
callback backing-byte cap and non-returning fatal OOM are explicitly limited;
zero ordinary imports does not prove freestanding headers, 32-bit/native ABI,
total memory cap, recoverable OOM, async cleanup, device readiness or performance.
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
SCHEMA = 'android-auto-h264-port-checkpoint-v1'
FIELD = 'latest_android_auto_codec_port_checkpoint'
CARD_ID = 'android-auto-codec-port-host-v1'
PRIOR_CARD_ID = 'android-auto-platform-gate-review-v1'
BUILD_PATH = 'staging/android-auto-h264-port-v1/build.json'
STAGE = ROOT / 'staging' / 'android-auto-h264-port-v1'
MAP_PATH = 'staging/android-auto-h264-port-v1/exports.map'
NEXT_ACTIONS = [
    '優先成立精確HWID1352的真正USB host／VBUS／AOA與可達Garmin平台／載入入口；host import清除不能取代端點、原機ABI或裝機證據。現在不查裝置或要求現場。',
    '將caller配置／時鐘／single-thread生命週期契約對接真正平台，再驗原機ABI／total memory／即時解碼、display／touch／audio ownership；fatal OOM並非可恢復失敗。',
    'Current phone／Google acceptance、原機AA／Google Maps／離線能力、可安裝UI、direct A2DP及原機音樂App仍未完成。導航／mic停止；原native中斷分支不重試／繞過，無來電或播音。',
]
GAPS = [
    '精確原機USB host／VBUS／AOA、可達execution／App loader與platform endpoints仍未成立；更多host fixtures不能代替。',
    'Hosted Linux C++ headers仍存在；ELF64/AArch64 host zero imports不等於ARM32／GarminOS ABI／freestanding target。',
    '上限只約束caller callback requested backing bytes；caller allocator metadata／pages、總記憶體、其他AA元件及原機heap仍未證。',
    'OOM使用non-returning fatal callback／隔離subprocess，不證recoverable OOM、failed-construction清理或裝置重啟恢復。',
    'CPU1／禁thread／log discard是明示policy；特定workload未碰stub不等於所有profile／配置均不會呼叫。',
    'Native時鐘／ABI／效能、OS task／IRQ／async quiescence、display／touch／audio／App／navigation coexistence未驗；無current phone／Google或Garmin Maps。',
]


def source_pin(name, pin):
    if name == MAP_PATH:
        path = P.resolve(name)
        P.require(path.stat().st_size <= 16 * 1024 and P.digest(path.read_bytes()) == pin,
            'Exact bounded new host-link export map')
    else:
        V.source_pin(name, pin)


def validate_proof(name, spec, suites):
    proof, reference = P.pinned_json(name, spec['proof_sha256'])
    P.require(proof['schema'] == 'android-auto-h264-port-host-v1' and
        isinstance(spec['claims'], dict) and spec['claims'], 'Actual reviewed port proof')
    for dotted, wanted in spec['claims'].items():
        observed = P.field(proof, dotted)
        P.require(type(observed) is type(wanted) and observed == wanted, 'Exact proof claim: ' + dotted)
    for key, wanted in [('pass_claim', True), ('device_io_claim', False), ('native_guest_claim', False),
                        ('host_function_claim', True), ('software_decode_claim', True)]:
        dotted = spec[key]
        P.require(dotted in spec['claims'] and P.field(proof, dotted) is wanted, 'Explicit actual host evidence: ' + key)
    count = spec['case_count']
    P.require(type(count) is int and count > 0 and spec['case_count_claim'] in spec['claims'] and
        type(P.field(proof, spec['case_count_claim'])) is int and P.field(proof, spec['case_count_claim']) == count,
        'Actual proof count, no inferred tests')
    P.require(isinstance(spec['count_label'], str) and 0 < len(spec['count_label']) <= 100 and
        isinstance(suites, dict) and set(suites) == {'abi', 'platform'}, 'Explicit separate ABI/platform count scopes')
    counts = {}
    for key, row in suites.items():
        P.require(isinstance(row, dict) and type(row['count']) is int and row['count'] > 0 and
            row['claim'] in spec['claims'] and type(P.field(proof, row['claim'])) is int and
            P.field(proof, row['claim']) == row['count'] and isinstance(row['label'], str) and
            0 < len(row['label']) <= 300 and not P.PRIVATE.search(row['label']), 'Actual ' + key + ' suite count/label')
        counts[key] = copy.deepcopy(row)
    recorded = P.field(proof, spec['source_pins_claim'])
    P.require(isinstance(recorded, dict) and spec['source_pins_claim'] in spec['claims'], 'Reviewed tested source dictionary')
    pins = {key: value['sha256'] if isinstance(value, dict) else value for key, value in recorded.items()}
    P.require(pins and pins == spec['source_pins'], 'Exactly the tested current source pins')
    for path, pin in pins.items():
        source_pin(path, pin)
    P.require(isinstance(spec['scope'], str) and 0 < len(spec['scope']) <= 2400 and
        isinstance(spec['completed'], list) and 0 < len(spec['completed']) <= 64 and
        all(isinstance(text, str) and 0 < len(text) <= 2400 for text in spec['completed']), 'Bounded reviewed scope/completed')
    P.require(not P.PRIVATE.search(spec['scope'] + '\n'.join(spec['completed']) + spec['count_label']), 'No private public summary')
    return proof, dict(reference, case_count=count, count_label=spec['count_label'], suite_counts=counts,
        scope=spec['scope'], completed=copy.deepcopy(spec['completed']), source_pins=pins,
        verified_claims=copy.deepcopy(spec['claims']), host_layer_only=True, software_decoded_frames_verified=True,
        device_IO=False, native_guest_execution=False, native_ABI_verified=False, install_candidate=False)


def validate_build(proof, spec):
    P.require(spec['path'] == BUILD_PATH, 'Only new public host-port build manifest')
    build, reference = P.pinned_json(spec['path'], spec['sha256'])
    P.require(build['schema'] == 'android-auto-h264-port-host-build-v1', 'Actual completed build schema')
    if spec.get('proof_reference_path'):
        P.require(P.field(proof, spec['proof_reference_path']) == reference, 'Actual test proof pins exact completed build reference')
    else:
        P.require(P.field(proof, spec['proof_path_claim']) == reference['path'] and
            P.field(proof, spec['proof_sha256_claim']) == reference['sha256'], 'Actual test proof pins separate exact build path/hash')
    P.require(isinstance(spec['claims'], dict) and spec['claims'], 'Exact reviewed build claims')
    for dotted, wanted in spec['claims'].items():
        observed = P.field(build, dotted)
        P.require(type(observed) is type(wanted) and observed == wanted, 'Exact build claim: ' + dotted)
    for key, wanted in [('pass', True), ('single_thread_policy', True), ('logging_discard_policy', True),
        ('fatal_OOM_no_recovery', True), ('retained_Linux_private_header_ABI', True),
        ('ordinary_host_only', True), ('hosted_Linux_headers_required', True), ('freestanding_target_build', False),
        ('original_Garmin_instructions', False), ('ARM_crosscompile', False), ('device_IO', False),
        ('install_candidate', False), ('target_ABI_portability_verified', False)]:
        P.require(build[key] is wanted, 'Explicit completed build boundary: ' + key)
    P.require(build['public_commit'] == '1a0073f0322c8b74cbcb75ca1bb1c3d19d75538d' and
        type(build['upstream_cpp_count']) is int and build['upstream_cpp_count'] == 29 and
        isinstance(build['excluded_cpp'], list) and len(build['excluded_cpp']) == 8, 'Actual selected public-source closure')
    for field in ('original_source_sha256', 'own_source_sha256', 'copied_source_sha256'):
        pins = build[field]
        P.require(isinstance(pins, dict) and pins, 'Actual complete build source inventory: ' + field)
        for name, pin in pins.items():
            source_pin(name, pin)
    P.require(isinstance(build['builds'], list) and len(build['builds']) == 2, 'Ordinary and checker builds separately recorded')
    by_name = {row['name']: row for row in build['builds']}
    P.require(set(by_name) == {'ordinary', 'asan-ubsan'}, 'Exact ordinary/checker build identities')
    ordinary, sanitizer = by_name['ordinary'], by_name['asan-ubsan']
    P.require(ordinary['undefined_symbols'] == [] and '(NEEDED)' not in ordinary['dynamic_section'] and
        ordinary['no_runtime_imports'] is True and ordinary['ELF64_AArch64_host'] is True and
        sanitizer['sanitizer_runtime_only'] is True and sanitizer['ELF64_AArch64_host'] is True,
        'Ordinary zero undefined/DT_NEEDED; sanitizer imports separate Linux checker scope')
    P.require(all(flag in ordinary['link_flags'] for flag in ('-nostdlib', '-Wl,--no-undefined', '-Wl,-Bsymbolic-functions')) and
        '-Wl,--version-script=' + str(ROOT / MAP_PATH) in ordinary['link_flags'] and
        ordinary['exported_symbols'] and all(line.split()[-1].startswith('aa_h264_') for line in ordinary['exported_symbols']),
        'Actual ordinary link localization/no-runtime policy and bounded API exports')
    libraries = []
    for row in build['builds']:
        path = P.resolve(row['shared_library'])
        P.require(path.is_relative_to(STAGE) and path.suffix == '.so' and not path.is_symlink() and
            path.stat().st_size <= 32 * 1024 * 1024 and path.stat().st_size == row['shared_library_bytes'],
            'Only bounded new own Linux-host shared library is hashed, never executed')
        P.require(P.digest(path.read_bytes()) == row['shared_library_sha256'], 'Actual tested/current host library bytes')
        libraries.append({key: row[key] for key in ('name', 'shared_library', 'shared_library_sha256', 'shared_library_bytes')})
    return dict(reference, public_commit=build['public_commit'], upstream_cpp_count=29, excluded_cpp_count=8,
        current_build_source_pins_verified=True, current_host_libraries=libraries,
        ordinary_undefined_count=0, ordinary_DT_NEEDED_count=0, sanitizer_runtime_imports_separate=True,
        hosted_Linux_headers_required=True, freestanding_target_build=False, target_ABI_portability_verified=False,
        fatal_OOM_no_recovery=True, total_memory_cap_proven=False, recoverable_OOM_proven=False,
        device_readiness_proven=False, device_IO=False, native_guest_execution=False)


def retained_pattern(before):
    state = json.loads(before[FILES[0]])
    prior = state[V.FIELD]
    artifact = copy.deepcopy(prior.get('software_frame_artifact'))
    if artifact is None:
        return None, None
    ref = artifact['proof']
    proof, _ = P.pinned_json(ref['path'], ref['sha256'])
    recorded = P.field(proof, artifact['proof_field'])
    P.require(recorded == {'path': artifact['source_path'], 'sha256': artifact['sha256'], 'width': artifact['width'],
        'height': artifact['height'], 'source': artifact['source']} and artifact['publish_target'] == V.ARTIFACT_TARGET and
        not artifact['Garmin_display_or_Google_Maps_verified'], 'Actual unchanged prior software-pattern provenance')
    target = V.software_artifact_target()
    P.require(target.exists(), 'Existing prior software pattern remains')
    raw = target.read_bytes()
    V.validate_png(raw)
    P.require(P.digest(raw) == artifact['sha256'], 'Existing exact PNG copy')
    V.verify_HTTP_embedded_artifact(before[FILES[3]], artifact, raw)
    return artifact, raw


def prepare(before, checkpoint, now):
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    P.require(state == public['deep_research'] and state['requested_goal'] == P.OBJECTIVE, 'Exact canonical/full objective')
    P.require(all(d['goal_status'] == 'active' and not d['goal_complete'] and d['current_goal_priority'] == 'android_auto_google_maps'
        for d in (state, task, public, web)), 'Full goal remains active/incomplete')
    P.require(state['navigation_repair']['status'] == 'stopped_by_user' and state['microphone_amplifier']['status'] == 'cancelled_by_user', 'Cancellations preserved')
    P.require(task['user_away'] and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'], 'No unattended real-device work')
    P.require(not state['native_android_auto']['native_receiver_running'] and not state['native_android_auto']['phone_session_verified'] and
        not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'] and
        not state['google_maps']['native_running'], 'No unsupported native/phone/Maps success')
    keys = ('audio', 'navigation_repair', 'microphone_amplifier', 'native_app_music', 'google_maps',
        'bluetooth_music_blocking_audit', 'research_goal_status_history') + tuple(k for k in state if k.startswith('latest_android_auto_'))
    preserved = {key: copy.deepcopy(state[key]) for key in keys}
    old_progress = copy.deepcopy(public['research_progress'])
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp, display = local.isoformat(timespec='seconds'), local.strftime('%Y/%m/%d %H:%M:%S')
    checkpoint.update(updated_utc=now.isoformat(), updated_Taiwan=stamp,
        prior_published_goal_turn=copy.deepcopy(state['last_goal_turn']))
    turn = {'classification': 'progress', 'previous_goal_turn_assessment': 'no_progress',
        'previous_goal_turn_reason': 'Preceding status-only goal turn had no new runtime research; older published progress is retained as history.',
        'validated_utc': now.isoformat(), 'goal_status': 'active', 'required_work_remaining': True, 'full_goal_complete': False,
        'focused_evidence': copy.deepcopy(checkpoint['proofs']), 'build_evidence': copy.deepcopy(checkpoint['build']),
        'host_layer_implementation_and_verification': True, 'software_decoded_frames_verified': True,
        'native_guest_execution': False, 'device_IO': False, 'device_files_written': False, 'device_calls_or_sound': False,
        'native_ABI_verified': False, 'display_hardware_verified': False, 'speaker_sound_verified': False,
        'reason': 'Actual new public host codec-port build/tests; ordinary runtime imports removed with explicit callbacks. No target ABI/device/install readiness.'}
    state.update(updated_utc=now.isoformat(), goal_status='active', goal_complete=False,
        current_priority='GarminOS Android Auto／Google Maps：公開H.264 host-port配置／時鐘／單執行緒policy與實際build/test驗證；原機platform gates仍未成立。',
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
    work['current_offline_line_status']['android_auto'] = 'Public H264 host-port build/tests only; hosted headers, target ABI/native readiness/real USB/phone/platform endpoints remain unverified'
    for document in (task, public, web):
        for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', FIELD, 'offline_24h_work_order', 'android_auto_blocking_audit'):
            document[key] = copy.deepcopy(state[key])
        document.update(goal_status='active', goal_complete=False, required_work_remaining=True)
        document.pop('goal_blocked_reason', None)
    task['native_android_auto'] = copy.deepcopy(aa)
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state))
    completed = checkpoint['proofs']['codec']['completed']
    progress = public['research_progress']
    progress['completed'].extend(completed)
    progress.update(research_updated_utc=now.isoformat(), next=NEXT_ACTIONS[0], goal_completed=False,
        method='工程37%維持歷史估計；新public H.264 host-port的callbacks／zero普通imports不證原機ABI、total memory或裝機。AA／Google Maps仍未完成，導航／mic停止。')
    P.require(progress['estimate_percent'] == old_progress['estimate_percent'] == 37 and
        progress['weighted_estimate_percent'] == old_progress['weighted_estimate_percent'] and
        progress['phases'] == old_progress['phases'], 'Historical estimate and entire phase objects unchanged')
    P.require(all(state[key] == old for key, old in preserved.items()), 'All older AA/audio/nav/cancel/history objects preserved')
    report = before[FILES[3]].decode()
    P.require(CARD_ID not in report, 'Codec port checkpoint not already published')
    previous = re.search(r'<section class="card" id="' + PRIOR_CARD_ID + r'">.*?</section>', report, re.S)
    P.require(previous is not None, 'Previous platform-gate card preserved complete')
    report = report.replace(previous.group(), '<details class="card" id="android-auto-platform-gate-review-history-v1">'
        '<summary>前轮平台gate與host ELF查證完整紀錄</summary>' + previous.group() + '</details>', 1)
    e = html.escape
    steps = ''.join('<li>' + e(text) + '</li>' for text in completed)
    codec = checkpoint['proofs']['codec']
    counts = ''.join('<li>' + str(row['count']) + ' ' + e(row['label']) + '</li>' for row in codec['suite_counts'].values())
    gaps = ''.join('<li>' + e(text) + '</li>' for text in GAPS)
    card = (f'<section class="card" id="{CARD_ID}"><h2>最新：公開H.264 codec平台移植原型（Linux-host）</h2>'
        f'<p>完整AA／Google Maps目標active／未完成。更新：<time datetime="{stamp}">{display}</time>（台灣時間）</p>'
        '<p><strong>本輪只有新的公開來源host build／test：29 CPP排除8，caller配置／clock／CPU1／log discard／禁thread。ordinary zero undefined／DT_NEEDED，ASan checker imports另計。</strong>'
        'C++仍需hosted Linux headers；不是freestanding target／Garmin ABI或可安裝App。</p>'
        '<h3>本輪實際完成</h3><ul>' + steps + '</ul><h3>精確測試計數</h3><ul>' + counts + '</ul>'
        '<p>' + e(codec['scope']) + '；總記錄' + str(codec['case_count']) + e(codec['count_label']) + '。舊decoder76、video20、interactive13/input10/audio156及所有TLS／wire／control歷史各守原scope，不當本輪重測。</p>'
        '<p><strong>配置／錯誤界線：</strong>cap只限callback requested backing bytes；不證total memory。OOM會呼叫non-returning fatal並由隔離subprocess測試，不是recoverable OOM、failed construction清理或native ready。</p>'
        '<p><strong>藍牙音樂：</strong>Pixel → Pi → Garmin 60秒有聲是歷史實機確認；Android APK v4仍只有host建置／DEX／簽章與18 gate＋12 lease。直接手機A2DP與原機菜單音樂App未完成。</p>'
        '<h3>仍待完成</h3><ul>' + gaps + '</ul><p>工程37%不升；導航／mic停止，原native中斷界線不重試／繞過。既有軟體PNG與HTTP data URI完整保留，不是Google Maps或Garmin display。現在無裝置操作、配對／來電／播音或安裝。</p></section>')
    P.require(report.count('<main>') == 1, 'Single report main')
    report = report.replace('<main>', '<main>' + card, 1)
    report = P.substitute(report, r'<span class="progress-status">.*?</span>', '<span class="progress-status">Android Auto／Google Maps：host codec移植研究中</span>', 'progress status')
    report = P.substitute(report, r'<p id="progress-method"[^>]*>.*?</p>', '<p id="progress-method" class="progress-note">' + e(progress['method']) + '</p>', 'method')
    report = P.substitute(report, r'<p id="offline-frontier-latest-v1">.*?</p>', '<p id="offline-frontier-latest-v1">最新actual scope：公開H.264 host-port的配置／clock／single-thread與普通zero imports驗證；hosted headers／native ABI／total memory／原機endpoints／current phone／硬體與安裝仍未完成。</p>', 'frontier')
    report = P.substitute(report, r'<p><strong>下一步：</strong>.*?</p>', '<p><strong>下一步：</strong>' + e(NEXT_ACTIONS[0]) + '</p>', 'next')
    old_list = re.search(r'<ul class="completed-progress">.*?</ul>', report, re.S)
    P.require(old_list is not None, 'Historical completed list')
    report = report.replace(old_list.group(), old_list.group()[:-5] + steps + '</ul>', 1)
    for element in ('report-updated-time', 'research-updated-time'):
        report = P.substitute(report, r'<time id="' + element + r'" datetime="[^"]+">[^<]+</time>', f'<time id="{element}" datetime="{stamp}">{display}</time>', element)
    P.require(not P.PRIVATE.search(report) and report.index('id="' + CARD_ID + '"') < report.index('id="' + PRIOR_CARD_ID + '"'), 'Public privacy/latest card')
    web.update(full_goal_complete=False, actual_goal_status_read='active', current_physical_test_requested=False)
    web['progress_display_verified'].update(estimate_percent=37, completed_items=len(progress['completed']), report_updated_time=stamp,
        research_updated_time=stamp, android_auto_codec_port_host_checkpoint_visible=True, all_prior_history_preserved=True,
        host_header_ABI_fatal_OOM_limits_visible=True, total_memory_native_ready_not_claimed=True,
        HTML_structure_checked=False, visual_browser_render_not_performed=True)
    return {FILES[0]: P.encoded(state), FILES[1]: P.encoded(task), FILES[2]: P.encoded(public), FILES[3]: report.encode(), FILES[4]: P.encoded(web)}, checkpoint


def short_summary(checkpoint, pid):
    codec = checkpoint['proofs']['codec']
    return {'schema': SCHEMA, 'goal_status': 'active', 'report_PID': pid,
        'proof': {key: codec[key] for key in ('path', 'sha256', 'case_count', 'count_label', 'suite_counts')},
        'build': {key: checkpoint['build'][key] for key in ('path', 'sha256', 'ordinary_undefined_count', 'ordinary_DT_NEEDED_count')},
        'hosted_Linux_headers_required': True, 'native_ABI_verified': False, 'total_memory_cap_proven': False,
        'recoverable_OOM_proven': False, 'device_readiness_proven': False, 'device_IO': False,
        'native_guest_execution': False, 'device_install_candidate': False, 'full_goal_complete': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proof', default='evidence/android-auto-h264-port-host-v1.json')
    parser.add_argument('--run-metadata', required=True)
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    path = P.resolve(args.run_metadata)
    P.require(path.suffix == '.json' and path.stat().st_size <= 512 * 1024, 'Bounded actual run metadata')
    meta_raw = path.read_bytes()
    meta = json.loads(meta_raw)
    P.require(meta['schema'] == SCHEMA and not meta.get('illustrative_template') and
        meta['previous_goal_turn_assessment'] == 'no_progress', 'Actual metadata/preceding status-only turn')
    P.require(P.digest(Path(P.__file__).read_bytes()) == meta['publisher_helper_sha256'] and
        P.digest(Path(V.__file__).read_bytes()) == meta['publisher_video_helper_sha256'], 'Reviewed pure helper sources')
    goal, goal_ref = P.pinned_json(meta['goal_receipt']['path'], meta['goal_receipt']['sha256'])
    P.require(P.field(goal, meta['goal_receipt'].get('status_path', 'status')) == 'active' and
        P.field(goal, meta['goal_receipt'].get('objective_path', 'objective')) == P.OBJECTIVE, 'Actual full-objective active goal receipt')
    proof, summary = validate_proof(args.proof, meta['proof'], meta['suite_counts'])
    build = validate_build(proof, meta['build'])
    P.require(isinstance(meta['terminal_receipts'], list) and meta['terminal_receipts'], 'Actual final build/test receipts')
    receipts, coverage = [], set()
    for row in meta['terminal_receipts']:
        receipt, reference = P.pinned_json(row['path'], row['sha256'])
        result = P.field(receipt, row['result_path']) if row.get('result_path') else receipt
        P.require(result['exit_code'] == 0 and 'session_id' not in result and result['chunk_id'] == row['chunk_id'], 'Actual final EXIT0 result')
        P.require(isinstance(row['covers'], list) and row['covers'] and set(row['covers']) <= {'build', 'test'}, 'Actual build/test coverage')
        coverage.update(row['covers'])
        receipts.append(dict(reference, chunk_id=row['chunk_id'], exit_code=0, covers=copy.deepcopy(row['covers'])))
    P.require(coverage == {'build', 'test'}, 'Actual receipts cover completed build and tests')
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    artifact, frame = retained_pattern(before)
    checkpoint = {'schema': SCHEMA, 'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
        'goal_receipt': goal_ref, 'proofs': {'codec': summary}, 'build': build, 'terminal_receipts': receipts,
        'run_metadata': {'path': str(path.relative_to(ROOT)), 'sha256': P.digest(meta_raw)},
        'previous_goal_turn_assessment': 'no_progress', 'software_decoded_frames_verified': True,
        'hosted_Linux_headers_required': True, 'freestanding_target_build': False, 'native_ABI_verified': False,
        'total_memory_cap_proven': False, 'recoverable_OOM_proven': False, 'device_readiness_proven': False,
        'phone_or_Pixel_or_Google_acceptance_verified': False, 'Garmin_native_receiver_or_Google_Maps_running': False,
        'display_hardware_verified': False, 'speaker_sound_verified': False, 'device_IO': False,
        'native_guest_execution': False, 'device_install_candidate': False,
        'remaining_work': copy.deepcopy(GAPS), 'historical_progress_estimates_not_increased': True}
    if artifact is not None:
        checkpoint['retained_software_frame_artifact'] = artifact
    web_before = json.loads(before[FILES[4]])
    pid, start = P.live_server(web_before)
    P.require(pid == 885568 and P.fetch(web_before['url']) == before[FILES[3]], 'Exact before HTTP and original report PID')
    now = datetime.now(timezone.utc)
    after, checkpoint = prepare(before, checkpoint, now)
    if frame is not None:
        V.verify_HTTP_embedded_artifact(after[FILES[3]], artifact, frame)
    P.require(all((ROOT / name).read_bytes() == raw for name, raw in before.items()), 'No concurrent canonical changes')
    if not args.publish:
        print(json.dumps(dict(short_summary(checkpoint, pid), all_input_and_preflight_checks_passed=True, publication_performed=False), ensure_ascii=False))
        return
    out = ROOT / 'staging' / ('android-auto-h264-port-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    (out / 'canonical-before.json.gz').write_bytes(gzip.compress(P.encoded({name: raw.decode() for name, raw in before.items()}), mtime=0))
    (out / 'publication-inputs.json').write_bytes(P.encoded(checkpoint))
    written = []
    try:
        for name in FILES[:4]:
            P.replace(name, after[name])
            written.append(name)
        served = P.fetch(web_before['url'])
        P.require(served == after[FILES[3]] and P.live_server(web_before) == (pid, start), 'Exact HTTP and same report process, no restart')
        web = json.loads(after[FILES[4]])
        web.update(HTTP_status=200, local_report_sha256=P.digest(served), served_report_sha256=P.digest(served),
            report_bytes=len(served), served_latest_report=True, service_not_restarted=True, canonical_hash_readback_uncached=True)
        retained = {}
        if frame is not None:
            P.require(V.software_artifact_target().read_bytes() == frame, 'Prior PNG remains unchanged')
            retained = V.verify_HTTP_embedded_artifact(served, artifact, frame)
            web.update(retained)
        after[FILES[4]] = P.encoded(web)
        P.replace(FILES[4], after[FILES[4]])
        written.append(FILES[4])
        P.require(all((ROOT / name).read_bytes() == raw for name, raw in after.items()), 'Exact five canonical file readback')
        docs = [json.loads(after[name]) for name in (FILES[0], FILES[1], FILES[2], FILES[4])]
        P.require(docs[0] == docs[2]['deep_research'] and all(d['goal_status'] == 'active' and not d['goal_complete'] and
            d[FIELD] == checkpoint for d in docs), 'Canonical active/incomplete equality')
        receipt = dict(short_summary(checkpoint, pid), all_publication_checks_passed=True, updated_at_Taiwan=checkpoint['updated_Taiwan'],
            report_url=web_before['url'], report_HTTP_exact_bytes=True, service_not_restarted=True,
            canonical_after_sha256={name: P.digest(raw) for name, raw in after.items()},
            previous_goal_turn_assessment='no_progress', current_goal_turn_assessment='progress', **retained)
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
