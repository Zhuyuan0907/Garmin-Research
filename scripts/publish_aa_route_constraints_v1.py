#!/usr/bin/env python3
"""Publish completed primary-source/metadata review, without device work."""
import argparse
import copy
import datetime
import gzip
import html
import json
import re
from pathlib import Path
from zoneinfo import ZoneInfo
import publish_android_auto_host_checkpoint_v1 as P
import publish_android_auto_video_checkpoint_v1 as V
import publish_aa_h264_port_checkpoint_v1 as R

ROOT, FILES = P.ROOT, P.FILES
FIELD = 'latest_android_auto_platform_route_constraints'
CARD = 'android-auto-platform-route-constraints-v1'
INPUTS = {
    'projection': ('staging/android-auto-phone-projection-requirements-v1/proof.json', '792883f371814175d34f0bcdfaf215ef24a676cc7db9b1cb458904f13877dce4'),
    'chip': ('staging/android-auto-chip-electrical-contract-review-v1/proof.json', '2dd2d57f5d5a068bd22ca3a2e44163213e2a6d2a7e371d882307012da389ed9f'),
    'execution': ('staging/android-auto-execution-gate-review-v1/proof.json', 'dc7ef8e7993c5b25b4284608e66f10e0463dd165089bec580afebee4dd9900e3'),
    'board': ('staging/android-auto-exact-board-next-review-v1/review.json', '29ccab48ed92cea4d0b1ec7107b549fb3d74b0490a943ac67b681868a695ec34'),
}
COMPLETED = [
    '核對 Android Auto 與 Android Automotive OS：前者呈現手機 App，後者才是車內獨立 Android；手機投影不代表 Google Maps APK 已在 GarminOS 運行。',
    '核對官方連線需求：無線 AA 需要 5 GHz Wi-Fi 與初次藍牙配對；AOA 有線配件需提供 USB host 和 5 V／500 mA。現有 HFP 音樂與 USB 孔均不能證明符合需求。',
    '核對 ST 晶片資料：3.3 V 的 VUSB 是 pad 電源，不能證明板上有 5 V VBUS 輸出；資料腳位也需確認 mux。晶片 LCD／JPEG 功能不是原機 framebuffer／H.264 加速驗證。',
    '交叉核對載入生命週期：TTS 映像的 3 MiB 預留與剩餘 682,868 bytes 不是解碼器可用 heap；需分開模組駐留、workspace、codec heap、GUI 回呼與持續事件處理的所有權及停止流程。',
    '核對手機離線 Maps 的下載範圍限制，AA 全離線冷啟動／搜尋／語音／重連仍待實測；八次板級官方搜尋未取得精確電路／認證板照，不推論硬體功能不存在。',
]
NEXT = [
    '取得精確台灣版裝置的認證碼／PCB 對應與 USB 角色、VBUS、資料腳位路由，再確認可駐留的程式載入與 typed 平台入口。使用者主動通知可操作前不查裝置、不要求配對或接線。',
    '平台入口成立後才對接模組／workspace／codec heap 的獨立所有權、UI／觸控／音訊／傳輸及完整停止；既有主機測試不能替代原機證據。',
    '再以實際 Pixel 驗證 Android Auto 與 Google Maps 離線操作。原機 AA／Maps、直接 A2DP 與菜單播放器仍未完成；導航及麥克風研究維持停止。',
]

def verify_inputs():
    docs, refs = {}, {}
    for key, (name, pin) in INPUTS.items():
        docs[key], refs[key] = P.pinned_json(name, pin)
        for path, expected in docs[key].get('source_sha256', {}).items():
            target = P.resolve(path)
            P.require(target.suffix in ('.json', '.txt', '.pdf') and target.stat().st_size <= 32 * 1024 * 1024,
                      'Only bounded captured metadata/public documents')
            P.require(P.digest(target.read_bytes()) == expected, 'Current captured source: ' + path)
    phone = docs['projection']
    retrievals, _ = P.pinned_json(phone['retrievals']['path'], phone['retrievals']['sha256'])
    P.require(phone['pass'] and phone['source_count'] == 9 and phone['runtime_tests'] == 0 and
              not phone['device_IO'] and not phone['whole_goal_complete'], 'Official projection review scope')
    P.require(len(retrievals['sources']) == 9 and all(s['HTTP_status'] == 200 and s['official_publisher']
              for s in retrievals['sources']), 'Actual official retrieval metadata, not runtime tests')
    chip, execution, board = [docs[k] for k in ('chip', 'execution', 'board')]
    P.require(chip['retrieval']['status'] == 200 and chip['same_as_saved_pdf'] and chip['runtime_tests'] == 0 and
              not chip['exact_board_host_VBUS_AOA_verified'] and not chip['device_IO'], 'Chip facts do not establish board support')
    P.require(execution['review_completed'] and execution['source_file_count'] == 8 and
              not execution['runtime_tests_run'] and not execution['device_IO'] and
              not any(execution['target_acceptance'].values()), 'Eight captured records, no execution success inferred')
    P.require(board['meaningful_new_board_feasibility_fact'] is False and board['absence_proved'] is False and
              board['impossibility_proved'] is False and not board['new_usb_host_or_vbus_or_execution_gate_closed'],
              'Exact-board search remains unresolved, no absence claim')
    historical = {}
    for key, name, field in (
        ('WFFF', 'evidence/native-warm-probe-physical-positive-20261005T045004Z.json', 'physical_modified_diagnostic_code_execution_observed'),
        ('restored_2_10', 'evidence/native-warm-probe-physical-final-control-20261005T045419Z.json', 'physical_A_B_A_sequence_complete')):
        data = P.resolve(name).read_bytes(); d = json.loads(data)
        P.require(d[field] is True, 'Historical exact WFFF/restore chain')
        P.require(d['user_answer_verbatim'] == ('WFFF' if key == 'WFFF' else '已回到 2.10'), 'Exact historical marker provenance')
        historical[key] = dict(path=name, sha256=P.digest(data), not_rerun=True)
    return refs, historical

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--goal-receipt', required=True)
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    goal_raw = P.resolve(args.goal_receipt).read_bytes(); goal = json.loads(goal_raw)
    P.require(goal['goal']['status'] == 'active' and goal['goal']['objective'] == P.OBJECTIVE, 'Full objective remains active')
    refs, historical = verify_inputs()
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public, web = [json.loads(before[name]) for name in (FILES[0], FILES[1], FILES[2], FILES[4])]
    P.require(state == public['deep_research'] and state['last_goal_turn']['classification'] == 'progress', 'Prior actual codec-port progress')
    P.require(all(d['goal_status'] == 'active' and not d['goal_complete'] for d in (state, task, public, web)), 'Active/incomplete canonical')
    P.require(task['user_away'] and not state['audio']['audible_tests_allowed'] and
              state['navigation_repair']['status'] == 'stopped_by_user' and state['microphone_amplifier']['status'] == 'cancelled_by_user', 'Unattended scope and cancellations')
    prior = state['latest_android_auto_codec_port_checkpoint']['proofs']['codec']
    codec, _ = P.pinned_json(prior['path'], prior['sha256'])
    P.require(codec['pass'] and codec['original_ABI_case_count'] == 76 and codec['separate_platform_case_count'] == 36,
              'Completed codec112 remains unchanged, not rerun')
    preserved = {k: copy.deepcopy(v) for k, v in state.items() if k.startswith('latest_android_auto_') or
                 k in ('audio', 'native_app_music', 'google_maps', 'navigation_repair', 'microphone_amplifier', 'research_goal_status_history')}
    old_progress = copy.deepcopy(public['research_progress'])
    artifact, frame = R.retained_pattern(before)
    pid, started = P.live_server(web)
    P.require(P.fetch(web['url']) == before[FILES[3]], 'Fresh current HTTP report')
    now = datetime.datetime.now(datetime.timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp, display = local.isoformat(timespec='seconds'), local.strftime('%Y/%m/%d %H:%M:%S')
    checkpoint = dict(schema='android-auto-platform-route-constraints-v1', updated_utc=now.isoformat(), updated_Taiwan=stamp,
        goal_status='active', full_goal_complete=False, evidence=refs, historical_diagnostic=historical,
        official_projection_sources=9, chip_contracts=4, execution_metadata_files=8, runtime_tests=0,
        device_IO=False, original_Garmin_execution=False, native_crosscompile=False,
        board_gate_new_positive_evidence=False, native_install_candidate=False,
        current_phone_or_Google_acceptance=False, previous_codec112_preserved=True, next_actions=NEXT,
        goal_receipt=dict(path=args.goal_receipt, sha256=P.digest(goal_raw)),
        publisher_sha256=P.digest(Path(__file__).read_bytes()),
        updated_platform_note=dict(path='docs/android-auto-platform-gates-v1.md', sha256=P.digest((ROOT / 'docs/android-auto-platform-gates-v1.md').read_bytes())))
    turn = dict(classification='progress', previous_goal_turn_assessment='progress', validated_utc=now.isoformat(),
        goal_status='active', full_goal_complete=False, required_work_remaining=True, focused_evidence=refs,
        reason='New primary route/electrical constraints and cross-record residency dependencies change required platform work; exact board search adds no positive feasibility evidence.',
        runtime_tests_this_turn=0, device_IO=False, native_guest_execution=False, firmware_or_device_changes=False)
    state.update(updated_utc=now.isoformat(), current_priority='原機 AA／Maps：USB／Wi-Fi 路徑與程式駐留、記憶體及平台入口查證。',
                 next_actions=NEXT, last_goal_turn=turn)
    state[FIELD] = checkpoint
    state['native_android_auto'][FIELD] = copy.deepcopy(checkpoint)
    state['offline_24h_work_order'][FIELD] = copy.deepcopy(checkpoint)
    state['android_auto_blocking_audit'].update(updated_utc=now.isoformat(), condition=None, consecutive_no_progress_goal_turns=0,
        current_goal_turn_classification='progress', goal_status='active', full_goal_complete=False)
    P.require(all(state[k] == old for k, old in preserved.items()), 'All previous evidence/claims retained')
    for d in (task, public, web):
        for key in ('updated_utc', 'current_priority', 'next_actions', 'last_goal_turn', 'android_auto_blocking_audit', 'offline_24h_work_order', FIELD):
            d[key] = copy.deepcopy(state[key])
    task['native_android_auto'] = copy.deepcopy(state['native_android_auto'])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state))
    progress = public['research_progress']; progress['completed'].extend(COMPLETED)
    progress.update(research_updated_utc=now.isoformat(), next=NEXT[0],
        method='工程 37% 維持歷史估計；本輪查連線與原機程式駐留條件，新增 runtime 為 0。既有解碼 112 項保留；USB／Wi-Fi／載入／硬體與實際手機仍未驗證。')
    P.require(progress['estimate_percent'] == old_progress['estimate_percent'] == 37 and
              progress['weighted_estimate_percent'] == old_progress['weighted_estimate_percent'] and
              progress['phases'] == old_progress['phases'], 'No percentage or phase inflation')
    e = html.escape; steps = ''.join('<li>' + e(s) + '</li>' for s in COMPLETED)
    card = (f'<section class="card" id="{CARD}"><h2>最新：連線路徑與原機程式駐留條件</h2>'
        f'<p>更新：<time datetime="{stamp}">{display}</time>（台灣時間）。本輪只查官方文件與既有紀錄，新增 runtime 測試為 0。</p>'
        '<ul>' + steps + '</ul><p>來源：<a href="https://developer.android.com/training/cars">AA 與 AAOS</a>、'
        '<a href="https://support.google.com/androidauto/answer/6348019?hl=en">AA 連線需求</a>、'
        '<a href="https://source.android.com/docs/core/interaction/accessories/protocol">AOA 角色與供電</a>、'
        '<a href="https://support.google.com/maps/answer/6291838?hl=en&amp;co=GENIE.Platform%3DAndroid">手機離線 Maps</a>、'
        '<a href="https://mm.digikey.com/Volume0/opasdata/d220001/medias/docus/581/STA2064.pdf">ST 晶片資料（代理商鏡像）</a>。</p>'
        '<p><strong>實機條件仍未成立：</strong>未取得此 PCB 的 USB host／VBUS／Wi-Fi、可駐留 App、硬體顯示與真正手機 session 證據。官方 NCC 查詢在此環境回傳 403；硬體未證明可行，也未證明不可能。</p>'
        '<p>WFFF 診斷與恢復 2.10 的實機紀錄仍保留；它只證明有限診斷執行。既有主機解碼 112 項未重跑，工程估計 37% 不變。完整 AA／Maps、直接 A2DP 和原機菜單播放器尚未完成，沒有可安裝包；未查 USB／藍牙、發來電、播音或寫入車機。</p></section>')
    report = before[FILES[3]].decode()
    P.require(CARD not in report and report.count('<main>') == 1, 'New unique card')
    report = report.replace('<main>', '<main>' + card, 1)
    report = P.substitute(report, r'<span class="progress-status">.*?</span>', '<span class="progress-status">Android Auto／Maps：原機連線與載入條件查證</span>', 'status')
    report = P.substitute(report, r'<p id="progress-method"[^>]*>.*?</p>',
        '<p id="progress-method" class="progress-note">' + e(progress['method']) + '</p>', 'method')
    report = P.substitute(report, r'<p id="offline-frontier-latest-v1">.*?</p>',
        '<p id="offline-frontier-latest-v1">最新範圍：官方連線／離線 Maps／電氣條件與模組駐留查證；本輪 runtime 0。既有主機解碼 112 項保留，原機端點／載入／手機與硬體仍未成立。</p>', 'frontier')
    report = P.substitute(report, r'<p><strong>下一步：</strong>.*?</p>', '<p><strong>下一步：</strong>' + e(NEXT[0]) + '</p>', 'next')
    previous = re.search(r'<ul class="completed-progress">.*?</ul>', report, re.S)
    P.require(previous is not None, 'Detailed progress list remains')
    report = report.replace(previous.group(), previous.group()[:-5] + steps + '</ul>', 1)
    for element in ('report-updated-time', 'research-updated-time'):
        report = P.substitute(report, r'<time id="' + element + r'" datetime="[^"]+">[^<]+</time>',
                              f'<time id="{element}" datetime="{stamp}">{display}</time>', element)
    P.require(not P.PRIVATE.search(report), 'Public privacy')
    web['progress_display_verified'].update(report_updated_time=stamp, research_updated_time=stamp,
        completed_items=len(progress['completed']), platform_route_constraints_visible=True)
    after = {FILES[0]: P.encoded(state), FILES[1]: P.encoded(task), FILES[2]: P.encoded(public), FILES[3]: report.encode(), FILES[4]: P.encoded(web)}
    if frame is not None: V.verify_HTTP_embedded_artifact(after[FILES[3]], artifact, frame)
    P.require(all((ROOT / name).read_bytes() == raw for name, raw in before.items()), 'No concurrent canonical changes')
    if not args.publish:
        print(json.dumps(dict(preflight_pass=True, publication_performed=False, evidence=refs, runtime_tests=0, full_goal_complete=False)))
        return
    out = ROOT / 'staging' / ('android-auto-route-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ')); out.mkdir(mode=0o700)
    (out / 'canonical-before.json.gz').write_bytes(gzip.compress(P.encoded({k: v.decode() for k, v in before.items()}), mtime=0))
    written = []
    try:
        for name in FILES[:4]: P.replace(name, after[name]); written.append(name)
        served = P.fetch(web['url'])
        P.require(served == after[FILES[3]] and P.live_server(web) == (pid, started), 'Fresh HTTP exact and same live report process')
        if frame is not None: V.verify_HTTP_embedded_artifact(served, artifact, frame)
        web.update(updated_utc=now.isoformat(), local_report_sha256=P.digest(served), served_report_sha256=P.digest(served),
                   report_bytes=len(served), served_latest_report=True, service_not_restarted=True, canonical_hash_readback_uncached=True)
        after[FILES[4]] = P.encoded(web); P.replace(FILES[4], after[FILES[4]]); written.append(FILES[4])
        P.require(all((ROOT / name).read_bytes() == raw for name, raw in after.items()), 'Exact five canonical readback')
        P.require(json.loads(after[FILES[0]]) == json.loads(after[FILES[2]])['deep_research'], 'Deep/public equality')
        receipt = dict(pass_=True, goal_status='active', full_goal_complete=False, updated_Taiwan=stamp,
            report_url=web['url'], runtime_tests=0, evidence=refs, previous_codec112_preserved=True,
            board_gate_closed=False, report_HTTP_exact=True, report_PID=pid, report_service_not_restarted=True,
            canonical_after_sha256={k: P.digest(v) for k, v in after.items()}, snapshot=str(out.relative_to(ROOT)))
        (out / 'fresh-readback.json').write_bytes(P.encoded(receipt)); print(json.dumps(receipt, ensure_ascii=False))
    except BaseException as error:
        conflicts = []
        for name in reversed(written):
            if (ROOT / name).read_bytes() == after[name]: P.replace(name, before[name])
            else: conflicts.append(name)
        (out / 'failure.json').write_bytes(P.encoded(dict(error=str(error), concurrent_conflicts=conflicts)))
        raise

if __name__ == '__main__': main()
