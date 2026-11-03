#!/usr/bin/env python3
"""Publish reviewed host-built HFP preflight changes; never operate a device."""
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

FIELD = 'latest_android_hfp_prototype_checkpoint'
APK_PUBLIC = 'reports/garmin-hfp-prototype.apk'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--goal-receipt', required=True)
    parser.add_argument('--source-review', required=True)
    parser.add_argument('--route-review', required=True)
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    root = P.ROOT
    goal = json.loads(P.resolve(args.goal_receipt).read_bytes())
    P.require(goal['goal']['status'] == 'active' and goal['goal']['objective'] == P.OBJECTIVE,
              'Original full goal active')
    build_path = 'staging/android-hfp-prototype-apk-v5/proof.json'
    build_raw = P.resolve(build_path).read_bytes()
    build = json.loads(build_raw)
    terminal = json.loads(P.resolve('staging/android-hfp-prototype-apk-v5/actual-build-tool-receipt.json').read_bytes())
    P.require(terminal['exit_code'] == 0 and build['all_build_checks_passed'] and
              build['APK_signature_verified_for_min_API28'] and build['DEX_generated'] and
              build['versionCode'] == 5 and build['versionName'] == '0.5-hfp-preflight' and
              build['host_gate_cases']['host_cases'] == 18 and
              build['host_load_lease_cases']['host_cases'] == 12 and
              build['host_hfp_preflight_cases']['all_passed'] and
              not build['Android_runtime_or_phone_install_or_call_or_route_or_sound_verified'],
              'Actual compile, host checks, DEX and signature only')
    P.require(terminal['build_proof_sha256'] == P.digest(build_raw) and
              terminal['command'] == ['python3', 'scripts/build_android_hfp_prototype_v5.py'] and
              terminal['actual_tool_result']['exit_code'] == 0 and
              terminal['result']['apk'] == build['apk'] and
              terminal['result']['source_files'] == build['source_files'] and
              terminal['result']['host_gate_cases'] == build['host_gate_cases']['host_cases'] and
              terminal['result']['host_load_lease_cases'] == build['host_load_lease_cases']['host_cases'] and
              terminal['result']['host_hfp_preflight_cases'] == build['host_hfp_preflight_cases']['host_cases'],
              'Actual tool output bound to this build proof and artifact')
    P.require(terminal['builder_sha256'] == build['source_pins']['scripts/build_android_hfp_prototype_v5.py'],
              'Exact executed builder source')
    actual_output = json.loads(terminal['actual_tool_result']['output'].strip())
    P.require(actual_output == terminal['result'] and
              actual_output['build_proof'] == dict(path=build_path, sha256=P.digest(build_raw)) and
              actual_output['all_build_checks_passed'] and not actual_output['device_IO'] and
              not actual_output['runtime_audio_verified'], 'Actual final stdout identifies this exact proof')
    P.require(build['min_API'] == 28 and build['target_API'] == 35 and
              all(build[key]['all_passed'] and not build[key]['Android_runtime'] for key in
                  ('host_gate_cases', 'host_load_lease_cases', 'host_hfp_preflight_cases')) and
              build['host_hfp_preflight_cases']['host_cases'] > 0, 'Report claims match all host results')
    for path, pin in build['source_pins'].items():
        P.require(P.digest(P.resolve(path).read_bytes()) == pin, 'Compiled source still current: ' + path)
    review_raw = P.resolve(args.source_review).read_bytes()
    review = json.loads(review_raw)
    P.require(review['all_checks_passed'] and not review['device_IO'] and
              not review['original_Garmin_execution'], 'Root source review, no target execution')
    P.require(review['build_proof_sha256'] == P.digest(build_raw), 'Reviewed exact build')
    route_raw = P.resolve(args.route_review).read_bytes()
    route = json.loads(route_raw)
    P.require(route['review_completed'] and not route['device_IO'] and
              not route['actual_Pixel_behavior_verified'], 'Bounded public Android source scope')
    before = {path: P.resolve(path).read_bytes() for path in P.FILES}
    state, task, public, web = [json.loads(before[path]) for path in
                              (P.FILES[0], P.FILES[1], P.FILES[2], P.FILES[4])]
    P.require(state == public['deep_research'], 'Canonical agreement')
    P.require(all(d['goal_status'] == 'active' and not d['goal_complete'] for d in
                  (state, task, public, web)), 'No completion claim')
    P.require(task['user_away'] and not state['audio']['audible_tests_allowed'] and
              state['device_connectivity_user_confirmation']['builtin_wifi_present'] is False,
              'User-away and Bluetooth-only premises preserved')
    old_checkpoint = copy.deepcopy(state[FIELD])
    old_android_history = copy.deepcopy(state.get('android_hfp_prototype_checkpoints', {}))
    apk = P.resolve(build['apk']['path']).read_bytes()
    old_apk = P.resolve(APK_PUBLIC).read_bytes()
    P.require(P.digest(apk) == build['apk']['sha256'] and len(apk) == build['apk']['bytes'],
              'Signed APK identity')
    P.require(P.digest(old_apk) == old_checkpoint['artifact']['sha256'], 'Old served APK identity')
    P.require(P.resolve(old_checkpoint['artifact']['path']).read_bytes() == old_apk,
              'Existing retained v4 artifact supplies durable APK rollback bytes')
    pid, start = P.live_server(web)
    P.require(P.fetch(web['url']) == before[P.FILES[3]], 'Fresh prior HTTP report')
    now = datetime.datetime.now(datetime.timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp, display = local.isoformat(timespec='seconds'), local.strftime('%Y/%m/%d %H:%M:%S')
    checkpoint = copy.deepcopy(old_checkpoint)
    checkpoint.update(updated_utc=now.isoformat(), artifact=build['apk'], versionCode=5,
                      versionName='0.5-hfp-preflight',
                      build_proof=dict(path=build_path, sha256=P.digest(build_raw)),
                      HFP_connection_preflight_before_local_incoming_call=True,
                      HFP_snapshot_is_continuous_connection_proof=False,
                      pending_proxy_force_cancellation_verified=False,
                      host_hfp_preflight_cases=build['host_hfp_preflight_cases']['host_cases'],
                      preflight_source_review=dict(path=args.source_review, sha256=P.digest(review_raw)),
                      SCO_registration_review=dict(path=args.route_review, sha256=P.digest(route_raw)))
    turn = dict(classification='progress', previous_goal_turn_assessment='progress',
                previous_goal_turn_reason='User hardware correction ruled out built-in wireless AA and reconciled Bluetooth priority.',
                validated_utc=now.isoformat(), goal_status='active', full_goal_complete=False,
                required_work_remaining=True,
                reason='Production Android HFP preflight implemented, compiled, signed and host-tested; public SCO registration evidence refined target diagnostics.',
                device_IO=False, original_Garmin_execution=False, native_runtime_progress=False,
                phone_call_route_or_speaker_verified=False)
    preserved = {key: copy.deepcopy(state[key]) for key in
                 ('audio', 'navigation_repair', 'microphone_amplifier', 'device_connectivity_user_confirmation')}
    history = state.setdefault('android_hfp_prototype_checkpoints', {})
    P.require('v5' not in history, 'Do not republish v5')
    history.setdefault('v4', old_checkpoint)
    history['v5'] = copy.deepcopy(checkpoint)
    state.update(updated_utc=now.isoformat(), last_goal_turn=turn)
    state[FIELD] = checkpoint
    state['native_app_music'][FIELD] = copy.deepcopy(checkpoint)
    state['offline_24h_work_order'][FIELD] = copy.deepcopy(checkpoint)
    for d in (task, public, web):
        for key in ('updated_utc', 'last_goal_turn', FIELD, 'android_hfp_prototype_checkpoints', 'offline_24h_work_order'):
            d[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state))
    progress = public['research_progress']
    original_progress = copy.deepcopy(progress)
    completed = 'Android 第五版：建立本機來電前以公開 HEADSET API 背景核對所選 Garmin 通話連線；取消／逾時不接受晚結果，未回收 proxy 保留單一占用。已编譯與主機測試，手機／車機未實測。'
    progress['completed'].append(completed)
    progress.update(research_updated_utc=now.isoformat(),
                    method='整體工程 37% 維持歷史里程碑估計；第五版手機 HFP preflight 完成主機檢查與封裝，不計為原機 A2DP、菜單 App 或實機音樂完成。')
    for key in ('estimate_percent', 'weighted_estimate_percent', 'phases'):
        P.require(progress[key] == original_progress[key], 'No percentage inflation')
    count = build['host_hfp_preflight_cases']['host_cases']
    card = (f'<section class="card" id="bluetooth-music-current-checkpoint-v1"><h2>藍牙音樂：Android 第五版通話連線檢查</h2>'
            f'<p>更新：<time datetime="{stamp}">{display}</time>（台灣時間）</p>'
            f'<p><a href="/garmin-hfp-prototype.apk" download="garmin-hfp-prototype.apk">下載 Android 第五版實驗 APK</a>（{len(apk):,} bytes，Android 9／API28 以上）。手機端原型尚未實測。</p>'
            '<ul><li>建立本機來電前，背景查所選 Garmin 是否已接通 HFP；只有配對、只接其他裝置、權限拒絕或逾時均不建立來電。</li>'
            '<li>Stop／逾時取消本次准許；晚回來的 proxy 先清理。沒收到回呼或清理失敗時保留單一占用，拒絕累積重試。連線快照只是來電前條件，沒有強制取消 Binder 或持续連線保證。</li>'
            f'<li>官方 API35 編譯、DEX、API28 簽章與版本核對通過；18 項播放 gate、12 項音檔 lease、{count} 項 HFP preflight 主機案例通過。</li>'
            '<li>保留明確按播放、靜音核對實際 SCO、最多 10 秒及完整位址匹配；未安裝、配對、發來電或播音，音質改善與省去 Pi 尚未驗證。</li></ul>'
            '<p>公開 <a href="https://android.googlesource.com/platform/frameworks/base/+/android-15.0.0_r1/services/core/java/com/android/server/audio/BtHelper.java#859">Android15 固定來源</a>顯示 SCO 建立時可能因不合法位址使用空字串；這不能一律歸因權限遮蔽，也不能當成 Pixel 的實際行为。完整位址無法辨識時仍拒絕播放。</p>'
            '<p>原機沒有 Wi-Fi；直接 A2DP、GarminOS 菜單播放器與 Android Auto／Maps 都尚未完成。Pi 轉送歷史 60 秒成功保留，整體工程估計 37% 不變。</p></section>')
    report = before[P.FILES[3]].decode()
    report, replaced = re.subn(r'<section class="card" id="bluetooth-music-current-checkpoint-v1">.*?</section>',
                              '', report, count=1, flags=re.S)
    P.require(replaced == 1 and report.count('<main>') == 1, 'Move current Android card to front')
    report = report.replace('<main>', '<main>' + card, 1)
    report = P.substitute(report, r'<p id="offline-frontier-latest-v1">.*?</p>',
                          '<p id="offline-frontier-latest-v1">最新：手機 HFP preflight 已加入第五版 APK 並完成主機檢查；實際 Pixel／Garmin 來電、路由與喇叭仍未驗證。原機無 Wi-Fi、直接 A2DP／菜單 App 尚未完成。</p>', 'frontier')
    report = P.substitute(report, r'<p id="progress-method"[^>]*>.*?</p>',
                          '<p id="progress-method" class="progress-note">' + html.escape(progress['method']) + '</p>', 'method')
    m = re.search(r'<ul class="completed-progress">.*?</ul>', report, re.S)
    P.require(m is not None, 'Progress history')
    report = report.replace(m.group(), m.group()[:-5] + '<li>' + html.escape(completed) + '</li></ul>', 1)
    for element in ('report-updated-time', 'research-updated-time'):
        report = P.substitute(report, r'<time id="' + element + r'" datetime="[^"]+">[^<]+</time>',
                              f'<time id="{element}" datetime="{stamp}">{display}</time>', element)
    P.require(not P.PRIVATE.search(report), 'Public privacy')
    P.require(all(state[k] == v for k, v in preserved.items()), 'Preserve device/audio/cancellation evidence')
    P.require(all(history[k] == v for k, v in old_android_history.items()), 'Preserve old Android versions')
    web['progress_display_verified'].update(report_updated_time=stamp, research_updated_time=stamp,
                                          completed_items=len(progress['completed']), Android_v5_HFP_preflight_visible=True)
    after = {P.FILES[0]: P.encoded(state), P.FILES[1]: P.encoded(task), P.FILES[2]: P.encoded(public),
             P.FILES[3]: report.encode(), P.FILES[4]: P.encoded(web), APK_PUBLIC: apk}
    before[APK_PUBLIC] = old_apk
    P.require(all(P.resolve(n).read_bytes() == raw for n, raw in before.items()), 'No concurrent canonical edits')
    if not args.publish:
        print(json.dumps(dict(preflight_pass=True, publication_performed=False, runtime_verified=False)))
        return
    out = root / 'staging' / ('android-hfp-v5-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    (out / 'canonical-before.json.gz').write_bytes(gzip.compress(P.encoded({k: v.decode() for k, v in before.items() if k != APK_PUBLIC}), mtime=0))
    (out / 'old-apk-reference.json').write_bytes(P.encoded(old_checkpoint['artifact']))
    written = []
    try:
        for name in [APK_PUBLIC] + list(P.FILES[:4]):
            P.replace(name, after[name]); written.append(name)
        served = P.fetch(web['url'])
        P.require(served == after[P.FILES[3]] and P.live_server(web) == (pid, start), 'Exact report HTTP, same PID')
        P.require(P.fetch(checkpoint['download_url']) == apk, 'Exact APK HTTP bytes')
        web.update(local_report_sha256=P.digest(served), served_report_sha256=P.digest(served),
                   report_bytes=len(served), service_not_restarted=True, served_latest_report=True)
        after[P.FILES[4]] = P.encoded(web)
        P.replace(P.FILES[4], after[P.FILES[4]]); written.append(P.FILES[4])
        P.require(all(P.resolve(n).read_bytes() == raw for n, raw in after.items()), 'Six artifact readback')
        P.require(json.loads(after[P.FILES[0]]) == json.loads(after[P.FILES[2]])['deep_research'], 'Canonical agreement')
        P.require(P.live_server(web) == (pid, start), 'Same live service at final readback')
        receipt = dict(pass_=True, goal_status='active', full_goal_complete=False, updated_Taiwan=stamp,
                       report_url=web['url'], download_url=checkpoint['download_url'], report_PID=pid,
                       APK_HTTP_exact=True, report_HTTP_exact=True, target_runtime_verified=False,
                       build_proof_sha256=P.digest(build_raw), source_review_sha256=P.digest(review_raw),
                       route_review_sha256=P.digest(route_raw),
                       canonical_after_sha256={n: P.digest(raw) for n, raw in after.items()})
        (out / 'fresh-readback.json').write_bytes(P.encoded(receipt))
        print(json.dumps(dict(pass_=True, updated_Taiwan=stamp, snapshot=str(out.relative_to(root)),
                             download_url=checkpoint['download_url'], APK_bytes=len(apk), target_runtime_verified=False)))
    except BaseException as error:
        rollback_errors = []
        for name in reversed(written):
            try:
                if P.resolve(name).read_bytes() == after[name]:
                    P.replace(name, before[name])
                else:
                    rollback_errors.append(dict(path=name, reason='Concurrent change; left untouched'))
            except BaseException as restore_error:
                rollback_errors.append(dict(path=name, reason=str(restore_error)))
        (out / 'failure.json').write_bytes(P.encoded(dict(error=str(error), rollback_errors=rollback_errors)))
        raise


if __name__ == '__main__':
    main()
