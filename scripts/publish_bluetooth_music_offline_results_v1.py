#!/usr/bin/env python3
"""Publish bounded host music checks without changing live audio services."""
import argparse
import copy
import gzip
import html
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json',
         'reports/findings.json', 'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
PINS = {
    'staging/music-pi-conversion-baseline-20261007-v1/proof.json':
        'c4d0c99b86746e3df7dcdca16e75b1ed127ec752988576c347ae3f2b18dc9cea',
    'staging/music-pi-conversion-baseline-20261007-v1/sealed-files.json':
        'c212e042ae763a65a6245ad86f3f1612aad41081cbf361ff81c1bda87f53337f',
    'staging/music-pi-conversion-offline-input-guards-20261007-v2/proof.json':
        '939289c843e98931f919cda93f4527953cdf341f0df91bf9f0d87842cdaa4ab0',
    'staging/music-pi-conversion-offline-input-guards-20261007-v2/sealed-files.json':
        'bfc8339c9025e2ccc951a8a25ef8647dde6474b952578140deddea386135d5cf',
    'staging/music-offline-cli-root-integration-v1/proof.json':
        '0a9b0c96e1fa1e30a62e97d7ac5b79845a5a0ea43873914cbfbdf31c2a3c3e06',
    'staging/music-offline-cli-root-integration-v1/sealed-files.json':
        '187b3dbd3a3118d2f360eca1c6e18e3cfc040ba4c3add7e5918b5693b801d2d6',
    'staging/music-hfp-quality-protocol-audit-20261007-v1/proof.json':
        '14c500e0129df9267f3a21122b03d7215a5932ae891587b203e80ccdebce806e',
    'staging/music-hfp-quality-protocol-audit-20261007-v1/sealed-files.json':
        '41ca66a4b90cd8a7a566f23be87b5f25139013fe9c3ee79fd2b01e247e173df0',
    'staging/music-native-readonly-feasibility-20261007-v1/sealed-files.json':
        'a3315c2ea62ee44cda877bc0779bef66897e346e3481b3304ae97ddb4278145f',
}
SOURCES = {
    'scripts/garmin_phone_audio_bridge.py': '8454b61d2dc329b6f9b1e2ba326f671aaf99ac92f61562774606728fe9abe72b',
    'scripts/garmin_music_player.py': 'f9e04d28632b60fc97dffb11e04432e1ba77614a3a94a5373885188878eef111',
    'scripts/garmin_audio_conversion.py': 'cfa0391ad6f121f55bc3523873621bcc8403b4837f463d161ffe0af5cb23087f',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--hfp-review', required=True)
    parser.add_argument('--hfp-sha256', required=True)
    parser.add_argument('--native-review', required=True)
    parser.add_argument('--native-sha256', required=True)
    args = parser.parse_args()
    pins = dict(PINS)
    for path, pin, prefix in [(args.hfp_review, args.hfp_sha256, 'staging/music-hfp-quality-protocol-audit-20261007-v1/'),
                              (args.native_review, args.native_sha256, 'staging/music-native-readonly-feasibility-20261007-v1/')]:
        require(path.startswith(prefix) and '..' not in path.split('/') and len(pin) == 64,
                'Scoped ordinary review file')
        pins[path] = pin
    docs = {}
    for path, pin in pins.items():
        raw = (ROOT / path).read_bytes()
        require(len(raw) <= 131072 and sha(raw) == pin, 'Pinned small evidence ' + path)
        docs[path] = json.loads(raw)
    for path, pin in SOURCES.items():
        require(sha((ROOT / path).read_bytes()) == pin, 'Stable final host source ' + path)
    baseline = docs['staging/music-pi-conversion-baseline-20261007-v1/proof.json']
    guards = docs['staging/music-pi-conversion-offline-input-guards-20261007-v2/proof.json']
    integration = docs['staging/music-offline-cli-root-integration-v1/proof.json']
    hfp = docs[args.hfp_review]
    require(hfp['status'] == 'closed_read_only_audit_no_sound_quality_fix_claim'
            and hfp['protocol_evidence']['codec_observed'] == 'CVSD'
            and not hfp['protocol_evidence']['HF_codec_negotiation_advertised'], 'Captured HFP scope')
    require(docs[args.native_review]['status'] == 'STOPPED_PARTIAL_READER_OUTPUT_GUARD',
            'Native file review retains partial status')
    require(baseline['all_assigned_checks_passed'] and baseline['actual_FFmpeg_methods'] == 11
            and baseline['actual_new_channel_guard_methods'] == 3 and baseline['default_live_conversion_argv_unchanged'],
            'Closed short host conversion measurements')
    require(guards['all_assigned_checks_passed'] and guards['failed_suite_actual_exit'] == 1
            and guards['corrected_test_only_index_error'], 'Successful guards retain original failed test receipt')
    require(integration['all_passed'] and integration['offline_bridge_frames'] == 3200
            and integration['prepared_playlist_frames'] == 6400 and integration['generated_playlist_removed']
            and not integration['unexpected_device_operations'] and not integration['device_IO'], 'Root offline CLI integration')
    before = {p: (ROOT / p).read_bytes() for p in FILES}
    state, task, public = [json.loads(before[p]) for p in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'] and state['navigation_repair']
            == task['navigation_repair'] == public['navigation_repair'], 'Canonical initial equality')
    require(all(d['current_goal_priority'] == 'bluetooth_music' and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in [state, task, public, web]), 'User music priority active')
    require(task['user_away'] and not state['audio']['audible_tests_allowed']
            and not web['current_physical_test_requested'], 'Silent away work')
    live = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Existing served report exact')
    old_nav = copy.deepcopy(state['navigation_repair'])
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    checkpoint = {
        'updated_utc': now.isoformat(), 'prerequisite_pins': pins, 'host_source_pins': SOURCES,
        'short_FFmpeg_conversion_methods_passed': 11, 'opt_in_channel_controls_passed': 3,
        'root_offline_CLI_actual_run': '6b7fb2 EXIT0', 'root_offline_CLI_two_tracks_frames': 6400,
        'root_offline_bridge_frames': 3200, 'reference_conversion_byte_identical': True,
        'fixed_gain_short_fixture_ratios': [0.49997443264532604, 0.4999988291494022, 0.49997443264532604],
        'short_fixture_converter_gain_pumping_observed': False,
        'irregular_chunk_and_whole_buffer_outputs_identical': True,
        '8kHz_resampler_high_frequency_loss_observed_on_host': True,
        'antiphase_stereo_default_downmix_cancellation_observed_on_host': True,
        'optional_channel_selection_discards_other_channel': True,
        'optional_fixed_headroom_is_not_automatic_gain_control': True,
        'offline_file_preopen_guards_and_exclusive_modes_verified': True,
        'guard_suite_test_index_failure_preserved_and_separately_corrected': True,
        'live_conversion_defaults_preserved': True, 'audio_daemon_replaced': False,
        'previous_60_second_user_audible_bridge_evidence_retained': True,
        'current_device_connected_or_audible_verified_this_turn': False,
        'long_duration_device_playback_verified': False, 'Garmin_volume_fluctuation_cause_proven': False,
        'Garmin_voice_DSP_bypassed': False, 'mSBC_forced': False,
        'HFP_received_feature_masks': hfp['protocol_evidence']['HF_BRSF_values_received'],
        'HFP_HF_codec_negotiation_advertised_in_captured_logs': False,
        'HFP_captured_codec': 'CVSD',
        'HFP_NREC_request_replied_ERROR_in_retained_tail': True,
        'phone_volume_control_event_count_in_complete_saved_log': hfp['phone_volume_evidence']['event_count'],
        'phone_volume_control_changes_cause_of_heard_fluctuations_proven': False,
        'native_file_review': args.native_review, 'native_review_status': 'partial_file_review',
        'native_guest_retried': False, 'native_direct_phone_A2DP_verified': False,
        'native_App_menu_installed': False, 'physical_music_quality_improvement_verified': False,
        'device_IO': False, 'played': False, 'navigation_repair_resumed': False,
        'whole_goal_complete': False,
    }
    next_actions = [
        '既有手機音樂轉送可用路徑保留；先完成 Linux host 轉換、連線斷開及停止流程的離線檢查。',
        '音量起伏未確診；HFP 窄頻限制與左右聲道抵消分開處理，選聲道／固定衰減只作明確可選設定。',
        '原機直接 A2DP 與 App 繼續唯讀整理缺口，真實端點、正常模式音訊所有權、停止生命週期及實機載入仍未驗證。',
        '使用者回來會主動通知；現場實測時優先連線，再測已知旋律與相同音樂片段。目前不詢問在場或自動播聲。',
    ]
    state.update(updated_utc=now.isoformat(), next_actions=copy.deepcopy(next_actions),
                 latest_bluetooth_music_offline_checkpoint=copy.deepcopy(checkpoint))
    state['audio']['latest_music_offline_conversion_checkpoint'] = copy.deepcopy(checkpoint)
    state['audio']['latest_HFP_quality_review'] = {'path': args.hfp_review, 'sha256': args.hfp_sha256,
                                                'captured_log_review_only': True, 'physical_cause_proven': False}
    state['native_app_music']['latest_music_readonly_feasibility_review'] = {
        'path': args.native_review, 'sha256': args.native_sha256, 'status': 'partial_file_review',
        'guest_executed': False, 'direct_A2DP_or_App_complete': False}
    work = state['offline_24h_work_order']
    work['latest_bluetooth_music_offline_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status'].update(
        pi_music='short conversion, channel and file guards closed; root offline phone/playlist CLI passed',
        hfp_music='captured protocol audit saved; Garmin gain-fluctuation cause remains unproven',
        native_audio='partial file-only acceptance review saved; no interrupted native guest retry')
    turn = {'classification': 'offline_music_progress', 'validated_utc': now.isoformat(),
            'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
            'device_files_written': False, 'reason': 'Bounded Linux host music conversion and offline CLI verified.'}
    state['last_goal_turn'] = copy.deepcopy(turn)
    for key in ['updated_utc', 'next_actions', 'native_app_music', 'offline_24h_work_order',
                'latest_bluetooth_music_offline_checkpoint', 'last_goal_turn']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state),
                  offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn),
                  latest_bluetooth_music_offline_checkpoint=copy.deepcopy(checkpoint))
    progress = public['research_progress']
    progress.update(research_updated_utc=now.isoformat(), next=next_actions[0])
    for phase in progress['phases']:
        name = phase['name']
        if '原生音訊' in name or 'App' in name:
            phase['next'] = next_actions[2]
        elif '備份' in name:
            phase['next'] = '既有備份與實測地圖保留；導航修復依使用者指示停止。'
        elif 'USB' in name or '畫面' in name:
            phase['status'] = 'deferred_while_bluetooth_music_is_priority'
    report = before[FILES[3]].decode()
    card = ('<section class="card" id="bluetooth-music-current-checkpoint-v1">'
            '<h2>藍牙音樂：離線轉換與播放清單流程已驗證</h2>'
            f'<p>更新：<time datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
            '<p><strong>目前可用：</strong>Pixel → Pi → Garmin 的通話音訊路徑曾由使用者確認連續60秒有聲；'
            '仍是8 kHz單聲道與電話畫面。此次只做離線檢查，沒有確認目前連線。</p><ul>'
            '<li>11項短音訊轉換、3項聲道檢查通過；固定音量及同一轉換程序的分塊輸入保持預期輸出。</li>'
            '<li>新增純離線／轉換計畫模式，可選左／右聲道及固定衰減；播放預設保留。'
            '單邊聲道會捨棄另一邊，這些設定尚未驗證能改善實機音質。</li>'
            '<li>完整CLI檢查通過：手機離線模式輸出3,200個樣本；兩首播放清單輸出6,400個樣本，'
            '與原固定音量流程逐byte相同。沒有載入D-Bus、開啟音訊裝置或播放。</li>'
            '<li>離線輸入在開檔前拒絕FIFO／symlink，模式選項互斥；測試索引錯誤有保留紀錄並另行更正。</li>'
            '<li>歷史HFP協商記錄使用CVSD，Garmin回報的功能未包含寬頻codec協商。'
            'NREC要求收到ERROR，不能據此宣稱已關閉Garmin喇叭降噪；'
            '手機音量控制有變動紀錄，但與聽感起伏的因果仍未證實。</li>'
            '</ul><p><strong>仍待確認：</strong>Garmin音量起伏原因、長時間播放；'
            '手機直接連Garmin的A2DP、原機播放器App與實機音訊所有權尚未完成。'
            '原生整合此次僅有部分檔案審閱，沒有執行受中斷的guest。</p>'
            '<details><summary>不用車機即可檢查轉換計畫</summary><pre>'
            'python3 scripts/garmin_phone_audio_bridge.py --plan-conversion\n'
            'python3 scripts/garmin_music_player.py --plan-conversion</pre>'
            '<p>可選參數：<code>--mono-mode left</code>／<code>right</code>與<code>--headroom-db 3</code>。'
            '這些只改Pi轉換，不改Garmin韌體或喇叭處理。</p></details>'
            '<p>轉換參數依 <a href="https://ffmpeg.org/ffmpeg-filters.html#pan">FFmpeg pan</a>、'
            '<a href="https://ffmpeg.org/ffmpeg-filters.html#volume">volume</a> 文件。'
            'HFP協商欄位依 <a href="https://github.com/arkq/bluez-alsa/blob/v4.3.1/src/hfp.h">BlueALSA 4.3.1</a> 核對。'
            '導航工作已停止；使用者返回會主動通知，目前不要求操作或配對。</p></section>')
    require('id="bluetooth-music-current-checkpoint-v1"' not in report, 'New single music card')
    marker = '<section class="card" id="offline-research-24h">'
    require(report.count(marker) == 1, 'One insertion point')
    report = report.replace(marker, card + marker, 1)
    report = report.replace('<span class="progress-status">導航修復進行中；原研究暫緩</span>',
                            '<span class="progress-status">藍牙音樂研究中；導航工作已停止</span>', 1)
    report, n = re.subn(r'<p id="progress-method" class="progress-note">.*?</p>',
                        lambda _: '<p id="progress-method" class="progress-note">'
                        + html.escape(progress['method']) + '</p>', report, count=1, flags=re.S)
    require(n == 1, 'Current estimate explanation')
    start = report.index('<section class="card" id="navigation-repair-checkpoint-v2">')
    end = report.index('</section>', start)
    section = report[start:end]
    section, n = re.subn(r'<h3>接著處理</h3><ol>.*?</ol>',
                         lambda _: '<h3>目前狀態</h3><p>導航修復與圖資包工作依使用者指示停止；'
                         '保留已實測版本與歷史研究資料。</p>', section, count=1, flags=re.S)
    require(n == 1, 'Stopped navigation next actions')
    report = report[:start] + section + report[end:]
    report, n = re.subn(r'<p><strong>下一步：</strong>解析原廠TWNJAI.*?</p>',
                        lambda _: '<p><strong>下一步：</strong>' + html.escape(next_actions[0]) + '</p>',
                        report, count=1, flags=re.S)
    require(n == 1, 'Current visible next action')
    for phase in progress['phases']:
        pattern = r'(<tr><td>' + re.escape(phase['name']) + r'</td><td>[^<]*</td><td>).*?(</td></tr>)'
        report, n = re.subn(pattern, lambda m, p=phase: m.group(1) + html.escape(p['next']) + m.group(2),
                            report, count=1, flags=re.S)
        require(n == 1, 'Current phase row ' + phase['name'])
    for ident in ['report-updated-time', 'research-updated-time']:
        report, n = re.subn(r'<time id="' + ident + r'" datetime="[^"]+">[^<]+</time>',
                            lambda _: f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">'
                            f'{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        require(n == 1, 'One timestamp ' + ident)
    require(old_nav == state['navigation_repair'], 'Stopped navigation and device evidence preserved')
    out = ROOT / 'staging' / ('bluetooth-music-results-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, raw in before.items():
        with (out / (path.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for path, value in zip(FILES[:4], [state, task, public, report]):
        replace(path, value)
    served, response = http(web['url'])
    require(served == report.encode() and service() == live, 'Current exact HTTP, original service')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
               served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
               latest_bluetooth_music_offline_checkpoint=copy.deepcopy(checkpoint),
               offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web['progress_display_verified'].update(report_updated_time=local.isoformat(timespec='seconds'),
                                          research_updated_time=local.isoformat(timespec='seconds'))
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / p).read_bytes()) for p in [FILES[0], FILES[1], FILES[2], FILES[4]]]
    require(fresh[0] == fresh[2]['deep_research'] and fresh[0]['navigation_repair']
            == fresh[1]['navigation_repair'] == fresh[2]['navigation_repair'], 'Fresh canonical equality')
    require(all(d['current_goal_priority'] == 'bluetooth_music' and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in fresh), 'Music scope remains active and incomplete')
    create(out / 'fresh-readback.json', {
        'all_passed': True, 'checkpoint': checkpoint, 'service': live,
        'report_sha256': sha(served), 'report_url': web['url'],
        'canonical_sha256': {p: sha((ROOT / p).read_bytes()) for p in FILES},
        'updated_at_Taiwan': local.isoformat(timespec='seconds'),
        'device_IO': False, 'goal_status': 'active', 'goal_complete': False,
    })
    print(json.dumps({'all_passed': True, 'checkpoint': str(out.relative_to(ROOT)),
                      'updated_at_Taiwan': local.isoformat(timespec='seconds'),
                      'report_url': web['url'], 'current_goal_priority': 'bluetooth_music',
                      'service': live, 'device_IO': False}, ensure_ascii=False))


if __name__ == '__main__':
    main()
