#!/usr/bin/env python3
"""Publish completed, silent host diagnostics while preserving device evidence."""
import argparse
import copy
from datetime import datetime, timezone
import gzip
import html
import json
import os
import re
from zoneinfo import ZoneInfo

from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json',
         'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
PINS = {
    'staging/music-volume-diagnostics-root-v1/proof.json': 'f9e2422dd19dc59a540893cf16538fe22d0156f3c6912e8c8c57bcd4e2abc073',
    'staging/music-volume-diagnostics-root-v1/sealed-files.json': 'bba62c779c058bb2df2a9246f33a3141940c67b0c06d6fe8779f25739db87b7b',
    'staging/music-readonly-volume-observer-20261007-v1/proof.json': '68c1dbbdb55d1f2ff99c73c3bf9a06c2323ad2dcce45a49fe3174341dcd23a71',
    'staging/music-readonly-volume-observer-20261007-v1/sealed-files.json': 'f7fd23b3592e29b62405105dfadf3eb5319a7fcc1573f92a3e18ae417100aa63',
    'staging/music-diagnostic-timeline-analyzer-20261007-v1/sealed-files.json': '1f545bda6767de75fec94de1bcb53810ef7fcea7d03170bc2258200ac0f33c0a',
    'staging/music-diagnostic-observation-safety-review-20261007-v1/sealed-files.json': '52688f2b39bf1a1d97e806ffba07231da28ba5140f490f1c2dd30083f7b753f4',
    'staging/music-diagnostic-observation-safety-review-20261007-v1/final-seal.json': '67af85ecbb44ef1a16c4c15dfd88ff3019ac88eaff10b7fb6c01179499e7acf5',
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def small_proof(path, pin):
    require(path.startswith('staging/') and '..' not in path.split('/'), 'Small local proof path')
    raw = (ROOT / path).read_bytes()
    require(len(raw) <= 65536 and sha(raw) == pin, 'Exact proof pin ' + path)
    return json.loads(raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--analysis-proof', required=True)
    parser.add_argument('--analysis-sha', required=True)
    parser.add_argument('--review-proof', required=True)
    parser.add_argument('--review-sha', required=True)
    args = parser.parse_args()
    pins = {**PINS, args.analysis_proof: args.analysis_sha, args.review_proof: args.review_sha}
    proofs = {path: small_proof(path, pin) for path, pin in pins.items()}
    root = proofs['staging/music-volume-diagnostics-root-v1/proof.json']
    observer = proofs['staging/music-readonly-volume-observer-20261007-v1/proof.json']
    analysis, review = proofs[args.analysis_proof], proofs[args.review_proof]
    require(root['all_required_host_checks_passed'] and root['new_controls'] == 10,
            'Ten closed host controls, partial suites kept partial')
    require(observer['all_assigned_checks_passed'] and observer['actual_methods'] == 12
            and not observer['live_provider_constructed'], 'Twelve inert observer controls')
    # Final agent proofs must explicitly close their own assigned source-review scopes.
    require(analysis.get('all_assigned_checks_passed') and analysis.get('STOP'), 'Closed analyzer proof')
    require(review.get('all_assigned_checks_passed') and review.get('STOP') and review.get('review_only')
            and review.get('no_execution'), 'Closed source-only review proof')
    source_pins = {'scripts/' + name: pin for name, pin in root['source_bindings'].items()}
    analyzer_source = analysis['source']
    require(analyzer_source['path'] == 'scripts/analyze_garmin_music_diagnostics.py', 'Exact analyzer source path')
    source_pins[analyzer_source['path']] = analyzer_source['sha256']
    for path, pin in source_pins.items():
        require(sha((ROOT / path).read_bytes()) == pin, 'Current host source pin ' + path)
    require(review['final_source_hashes'] == source_pins, 'Complete final review source bindings')
    before = {path: (ROOT / path).read_bytes() for path in FILES}
    state, task, public = [json.loads(before[path]) for path in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'] and state['navigation_repair'] == task['navigation_repair']
            == public['navigation_repair'], 'Prior canonical equality')
    require(all(value['current_goal_priority'] == 'bluetooth_music' and value['goal_status'] == 'active'
                and not value['goal_complete'] for value in (state, task, public, web)), 'Latest music objective active')
    require(task['user_away'] and state['navigation_repair']['status'] == 'stopped_by_user'
            and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'],
            'Navigation stopped; user away; no physical tests requested')
    old_navigation = copy.deepcopy(state['navigation_repair'])
    old_native = copy.deepcopy(state['native_app_music'])
    old_audible = copy.deepcopy(state['audio']['latest_physical_test_evidence'])
    prior_service = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Prior report exact HTTP')
    now = datetime.now(timezone.utc); local = now.astimezone(ZoneInfo('Asia/Taipei'))
    timestamp = local.isoformat(timespec='seconds')
    checkpoint = {
        'updated_utc': now.isoformat(), 'proof_pins': pins, 'current_source_pins': source_pins,
        'host_required_controls': 10, 'observer_offline_controls': 12,
        'periodic_Volume_SoftVolume_monitor_implemented': True,
        'monitor_default_enabled': False, 'monitor_live_mode_run_this_turn': False,
        'observer_not_in_PCM_pipe': True, 'observer_failure_nonfatal_to_audio': True,
        'critical_audio_failure_still_fatal': True, 'all_owned_process_groups_reaped_in_host_cases': True,
        'default_and_diagnostic_output_match_original_fixed_filter': True,
        'host_frames_each_fixture': 2400,
        'common_run_token_and_monotonic_clock_implemented': True,
        'clock_scope': 'host read/wait intervals and metadata observation; not acoustic/sample timestamps',
        'cross_tap_sample_content_alignment_verified': False,
        'timeline_analyzer_implemented': True, 'timeline_live_music_validated': False,
        'unknown_gaps_or_unbound_clocks_do_not_prove_gain_cause': True,
        'reports_per_stream_max_bytes': 1048576, 'PCM_samples_retained': False,
        'legacy_debug_logs_bounded_or_deidentified': False,
        'inline_meter_processing_delay_or_live_performance_verified': False,
        'historical_partial_suites_preserved': ['a59389 EXIT1', 'bf7d3d EXIT1', '13820a EXIT1'],
        'remaining_conversion_followup': '1e2a46 EXIT0',
        'current_phone_or_Garmin_connection_checked': False,
        'daemon_modified_or_restarted': False, 'device_IO': False, 'audible_playback': False,
        'loudness_fluctuation_cause_proven': False, 'music_quality_improved': False,
        'long_duration_Garmin_music_verified': False, 'native_phone_A2DP_or_App_installed': False,
        'native_guest_retried': False, 'full_goal_complete': False,
    }
    next_actions = [
        '以新時間線工具分析後續手動音樂診斷，分清上游音量控制、Pi轉換與下游處理；無同步完整資料時保留未知。',
        '持續改善Pi音樂轉送的穩定度與操作流程；原生App／直接A2DP仍需真正音訊所有權、端點與停止收尾證據。',
        '使用者返回會主動通知；屆時先維持藍牙連線再測相同音樂。目前不要求接車機、不自動來電或播放。',
    ]
    state.update(updated_utc=now.isoformat(), next_actions=copy.deepcopy(next_actions),
                 latest_music_volume_diagnostics_checkpoint=copy.deepcopy(checkpoint))
    state['audio']['latest_music_volume_diagnostics_checkpoint'] = copy.deepcopy(checkpoint)
    work = state['offline_24h_work_order']
    work['latest_music_volume_diagnostics_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status'].update(
        pi_music='opt-in volume observer separate from PCM; shared host clock and output invariance verified offline',
        hfp_music='offline metadata/level timeline added; no live gain or audible quality conclusion')
    turn = {'classification': 'offline_music_progress', 'validated_utc': now.isoformat(),
            'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
            'device_files_written': False,
            'reason': 'Read-only optional volume observer, common-clock meter and offline timeline closed without device IO.'}
    state['last_goal_turn'] = copy.deepcopy(turn)
    for key in ('updated_utc', 'next_actions', 'offline_24h_work_order', 'latest_music_volume_diagnostics_checkpoint', 'last_goal_turn'):
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state),
                  offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn),
                  latest_music_volume_diagnostics_checkpoint=copy.deepcopy(checkpoint))
    public['research_progress'].update(research_updated_utc=now.isoformat(), next=next_actions[0])
    report = before[FILES[3]].decode()
    card = ('<section class="card" id="bluetooth-music-current-checkpoint-v1"><h2>藍牙音樂：同步音量紀錄與離線分析</h2>'
            f'<p>更新：<time datetime="{timestamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
            '<p>Pixel → Pi → Garmin先前已實測持續60秒有聲，仍是8kHz單聲道通話音訊。'
            '這輪新增診斷工具，沒有查詢真實藍牙服務、來電或播放。</p><ul>'
            '<li>可選的音量觀察器只讀兩個已授權裝置的Volume、SoftVolume與Codec；它與音訊管線分開，失敗不會停止音樂。12項離線控制通過。</li>'
            '<li>轉換前後的數值測量與音量事件共用run token及主機單調時間。'
            '三種短管線輸出各2,400個樣本，均與原固定轉換逐byte一致；全部自有程序與檔案描述符已收回。</li>'
            '<li>離線分析器檢查紀錄缺漏、時鐘綁定、格式變更與附近音量事件。時間接近不能證明因果，取樣數相同也不能證明音樂片段對齊。</li>'
            '<li>每份數值JSONL最多1MiB，不保留音樂內容。原有工程stderr紀錄另行保留，不將它們宣稱成有限長度或已去識別資料。</li>'
            '</ul><p><strong>測量限制：</strong>主機read區間包含等待，是管線觀察時間，並非聲音取樣時間。'
            '輸入在BlueALSA音量處理之後，輸出在SCO／喇叭處理之前；這些數值不能量到喇叭聲壓或確認Garmin降噪。'
            '測量器本身也會增加處理時間，實機效能與忽大忽小原因尚未確認。</p>'
            '<p><strong>原生App／手機直接配對播放：</strong>仍未完成。原機藍牙端點、音訊所有權、多工及安全停止／回收仍需實際證據；本輪未執行native guest或安裝韌體。</p>'
            '<p><strong>現在不需操作車機。</strong>導航研究依使用者指示停止。返回後先處理藍牙連線再做聲音測試。</p>'
            '<details><summary>日後手動診斷（目前未執行）</summary><pre>'
            'python3 scripts/garmin_phone_audio_bridge.py --max-seconds 60 --volume 0.7 --live-cind-test --diagnostics'
            '</pre><p>只在一般模式已有藍牙連線且可接聽模擬來電時使用。'
            '未加--diagnostics時保留原三段播放管線。</p></details></section>')
    report, count = re.subn(r'<section class="card" id="bluetooth-music-current-checkpoint-v1">.*?</section>',
                           lambda _: card, report, count=1, flags=re.S)
    require(count == 1, 'One current music card')
    frontier = ('<p id="offline-frontier-latest-v1">最新：藍牙音樂已加入可選的音量控制紀錄、共用主機時鐘與離線時間線分析。'
                '一般Linux短管線輸出保持一致；實機音質、長時間穩定度、原生App與直接A2DP仍未完成。導航工作保持停止。</p>')
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: frontier, report, count=1, flags=re.S)
    require(count == 1, 'Current frontier')
    report, count = re.subn(r'<p><strong>下一步：</strong>增加可選.*?</p>',
                           lambda _: '<p><strong>下一步：</strong>' + html.escape(next_actions[0]) + '</p>', report, count=1, flags=re.S)
    require(count == 1, 'Current next action')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
                               lambda _: f'<time id="{name}" datetime="{timestamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        require(count == 1, 'Timestamp ' + name)
    require(old_navigation == state['navigation_repair'] and old_native == state['native_app_music']
            and old_audible == state['audio']['latest_physical_test_evidence'], 'Historical native/device/navigation evidence unchanged')
    out = ROOT / 'staging' / ('music-volume-diagnostics-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, raw in before.items():
        with (out / (path.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for path, value in zip(FILES[:4], (state, task, public, report)):
        replace(path, value)
    served, response = http(web['url'])
    require(served == report.encode() and service() == prior_service, 'Fresh exact HTTP and unchanged report service')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
               served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
               latest_music_volume_diagnostics_checkpoint=copy.deepcopy(checkpoint),
               offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web['progress_display_verified'].update(report_updated_time=timestamp, research_updated_time=timestamp)
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / path).read_bytes()) for path in (FILES[0], FILES[1], FILES[2], FILES[4])]
    require(fresh[0] == fresh[2]['deep_research'] and fresh[0]['navigation_repair'] == fresh[1]['navigation_repair']
            == fresh[2]['navigation_repair'], 'Fresh canonical equality')
    require(all(value['latest_music_volume_diagnostics_checkpoint'] == checkpoint and value['goal_status'] == 'active'
                and not value['goal_complete'] for value in fresh), 'Incomplete active goal, exact current checkpoint')
    create(out / 'fresh-readback.json', {'all_passed': True, 'updated_at_Taiwan': timestamp, 'checkpoint': checkpoint,
                                      'report_url': web['url'], 'report_sha256': sha(served), 'service': prior_service,
                                      'device_IO': False, 'goal_complete': False})
    print(json.dumps({'all_passed': True, 'snapshot': str(out.relative_to(ROOT)), 'updated_at_Taiwan': timestamp,
                      'report_url': web['url'], 'service': prior_service, 'device_IO': False}))


if __name__ == '__main__':
    main()
