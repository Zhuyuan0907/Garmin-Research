#!/usr/bin/env python3
"""Update the existing report with bounded, device-free music evidence."""
import copy
import gzip
import html
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json',
         'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
PINS = {
    'staging/music-host-pipeline-supervision-20261007-v2/proof.json': 'a3e137b78d82dfefaedea58b851dc0ee5d45caf804ccce319c4ca946e859fffe',
    'staging/music-host-pipeline-supervision-20261007-v2/sealed-files.json': '3c022e3e6d77f230dd3f00785a62db637bd15d61919f654e6804c773a6461559',
    'staging/music-host-bridge-integration-v2/proof.json': '1370e2e9d78240c27279d61acaad563214b000d76a31c3ae8241732edf5eab8e',
    'staging/music-host-bridge-integration-v2/sealed-files.json': '416b59b16f9250a91ac1f991d9cf40bdfe9cba6cee6da25250cbef028273c739',
    'staging/music-pcm-meter-host-v1/proof-v2.json': '135962991f5b194fe90bae9f0740b420647985129de6963e2dd41538e119c58e',
    'staging/music-pcm-meter-host-v1/sealed-files.json': '3472818749634b094cfa088f16ed3bcf7f1c95e28f078f7116ca98373e0a79a6',
    'staging/music-hfp-volume-control-chain-20261007-v2/proof.json': '9167989dae81175bb4334a5c91406fd55583c251fe3f93b8d2ca014c6d8144a4',
    'staging/music-hfp-volume-control-chain-20261007-v2/sealed-files.json': '71e56dad1c047706cf55f4b5e9cfb377b0c650a54b737eb30d66761798c805f0',
    'staging/music-native-ownership-evidence-gap-20261007-v2/proof.json': '8e6e656111be0f57e4e78082a2f1d74b759f4778cd8a66f26a8436fa35755b9b',
    'staging/music-native-ownership-evidence-gap-20261007-v2/sealed-files.json': 'ecfd64ee888c060f5a75d126310b72cdd4056965e7a80aee9c87ce7b83a20ce6',
}
SOURCES = {
    'scripts/garmin_phone_audio_bridge.py': '0c29870fd5d607e89b19beeaed540c38d3ed6f1880cb6f2ab56081eba8ed12ca',
    'scripts/garmin_music_player.py': 'f9a3f1ea96d5a68ed97b570173248757a1efc4311374dd693abcf8e516ff6277',
    'scripts/garmin_pcm_meter.py': '5186a3e2c8f6ed75aee5d2f22916e95340dd58bf44c4ff8cef1e7c33f4dcb6a7',
    'scripts/garmin_host_audio_pipeline.py': '47bd40c4dc1a698a454b5171df6a6ee3898256a17bd7665fc3ae81bb60af2e63',
    'scripts/garmin_audio_conversion.py': 'cfa0391ad6f121f55bc3523873621bcc8403b4837f463d161ffe0af5cb23087f',
}


def require(value, why):
    if not value:
        raise ValueError(why)


def main():
    docs = {}
    for path, pin in PINS.items():
        raw = (ROOT / path).read_bytes()
        require(len(raw) < 65536 and sha(raw) == pin, 'Exact small proof ' + path)
        docs[path] = json.loads(raw)
    for path, pin in SOURCES.items():
        require(sha((ROOT / path).read_bytes()) == pin, 'Current source pin ' + path)
    integration = docs['staging/music-host-bridge-integration-v2/proof.json']
    meter = docs['staging/music-pcm-meter-host-v1/proof-v2.json']
    require(integration['all_passed'] and len(integration['cases']) == 4
            and integration['default_audio_argv_format_and_fixed_gain_retained']
            and not integration['real_live_endpoints_executed'], 'Bounded host integration scope')
    require(meter['all_assigned_checks_passed'] and len(meter['initial_passed_cases']) == 8
            and meter['actual_followup_cases'] == 1 and meter['initial_suite_actual_exit'] == 1,
            'Meter followup does not erase the initial failed capacity assumption')
    before = {p: (ROOT / p).read_bytes() for p in FILES}
    state, task, public = [json.loads(before[p]) for p in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'] and state['navigation_repair']
            == task['navigation_repair'] == public['navigation_repair'], 'Previous canonical equality')
    require(all(x['current_goal_priority'] == 'bluetooth_music' and x['goal_status'] == 'active'
                and not x['goal_complete'] for x in [state, task, public, web]), 'Latest user music priority')
    require(state['navigation_repair']['status'] == 'stopped_by_user' and task['user_away']
            and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'],
            'Navigation stays stopped; away, silent work')
    live = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Existing exact HTTP report')
    old_nav = copy.deepcopy(state['navigation_repair'])
    old_audible = state['audio']['latest_physical_test_evidence']
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    checkpoint = {
        'updated_utc': now.isoformat(), 'prerequisite_pins': PINS, 'current_source_pins': SOURCES,
        'previous_goal_turn_classification': 'progress',
        'previous_turn_evidence': 'staging/bluetooth-music-results-publication-20261007T095734084207Z/fresh-readback.json',
        'supervisor_real_inert_child_controls': 11,
        'root_bridge_integration_actual': 'afa20c EXIT0',
        'default_three_stage_and_opt_in_five_stage_host_PCM_outputs_byte_identical': True,
        'root_integration_PCM_frames_per_case': 2400,
        'observed_upstream_failure_cannot_be_hidden_by_player_zero': True,
        'own_child_groups_only_signalled': True, 'bounded_cleanup_and_watchdog_implemented': True,
        'normal_child_eof_is_not_speaker_consumption_evidence': True,
        'meter_checks': {'first_suite_actual': '9152c3 EXIT1', 'first_passed_controls': 8,
                         'followup_actual': 'c6c463 EXIT0', 'followup_controls': 1,
                         'failed_case_was_test_pipe_capacity_assumption': True,
                         'requested_pipe_capacity': 4096, 'actual_pipe_capacity': 16384,
                         'own_real_pipe_wait_ms_observed': meter['followup']['maximum_forward_wait_ms'],
                         'unchanged_PCM_bytes_verified': True,
                         'scalar_report_cap_bytes_per_tap': 1048576, 'PCM_content_saved': False},
        'diagnostics_flag': '--diagnostics', 'diagnostics_default_enabled': False,
        'initial_phone_PCM_properties_available_when_live_diagnostics_invoked': True,
        'periodic_PCM_Volume_SoftVolume_monitor_implemented': False,
        'input_tap': 'after BlueALSA volume and arecord, before FFmpeg',
        'output_tap': 'after FFmpeg, before SCO daemon gain and physical speaker',
        'Volume_property_is_uint16_packed_control_not_dB': True,
        'current_live_SoftVolume_or_Volume_verified': False,
        'source_default_A2DP_gain_can_change_captured_PCM': 'conditional on live soft_volume mode, not cause proof',
        'native_file_review_completed': True,
        'native_file_review_inputs': 11,
        'native_missing_providers': ['ownership_snapshot', 'prepare_session'],
        'native_software_CONFIG_grant_proves_all_writer_exclusion': False,
        'native_future_callback_barrier_verified': False,
        'native_hardware_ownership_or_STOP_DONE_verified': False,
        'native_interrupted_guest_retried': False,
        'native_direct_phone_A2DP_App_or_speaker_verified': False,
        'daemon_changed_or_restarted': False, 'device_IO': False, 'audible_playback': False,
        'physical_quality_improved': False, 'loudness_fluctuation_cause_proven': False,
        'long_duration_device_music_verified': False, 'full_goal_complete': False,
    }
    next_actions = [
        '增加可選的Volume／SoftVolume定時唯讀紀錄，與兩個Pi音量測量點使用同一時間基準；目前未啟用實際服務或播放。',
        '原機直接A2DP／App維持唯讀分析：音訊所有權見證、所有寫入者排除、未來回呼屏障及停止收尾仍缺實際provider。',
        '使用者返回會主動通知；現場先維持藍牙連線，再以相同音樂與固定手機音量測量，不能將Pi數值當喇叭音質。',
    ]
    state.update(updated_utc=now.isoformat(), next_actions=copy.deepcopy(next_actions),
                 latest_music_supervision_meter_checkpoint=copy.deepcopy(checkpoint))
    state['audio']['latest_music_supervision_meter_checkpoint'] = copy.deepcopy(checkpoint)
    state['audio']['latest_gain_control_chain_review'] = {
        'proof': 'staging/music-hfp-volume-control-chain-20261007-v2/proof.json',
        'source_only': True, 'current_modes_unverified': True, 'fluctuation_cause_proven': False}
    state['native_app_music']['latest_native_ownership_evidence_gap_review'] = {
        'proof': 'staging/music-native-ownership-evidence-gap-20261007-v2/proof.json',
        'finite_file_review_complete': True, 'native_execution': False,
        'ownership_snapshot_provider_bound': False, 'prepare_session_provider_bound': False,
        'software_grant_is_hardware_ownership': False, 'direct_phone_App_or_speaker_complete': False}
    work = state['offline_24h_work_order']
    work['latest_music_supervision_meter_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status'].update(
        pi_music='host supervisor and optional scalar PCM taps integrated; default/diagnostic byte outputs verified',
        hfp_music='captured-source gain chain and packed Volume ABI closed; live control correlation remains unverified',
        native_audio='finite file-only ownership/provider gap matrix closed; no guest retry or hardware acceptance')
    turn = {'classification': 'offline_music_progress', 'validated_utc': now.isoformat(),
            'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
            'device_files_written': False, 'reason': 'Actual inert process supervision and PCM meter integration verified; native ABI gaps documented.'}
    state['last_goal_turn'] = copy.deepcopy(turn)
    for key in ['updated_utc', 'next_actions', 'native_app_music', 'offline_24h_work_order',
                'latest_music_supervision_meter_checkpoint', 'last_goal_turn']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state),
                  offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn),
                  latest_music_supervision_meter_checkpoint=copy.deepcopy(checkpoint))
    public['research_progress'].update(research_updated_utc=now.isoformat(), next=next_actions[0])
    report = before[FILES[3]].decode()
    card = ('<section class="card" id="bluetooth-music-current-checkpoint-v1"><h2>藍牙音樂：加入播放失敗監督與音量診斷</h2>'
            f'<p>更新：<time datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
            '<p>既有Pixel → Pi → Garmin路徑曾實测連續60秒有聲，仍是8kHz單聲道通話音訊。'
            '本輪只執行一般Linux子程序與檔案音訊，沒有來電、播放或藍牙連線。</p><ul>'
            '<li>播放程式會監督錄音、轉換與播放全部程序；上游失敗不再被player成功掩蓋。'
            'EOF、掛斷、Ctrl+C、逾時與啟動失敗分開記錄，並限時收回自有子程序群。</li>'
            '<li>11項真實短程序控制通過；加入測量前／後的完整轉換輸出各2,400個樣本，與原固定音量流程逐byte相同。</li>'
            '<li>可選<code>--diagnostics</code>記錄轉換前後的RMS、峰值、滿刻度樣本數、立體聲相位與管線等待時間。'
            '不留音樂內容，每個測量點最多1MiB。測量器8項控制加1項管線等待控制通過；初次測試的pipe容量假設錯誤保留並另行驗證。</li>'
            '<li>初始PCM音量／SoftVolume可隨診斷保存；Volume是打包控制量，不能當dB。'
            '動態音量事件的定時記錄尚未接入，現在不能據此確認忽大忽小的原因。</li>'
            '</ul><p><strong>測量位置：</strong>輸入在BlueALSA音量處理之後；輸出在SCO與喇叭處理之前。'
            '數值不代表喇叭聲壓、藍牙丟包或Garmin降噪。</p>'
            '<p><strong>原機App／手機直連：</strong>有限唯讀審閱找出缺少的音訊所有權與session初始化provider。'
            '軟體啟動許可不能證明所有寫入者排除、未來回呼屏障或STOP_DONE，原機播放與App安裝仍未完成。'
            '沒有執行先前被中止的native guest。</p>'
            '<p><strong>目前不需操作車機。</strong>使用者返回會主動通知，現場配對仍第一優先；導航研究保持停止。</p>'
            '<details><summary>後續現場診斷指令（目前未執行）</summary><pre>'
            'python3 scripts/garmin_phone_audio_bridge.py --max-seconds 60 --volume 0.7 --live-cind-test --diagnostics'
            '</pre><p>需要Garmin一般模式、既有藍牙連線及接聽模擬來電。原播放格式與固定音量預設保持；'
            '測量程序的實機效能、通話狀態還原與長時間播放尚未驗證。</p></details>'
            '<p>PCM控制欄位依<a href="https://github.com/arkq/bluez-alsa/blob/v4.3.1/doc/org.bluealsa.PCM1.7.rst">'
            'BlueALSA 4.3.1 PCM1文件</a>核對。</p></section>')
    report, n = re.subn(r'<section class="card" id="bluetooth-music-current-checkpoint-v1">.*?</section>',
                        lambda _: card, report, count=1, flags=re.S)
    require(n == 1, 'One latest music card')
    frontier = ('<p id="offline-frontier-latest-v1">最新：藍牙音樂程式已加入程序失敗監督及可選的純數值音量測量。'
                '一般Linux離線管線與原轉換結果一致；沒有驗證當下車機聲音。'
                '手機直接A2DP、原機App、音量波動原因及長時間播放仍未完成。導航修復保持停止。</p>')
    report, n = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: frontier, report, count=1, flags=re.S)
    require(n == 1, 'Current frontier')
    report, n = re.subn(r'<p><strong>下一步：</strong>既有手機音樂.*?</p>',
                        lambda _: '<p><strong>下一步：</strong>' + html.escape(next_actions[0]) + '</p>',
                        report, count=1, flags=re.S)
    require(n == 1, 'Current next step')
    for ident in ['report-updated-time', 'research-updated-time']:
        report, n = re.subn(r'<time id="' + ident + r'" datetime="[^"]+">[^<]+</time>',
                            lambda _: f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">'
                            f'{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        require(n == 1, 'Current timestamp ' + ident)
    require(old_nav == state['navigation_repair'] and old_audible == state['audio']['latest_physical_test_evidence'],
            'Stopped navigation and original user-audible evidence preserved')
    out = ROOT / 'staging' / ('music-supervision-meter-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, data in before.items():
        with (out / (path.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(data, mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for path, value in zip(FILES[:4], [state, task, public, report]):
        replace(path, value)
    served, response = http(web['url'])
    require(served == report.encode() and live == service(), 'Fresh exact HTTP, same original service')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
               served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
               latest_music_supervision_meter_checkpoint=copy.deepcopy(checkpoint),
               offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web['progress_display_verified'].update(report_updated_time=local.isoformat(timespec='seconds'),
                                          research_updated_time=local.isoformat(timespec='seconds'))
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / p).read_bytes()) for p in [FILES[0], FILES[1], FILES[2], FILES[4]]]
    require(fresh[0] == fresh[2]['deep_research'] and fresh[0]['navigation_repair']
            == fresh[1]['navigation_repair'] == fresh[2]['navigation_repair'], 'Canonical fresh readback equality')
    require(all(x['goal_status'] == 'active' and not x['goal_complete'] and x['current_goal_priority'] == 'bluetooth_music'
                for x in fresh) and fresh[1]['user_away'], 'Goal incomplete; latest music priority remains authoritative')
    create(out / 'fresh-readback.json', {'all_passed': True, 'checkpoint': checkpoint, 'service': live,
                                      'report_sha256': sha(served), 'report_url': web['url'],
                                      'updated_at_Taiwan': local.isoformat(timespec='seconds'),
                                      'device_IO': False, 'goal_status': 'active', 'goal_complete': False,
                                      'native_App_estimate': 40, 'historical_overall_estimate': 37})
    print(json.dumps({'all_passed': True, 'checkpoint': str(out.relative_to(ROOT)), 'report_url': web['url'],
                      'updated_at_Taiwan': local.isoformat(timespec='seconds'), 'device_IO': False, 'service': live}))


if __name__ == '__main__':
    main()
