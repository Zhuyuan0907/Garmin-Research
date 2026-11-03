#!/usr/bin/env python3
"""Publish closed FILE reviews while preserving all physical acceptance history."""
import copy
from datetime import datetime, timezone
import gzip
import html
import json
import os
import re
from zoneinfo import ZoneInfo

from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, replace, service, sha
from publish_native_music_contracts_findings_v1 import require, pinned, FILES

SYMBOL = 'staging/native-music-named-symbol-binding-readonly-20261007-v1/'
TOKEN = 'staging/native-music-persistent-token-provider-readonly-20261007-v1/'
ENDPOINT = 'staging/native-music-endpoint-activation-contract-readonly-20261007-v1/'
ANDROID = 'staging/android-garmin-HFP-direct-feasibility-20261007-v1/'
FIELD = 'latest_native_music_provider_checkpoint'
PINS = {
    SYMBOL + 'proof.json': '8a1bb325097f652700cd4b8c1174af2e7ad04cd72c047f087243b7a7027f4585',
    SYMBOL + 'symbol-binding-ledger.json': '9828727f6114b51505182c9bbe008b27367846ed88ee8208fa1610e624d8e80c',
    SYMBOL + 'sealed-files.json': 'dede2f5e3d9681950d2618901885eadda9f320cdea62c4aa176af7a99bc864b1',
    SYMBOL + 'actual-review-tool-receipt.json': '2b1e354e5ea52cc3fc315b9ca1f5a9b1b528968ce74cb4322b5d1da1b1e48b1e',
    TOKEN + 'proof.json': '32dc51c25e9aa7321a5b040bc5abe938df9098a4813b11f0521616b724b3ac67',
    TOKEN + 'producer-consumer-matrix.json': '8830eb5cc8c33b8ac83b37b5e74b8ed9e1e7c0b4f62f189d030695cf3830ede1',
    TOKEN + 'sealed-files.json': 'ae995c7c804c5b3ceb62d44def65d6b471fc186023b6155656c73b896785cb8f',
    TOKEN + 'actual-terminal-closure.json': '6534fb6d19cae83a9f36ea43b47ffe2fe4596e1ff9948920b75a9a26fbbcad5f',
    ENDPOINT + 'proof.json': 'ecb11ac11b208cd78aa17f82489db76d93830975bf0da455c12c0ef59471bf4a',
    ENDPOINT + 'activation-provider-ledger.json': '9a2814084c35956454df9e083608254b6da7e8612be0cda5cc08b72b6d379333',
    ENDPOINT + 'sealed-files.json': 'e4db2c7ba1b3b663c9ecc6e969b807900fabbc3eb5cdc280a340c7b5a2f71699',
    ENDPOINT + 'actual-sealer-receipt.json': '065c0ed31a46db42f77c0e27019e6b8229cd1eecc763e0236e0f804e7169183a',
    ANDROID + 'proof.json': 'c4bab6c18acc1fb2cebdb9d7ded408a9c21f94a5925b9f68b715ebf49b9fc439',
    ANDROID + 'feasibility-summary.json': '6fa399f29b413ff2cadd49fc2ee9d31316017bbe72257bda4ab297dbaf14b489',
    ANDROID + 'sources.json': '980d4c0bda8f6e42cce42b5ca481db03880bb9fc6e2dbb657d510475e9a851d5',
    ANDROID + 'sealed-files.json': '2faa1a85ad51a59b4851c8eb8de91063ea54e481641665a344e1d513f0b0da4a',
    ANDROID + 'actual-sealer-terminal-receipt.json': '36bbade7e898e3ee3f88686e83a3b8110a2c87df584f674438aaef586af53f61',
}


def main():
    evidence = {name: pinned(name, pin) for name, pin in PINS.items()}
    symbols = evidence[SYMBOL + 'symbol-binding-ledger.json']
    symbol_proof = evidence[SYMBOL + 'proof.json']
    token = evidence[TOKEN + 'proof.json']
    endpoint = evidence[ENDPOINT + 'proof.json']
    android_proof = evidence[ANDROID + 'proof.json']
    android = evidence[ANDROID + 'feasibility-summary.json']
    require(symbol_proof['STOP'] and symbol_proof['all_assigned_FILE_checks_passed']
            and symbols['present_declared_functions_per_build'] == 8
            and len(symbols['absent_from_both_declared_symbol_maps']) == 4
            and symbols['public_getter_absent_from_both_maps'] == 'ui_music_control_api', 'Closed symbol FILE comparison')
    require(token['STOP'] and token['all_assigned_checks_passed'] and token['no_native_implementation'],
            'Closed identity FILE comparison')
    require(endpoint['STOP'] and endpoint['all_assigned_checks_passed'] and endpoint['checks_passed'] == 36
            and not endpoint['hardware_phone_music_complete'] and not endpoint['device_BT_DBUS_audio'],
            'Closed activation FILE comparison')
    require(evidence[SYMBOL + 'actual-review-tool-receipt.json']['exit_code'] == 0, 'Actual root metadata review succeeded')
    require(android_proof['stop'] and android_proof['all_assigned_research_checks_passed']
            and not android_proof['runtime_or_audio_success'] and not any(android['flags'].values()), 'Closed public Android research; no runtime success')
    require(android['layers']['self_managed_call_hfp_visibility_and_remote_controls']['status'] == 'officially_supported'
            and android['layers']['local_music_media_player_actual_sco_delivery']['status'] == 'unverified'
            and not android['carrier_and_microphone']['no_microphone_permission_guarantee'], 'Distinguish call support from actual music')

    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'] and state['navigation_repair'] == task['navigation_repair']
            == public['navigation_repair'], 'Prior canonical equality')
    require(all(d['current_goal_priority'] == 'bluetooth_music' and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in (state, task, public, web)), 'Music priority active')
    require(state['navigation_repair']['status'] == 'stopped_by_user' and task['user_away']
            and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'], 'No device test requested')
    old_native, old_audio, old_nav = [copy.deepcopy(state[k]) for k in ('native_app_music', 'audio', 'navigation_repair')]
    progress = public['research_progress']
    estimates = [progress['estimate_percent'], [p['estimate_percent'] for p in progress['phases']]]
    before_service = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Prior exact HTTP')
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp = local.isoformat(timespec='seconds')
    checkpoint = {
        'updated_utc': now.isoformat(), 'scope': 'finite FILE-only contracts and official public Android API review',
        'proof_pins': PINS, 'declared_controller_symbols': {
            'requested_unique': 12, 'present_per_saved_build': 8,
            'absent': copy.deepcopy(symbols['absent_from_both_declared_symbol_maps']),
            'public_table_getter_absent': 'ui_music_control_api', 'addresses_shift_between_v2_v3_bytes': 1500,
            'producer_name_whitelist': False, 'fresh_ELF_retention_callability_or_mode_verified': False,
            'missing_symbol_map_entry_proves_missing_C_implementation': False, 'linker_cause_known': False},
        'source_identity': {
            'registration_ticket_stable_within_guard_and_slot_recycling': True,
            'registration_ticket_is_native_allocation_generation_or_owner_authority': False,
            'native_anchor_and_pool_address_alone_prevent_ABA': False,
            'persistent_provider_ready': False, 'published_before_selected_state_possible': True,
            'published_unselected_retirement_bound': False, 'rearm_after_release_proven': False},
        'endpoint_activation': {
            'bootstrap_success_proves_music_activation': False,
            'older_start_preserves_result_but_entry_returns_original_voice_status': True,
            'partial_failure_transactional_rollback_proven': False,
            'old_native_music_callback_matches_new_nsg_native_callback': False,
            'combined_modern_activation_provider_bound': False,
            'current_specific_configuration_caller_guards_pointer_length_and_wrap': True,
            'guarded_C_caller_is_live_callsite_or_mapped_buffer_proof': False,
            'accepted_reply_requires_send_result_zero_and_two_bytes_written': True},
        'parallel_Android_direct_HFP': {'status': 'public_API_path_documented_runtime_unverified',
            'native_A2DP_or_menu_goal_replacement': False, 'phone_version_known': False,
            'call_or_audio_route_or_selected_music_playback_tested': False,
            'supported_public_layers': copy.deepcopy(android['layers']),
            'no_microphone_permission_guarantee': False,
            'minimum_future_test': copy.deepcopy(android['minimum_future_test']),
            'official_guide': 'https://developer.android.com/develop/connectivity/telecom/voip-app/telecom'},
        'FILE_accounting': {'root_fresh_metadata_bytes': 192915, 'root_fresh_inert_host_builder_bytes': 20192,
            'identity_fresh_C_bytes': 14133, 'activation_fresh_C_H_bytes': 15540,
            'activation_FILE_checks': 36, 'native_binary_or_object_fresh_reads': 0},
        'native_compile_execution_guest_original_ASM_MAIN_binary_RAM_source_changes': False,
        'device_BT_DBUS_audio_or_interrupted_guest_retry': False,
        'native_ownership_STOP_DONE_App_direct_phone_speaker_or_install_verified': False,
        'native_install_ready': False, 'full_goal_complete': False,
    }
    next_actions = [
        '原生整合先補足同一映像的狀態／開始／清理回報函式與public getter保留證據，再按型別接線；目前建置宣告缺四個函式，不能直接cast表或挪用另一版位址。',
        '端點啟用需使用新版callback，分開保留載入與啟用結果；補齊發布但未選取的停止、永久來源身分及重新啟動生命週期。原機直接A2DP、喇叭與菜單仍未驗證。',
        'Android公開自管通話與藍牙端點API已查明；下一個最小原型依序驗證Garmin接聽／掛斷回呼、實際切到Garmin端點、最後10秒本機音檔通話聲道播放。尚未證明免Pi或免RECORD_AUDIO；通話音質限制仍在。',
        '音樂為第一優先；導航／麥克風停止，Android Auto／Google Maps延後。不要求使用者接線或配對，不自動來電或播放，等使用者通知可實測時間。',
    ]
    state.update(updated_utc=now.isoformat(), next_actions=copy.deepcopy(next_actions))
    state[FIELD] = copy.deepcopy(checkpoint)
    native = state['native_app_music']
    native[FIELD] = copy.deepcopy(checkpoint)
    native['remaining_work'] = copy.deepcopy(next_actions[:3])
    work = state['offline_24h_work_order']
    work[FIELD] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['native_music'] = 'Missing declared status/start/cleanup/kick/getter; identity and activation provider gaps located; no native install candidate'
    turn = {'classification': 'native_music_symbol_identity_activation_FILE_progress', 'validated_utc': now.isoformat(),
        'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True, 'device_files_written': False,
        'reason': 'Named declaration gaps and activation identity/status gaps narrow native work; public Android call and endpoint APIs support a separate prototype, actual music remains unverified.'}
    state['last_goal_turn'] = copy.deepcopy(turn)
    for key in ('updated_utc', 'next_actions', 'offline_24h_work_order', FIELD, 'last_goal_turn'):
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    public[FIELD] = copy.deepcopy(checkpoint)
    progress.update(research_updated_utc=now.isoformat(), next=next_actions[0])
    for phase in progress['phases']:
        if phase['name'] in ('原生音訊與元件原型', '原生 App 入口與功能整合'):
            phase['next'] = next_actions[0] if 'App' in phase['name'] else next_actions[1]

    report = before[FILES[3]].decode()
    card = ('<section class="card" id="bluetooth-music-current-checkpoint-v1"><h2>藍牙音樂：找到控制器與端點啟用缺口</h2>'
        f'<p>更新：<time datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
        '<p>原機直接接手機的A2DP音樂與菜單App仍未完成，也沒有可安裝整合包。已證實能出聲的是先前Pixel→Pi→Garmin的60秒通話音訊中繼。</p><ul>'
        '<li><strong>控制器缺口：</strong>新舊兩組介面合計12個不同函式，兩版保存的建置宣告各列出其中8個；狀態查詢、開始／清理回報與kick四個未列出，public表getter也未列出。'
        '它們在先前保存的C來源有定義，因此不能說缺少實作；目前須確認映像保留與型別接線。現有8個位址在新版均偏移1500B，不能挪用舊位址。這輪未讀或執行ELF。</li>'
        '<li><strong>來源生命週期：</strong>registration_ticket在同一次guard生命期內固定，槽位回收不改它，可作軟體關聯值，但不代表原生配置世代或所有權。'
        '來源可先發布、後選取；未選取時的停止與停止後重新啟動仍缺完整接線。</li>'
        '<li><strong>端點啟用：</strong>較舊entry保存音樂啟動結果，卻回傳原廠語音初始化狀態；載入成功不能證明音樂端點成功。'
        '舊啟用callback與新載入路徑要求的callback不同，不能直接混接。部分失敗狀態的回復仍未證明。</li>'
        '<li><strong>縮小一項疑點：</strong>目前設定請求的特定C入口已檢查資料指標、長度與溢位，才呼叫helper。'
        '因此先前列出的helper前置條件在這個入口具備；仍未證明實機入口與緩衝區。接受回覆須同時送出成功並寫入2B。</li>'
        '<li><strong>平行方案：</strong>Android公開自管通話支援藍牙接聽／掛斷回呼，也可請求藍牙端點；'
        '<a href="https://developer.android.com/develop/connectivity/telecom/voip-app/telecom">官方Core-Telecom文件</a>要求通話音訊聲道並由Telecom管理路由。'
        '接下來的最小原型應先驗證Garmin回呼、再確認實際端點、最後短播10秒本機音檔。尚未建立通話或播放，因此不能說手機已可直接播音樂或省去Pi。'
        '不錄麥克風也不能直接推定免RECORD_AUDIO；Pixel版本未知。這條仍受通話音質限制，原生A2DP研究繼續。</li></ul>'
        '<p>本輪為有限檔案核對，沒有native編譯／執行、修改候選或操作裝置；原生App工程估計維持40%。'
        '導航／麥克風已停止，Android Auto／Google Maps延後。語音2.10恢復已確認，目前不需接線或配對。</p></section>')
    report, count = re.subn(r'<section class="card" id="bluetooth-music-current-checkpoint-v1">.*?</section>', lambda _: card, report, count=1, flags=re.S)
    require(count == 1, 'Current card')
    frontier = '<p id="offline-frontier-latest-v1">最新：控制器建置宣告缺四個函式與getter，端點entry成功不等於啟用成功；來源發布／停止與新版callback仍待接線。Android公開通話／藍牙端點API可做最小原型，音檔實際出聲未驗；原機A2DP／App未完成。</p>'
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: frontier, report, count=1, flags=re.S)
    require(count == 1, 'Current frontier')
    report, count = re.subn(r'<p><strong>下一步：</strong>下一段先對照同一映像的named controller symbols.*?</p>',
        lambda _: '<p><strong>下一步：</strong>' + html.escape(next_actions[0]) + '</p>', report, count=1, flags=re.S)
    require(count == 1, 'Current next action')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{name}" datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        require(count == 1, 'Current timestamp: ' + name)
    expected = copy.deepcopy(old_native)
    expected[FIELD] = copy.deepcopy(checkpoint)
    expected['remaining_work'] = copy.deepcopy(native['remaining_work'])
    require(native == expected and state['audio'] == old_audio and state['navigation_repair'] == old_nav, 'History retained')
    require(estimates == [progress['estimate_percent'], [p['estimate_percent'] for p in progress['phases']]], 'Estimates retained')
    out = ROOT / 'staging' / ('native-music-provider-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, raw in before.items():
        with (out / (path.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for path, value in zip(FILES[:4], (state, task, public, report)):
        replace(path, value)
    served, response = http(web['url'])
    require(served == report.encode() and service() == before_service, 'Fresh HTTP exact; same report service')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
        served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
        offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web[FIELD] = copy.deepcopy(checkpoint)
    web['progress_display_verified'].update(report_updated_time=stamp, research_updated_time=stamp,
        symbol_retention_gap_visible=True, endpoint_status_not_voice_bootstrap_visible=True,
        stable_software_label_not_native_generation_visible=True)
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / path).read_bytes()) for path in (FILES[0], FILES[1], FILES[2], FILES[4])]
    require(fresh[0] == fresh[2]['deep_research'] and fresh[0]['navigation_repair'] == fresh[1]['navigation_repair']
            == fresh[2]['navigation_repair'], 'Fresh canonical equality')
    require(all(d[FIELD] == checkpoint and d['goal_status'] == 'active' and not d['goal_complete'] for d in fresh), 'Music active incomplete')
    create(out / 'fresh-readback.json', {'all_passed': True, 'updated_at_Taiwan': stamp, 'checkpoint': checkpoint,
        'report_url': web['url'], 'report_sha256': sha(served), 'service': before_service, 'device_IO': False, 'goal_complete': False})
    print(json.dumps({'all_passed': True, 'snapshot': str(out.relative_to(ROOT)), 'updated_at_Taiwan': stamp,
        'report_url': web['url'], 'service': before_service, 'device_IO': False}))


if __name__ == '__main__':
    main()
