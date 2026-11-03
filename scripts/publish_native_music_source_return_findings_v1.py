#!/usr/bin/env python3
"""Publish finite C/contract reviews without loading or executing native code."""
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
WAKE = 'staging/native-music-source-wake-service-references-readonly-20261007-v1/'
CANCEL = 'staging/native-music-cancel-stop-provider-references-readonly-20261007-v1/'
CONTRACT = 'staging/native-music-cleanup-contract-scope-readonly-20261007-v1/'
FIELD = 'latest_native_music_source_return_checkpoint'
PINS = {
    WAKE + 'proof.json': '41096c3aa7c79db1e9a60de36030d1e6282b33ffe6feca82e6800ef4954ac34d',
    WAKE + 'call-reference-ledger.json': '25117cbeca084630a4fc0c782ebe12038baaf0b6c90b77cfc7392d366b472e59',
    WAKE + 'sealed-files.json': '098c23307efdd6ac96c4bfaa0e9378acfa37f616ea4dc1d99a7d1aafe19b9d9f',
    WAKE + 'actual-terminal-closure.json': 'fe49b35d5d9ae2ee48392a71e05b9f437c2159a003d21a9669f36adad8fc1fff',
    CANCEL + 'proof.json': 'ef1100c5b8b5935f943f6ae08cdfab58b1c5e31caa3a4057af88d17561e89117',
    CANCEL + 'provider-return-ledger.json': '01d887c3834ac065c96fd05b94acd12c6c362ceb92fdc28cbe638a0750c64305',
    CANCEL + 'sealed-files.json': 'b19be183bf98e1636e682469eb59a52970c71bfe28231f5774020588250f2c22',
    CONTRACT + 'proof.json': '1b698985f5644203d54e0b19cbeb529f937c2bab8f7ef624615e875abf588fb0',
    CONTRACT + 'contract-scope-ledger.json': '1b351680dd2dbeaca63e9786399a16442a32d30f1710fc383f5958c497a1627d',
    CONTRACT + 'actual-tool-receipt.json': 'a6a961b828b3d8c0c07e752d3e4c18984de6b95370664f2cb676bdc17f534a4a',
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def pinned_metadata(path, pin):
    p = ROOT / path
    require(p.stat().st_size <= 40000, 'Bounded metadata: ' + path)
    raw = p.read_bytes()
    require(sha(raw) == pin, 'Exact reviewed metadata: ' + path)
    return json.loads(raw)


def main():
    reviewed = {p: pinned_metadata(p, pin) for p, pin in PINS.items()}
    wake = reviewed[WAKE + 'proof.json']
    cancel = reviewed[CANCEL + 'proof.json']
    contract = reviewed[CONTRACT + 'proof.json']
    scope = reviewed[CONTRACT + 'contract-scope-ledger.json']
    require(wake['STOP'] and wake['all_assigned_checks_passed']
            and wake['fresh_sources'] == 4 and wake['fresh_source_bytes'] == 37685
            and wake['checks']['pre_sync_CONFIG_C_provider']
            and wake['checks']['post_sync_initializer_validation_C_provider']
            and wake['checks']['direct_fresh_target_controller_reference_count'] == 0,
            'Closed Source C review, bounded negative')
    require(cancel['STOP'] and cancel['all_assigned_checks_passed'] and cancel['checks_passed'] == 47
            and cancel['source_content']['fresh_files'] == 10 and cancel['source_content']['bytes'] == 105421,
            'Closed old cancel C review')
    records = {r['id']: r for r in reviewed[CANCEL + 'provider-return-ledger.json']['records']}
    require(records['request_chain']['implementation'] == 'direct C caller exists'
            and records['native_remove_release']['implementation'] == 'C full-call-return ordering exists'
            and records['exact_old_image_binding']['source_pin_match_count'] == 7,
            'Existing older implementation distinguished from newer provider')
    require(contract['STOP'] and contract['all_assigned_metadata_checks_passed']
            and contract['inputs'] == 3 and contract['bytes_this_check'] == 87862
            and scope['legacy_host_controls']['count'] == 12
            and not scope['legacy_host_controls']['rerun_this_turn']
            and not scope['native_cleanup_bridge_execution_or_installation_verified'],
            'Historical adapter controls are not native full-return proof')
    require(all(not v for v in wake['target_flags'].values())
            and not cancel['target_execution'] and not contract['native_executed'],
            'Native acceptance remains incomplete')

    before = {p: (ROOT / p).read_bytes() for p in FILES}
    state, task, public = [json.loads(before[p]) for p in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'] and state['navigation_repair'] == task['navigation_repair']
            == public['navigation_repair'], 'Prior canonical equality')
    require(all(d['current_goal_priority'] == 'bluetooth_music' and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in (state, task, public, web)), 'Music work active')
    require(task['user_away'] and state['navigation_repair']['status'] == 'stopped_by_user'
            and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'],
            'Navigation canceled; no physical request or playback')
    old_native, old_audio, old_nav = [copy.deepcopy(state[k]) for k in ('native_app_music', 'audio', 'navigation_repair')]
    progress = public['research_progress']
    old_estimates = [progress['estimate_percent'], [p['estimate_percent'] for p in progress['phases']]]
    before_service = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Prior exact HTTP report')

    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp = local.isoformat(timespec='seconds')
    checkpoint = {
        'updated_utc': now.isoformat(), 'proof_pins': PINS, 'review_scope': 'finite C/H/docs/JSON only',
        'Source_descriptor_entry_C_references_exist': True,
        'pre_sync_CONFIG_grant_and_after_original_initializer_validation_C_exist': True,
        'original_sync_completed_or_passive_initialized_equals_controller_READY': False,
        'initial_controller_init_READY_start_service_exists': 'inherited closed real-driver C review',
        'selected_Source_family_later_service_or_started_cleanup_token_callers_established': False,
        'entire_project_absence_claimed': False,
        'older_runtime_cancel_C_implementation_exists': True,
        'older_cancel_C_chain': ['stream AV unlock', 'runtime cancel', 'Source flag and POST',
                              'owner actor', 'native-idle observation', 'original remove return',
                              'release return', 'clear pending'],
        'older_request_return_zero_equals_stop_complete': False,
        'older_actor_guard_equals_durable_native_channel_ownership': False,
        'older_completion_C_receiver_exists': True,
        'older_manifest_names_completion_hook_symbols': True,
        'completion_ASM_body_or_installed_caller_reviewed': False,
        'older_exact_manifest_matches_captured_sources': 7,
        'older_cancel_state_ABI_matches_new_loaded_image_verified': False,
        'new_driver_cancel_and_observe_stop_minus200': 'inherited closed real-driver C review',
        'newer_cancel_observer_wired_from_older_runtime': False,
        'cleanup_contract_frame_bytes': 64,
        'cleanup_contract_scope': 'single source-record r0 ABI; preservation contract only',
        'legacy_adapter_controls': {'recorded_passed': 12, 'rerun_this_turn': False,
                                    'original_native_returns_or_hardware_proven': False},
        'required_full_return_witnesses': copy.deepcopy(scope['required_witnesses']),
        'production_Source_iteration_publication_cleanup_hooks_installed': False,
        'STOP_DONE_implies_safe_unload_or_no_future_callbacks': False,
        'native_ownership_STOP_DONE_App_direct_phone_speaker_verified': False,
        'FILE_scopes': {'wake': {'fresh_files': 4, 'fresh_source_bytes': 37685, 'prior_captures_reused': 5},
                        'old_cancel': {'fresh_files': 10, 'fresh_source_bytes': 105421, 'checks': 47},
                        'cleanup_contract': {'inputs': 3, 'bytes_this_check': 87862}},
        'activity': {'new_native_compile_execution_emulator': False, 'original_ASM_MAIN_RAM_read': False,
                     'native_source_or_call_site_changes': False, 'device_BT_DBUS_audio': False,
                     'interrupted_guest_retry': False},
        'native_install_ready': False, 'full_goal_complete': False,
    }
    next_actions = [
        '以保存的C介面與封裝清單核對新版控制器的generation／session epoch／source token，對照舊版取消與完整返回回報，列出可共用及必須重接的部分；不把舊版請求成功當成新版STOP_DONE。',
        '藍牙音樂後續仍需真實A2DP接收端點、音訊來源綁定與元件保留；先把原機直連必需條件與Pi通話中繼分開驗證，再研究菜單入口。',
        '導航與麥克風維持取消、Android Auto／Google Maps延後；使用者會通知可實測時間，現在不詢問是否在場、不要求USB或藍牙、不自動播放。',
    ]
    state.update(updated_utc=now.isoformat(), next_actions=copy.deepcopy(next_actions))
    state[FIELD] = copy.deepcopy(checkpoint)
    native = state['native_app_music']
    native[FIELD] = copy.deepcopy(checkpoint)
    native['remaining_work'] = copy.deepcopy(next_actions[:2]) + [
        '完整停止／所有權與原廠回呼退出、導航音訊共存、原機菜單及直接手機長時間播放尚未確認，沒有可安裝整合包。']
    work = state['offline_24h_work_order']
    work[FIELD] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['native_music'] = (
        'Concrete older cancel C chain found; Source synchronization flags are separate from UMC readiness; newer full-return/token integration remains open')
    turn = {'classification': 'native_music_Source_return_FILE_progress', 'validated_utc': now.isoformat(),
            'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
            'device_files_written': False,
            'reason': 'Source CONFIG/sync marker scope separated from controller readiness; actual old cancel actor chain and legacy full-return contract narrowed without target execution.'}
    state['last_goal_turn'] = copy.deepcopy(turn)
    for key in ('updated_utc', 'next_actions', 'offline_24h_work_order', FIELD, 'last_goal_turn'):
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), offline_24h_work_order=copy.deepcopy(work),
                  last_goal_turn=copy.deepcopy(turn))
    public[FIELD] = copy.deepcopy(checkpoint)
    progress.update(research_updated_utc=now.isoformat(), next=next_actions[0])
    for phase in progress['phases']:
        if phase['name'] in ('原生音訊與元件原型', '原生 App 入口與功能整合'):
            phase['next'] = next_actions[0] if 'App' in phase['name'] else next_actions[1]

    report = before[FILES[3]].decode()
    card = ('<section class="card" id="bluetooth-music-current-checkpoint-v1"><h2>藍牙音樂：找到舊版取消流程，核對新版接線</h2>'
            f'<p>更新：<time datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
            '<p>導航工作已停止，目前以藍牙音樂為優先。Pixel→Pi→Garmin曾實測持續播放60秒；'
            '這仍是8kHz單聲道通話中繼。原機直接接手機、原生音樂App及可安裝整合包尚未完成。</p><ul>'
            '<li><strong>這輪找到：</strong>舊版C程式有真正的取消請求與工作處理流程：解除藍牙鎖後提交請求，'
            '音訊工作等待閒置，再移除來源並釋放資料。它可作為參考，但不是新版控制器已完成停止的證明。</li>'
            '<li><strong>目前差異：</strong>新版cancel／observe_stop仍回傳未支援。舊版狀態、來源代號及回報介面不能直接套入；'
            '請求被接受也不代表原廠回呼已完整返回或元件可以卸載。</li>'
            '<li><strong>就緒標記：</strong>已確認原始初始化前的CONFIG授權與返回後的sync旗標C接線。'
            '這些只限制讀取時機，與音樂控制器READY、來源已開始、清理完成通知不同。'
            '選定來源家族仍未建立後續service與token通知；未宣稱整個專案沒有其他caller。</li>'
            '<li><strong>驗證範圍：</strong>兩條FILE研究線及清理介面核對已完成；舊adapter的12項通過紀錄屬既有測試，這輪沒有重跑。'
            '未編譯或執行原生候選、改裝置、連藍牙或播放，沒有新增實機成功結果。</li></ul>'
            '<p><strong>接下來：</strong>對照新版控制器與舊取消流程的狀態／返回介面，再追真正A2DP接收端點、音訊來源與元件保留。'
            '原機直接播放及菜單入口仍需要後續驗證；App工程估計維持40%，不把檔案核對計為實機完成。</p>'
            '<p>原語音恢復2.10已確認。麥克風取消，Android Auto／Google Maps延後；目前不需要操作車機，等使用者通知可實測時間。</p></section>')
    report, count = re.subn(r'<section class="card" id="bluetooth-music-current-checkpoint-v1">.*?</section>',
                           lambda _: card, report, count=1, flags=re.S)
    require(count == 1, 'One current card')
    frontier = ('<p id="offline-frontier-latest-v1">最新：已找到舊版實際取消C流程，並區分語音同步旗標與音樂就緒通知；'
                '新版取消／完整返回接線仍未完成。Pi中繼曾有聲，原機直接手機音樂與App仍未達成。</p>')
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: frontier, report, count=1, flags=re.S)
    require(count == 1, 'Current frontier')
    report, count = re.subn(r'<p><strong>下一步：</strong>續做有限FILE核對.*?</p>',
                           lambda _: '<p><strong>下一步：</strong>' + html.escape(next_actions[0]) + '</p>', report, count=1, flags=re.S)
    require(count == 1, 'Current next action')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
                               lambda _: f'<time id="{name}" datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',
                               report, count=1)
        require(count == 1, 'Current time: ' + name)
    expected = copy.deepcopy(old_native)
    expected[FIELD] = copy.deepcopy(checkpoint)
    expected['remaining_work'] = copy.deepcopy(native['remaining_work'])
    require(native == expected and state['audio'] == old_audio and state['navigation_repair'] == old_nav,
            'Preserve historical audio, native and navigation evidence')
    require(old_estimates == [progress['estimate_percent'], [p['estimate_percent'] for p in progress['phases']]],
            'No percentage inflation')

    out = ROOT / 'staging' / ('native-music-source-return-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, raw in before.items():
        with (out / (path.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0))
            stream.flush()
            os.fsync(stream.fileno())
    for path, value in zip(FILES[:4], (state, task, public, report)):
        replace(path, value)
    served, response = http(web['url'])
    require(served == report.encode() and service() == before_service, 'Fresh HTTP exact; same report service')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
               served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
               offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web[FIELD] = copy.deepcopy(checkpoint)
    web['progress_display_verified'].update(report_updated_time=stamp, research_updated_time=stamp,
                                           legacy_cancel_not_new_stop_visible=True,
                                           sync_flag_not_controller_READY_visible=True)
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / path).read_bytes()) for path in (FILES[0], FILES[1], FILES[2], FILES[4])]
    require(fresh[0] == fresh[2]['deep_research'] and fresh[0]['navigation_repair'] == fresh[1]['navigation_repair']
            == fresh[2]['navigation_repair'], 'Fresh canonical equality')
    require(all(d[FIELD] == checkpoint and d['goal_status'] == 'active' and not d['goal_complete'] for d in fresh),
            'Music goal active and incomplete')
    create(out / 'fresh-readback.json', {'all_passed': True, 'updated_at_Taiwan': stamp, 'checkpoint': checkpoint,
                                      'report_url': web['url'], 'report_sha256': sha(served), 'service': before_service,
                                      'device_IO': False, 'goal_complete': False})
    print(json.dumps({'all_passed': True, 'snapshot': str(out.relative_to(ROOT)), 'updated_at_Taiwan': stamp,
                      'report_url': web['url'], 'service': before_service, 'device_IO': False}))


if __name__ == '__main__':
    main()
