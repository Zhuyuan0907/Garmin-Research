#!/usr/bin/env python3
"""Publish finite FILE reviews; do not import or execute native targets."""
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
UI = 'staging/native-music-app-integration-readonly-20261007-v1/'
BT = 'staging/native-music-bluetooth-binding-readonly-20261007-v1/'
PHYSICAL = 'staging/native-music-physical-ingress-readonly-20261007-v1/'
PINS = {
    UI + 'integration-matrix.json': '1d50527ca431d3995cf671a1320dc224ad32d4d2970f368e9c2e3bd2cf49117e',
    UI + 'proof.json': '6eb3724e78b0739d7e5eb3f0b075340d6ef5d094fa91b0e7253852170fee8384',
    UI + 'sealed-files.json': 'b6860efdfd82412b5b70a0a688b9a2d99f0a4cbc64b7cab2753cd5af388ff60b',
    UI + 'actual-terminal-closure.json': 'd499a4ba6dff7c72701b7ef0b2755f9a0484a1b1ebbb2956e36c51417af36e34',
    BT + 'binding-matrix.json': 'bdd5f0fb13096680bab4a7712f4fa22f2bcdc29564d5afdec5184cb49365c7a1',
    BT + 'proof.json': '1df31df2838ebcb6f684aaad847e70abaceac2c726c445c52fc043ddacc0add6',
    BT + 'sealed-files.json': '9f6038d38ef45a8d41d7d679031185279a32d9e17f194bf377fa76e8961da03c',
    PHYSICAL + 'proof.json': 'b38f60f78202ae687febe5dcb5f6c77b98dff4bfdb56b999f706dc3f407e155b',
    PHYSICAL + 'source-pin.json': '66eb3a897c0007c284732912ce489122cb0ba0adf6a43c193bc049fae5bb0d8d',
    PHYSICAL + 'actual-tool-receipt.json': '7dcf3b17e194a7a4baf61ebdd66645aeeed789fdfb6b07e826939173828ed20f',
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def pinned_json(path, pin):
    raw = (ROOT / path).read_bytes()
    require(len(raw) <= 65536 and sha(raw) == pin, 'Exact bounded metadata ' + path)
    return json.loads(raw)


def main():
    proofs = {path: pinned_json(path, pin) for path, pin in PINS.items()}
    ui, bt, physical = [proofs[root + 'proof.json'] for root in (UI, BT, PHYSICAL)]
    require(all(p['all_assigned_checks_passed'] and p['STOP'] for p in (ui, bt, physical)),
            'Three closed finite review scopes')
    require(ui['review_only'] and ui['no_execution'] and ui['matrix_rows'] == 13
            and ui['source_body_bytes'] == 105929, 'UI FILE scope and disclosed bytes')
    require(bt['checks'] == {'passed': 27, 'failed': 0, 'runtime_cases': 0}
            and bt['matrix_rows'] == 13 and not bt['guardrails']['interrupted_guest_retry'],
            'BT review does not execute a guest')
    rows = {r['id']: r for r in proofs[UI + 'integration-matrix.json']['rows']}
    resource = next(s for s in rows['current_play_button_route']['sources']
                    if s['path'] == 'native/player-resources/player_menu.c')
    # This hash is explicitly only the reviewed prefix, not the entire variant.
    with (ROOT / resource['path']).open('rb') as stream:
        resource_prefix = stream.read(4352)
    require(sha(resource_prefix) == resource['sha256'], 'Current reviewed resource prefix')
    physical_source = proofs[PHYSICAL + 'source-pin.json']
    require(sha((ROOT / physical_source['path']).read_bytes()) == physical_source['sha256'],
            'Inert metadata reconciliation source pin')
    require(proofs[PHYSICAL + 'actual-tool-receipt.json']['exit_code'] == 0,
            'Actual metadata check completed')
    restored = physical['last_attended_original_voice_restoration']
    require(restored['sequence_complete'] and restored['cold_restart_Aud_Ver'] == '2.10'
            and not restored['duplicate_2_10_physical_question_needed'], 'Existing attended restoration')
    # Freshly validate the small historical metadata, without reopening any VPM/MAIN.
    for path, binding in physical['inputs'].items():
        raw = (ROOT / path).read_bytes()
        require(len(raw) == binding['bytes'] <= 16384 and sha(raw) == binding['sha256'],
                'Historical metadata pin ' + path)

    before = {path: (ROOT / path).read_bytes() for path in FILES}
    state, task, public = [json.loads(before[path]) for path in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'] and state['navigation_repair'] == task['navigation_repair']
            == public['navigation_repair'], 'Prior canonical equality')
    require(all(value['current_goal_priority'] == 'bluetooth_music' and value['goal_status'] == 'active'
                and not value['goal_complete'] for value in (state, task, public, web)), 'Latest user priority active')
    require(task['user_away'] and state['navigation_repair']['status'] == 'stopped_by_user'
            and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'],
            'No navigation resumption or unattended device work')
    old_navigation = copy.deepcopy(state['navigation_repair'])
    old_native = copy.deepcopy(state['native_app_music'])
    old_audio = copy.deepcopy(state['audio'])
    old_estimates = [public['research_progress']['estimate_percent'],
                     [phase['estimate_percent'] for phase in public['research_progress']['phases']]]
    prior_service = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Prior report exact HTTP')
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    timestamp = local.isoformat(timespec='seconds')
    checkpoint = {
        'updated_utc': now.isoformat(), 'proof_pins': PINS,
        'review_scopes': {'UI_rows': 13, 'BT_rows': 13, 'BT_FILE_checks': 27,
                         'physical_metadata_inputs': 8, 'physical_metadata_bytes_this_check': 22561},
        'UI_source_content_bytes': 105929,
        'BT_source_content_capture_bytes': 102389,
        'whole_turn_aggregate_read_bytes_or_one_pass_claimed': False,
        'BT_rg_index_IO_instrumented': False,
        'agent_UI_output_hash_scope': 'generated payload plus stat; root now freshly verifies pinned small output bytes',
        'reviewed_current_resource_prefix': {**resource, 'bytes': 4352},
        'current_menu_Play_source': 9, 'current_menu_Play_kind': 22,
        'current_menu_Play_is_diagnostic_WAV': True,
        'current_menu_Play_calls_channel8_umc_request_start': False,
        'controller_and_adapter_prototypes_exist': True,
        'actual_combined_GUI_core_Source_READY_service_binding_verified': False,
        'ownership_snapshot_provider_bound': False, 'AV_locked_prepare_session_provider_bound': False,
        'five_admission_and_post_register_publication_sites_integrated': False,
        'full_return_stop_cleanup_and_callback_quiescence_verified': False,
        'PSM25_profile_callback_is_application_SEP_callback': False,
        'compiled_custom_SEP_provider_and_later_F1_Source_decoder_pipeline_exist_offline': True,
        'later_remote_v1_PCM_evidence_scope': '744 music PCM bytes and 7168 original output bytes; not real phone or speaker',
        'offline_Source_API_import_addresses_are_live_bindings': False,
        'warm_WFFF_is_cached_module_initialization_snapshot': True,
        'warm_WFFF_proves_durable_ownership_or_current_READY': False,
        'historical_original_voice_final_control': copy.deepcopy(restored),
        'stale_current_marker_rollback_pending_corrected': True,
        'historical_marker_or_warm_preparation_records_rewritten': False,
        'larger_combined_music_VPM_accepted_on_device': False,
        'current_device_connected_or_audio_service_queried': False,
        'native_compile_or_guest_or_producer_imports': False,
        'interrupted_native_guest_retried': False,
        'native_call_site_or_shared_source_changes': False,
        'device_IO': False, 'audible_playback': False,
        'native_menu_visible_on_device': False, 'direct_phone_native_music_verified': False,
        'native_exclusive_ownership_verified': False, 'native_STOP_DONE': False,
        'native_install_ready': False, 'music_quality_improved': False,
        'long_duration_device_music_verified': False, 'full_goal_complete': False,
        'next_review_order': [
            'One resident image manifest binding legal GUI requests to controller, matching core/state map and actual Source READY/event service.',
            'Coherent session plus all-writer native ownership, actual endpoint publication and lifecycle observations.',
            'Original registration/publication/full-return cleanup and future-callback barrier before considering an integrated test image.',
        ],
    }
    next_actions = [
        '先核對原生選單、控制器與音訊工作是否屬於同一載入映像；目前播放按鈕仍是診斷WAV，尚未接到手機音樂啟動／停止與狀態回報。',
        '續做有限檔案核對，釐清真實藍牙工作階段、音訊通道所有權與停止收尾；不重跑中斷的native guest，不把離線位址当實機介面。',
        'Pi轉送的音量時間線工具已完成離線檢查；日後手動測試再查實機音量波動。目前不要求接車機、不自動來電或播放。',
    ]
    state.update(updated_utc=now.isoformat(), next_actions=copy.deepcopy(next_actions),
                 latest_native_music_binding_checkpoint=copy.deepcopy(checkpoint))
    native = state['native_app_music']
    marker = native['local_reversible_marker_voice_bundle']
    marker.update(rollback_Aud_Ver_2_10_pending=False, rollback_Aud_Ver_2_10_user_confirmed=True,
                  rollback_control_evidence='evidence/native-marker-physical-original-control-20261005T044607Z.json',
                  subsequent_final_control_evidence='evidence/native-warm-probe-physical-final-control-20261005T045419Z.json')
    native['latest_native_music_binding_checkpoint'] = copy.deepcopy(checkpoint)
    native['remaining_work'] = copy.deepcopy(next_actions[:2]) + [
        '手機直接配對、真正菜單顯示、導航語音共存、喇叭與長時間播放仍未驗證；原生安裝候選尚未完成。',
        'Android Auto／Google Maps延後；麥克風及導航修復已取消。',
    ]
    work = state['offline_24h_work_order']
    work['latest_native_music_binding_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status'].update(
        native_music='closed finite FILE UI/BT binding matrices; source9 WAV vs channel8 phone-start gap identified',
        pi_music='opt-in host volume/timeline tools retained; no live test or quality conclusion')
    turn = {'classification': 'native_music_FILE_review_progress', 'validated_utc': now.isoformat(),
            'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
            'device_files_written': False,
            'reason': 'Exact resource callback gap, UI/BT binding obligations and completed attended voice restoration reconciled.'}
    state['last_goal_turn'] = copy.deepcopy(turn)
    for key in ('updated_utc', 'next_actions', 'offline_24h_work_order', 'latest_native_music_binding_checkpoint', 'last_goal_turn'):
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state),
                  offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn),
                  latest_native_music_binding_checkpoint=copy.deepcopy(checkpoint))
    progress = public['research_progress']
    progress.update(research_updated_utc=now.isoformat(), next=next_actions[0])
    for phase in progress['phases']:
        if phase['name'] in ('原生音訊與元件原型', '原生 App 入口與功能整合'):
            phase['next'] = next_actions[0] if 'App' in phase['name'] else next_actions[1]
    report = before[FILES[3]].decode()
    card = ('<section class="card" id="bluetooth-music-current-checkpoint-v1"><h2>藍牙音樂：原機播放器的整合缺口</h2>'
            f'<p>更新：<time datetime="{timestamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
            '<p>目前優先目標是手機直接配對Garmin，從原機菜單播放音樂。導航修復已停止，麥克風功能已取消；Android Auto及Google Maps延後。</p>'
            '<ol><li><strong>選單接線：</strong>實際資源版的「播放」回呼仍註冊診斷WAV，未呼叫手機音樂控制器。'
            '控制器與介面轉接原型已有，但同一載入映像的選單入口、啟動／停止、就緒事件及狀態顯示尚未接齊。</li>'
            '<li><strong>藍牙及音訊：</strong>已有自製端點provider和離線媒體接收→SBC解碼→原廠輸出路徑證據。'
            '原機的通訊profile回呼與App媒體端點回呼是不同介面；真正手機工作階段、持續音訊所有權、端點發布及停止收尾仍未綁定。</li>'
            '<li><strong>實機證據：</strong>先前M7Q9確認診斷程式執行；WFFF是初始化當下的十二項狀態快照。'
            '兩者都未測原生藍牙音樂。原始美玲語音已還原，使用者也已冷重開機確認2.10；已更正舊的待確認旗標。</li></ol>'
            '<p><strong>這輪驗證：</strong>完成兩份各13層的有限檔案核對，以及8份既有實機紀錄核對。'
            '沒有重新編譯或執行native guest，也沒有操作車機、藍牙服務、來電或播放。原生App工程估計仍為40%；紙上核對不提高完成率。</p>'
            '<p><strong>已實測的另一條路徑：</strong>Pixel → Pi → Garmin先前持續60秒有聲，仍是8kHz單聲道通話音訊。'
            'Pi轉送的可選音量紀錄、程序收尾及離線時間線分析已通過主機檢查；實機音質與長時間穩定度尚未改善驗證。</p>'
            '<p><strong>原生手機直連、實際App菜單與喇叭播放尚未完成。</strong>目前沒有可安裝的整合音樂包。'
            '下一步先核對同一常駐映像的選單／控制器／音訊工作與生命週期。現在不需操作車機。</p></section>')
    report, count = re.subn(r'<section class="card" id="bluetooth-music-current-checkpoint-v1">.*?</section>',
                           lambda _: card, report, count=1, flags=re.S)
    require(count == 1, 'One current music card')
    frontier = ('<p id="offline-frontier-latest-v1">最新：原生播放按鈕仍走診斷WAV，手機音樂的GUI啟動／停止尚未接線。'
                '已核對藍牙端點、媒體與音訊所有權的整合缺口；原機直連播放仍未完成。語音恢復2.10已確認，導航工作停止。</p>')
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: frontier, report, count=1, flags=re.S)
    require(count == 1, 'Current frontier')
    report, count = re.subn(r'<p><strong>下一步：</strong>以新時間線工具.*?</p>',
                           lambda _: '<p><strong>下一步：</strong>' + html.escape(next_actions[0]) + '</p>', report, count=1, flags=re.S)
    require(count == 1, 'Current next action')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
                               lambda _: f'<time id="{name}" datetime="{timestamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        require(count == 1, 'Timestamp ' + name)
    expected_native = copy.deepcopy(old_native)
    expected_native['local_reversible_marker_voice_bundle'] = copy.deepcopy(marker)
    expected_native['latest_native_music_binding_checkpoint'] = copy.deepcopy(checkpoint)
    expected_native['remaining_work'] = copy.deepcopy(native['remaining_work'])
    require(state['navigation_repair'] == old_navigation and state['audio'] == old_audio
            and native == expected_native, 'Only named native summary changes; device/navigation evidence retained')
    require(old_estimates == [progress['estimate_percent'], [p['estimate_percent'] for p in progress['phases']]],
            'No milestone estimate increase from review')
    out = ROOT / 'staging' / ('native-music-binding-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, raw in before.items():
        with (out / (path.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for path, value in zip(FILES[:4], (state, task, public, report)):
        replace(path, value)
    served, response = http(web['url'])
    require(served == report.encode() and service() == prior_service, 'Fresh exact HTTP; report service unchanged')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
               served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
               latest_native_music_binding_checkpoint=copy.deepcopy(checkpoint),
               offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web['progress_display_verified'].update(report_updated_time=timestamp, research_updated_time=timestamp)
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / path).read_bytes()) for path in (FILES[0], FILES[1], FILES[2], FILES[4])]
    require(fresh[0] == fresh[2]['deep_research'] and fresh[0]['navigation_repair'] == fresh[1]['navigation_repair']
            == fresh[2]['navigation_repair'], 'Fresh canonical equality')
    require(all(value['latest_native_music_binding_checkpoint'] == checkpoint and value['goal_status'] == 'active'
                and not value['goal_complete'] for value in fresh), 'Same checkpoint; native goal incomplete and active')
    create(out / 'fresh-readback.json', {'all_passed': True, 'updated_at_Taiwan': timestamp,
                                      'checkpoint': checkpoint, 'report_url': web['url'], 'report_sha256': sha(served),
                                      'service': prior_service, 'device_IO': False, 'goal_complete': False})
    print(json.dumps({'all_passed': True, 'snapshot': str(out.relative_to(ROOT)), 'updated_at_Taiwan': timestamp,
                      'report_url': web['url'], 'service': prior_service, 'device_IO': False}))


if __name__ == '__main__':
    main()
