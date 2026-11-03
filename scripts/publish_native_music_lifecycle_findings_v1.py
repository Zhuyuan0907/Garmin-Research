#!/usr/bin/env python3
"""Publish scoped source findings; no firmware, native execution or device IO."""
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
CORE = 'staging/native-music-loaded-controller-lifecycle-readonly-20261007-v1/'
PAUSE = 'staging/native-music-loaded-pause-session-readonly-20261007-v1/'
ENTRY = 'staging/native-music-passive-lifetime-readonly-20261007-v1/'
PINSCOPE = 'staging/native-music-lifecycle-pin-comparison-readonly-20261007-v1/'
PINS = {
    CORE + 'proof.json': '451d9217e8d6faa832fb6cff574ba165db52e853f9297da3008c5d2a3cbc7271',
    CORE + 'provider-ledger.json': '545e37dd0bd1a0ff2ddd77179648dc175cd9a2983ac33727b81d7fca238cace5',
    CORE + 'sealed-files.json': 'a43d90d780373720d4dbe9eaceba3a5cc0186fe82ee953f5fb70700350969cd8',
    CORE + 'actual-terminal-closure.json': '148be067a7e57fdaa38695ba344d51a9c27f6de9e339935ae2f16d4501d78163',
    PAUSE + 'proof.json': 'c74b8fa111210b9dbc2a8be10fa218f5f35a55a1e87ddc36b3589edbe2c9b1e9',
    PAUSE + 'pause-session-ledger.json': 'bac20d48ba5b00281c274035f0888a47f8c2b417dda0451b40c919cd3480ee47',
    PAUSE + 'sealed-files.json': 'b250c22d0fb9c58937cfbd7708e37e0a2e417cb227638576a81f8574e44439fd',
    ENTRY + 'proof.json': '7e39a23ba20a55362e0d4678a5fa72b75e3b8fe8431e0b54b1cd1775c33fb9d9',
    ENTRY + 'actual-tool-receipt.json': '72a2ffb087583392e218f3962ee8860741dfb12369e8b24d6b1aaa08cc402f22',
    PINSCOPE + 'comparison.json': '404e412e47fee135e1eca131afbe97e60343d664203f29bbc2f355098ac6674b',
    PINSCOPE + 'actual-tool-receipt.json': '0574113e1aa57d0fae98fdeeca0532af47e8507e4478c4e9cd44afac74d0b732',
    PINSCOPE + 'ancillary-limit-observation.json': 'd90b479ef9389c6f16fc2f9f156f49dbf4514113fb7e4c907554656ccf53fde1',
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def small(path, pin):
    raw = (ROOT / path).read_bytes()
    require(len(raw) <= 65536 and sha(raw) == pin, 'Exact bounded proof ' + path)
    return json.loads(raw)


def main():
    proofs = {path: small(path, pin) for path, pin in PINS.items()}
    core, pause, entry = [proofs[root + 'proof.json'] for root in (CORE, PAUSE, ENTRY)]
    require(all(d['all_assigned_checks_passed'] and d['STOP'] for d in (core, pause, entry)), 'Closed source scopes')
    require(core['no_execution_of_reviewed_sources'] and core['checks']['cancel_is_minus200']
            and core['checks']['source_loop_no_service'] and core['source_content_bytes'] == 79152,
            'Real C provider findings and selected-set limits')
    require(pause['FILE_checks_passed'] == 33 and pause['original_to_generated_normalization_exact']
            and pause['runtime_targetimports_compile_tests_guest'] == 0, 'Pause-v2 source identity, no new runtime')
    require(entry['inputs'] == 6 and not entry['target_execution'], 'Passive lifetime scope')
    binding = entry['ledger']; path = ENTRY + binding['path']
    pins = {**PINS, path: binding['sha256']}; lifetime = small(path, binding['sha256'])
    require(not lifetime['entry_passive_ready_means_Source_or_player_READY'], 'Passive entry is not playback readiness')
    comparison = proofs[PINSCOPE + 'comparison.json']
    require(comparison['FILE_check_complete'] and comparison['STOP'] and comparison['metadata_bytes'] == 153635,
            'Two metadata comparisons, not target execution')
    require(all(sum(r['comparison'] == 'matched_declared_pin' for r in rows) == 14
                and sum(r['comparison'] == 'not_declared' for r in rows) == 2
                and not any(r['comparison'] == 'different_declared_pin' for r in rows)
                for rows in comparison['rows'].values()), 'Fourteen declared pins; two unpinned direct dependencies')
    before = {path: (ROOT / path).read_bytes() for path in FILES}
    state, task, public = [json.loads(before[path]) for path in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'] and state['navigation_repair'] == task['navigation_repair']
            == public['navigation_repair'], 'Prior canonical equality')
    require(all(d['current_goal_priority'] == 'bluetooth_music' and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in (state, task, public, web)), 'Music priority active')
    require(task['user_away'] and state['navigation_repair']['status'] == 'stopped_by_user'
            and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'],
            'No user or hardware test requested')
    old_native, old_audio, old_nav = [copy.deepcopy(state[k]) for k in ('native_app_music', 'audio', 'navigation_repair')]
    old_estimates = [public['research_progress']['estimate_percent'],
                     [p['estimate_percent'] for p in public['research_progress']['phases']]]
    before_service = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Prior HTTP exact')
    now = datetime.now(timezone.utc); local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp = local.isoformat(timespec='seconds')
    checkpoint = {
        'updated_utc': now.isoformat(), 'proof_pins': pins, 'baseline': 'loaded-v2 source',
        'real_direct_controller_ops_init_READY_start_first_service_C_exists': True,
        'same_loaded_baseline_core_is_only_host_fixture': False,
        'caller_resident_one_and_cookie_1352_are_physical_lifetime_proof': False,
        'cancel_provider_result': -200, 'observe_stop_provider_result': -200,
        'selected_Source_loop_has_later_umc_service_call': False,
        'selected_12_files_establish_source_started_cleanup_returned_callers': False,
        'whole_project_missing_callers_claimed': False,
        'native_full_return_leases_or_production_hooks_installed': False,
        'cancel_ready_caller_Source_cleanup_preconditions_enforced_by_body': False,
        'passive_TTS_entry_status_11_or_6_equals_music_READY': False,
        'BSS_reset_span_includes_Source_stack_PCM_queue': True,
        'voice_replacement_protection_in_entry_verified': False,
        'actual_voice_replacement_or_stack_overwrite_reproduced': False,
        'loaded_v2_generated_pause_C_matches_original_pause_body_except_include_paths': True,
        'same_configuration_suspend_resume_source_implementation_exists': True,
        'same_configuration_suspend_resume_runtime_scope': 'inherited six closed offline cases; no runtime rerun this turn',
        'event19_pause_command': 8, 'resume_after_acceptedStart_first_validF1_command': 9,
        'F2_retire_command': 5, 'accepted_command_means_Source_finished_processing': False,
        'busy_mailbox_rejects_without_coalescing': True,
        'phone_epoch_preserved_on_same_configuration_pause_resume': True,
        'reply_scope_Source_pause_epoch_are_separate': True,
        'live_reconnect_newconfiguration_phone_resume_verified': False,
        'v2_v3_declared_pin_comparison_each': {'matched': 14, 'different': 0, 'not_declared': 2},
        'not_declared_proves_not_compiled': False,
        'all_v2_v3_code_ABI_or_lifecycle_equivalence_claimed': False,
        'ancillary_wrapper_stat_cap': {'actual': '4de302 EXIT1', 'source_body_read': False,
                                      'scope_not_expanded': True, 'whole_turn_all_operations_passed': False},
        'FILE_scopes': {'core': {'files': 12, 'bytes': 79152},
                        'pause': {'files': 12, 'bytes': 104472, 'FILE_checks': 33},
                        'root_lifetime': {'inputs': 6, 'bytes_this_check': 90405},
                        'root_manifest_comparison': {'inputs': 2, 'bytes_this_check': 153635}},
        'native_compile_guest_producer_import_call_site_changes': False,
        'interrupted_guest_retried': False, 'device_IO': False, 'audio_service_query_restart_or_playback': False,
        'native_GUI_phone_speaker_ownership_STOP_DONE_verified': False,
        'native_install_ready': False, 'full_goal_complete': False,
    }
    next_actions = [
        '續做有限FILE核對：找出Source每次喚醒到控制器service的實際接線，及publication／cleanup完整返回到控制器token的橋；本輪只證選定12檔缺口，不外推全專案。',
        '核對真實cancel／observe_stop provider及語音重新載入時的元件保留方式；被動TTS初始化、resident宣告與本地租約不能當作播放器就緒／完整停止。',
        '保持導航與麥克風取消、Android Auto／Google Maps延後；現在不要求車機、不自動來電播放，不重試系統中斷的native guest。',
    ]
    state.update(updated_utc=now.isoformat(), next_actions=copy.deepcopy(next_actions),
                 latest_native_music_lifecycle_source_checkpoint=copy.deepcopy(checkpoint))
    native = state['native_app_music']
    native['latest_native_music_lifecycle_source_checkpoint'] = copy.deepcopy(checkpoint)
    native['remaining_work'] = copy.deepcopy(next_actions[:2]) + [
        '真正GUI菜單／觸控、手機端點、暖啟動所有權、導航音訊共存與喇叭長時間播放尚未確認；沒有可安裝原生整合包。']
    work = state['offline_24h_work_order']
    work['latest_native_music_lifecycle_source_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['native_music'] = (
        'real loaded controller providers found; later service/token returns and -200 cancel/stop are scoped gaps; pause-v2 reviewed')
    turn = {'classification': 'native_music_lifecycle_source_FILE_progress', 'validated_utc': now.isoformat(),
            'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True, 'device_files_written': False,
            'reason': 'Direct core provider code distinguished from fixtures; concrete wake/service/stop and passive residency gaps found; pause-v2 lifecycle source verified.'}
    state['last_goal_turn'] = copy.deepcopy(turn)
    for key in ('updated_utc', 'next_actions', 'offline_24h_work_order', 'latest_native_music_lifecycle_source_checkpoint', 'last_goal_turn'):
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), offline_24h_work_order=copy.deepcopy(work),
                  last_goal_turn=copy.deepcopy(turn), latest_native_music_lifecycle_source_checkpoint=copy.deepcopy(checkpoint))
    progress = public['research_progress']
    progress.update(research_updated_utc=now.isoformat(), next=next_actions[0])
    for phase in progress['phases']:
        if phase['name'] in ('原生音訊與元件原型', '原生 App 入口與功能整合'):
            phase['next'] = next_actions[0] if 'App' in phase['name'] else next_actions[1]
    report = before[FILES[3]].decode()
    card = ('<section class="card" id="bluetooth-music-current-checkpoint-v1"><h2>藍牙音樂：啟動／停止的具體接線缺口</h2>'
            f'<p>更新：<time datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
            '<p>新映像的Source程式確實有控制器初始化、就緒、開始播放與第一次service的C實作，並非只有測試替身。'
            '本輪讀原始檔核對，沒有重新編譯、執行native guest、連車機或播放。</p><ul>'
            '<li><strong>工作迴圈：</strong>選定12檔中的Source迴圈尚未持續呼叫控制器service，也未找到開始／清理完整返回通知的caller。'
            '這是指定來源範圍的缺口，尚未證明整個專案沒有其他接線。</li>'
            '<li><strong>停止：</strong>cancel及observe_stop provider目前回傳-200（未支援）；命令送入mailbox不代表Source處理或清理完成。'
            '局部回呼租約不能證明所有原廠回呼已退出，也不能宣告STOP_DONE或卸載。</li>'
            '<li><strong>載入與保留：</strong>resident_passive_ready只取原廠語音初始化回傳11／6。入口沒有啟動音樂；'
            '初始化清零範圍包含音訊工作堆疊、PCM與佇列。程式未建立跨語音重新載入的保留機制，未在實機重現覆寫。</li>'
            '<li><strong>暫停／恢復：</strong>已核較新pause-v2實作；同設定的Suspend／Resume有程式及既有離線案例。'
            'Suspend送8，接受Start後首個有效F1送9，Disconnect才retire並送5。真手機操作、重連及完整停止仍未驗證。</li></ul>'
            '<p><strong>來源核對：</strong>兩版封裝清單各14個宣告來源hash吻合，另2個未列直接pin；未列不代表未編入，也不證明所有版本或實機ABI相同。</p>'
            '<p><strong>下一段：</strong>追Source喚醒、控制器狀態及原廠publication／cleanup完整返回的橋，再核停止與元件保留。'
            '原機菜單、直接手機音樂、所有權與喇叭仍未完成，沒有可安裝整合包。App工程估計維持40%。</p>'
            '<p>Pixel→Pi→Garmin先前60秒有聲是8kHz單聲道中繼方案。原語音恢復2.10已確認。'
            '導航／麥克風保持取消，Android Auto／Google Maps延後；現在不需操作車機。</p></section>')
    report, count = re.subn(r'<section class="card" id="bluetooth-music-current-checkpoint-v1">.*?</section>',
                           lambda _: card, report, count=1, flags=re.S)
    require(count == 1, 'One current card')
    frontier = ('<p id="offline-frontier-latest-v1">最新：新映像確有控制器C實作，但後續喚醒service／完整返回接線尚未閉合，'
                'cancel／停止觀察仍未支援；pause-v2暫停恢復已有來源證據。載入成功不是播放器就緒，原機直連／App仍未完成。</p>')
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: frontier, report, count=1, flags=re.S)
    require(count == 1, 'Current frontier')
    report, count = re.subn(r'<p><strong>下一步：</strong>以較新的單一映像.*?</p>',
                           lambda _: '<p><strong>下一步：</strong>' + html.escape(next_actions[0]) + '</p>', report, count=1, flags=re.S)
    require(count == 1, 'Current next action')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
                               lambda _: f'<time id="{name}" datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        require(count == 1, 'Current time ' + name)
    expected = copy.deepcopy(old_native)
    for key in ('latest_native_music_lifecycle_source_checkpoint', 'remaining_work'):
        expected[key] = copy.deepcopy(native[key])
    require(native == expected and state['audio'] == old_audio and state['navigation_repair'] == old_nav, 'History retained')
    require(old_estimates == [progress['estimate_percent'], [p['estimate_percent'] for p in progress['phases']]], 'Estimates unchanged')
    out = ROOT / 'staging' / ('native-music-lifecycle-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, raw in before.items():
        with (out / (path.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for path, value in zip(FILES[:4], (state, task, public, report)):
        replace(path, value)
    served, response = http(web['url'])
    require(served == report.encode() and service() == before_service, 'Fresh exact HTTP; same report service')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
               served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
               latest_native_music_lifecycle_source_checkpoint=copy.deepcopy(checkpoint),
               offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web['progress_display_verified'].update(report_updated_time=stamp, research_updated_time=stamp)
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / path).read_bytes()) for path in (FILES[0], FILES[1], FILES[2], FILES[4])]
    require(fresh[0] == fresh[2]['deep_research'] and fresh[0]['navigation_repair'] == fresh[1]['navigation_repair']
            == fresh[2]['navigation_repair'], 'Fresh canonical equality')
    require(all(d['latest_native_music_lifecycle_source_checkpoint'] == checkpoint and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in fresh), 'Native goal active and incomplete')
    create(out / 'fresh-readback.json', {'all_passed': True, 'updated_at_Taiwan': stamp, 'checkpoint': checkpoint,
                                      'report_url': web['url'], 'report_sha256': sha(served), 'service': before_service,
                                      'device_IO': False, 'goal_complete': False})
    print(json.dumps({'all_passed': True, 'snapshot': str(out.relative_to(ROOT)), 'updated_at_Taiwan': stamp,
                      'report_url': web['url'], 'service': before_service, 'device_IO': False}))


if __name__ == '__main__':
    main()
