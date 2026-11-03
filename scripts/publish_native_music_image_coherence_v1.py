#!/usr/bin/env python3
"""Publish image/session FILE evidence without operating native targets."""
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
RESOURCE = 'staging/native-music-resource-membership-readonly-20261007-v1/'
LOADED = 'staging/native-music-loaded-membership-readonly-20261007-v1/'
PINS = {
    RESOURCE + 'proof.json': '4571f9e3ff7f054a86dcf5720e9e090e0dd4ba016253b85ce250caa353a9874f',
    RESOURCE + 'actual-tool-receipt.json': '9329807f38f50d353477c05f5854e85c49b53132536b2b692992aa03ca2ff867',
    LOADED + 'proof.json': '33f0bc159bbda1872c947ad2d9d9418616140044889d168fd1926c12c031a841',
    LOADED + 'actual-tool-receipt.json': '30ff5d659fc7b66faf697ad98049d7b889191baa4a33c88f875c6da636c52758',
    'staging/native-music-single-image-map-readonly-20261007-v1/compatibility-ledger.json':
        '03d214ce459ab8f67ef684d9817b431a92e54d1d7c5bd8c85dde3f8226960758',
    'staging/native-music-single-image-map-readonly-20261007-v1/actual-terminal-closure.json':
        'd589b4518d79ffc14bf28e1b8ad72dbe95bc7a163b168e4fb9759cb7ae45023e',
    'staging/native-music-session-provider-readonly-20261007-v1/session-provider-ledger.json':
        '7e3c154a61b5faa04190bd3c72e7b25c53fdbe0cf06153ee3de2489ef734df88',
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def small(path, pin):
    require(path.startswith('staging/') and '..' not in path.split('/'), 'Local FILE proof path')
    raw = (ROOT / path).read_bytes()
    require(len(raw) <= 65536 and sha(raw) == pin, 'Fresh exact metadata ' + path)
    return json.loads(raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--map-proof', required=True)
    parser.add_argument('--map-sha', required=True)
    parser.add_argument('--session-proof', required=True)
    parser.add_argument('--session-sha', required=True)
    parser.add_argument('--review-seals', required=True)
    args = parser.parse_args()
    seals = json.loads(args.review_seals)
    require(isinstance(seals, dict) and len(seals) == 2, 'Two closed reviewer seals')
    pins = {**PINS, args.map_proof: args.map_sha, args.session_proof: args.session_sha, **seals}
    proofs = {path: small(path, pin) for path, pin in pins.items()}
    resource, loaded = [proofs[p + 'proof.json'] for p in (RESOURCE, LOADED)]
    for parent, proof in ((RESOURCE, resource), (LOADED, loaded)):
        require(proof['FILE_review_completed'] and proof['STOP']
                and proof['all_assigned_metadata_checks_passed'] and proof['native_target_runs'] == 0,
                'Finite root metadata check')
        binding = proof['ledger']
        path = parent + binding['path']
        pins[path] = binding['sha256']
        proofs[path] = small(path, binding['sha256'])
        require(proofs[parent + 'actual-tool-receipt.json']['exit_code'] == 0, 'Actual root check EXIT0')
    for path in (args.map_proof, args.session_proof):
        proof = proofs[path]
        require(proof.get('STOP') and proof.get('all_assigned_checks_passed'), 'Closed agent FILE scope')
    map_proof, session_proof = proofs[args.map_proof], proofs[args.session_proof]
    require(map_proof['checks']['map_exact_address_matches'] == 11
            and map_proof['checks']['selected_registry_matches'] == 5
            and map_proof['no_target_execution'], 'Conditional old-map consistency')
    require(session_proof['file_only_checks_passed'] == 35
            and session_proof['target_execution_import_compile_test_guest'] == 0
            and session_proof['all_source_handles_closed'], 'Closed session FILE scope')
    require(resource['missing_UI_units'] == 3 and loaded['newer_controller_declared_linked']
            and not loaded['older_resources_GUI_and_adapter_declared_linked'], 'Variant-specific membership')
    before = {path: (ROOT / path).read_bytes() for path in FILES}
    state, task, public = [json.loads(before[path]) for path in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'] and state['navigation_repair'] == task['navigation_repair']
            == public['navigation_repair'], 'Prior canonical equality')
    require(all(d['current_goal_priority'] == 'bluetooth_music' and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in (state, task, public, web)), 'Latest human music objective active')
    require(task['user_away'] and state['navigation_repair']['status'] == 'stopped_by_user'
            and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'],
            'No physical request or sound')
    old_native = copy.deepcopy(state['native_app_music'])
    old_navigation = copy.deepcopy(state['navigation_repair'])
    old_audio = copy.deepcopy(state['audio'])
    old_estimates = [public['research_progress']['estimate_percent'],
                     [p['estimate_percent'] for p in public['research_progress']['phases']]]
    old_service = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Prior HTTP exact')
    now = datetime.now(timezone.utc); local = now.astimezone(ZoneInfo('Asia/Taipei'))
    stamp = local.isoformat(timespec='seconds')
    checkpoint = {
        'updated_utc': now.isoformat(), 'proof_pins': pins,
        'reviewer_source_content_scopes': {
            'old_map': {'files': 12, 'bytes': 139365, 'runtime_cases': 0},
            'session_provider': {'files': 12, 'bytes': 118232, 'FILE_checks': 35, 'runtime_cases': 0}},
        'root_resource_recipe_checks': {'inputs': 2, 'input_bytes_this_check': 49451,
                                        'compiler_units': 17, 'missing_UI_controller_adapter_units': 3},
        'root_loaded_metadata_checks': {'inputs': 3, 'input_bytes_this_check': 86250,
                                       'declared_Source_remote_controller_in_one_image': True,
                                       'declared_old_GUI_adapter_in_that_image': False},
        'old_exact_adapter_map': {'addresses_checked': 11, 'matches_intended_old_continuous_artifact': True,
                                 'old_map_is_wrong_proved': False, 'generic_across_relinks': False,
                                 'five_runtime_linker_import_source_hashes_match': True,
                                 'old_adapter_core_table_fixture_entries': 10,
                                 'old_adapter_real_core_provider_bound': False},
        'newer_loaded_comparison_manifest': 'staging/native-player-loaded-single-image/build-v2.json',
        'newer_loaded_comparison_manifest_sha256': 'ee7d464e806cfc2d2f506989ffc7b2d7b30c6ce5e2d5f068b95f303cc6b76f75',
        'loaded_symbol_membership_is_metadata_not_fresh_ELF_or_runtime_validation': True,
        'loaded_entry_is_passive': True, 'loaded_entry_activation_verified': False,
        'older_remote_v1_and_loaded_pause_v2_lifecycle_semantics_assumed_equal': False,
        'phone_session_epoch_and_Source_queue_generation_are_distinct': True,
        'epoch_contract_review_scope': 'Reviewed remote-v1 and Source-build-v3; later loaded pause implementation not assumed equivalent.',
        'typed_Source_API_carries_phone_epoch_argument': False,
        'actual_provider_session_to_Source_mapping_verified': False,
        'Source_command_zero_is_queued_request_not_Stop_completion': True,
        'whole_turn_aggregate_source_read_budget_claimed': False,
        'native_compile_import_producer_guest_or_call_site_changes': False,
        'interrupted_guest_retried': False, 'device_IO': False, 'audio_service_queried_or_restarted': False,
        'audible_playback': False, 'native_GUI_phone_transport_speaker_verified': False,
        'native_ownership_or_STOP_DONE_verified': False, 'native_install_ready': False,
        'full_goal_complete': False,
    }
    next_actions = [
        '以較新的單一映像作比較基礎，有限讀取它本身的控制器provider與生命週期源碼，查清GUI啟動／停止、Source就緒及狀態回報；不直接套用舊adapter固定表。',
        '核對藍牙session與Source工作世代的實際對應，以及停止完整返回與回呼收尾。命令已排隊或映像有符號均不代表手機直連有聲。',
        '保持Pi轉送及診斷工具，日後手動測音量與長時間播放；目前不要求接車機或配對，不自動來電／播音，不重試被中斷的native guest。',
    ]
    state.update(updated_utc=now.isoformat(), next_actions=copy.deepcopy(next_actions),
                 latest_native_music_image_coherence_checkpoint=copy.deepcopy(checkpoint))
    native = state['native_app_music']
    native['latest_native_music_image_coherence_checkpoint'] = copy.deepcopy(checkpoint)
    native['newer_coherent_backend_comparison_manifest'] = checkpoint['newer_loaded_comparison_manifest']
    native['remaining_work'] = copy.deepcopy(next_actions[:2]) + [
        '真正手機配對、菜單前景與觸控、導航音訊共存、喇叭及長時間穩定度仍未驗證；沒有可安裝的原生整合音樂包。',
        '導航修復、麥克風保持取消；Android Auto／Google Maps延後。',
    ]
    work = state['offline_24h_work_order']
    work['latest_native_music_image_coherence_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['native_music'] = (
        'closed image-specific FILE evidence: newer backend already declares Source/remote/controller together; GUI/provider lifecycle still unbound')
    turn = {'classification': 'native_music_image_coherence_FILE_progress', 'validated_utc': now.isoformat(),
            'goal_status': 'active', 'full_goal_complete': False, 'required_work_remaining': True,
            'device_files_written': False,
            'reason': 'Newer coherent backend membership located; old exact map verified conditionally and independent phone/Source epochs distinguished.'}
    state['last_goal_turn'] = copy.deepcopy(turn)
    for key in ('updated_utc', 'next_actions', 'offline_24h_work_order', 'latest_native_music_image_coherence_checkpoint', 'last_goal_turn'):
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), offline_24h_work_order=copy.deepcopy(work),
                  last_goal_turn=copy.deepcopy(turn), latest_native_music_image_coherence_checkpoint=copy.deepcopy(checkpoint))
    progress = public['research_progress']
    progress.update(research_updated_utc=now.isoformat(), next=next_actions[0])
    for phase in progress['phases']:
        if phase['name'] in ('原生音訊與元件原型', '原生 App 入口與功能整合'):
            phase['next'] = next_actions[0] if 'App' in phase['name'] else next_actions[1]
    report = before[FILES[3]].decode()
    card = ('<section class="card" id="bluetooth-music-current-checkpoint-v1"><h2>藍牙音樂：找到較新的整合映像</h2>'
            f'<p>更新：<time datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>（台灣時間）</p>'
            '<p>目標仍是手機直接配對Garmin，從原機菜單播放音樂。這輪只核對既有程式與封裝資料，沒有操作車機或播放。</p>'
            '<table><thead><tr><th>版本</th><th>已核對</th><th>仍缺</th></tr></thead><tbody>'
            '<tr><td>舊菜單資源版</td><td>17個編譯單元；播放仍走診斷WAV</td><td>未包含手機控制器及舊介面轉接程式</td></tr>'
            '<tr><td>舊獨立轉接原型</td><td>11個固定位址與指定舊映像吻合，沒有證據顯示表寫錯</td><td>核心表目前由主機fixture提供；不能直接套到新映像</td></tr>'
            '<tr><td>較新的單一映像</td><td>清單包含藍牙接收、音訊工作和音樂控制器；Source呼叫已改為同映像符號</td><td>沒有連接原機菜單；入口被動初始化，實際啟用與生命週期未驗證</td></tr>'
            '</tbody></table>'
            '<p><strong>重要缺口：</strong>已核的舊原型分別管理藍牙工作階段與音訊工作的世代，尚需真正provider對應。'
            '「停止」API只表示命令入佇列，不代表音訊、原廠清理與回呼全部返回。較新映像採不同暫停實作，不能直接沿用舊版停止結論。</p>'
            '<p><strong>下一段研究：</strong>核對新映像本身的控制器provider，確認原機GUI啟動／停止、就緒事件與狀態顯示如何接入。'
            '同映像符號是封裝證據，這輪沒有讀取ELF／韌體binary或執行native guest；不宣稱實機介面已驗證。</p>'
            '<p>原始美玲語音恢復2.10先前已確認。Pixel→Pi→Garmin持續60秒有聲仍是已實測的中繼方案，使用8kHz單聲道通話音訊；'
            '它不代表原生手機直連完成。</p><p><strong>原生App、直接藍牙音樂與喇叭播放仍未完成，沒有可安裝整合包。</strong>'
            'App工程估計保持40%，導航修復／麥克風保持取消，Android Auto／Google Maps延後。現在不需操作車機。</p></section>')
    report, count = re.subn(r'<section class="card" id="bluetooth-music-current-checkpoint-v1">.*?</section>',
                           lambda _: card, report, count=1, flags=re.S)
    require(count == 1, 'Single current card')
    frontier = ('<p id="offline-frontier-latest-v1">最新：較新的既有單一映像已包含音樂控制器及藍牙／Source後端，'
                '仍缺原機GUI與真實工作階段／停止收尾接線。舊固定表只對指定舊映像有效；原機直連與App未完成，導航研究停止。</p>')
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: frontier, report, count=1, flags=re.S)
    require(count == 1, 'Current frontier')
    report, count = re.subn(r'<p><strong>下一步：</strong>先核對原生選單.*?</p>',
                           lambda _: '<p><strong>下一步：</strong>' + html.escape(next_actions[0]) + '</p>', report, count=1, flags=re.S)
    require(count == 1, 'Current action')
    for name in ('report-updated-time', 'research-updated-time'):
        report, count = re.subn(r'<time id="' + name + r'" datetime="[^"]+">[^<]+</time>',
                               lambda _: f'<time id="{name}" datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        require(count == 1, 'Current time ' + name)
    expected = copy.deepcopy(old_native)
    for key in ('latest_native_music_image_coherence_checkpoint', 'newer_coherent_backend_comparison_manifest', 'remaining_work'):
        expected[key] = copy.deepcopy(native[key])
    require(native == expected and state['audio'] == old_audio and state['navigation_repair'] == old_navigation,
            'Only named native summary changes; physical/audio/navigation history retained')
    require(old_estimates == [progress['estimate_percent'], [p['estimate_percent'] for p in progress['phases']]], 'Estimates unchanged')
    out = ROOT / 'staging' / ('native-music-image-coherence-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, raw in before.items():
        with (out / (path.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for path, value in zip(FILES[:4], (state, task, public, report)):
        replace(path, value)
    served, response = http(web['url'])
    require(served == report.encode() and service() == old_service, 'Fresh exact HTTP and unchanged report service')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
               served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
               latest_native_music_image_coherence_checkpoint=copy.deepcopy(checkpoint),
               offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web['progress_display_verified'].update(report_updated_time=stamp, research_updated_time=stamp)
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / path).read_bytes()) for path in (FILES[0], FILES[1], FILES[2], FILES[4])]
    require(fresh[0] == fresh[2]['deep_research'] and fresh[0]['navigation_repair'] == fresh[1]['navigation_repair']
            == fresh[2]['navigation_repair'], 'Fresh canonical equality')
    require(all(d['latest_native_music_image_coherence_checkpoint'] == checkpoint and d['goal_status'] == 'active'
                and not d['goal_complete'] for d in fresh), 'Same checkpoint; full native goal active and incomplete')
    create(out / 'fresh-readback.json', {'all_passed': True, 'updated_at_Taiwan': stamp, 'checkpoint': checkpoint,
                                      'report_url': web['url'], 'report_sha256': sha(served), 'service': old_service,
                                      'device_IO': False, 'goal_complete': False})
    print(json.dumps({'all_passed': True, 'snapshot': str(out.relative_to(ROOT)), 'updated_at_Taiwan': stamp,
                      'report_url': web['url'], 'service': old_service, 'device_IO': False}))


if __name__ == '__main__':
    main()
