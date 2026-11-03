"""Publish actual expanded4K full restore and closed recovery preparation."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json',
         'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
ACTUAL = 'staging/navigation-AP-coherent-expanded4K-actual-restore-v1/'
RECOVERY = 'staging/navigation-known-working-country-v2-recovery-preparation-v1/'
PINS = {
    ACTUAL + 'proof.json': '39b4c2566e7ec5b229683f462a459936cb9e18e147a4213ddd4a36d69009731d',
    ACTUAL + 'sealed-files.json': '20f56f987dcfdba41db4b8c953ebadda2372f1beac2b662c5e4e58bbfa58d2d7',
    RECOVERY + 'proof.json': '1562e2c8b0a58d5fc30eb3f0c2c361b8f1b683492596cd687c5bc3602c9111cf',
    RECOVERY + 'sealed-files.json': 'bde5e670a8346665ada6ab4299f36160e60060cfe3660c1dc9917275466494a0',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    docs = {}
    for path, pin in PINS.items():
        raw = (ROOT / path).read_bytes()
        require(len(raw) <= 32768 and sha(raw) == pin, 'Pinned small prerequisite ' + path)
        docs[path] = json.loads(raw)
    actual = docs[ACTUAL + 'proof.json']
    recovery = docs[RECOVERY + 'proof.json']
    require(actual['all_assigned_checks_passed'] and actual['all_handles_closed']
            and actual['candidate']['bytes'] == 153337856
            and actual['candidate']['sha256'] == '8749b2614f0ef4cfb3ac631dd316b35dd3551e3ab97d2ac058f13a89052f50f6'
            and actual['exact_stock_bytes'] == 96739328 and actual['exact_stock_blocks'] == 23618
            and actual['exact_stock_SHA256'] == '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2'
            and actual['actual_total_IMG_reads'] == 556108401
            and actual['actual_candidate_verify_restore_reads'] == 249432689, 'Actual full candidate and stock EOF evidence')
    require(recovery['all_assigned_checks_passed'] and recovery['pure_host_controls_passed'] == 15
            and recovery['public_execution_hard_refusal_verified']
            and not recovery['actual_orchestration_executed'] and not recovery['installable'], 'Recovery preparation scope')
    before = {p: (ROOT / p).read_bytes() for p in FILES}
    state, task, public = [json.loads(before[p]) for p in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'] and state['navigation_repair'] == task['navigation_repair']
            == public['navigation_repair'], 'Current canonical equality')
    require(all(x['goal_status'] == 'active' and not x['goal_complete'] for x in [state, task, public, web]),
            'Active incomplete goal')
    require(task['user_away'] and not state['attended_testing']['user_present']
            and state['attended_testing']['no_pending_question']
            and not state['audio']['audible_tests_allowed'] and not web['current_physical_test_requested'], 'Silent away scope')
    svc = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Current exact served report')
    old_audio = copy.deepcopy(state['audio'])
    old_app = copy.deepcopy(state['native_app_music'])
    nav = state['navigation_repair']
    old_device = copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    checkpoint = {
        'updated_utc': now.isoformat(), 'prerequisite_pins': PINS,
        'actual_run_initial': '9706e9 session65898', 'actual_run_terminal': '2b949f EXIT0',
        'actual_root_sealer': '7fc1d0 EXIT0',
        'actual_candidate_path': actual['candidate']['path'], 'actual_candidate_bytes': 153337856,
        'actual_candidate_sha256': actual['candidate']['sha256'], 'saved_full_readback_verified': True,
        'fresh_second_full_candidate_SHA_verified': True, 'final_separate_API_executed_unchanged': True,
        'complete_stock_reconstruction_bytes': 96739328, 'complete_stock_blocks': 23618,
        'complete_stock_sha256': actual['exact_stock_SHA256'],
        'actual_candidate_verify_and_stock_restore_read_bytes': 249432689,
        'actual_total_materialize_readback_verify_restore_IMG_read_bytes': 556108401,
        'total_IMG_read_cap': 600000000, 'current_process_peak_KiB': actual['current_memory']['VmHWM'],
        'existing_strict_helper_guards_unchanged': True,
        'known_working_v2_recovery_preparation': 'closed_15_host_spy_controls',
        'known_working_v2_actual_orchestration_executed': False,
        'new_actual_full_candidate_files_in_this_scope': 1,
        'actual_coherent8K_and_expanded4K_candidate_files_total': 2,
        'stock_image_saved': False, 'second_full_backup_created': False,
        'portable_test_packet_complete': False, 'new_reviewed_test_entrypoint_preparation': 'active',
        'device_IO': False, 'installed': False, 'installable': False,
        'hardware_admission_verified': False, 'checksum_policy_verified': False,
        'Garmin_UI_renderer_verified': False, 'road_loss_rootcause_proven': False,
        'full_Taiwan_update_complete': False, 'full_goal_complete': False,
    }
    nav['actual_coherent_expanded4K_restore_checkpoint_v1'] = copy.deepcopy(checkpoint)
    nav['known_working_v2_recovery_checkpoint_v1'] = {
        'updated_utc': now.isoformat(), 'proof': RECOVERY + 'proof.json', 'seal': RECOVERY + 'sealed-files.json',
        'preparation_closed': True, 'host_spy_controls': 15, 'actual_orchestration_executed': False,
        'order': ['coherent8K -> exact factory stock', 'unchanged original installer -> working country v2'],
        'zero_exit_waiting_for_USB_never_advances': True, 'actual_execute_currently_refused': True,
        'complete_packet_and_new_binding_pending': True, 'device_IO': False, 'installable': False,
    }
    nav['closed_restore_and_test_tools_checkpoint_v1']['expanded4K_restore_binding'] = 'actual_full_candidate_and_complete_stock_SHA_passed'
    nav['closed_restore_and_test_tools_checkpoint_v1']['known_working_v2_recovery'] = 'closed_two_step_preparation_15_host_spy_controls'
    nav['actual_coherent8K_restore_checkpoint_v1']['expanded4K_restore_binding'] = 'actual_full_candidate_and_complete_stock_SHA_passed'
    nav['next'] = ('組合保留新增門牌內容的受審實機測試包及目前正常v2的恢復流程；'
                   '新8K與4K兩個實際封裝的全檔讀回及完整原廠還原已通過，'
                   '道路顯示根因與全台地址更新仍未驗收。使用者返回會自行通知，目前不要求車機操作。')
    phases = nav['native_country_address_update_progress']['phases']
    phases.extend([
        '另一個4K幾何對照已真正產生153337856-byte完整檔，僅改五個標頭位元組，原完整門牌內容保持；存檔讀回與再次完整input SHA8749…50f6均通過。獨立final API未改，完整metadata/FAT/MDR/DIR綁定及23618個stock block的96739328-byte SHA864d…053c2通過；不是只做虛擬hash或小型fixture。',
        '上述4K產檔／读回／再驗證／還原的實際IMG總讀量556108401 bytes低於600M上限，其中驗證還原249432689 bytes；原指令與logical receipt兩個計數相符，current-mm峰32528KiB。原廠還原影像不另存，只有新增一個.disabled對照檔，未裝到Garmin，未知checksum、道路顯示及根因未證。',
        '恢復目前正常country v2的便攜雙步準備完成：先從新8K回精確stock，再由未修改原v2installer裝回925a版本；15項小型替身控制通過，未校驗／未安全卸載或僅waiting_for_USB不會推進第二步。新入口綁定及完整packet仍在準備，未執行裝置恢復。',
    ])
    nav['updated_utc'] = now.isoformat()
    nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    work = state['offline_24h_work_order']
    work['latest_actual_expanded4K_and_v2_recovery_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['navigation'] = nav['next']
    turn = {'classification': 'progress', 'validated_utc': now.isoformat(), 'goal_status': 'active',
            'full_goal_complete': False, 'required_work_remaining': True, 'device_files_written': False,
            'reason': 'Actual coherent expanded4K full saved readback and strict complete stock reconstruction passed; working-v2 recovery preparation closed.'}
    state.update(updated_utc=now.isoformat(), last_goal_turn=copy.deepcopy(turn))
    for key in ['updated_utc', 'navigation_repair', 'offline_24h_work_order', 'last_goal_turn']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav),
                  offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn),
                  native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    report = before[FILES[3]].decode()
    paragraph = ('<p id="offline-frontier-latest-v1">最新：保留全部新增門牌內容的8K與4K兩個封裝對照檔都已實際產生、'
                 '全檔讀回校驗完成，並能精確重建原廠Address Point。安裝工具通過9項小型控制；'
                 '恢復目前正常v2的雙步流程準備另通過15項控制。正在整理完整實機測試包及其入口綁定，尚未裝到車機。'
                 '上述資料驗證仍不證明道路消失已修復；目前車機維持已实測正常v2＋Search v2。'
                 '全台更新、原機App與手機直接藍牙音樂仍未完成。</p>')
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>', lambda _: paragraph, report, count=1, flags=re.S)
    require(count == 1, 'One latest frontier paragraph')
    report, count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>', lambda _: '<h3>已完成</h3><ul>'
                           + ''.join('<li>' + x + '</li>' for x in phases) + '</ul>', report, count=1, flags=re.S)
    require(count == 1, 'One navigation detail list')
    for ident in ['navigation-address-updated-time', 'report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + ident + r'" datetime="[^"]+">[^<]+</time>',
                               lambda _: f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        require(count == 1, 'One current timestamp ' + ident)
    require(state['audio'] == old_audio and state['native_app_music'] == old_app
            and nav['latest_country_v2_comparison_checkpoint'] == old_device, 'Audio, App, current device evidence retained')
    require(nav['native_country_address_update_progress']['estimate_percent'] == 75, 'Engineering estimate unchanged')
    out = ROOT / 'staging' / ('expanded4K-and-v2-recovery-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, data in before.items():
        with (out / (path.replace('/', '__') + '.gz')).open('xb') as f:
            f.write(gzip.compress(data, mtime=0)); f.flush(); os.fsync(f.fileno())
    for path, value in zip(FILES[:4], [state, task, public, report]):
        replace(path, value)
    served, response = http(web['url'])
    require(served == report.encode() and service() == svc, 'Exact fresh HTTP and original live service')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
               served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
               actual_coherent_expanded4K_restore_checkpoint_v1=copy.deepcopy(checkpoint),
               known_working_v2_recovery_checkpoint_v1=copy.deepcopy(nav['known_working_v2_recovery_checkpoint_v1']),
               closed_restore_and_test_tools_checkpoint_v1=copy.deepcopy(nav['closed_restore_and_test_tools_checkpoint_v1']),
               offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web['progress_display_verified'].update(report_updated_time=local.isoformat(timespec='seconds'),
                                          research_updated_time=local.isoformat(timespec='seconds'), navigation_repair_estimate_percent=75)
    replace(FILES[4], web)
    fresh = [json.loads((ROOT / p).read_bytes()) for p in [FILES[0], FILES[1], FILES[2], FILES[4]]]
    require(fresh[0] == fresh[2]['deep_research'] and fresh[0]['navigation_repair']
            == fresh[1]['navigation_repair'] == fresh[2]['navigation_repair'], 'Fresh canonical equality')
    require(all(x['goal_status'] == 'active' and not x['goal_complete'] for x in fresh)
            and fresh[1]['user_away'] and not fresh[3]['current_physical_test_requested'], 'Incomplete silent away goal')
    create(out / 'fresh-readback.json', {'all_passed': True, 'prerequisite_pins': PINS, 'service': svc,
                                       'report_sha256': sha(served), 'device_IO': False, 'goal_status': 'active',
                                       'navigation_estimate': 75, 'native_App_estimate': 40, 'overall_estimate': 37})
    print(json.dumps({'all_passed': True, 'checkpoint': str(out.relative_to(ROOT)), 'report_url': web['url'],
                      'updated_at_Taiwan': local.isoformat(timespec='seconds'), 'device_IO': False}))


if __name__ == '__main__':
    main()
