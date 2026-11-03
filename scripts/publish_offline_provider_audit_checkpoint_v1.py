"""Publish bounded map/provider evidence and the failed audio scope honestly."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json',
         'reports/findings.json', 'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
PINS = {
    'staging/navigation-native-jai-img-materializer-abi-v1/final-proof.json': 'f80447c966c5d29fdcafc348c03c35fe7ad1512f869af275fbeb1bd4414d748b',
    'staging/navigation-native-ap-mount-registry-binding-v1/proof.json': '27f103fee7eee27fbbc0853c3913d44f393f071c6ab6e3dd8319a619ac1638a2',
    'staging/navigation-native-ap-map-registry-consumer-v1/proof.json': '0ba208d032ac6e061c7cfa1fdbfe713cc7dd75f2708bbe0dce5497ad9ad6a0a7',
    'staging/native-os20-mixer-allocator-v1/contract-v1.json': 'a61010b436c91edfe66c3f7d682dbad61cbe5fae292e5278b79ccdaae5da9c9d',
    'staging/native-os20-mixer-admission-readonly-review-v1/review.json': '7a2713020014620cc1f0661d4401ff2b9d0cfe49666b719bba37423ae8b21506',
    'staging/navigation-Dunfu6-official-name-primary-source-v1/proof.json': 'd75272e96e06aa6ba490fb7f53dbd011a8a97cd35b179af59537ffac283dfef1',
}


def main():
    inputs = []
    for name, expected in PINS.items():
        raw = (ROOT / name).read_bytes()
        assert len(raw) < 150000 and sha(raw) == expected
        inputs.append(json.loads(raw))
    materializer, mount, registry, allocator, review, official = inputs
    assert materializer['all_assigned_checks_passed'] and materializer['actual_exit_code'] == 0
    assert not materializer['uninterrupted_provider_getter_UI_device_acceptance']
    assert mount['all_assigned_checks_passed'] and mount['actual_mount_cases'] == 3
    assert registry['assigned_bounded_checks_passed'] and registry['durable_original_guest_cases'] == 3
    assert not registry['renderer_or_device_success']
    assert allocator['original_initialized_heap_append_and_mixer_creation_passed']
    assert allocator['actual_guest_EXIT'] == 1 and not allocator['original_Source_factory_reader_pipeline_passed']
    assert review['review_completed'] and review['review_is_static_file_only']
    assert review['current_execution_evidence']['EXIT'] == 1
    assert not review['unexecuted_media_v2_build']['guest_executed']
    assert official['historical_official_literal_road_name_confirmed']
    assert not official['specific_house368_or_OSM_node_position_officially_verified']
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    assert state == public['deep_research']
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    assert state['goal_status'] == 'active' and not state['goal_complete']
    assert not state['attended_testing']['user_present'] and state['attended_testing']['no_pending_question']
    assert not state['audio']['audible_tests_allowed']
    svc = service()
    served, _ = http(web['url'])
    assert served == before[FILES[3]]
    nav = state['navigation_repair']
    current_v2 = copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
    progress_before = copy.deepcopy(public['research_progress']['phases'])
    checkpoint = dict(
        updated_utc=now.isoformat(), prerequisite_pins=PINS,
        original_query_result_materializer_returned=True,
        actual_new_IMG_MDR_chain=materializer['true_result_chain'],
        actual_new_IMG_CP950_street_house_labels_verified=True,
        actual_IMG_read_bytes=materializer['actual_IMG_bytes_read'],
        uninterrupted_provider_getter_UI_verified=False, original_SQLite_engine_verified=False,
        shared_filesystem_parser_three_actual_container_mounts=True,
        shared_parser_proof_is_physical_AP_mount=False,
        actual_map_registry_guards=registry['durable_original_guest_cases'],
        true_overlay_policy_or_board_driver_verified=False,
        v3_display_regression_rootcause_verified=False,
        historical_official_road_name='敦富六街', historical_official_road_name_observed=True,
        official_name_source=official['sources'][0]['url'],
        official_specific_house_or_exhaustive_alias_verified=False,
        original_vm_backing_append_and_real_mixer_creation_verified=True,
        original_Source_CONFIG_priority_race_observed=True,
        later_admission_guest_EXIT=1, later_admission_full_PCM_or_lease_verified=False,
        audio_new_execution_status='system_interrupted_then_static_file_review_only',
        audio_static_review_completed=True, audio_new_v2_guest_executed=False,
        device_IO=False, installable=False, current_device_v2_unchanged=True,
        full_Taiwan_update_complete=False, full_goal_complete=False)
    nav['offline_provider_audit_checkpoint_v1'] = copy.deepcopy(checkpoint)
    nav['next'] = ('保留已實測正常的v2；繼續新街道完整getter後處理、Map註冊／圖層顯示回歸及新街／之號資料更新。使用者回來會通知，現在不要求實機操作。')
    nav['remaining_next_actions'] = [nav['next'],
        '單街完整IMG、完整JAI及原查詢materializer已分段驗證；連續provider/getter/UI、別名與整批新街道尚未驗收。',
        '音樂新執行子工作被系統風險標記中斷，現先唯讀核對；失敗輪次與未執行build均不列為通過。']
    phases = nav['native_country_address_update_progress']['phases']
    phases.append('一條新街原查詢materializer已返回，結果鏈48312→74→8與實際新IMG一致，路名／門牌CP950分段讀取通過；完整getter／UI仍待閉合。')
    phases.append('三種實際圖資由全零volume入口走原共用檔案系統parser完成掛載；另三個Map registry guard案例完成，尚未證真AP開啟／繪圖或定位v3道路回歸根因。')
    nav['updated_utc'] = now.isoformat()
    nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    app = state['native_app_music']
    app['original_OS20_mixer_creation_and_CONFIG_countercase_offline'] = dict(
        contract=list(PINS)[3], proof_sha256=list(PINS.values())[3], actual_guest='10c9cc EXIT1',
        original_initialized_software_backing_append=True, real_original_Mixer_TCB_created=True,
        Source_priority=89, Mixer_priority=23, first_selector_before_CONFIG_grant=True,
        selector_and_Source_binding_reject=-201, full_original_Source_to_mixer_passed=False,
        physical_memory_availability='unknown', native_owner_certified=False,
        native_STOP_DONE=False, pinned_storage=True, installable=False)
    app['latest_mixer_admission_review'] = dict(
        review=list(PINS)[4], sha256=list(PINS.values())[4], review_is_static_only=True,
        actual_readonly_receipt='d35a70 EXIT0', actual_guest_terminal='9eb25d EXIT1',
        complete_PCM_and_held_lease_verification=False, completed_guest_FILE_proof_or_seal=False,
        v2_source_assertion_only_changed=True, v2_ELF_not_one_constant_changed=True,
        v2_guest_executed=False, original_frozen_inputs_hashes_match=True,
        new_decoder_or_full40_TTS_runtime_checks=False,
        system_risk_interruption='Sub-agent execution interrupted after a potential cybersecurity risk flag.',
        current_line='pure file review; no further guest or call-site edits in this scope',
        native_exclusive_witness=-200, native_STOP_DONE=False,
        native_App_phone_speaker_install_verified=False)
    app['remaining_work'][0] = ('原VM backing-page追加與Mixer真正建立已通過；Source89／Mixer23搶先執行造成CONFIG尚未授予而拒絕。後續admission輪仍EXIT1、沒有完整PCM／lease／FILE證據；系統中斷後只做檔案核對，不把未執行新版ELF當成功。')
    work = state['offline_24h_work_order']
    work['latest_completed_provider_audit_checkpoint'] = copy.deepcopy(checkpoint)
    work['latest_audio_partial_checkpoint'] = copy.deepcopy(app['original_OS20_mixer_creation_and_CONFIG_countercase_offline'])
    work['current_offline_line_status'] = dict(
        navigation='active original getter and registry research',
        native_audio='static review completed after system risk interruption; new guest not verified',
        user_presence_question_pending=False, device_audio_allowed=False)
    state['updated_utc'] = now.isoformat()
    for key in ['updated_utc', 'navigation_repair', 'native_app_music', 'offline_24h_work_order']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state),
        navigation_repair=copy.deepcopy(nav), offline_24h_work_order=copy.deepcopy(work),
        native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert nav['latest_country_v2_comparison_checkpoint'] == current_v2
    assert nav['native_country_address_update_progress']['estimate_percent'] == 75
    assert public['research_progress']['phases'] == progress_before
    report = before[FILES[3]].decode()
    paragraph = ('<div id="new-street-full-offline-result-v1"><h3>新增道路：查詢資料建立已通過，繼續完整getter</h3>'
        '<p>132 MB原4K圖資原型完整封裝、讀回與精確還原v2已通過。原查詢結果materializer已返回，新街道48312→北屯74→台中8與實際IMG一致，CP950路名「敦富六街」與368號分段解讀成功；完整provider/getter、搜尋畫面與原機接受仍待驗證。</p>'
        '<p>找到<a href="https://www.hbeitun.taichung.gov.tw/1584911/post">北屯戶政正式路名公告</a>，敦富六街命名於2016年5月25日生效；這份公告未驗證368號的位置或完整別名。</p>'
        '<p>道路消失：三種封裝的原共用檔案系統parser皆能建立volume，原Map registry的三項guard亦已執行；底層儲存仍使用明示fixture，尚未定位v3的原機顯示回歸。車機保留已實測正常的Address Point v2＋Search v2。</p>'
        '<p>音樂：模擬backing-page追加後，原Mixer工作程序真正建立；也觀察到Mixer先於Source取得CONFIG而拒絕的排程順序。後續輪次仍失敗，完整PCM與lease證據未完成，不能算音訊整合成功。</p>'
        '<p>音樂子代理的一輪執行被系統標記為潛在資安風險而中斷，已改做純檔案核對；未執行新版ELF未列為通過。原機App、手機直接藍牙與喇叭驗收仍未完成。</p></div>')
    report, count = re.subn(r'<div id="new-street-full-offline-result-v1">.*?</div>',
                           lambda _: paragraph, report, count=1, flags=re.S)
    assert count == 1
    report, count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>',
        lambda _: '<h3>已完成</h3><ul>' + ''.join('<li>' + item + '</li>' for item in phases) + '</ul>',
        report, count=1, flags=re.S)
    assert count == 1
    for ident in ['navigation-address-updated-time', 'report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + ident + r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',
            report, count=1)
        assert count == 1
    out = ROOT / 'staging' / ('offline-provider-audit-publication-' + now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir()
    for name, raw in before.items():
        with (out / (name.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0)); stream.flush(); os.fsync(stream.fileno())
    for name, value in zip(FILES[:4], [state, task, public, report]):
        replace(name, value)
    served, response = http(web['url'])
    assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'],
        local_report_sha256=sha(served), served_report_sha256=sha(served), report_bytes=len(served),
        service_not_restarted=True, offline_provider_audit_checkpoint_v1=checkpoint,
        offline_24h_work_order=copy.deepcopy(work))
    replace(FILES[4], web)
    assert read(FILES[0]) == read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    assert read(FILES[0])['native_app_music'] == read(FILES[1])['native_app_music']
    create(out / 'fresh-readback.json', dict(all_passed=True, prerequisite_pins=PINS,
        service=svc, report_sha256=sha(served), actual_goal_status='active',
        nav_estimate=75, overall_estimate=37, new_admission_guest_passed=False,
        current_device_v2_unchanged=True, device_IO=False, full_goal_complete=False))
    print(json.dumps(dict(all_passed=True, checkpoint=str(out.relative_to(ROOT)),
                          report_url=web['url'], device_IO=False)))


if __name__ == '__main__':
    main()
