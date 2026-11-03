"""Publish new bounded offline checks without expanding physical claims."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json',
         'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
PINS = {
    'staging/native-os20-worker-fifo-v1/contract-v1.json': 'a2136d697fd905972379591ca9e42bb5380257ffd4a6f65dc6accbbc4725b28b',
    'staging/native-os20-source-ready-v1/contract-v1.json': 'a72f58a9eb799d499c00b07cbd146760821f53a2f9448781a34c9254de76e6da',
    'staging/navigation-native-jai-full-db-adapter-prototype-v1/proof.json': '8ed50b2a5f156fa30514796179ac5944d8336b5bba699fcbb201c82871de4dc2',
    'staging/navigation-beitun-district-geometry-v1/proof.json': '7000011d0cc84272d0ceb4a23b23e8dc2097cf414b9b0b4fea7dd0bbd82cd4e1',
    'staging/navigation-native-ap-driver-binding-v1/proof.json': 'ccb208a3eaf3f32b57a23b0b8ee48dc9bd775160ab4c711d029d527bdea85477',
    'staging/navigation-native-new-street-v2-family-payload-v1/proof.json': 'daf069db189eb28408b24f326e1f0b2ef2b92157b4601231acbd9978930f0b82',
}


def main():
    bound = {}
    for name, expected in PINS.items():
        raw = (ROOT / name).read_bytes()
        assert len(raw) < 20000 and sha(raw) == expected
        bound[name] = json.loads(raw)
    fifo, ready, db, geo, driver, payload = bound.values()
    assert fifo['all_passed'] and ready['all_passed'] and not fifo['physical_install_candidate']
    assert not ready['physical_install_candidate'] and ready['actual_guest_terminal']['exit_code'] == 0
    assert ready['runtime_guest_executed_in_this_new_ready_scope']
    assert db['all_assigned_execution_and_preservation_checks_passed'] and db['all_database_handles_closed']
    assert not db['complete_geometry_gate_passed'] and geo['source_and_exact_quantized_point_inside_same_source_district']
    assert driver['all_assigned_finite_checks_passed'] and payload['all_assigned_checks_passed']
    assert payload['original_4K_declared_profile_capacity_fits'] and not payload['installable']
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    before = {n: (ROOT/n).read_bytes() for n in FILES}
    state, task, public = [json.loads(before[n]) for n in FILES[:3]]
    web = json.loads(before[FILES[4]])
    assert state == public['deep_research']
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    assert state['goal_status'] == 'active' and not state['attended_testing']['user_present']
    assert state['attended_testing']['no_pending_question'] and not state['audio']['audible_tests_allowed']
    svc = service()
    served, _ = http(web['url'])
    assert served == before[FILES[3]]
    nav = state['navigation_repair']
    current_v2 = copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
    previous_percent = public['research_progress']['overall_estimate_percent'] if 'overall_estimate_percent' in public['research_progress'] else None
    checks = dict(updated_utc=now.isoformat(), prerequisite_pins=PINS,
        full_JAI_original_rows_preserved=True, full_JAI_other_complete_tables_exact=90,
        original_1024_byte_DB_pages_preserved=True, source_and_quantized_point_in_complete_Beitun_geometry=True,
        district_geometry_is_new_separate_evidence_not_rewritten_old_DB_scope=True,
        current_v2_family_cloned_verbatim=441, proposed_v2_based_new_street_4K_IMG_bytes=payload['proposed_complete_4K_IMG_bytes'],
        new_street_full_IMG_created=False, native_frontend_query_verified=False,
        missing_Dun_prefix_not_proof_of_frontend_failure=True,
        true_original_filesystem_descriptor_chain_identified=True, real_AP_renderer_verified=False,
        original_OS20_resident_FIFO_guest_passed=True, original_OS20_warm_Source_ready_guest_passed=True,
        Source_initializer_complete_returns=6, Source_READY_POST_returns_distinguished_from_controller_wake=True,
        Source_to_original_mixer_media_integrated_in_this_checkpoint=False,
        native_owner_certified=False, native_STOP_DONE=False, native_App_menu_or_direct_phone_or_speaker_verified=False,
        device_IO=False, installable=False, current_device_candidate='physically_verified_country_v2_original4K',
        full_Taiwan_update_complete=False, full_goal_complete=False)
    nav['offline_integration_checkpoint_v1'] = copy.deepcopy(checks)
    phases = nav['native_country_address_update_progress']['phases']
    phases[:] = [x for x in phases if not x.startswith('新街道完整DB離線')]
    phases.append('新街道完整DB離線：原17,252筆FTS8保留並新增一街，441筆既有街道索引搬移；90個其他完整表與原1024-byte頁設定一致。完整北屯區來源點／量化點另案通過，原機前端尚未驗證。')
    phases.append('新街道v2前置：441個現行v2街道指標原樣複製；一街一門牌的完整4K封裝估132,173,824 bytes，仍在原容量宣告內。尚未產整張圖資或安裝包。')
    nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    nav['updated_utc'] = now.isoformat()
    app = state['native_app_music']
    app['original_OS20_copied_media_FIFO_offline'] = dict(contract=list(PINS)[0], proof_sha256=list(PINS.values())[0],
        actual_guest_terminal=fifo['actual_guest_terminal'], frames=4, streams=2, reference_PCM_bytes=1024,
        real_original_Source_or_mixer=False, physical_installed=False)
    app['original_OS20_warm_Source_READY_offline'] = dict(contract=list(PINS)[1], proof_sha256=list(PINS.values())[1],
        actual_guest_terminal=ready['actual_guest_terminal'], instructions=33288, CPU_stores=11440,
        full_initializer_returns=6, native_current_POST_WAIT=True, native_owner_certified=False,
        Source_media_original_mixer_verified=False, physical_installed=False)
    app['remaining_work'] = [
        'Original OS20 named creation, persistent copied-media FIFO and warm Source initialization now have separate actual guest evidence. Next connect the actual Source to factory/reader/mixer with media and native scheduler; never substitute a private test consumer for the mixer.',
        'Complete all-writer backend/source ownership, Stop acknowledgement/quiescence and preserving package lifetime. Resident stacks/modules remain pinned; exclusive certification and native STOP_DONE are false.',
        'Integrate original native menu/App and authorized Android direct A2DP, then test real phone transport, navigation coexistence and speaker when the user returns. No presence questions, USB requests or automatic sound while away.',
        'Android Auto follows native music/App; native offline Google Maps remains deferred. Microphone and rendering-speed trials remain cancelled.'
    ]
    work = state['offline_24h_work_order']
    work['latest_completed_integration_checkpoint'] = copy.deepcopy(checks)
    work['parallel_tasks'] = ['native_address_candidate_check', 'taiwan_address_ingestion_plan', 'continuous_music_binding']
    state['updated_utc'] = now.isoformat()
    for key in ['updated_utc', 'navigation_repair', 'native_app_music', 'offline_24h_work_order']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav),
        native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']),
        offline_24h_work_order=copy.deepcopy(work))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert nav['latest_country_v2_comparison_checkpoint'] == current_v2
    assert nav['native_country_address_update_progress']['estimate_percent'] == 75
    if previous_percent is not None:
        assert public['research_progress']['overall_estimate_percent'] == previous_percent
    paragraph = ('<div id="offline-integration-results-v1"><h3>最新本機驗證</h3><ul>'
        '<li>新街道完整地址資料庫原型：441條既有街道索引搬移、新增敦富六街；原17,252筆FTS8搜尋記錄、90個其他完整資料表與原頁設定保留。來源點與量化點均通過完整北屯區範圍檢查。</li>'
        '<li>以目前實機正常的v2重新建立新街道小型資料：既有門牌指標原樣保留，一街一門牌封裝估132 MB，仍在原4K容量宣告內；尚未產出完整可安裝圖資。</li>'
        '<li>原生音樂：同一原廠OS20工作程序的複製音訊佇列已解出1,024 bytes正確PCM；另案原廠Source工作程序完成六個初始化呼叫，READY通知和通知返回均由原排程驗證。</li>'
        '<li>下一步驗原讀圖driver、真正新街道查詢流程，以及Source到原混音器的播放資料。原機App、手機直接A2DP和喇叭播放尚未完成。</li></ul></div>')
    report = before[FILES[3]].decode()
    marker = '<section class="card" id="offline-research-24h">'
    assert report.count(marker) == 1 and 'id="offline-integration-results-v1"' not in report
    report = report.replace(marker, marker + paragraph, 1)
    report, count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>', lambda _: '<h3>已完成</h3><ul>' + ''.join('<li>'+x+'</li>' for x in phases)+'</ul>', report, count=1, flags=re.S)
    assert count == 1
    report = report.replace('區界及歷史別名未驗，僅供離線原型。', '完整北屯區範圍另案已驗，歷史別名與官方街名仍未驗，僅供離線原型。')
    # This exact obsolete download sentence is independent of the historical
    # v2 scope proofs; fix its current-device wording after actual installation.
    report = report.replace('ZIP／區網完整下載校驗一致；尚未實機安裝。前版1筆',
        'ZIP／區網完整下載校驗一致；已實機安裝，道路顯示及民權路6／150／184號限定搜尋／位置／路線通過。前版1筆')
    for ident in ['navigation-address-updated-time', 'report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        assert count == 1
    out = ROOT/'staging'/('offline-integration-publication-'+now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir()
    for name, data in before.items():
        with (out/(name.replace('/','__')+'.gz')).open('xb') as f:
            f.write(gzip.compress(data, mtime=0)); f.flush(); os.fsync(f.fileno())
    for name, value in zip(FILES[:4], [state, task, public, report]):
        replace(name, value)
    served, response = http(web['url'])
    assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
        served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
        offline_integration_checkpoint_v1=checks, offline_24h_work_order=copy.deepcopy(work))
    replace(FILES[4], web)
    assert read(FILES[0]) == read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    assert read(FILES[0])['native_app_music'] == read(FILES[1])['native_app_music']
    create(out/'fresh-readback.json', dict(all_passed=True, prerequisite_pins=PINS, service=svc,
        report_sha256=sha(served), native_country_engineering_estimate_percent=75,
        device_IO=False, full_goal_complete=False, actual_goal_status='active'))
    print(json.dumps(dict(all_passed=True, checkpoint=str(out.relative_to(ROOT)), report_url=web['url'], device_IO=False)))


if __name__ == '__main__':
    main()
