"""Publish closed host writer tests, whole-group limits and current guidance."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, replace, service, sha

FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json',
         'reports/findings.json', 'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
MAT = 'staging/navigation-AP-header-control-materializer-v1/'
LEAF = 'staging/navigation-v3-L6-whole-group-stock-sharing-preflight-v1/'
AUDIT = 'staging/navigation-report-current-guidance-audit-v1/'
PINS = {
    MAT+'proof.json': 'c9b7b59d962f262b3c89f089eab04aeed5cfbdcc29657705703515cc0d128d7e',
    MAT+'sealed-files.json': '442653f6ea55b5792f40048aa391c2c3a19b11cf0c7ed0af1a592d13df48197d',
    'scripts/materialize_ap_header_control_v1.py': 'dfbf182f4d1b40fc4315c5568a7e92c521c35d1c764bc1946e53269f7f958142',
    'staging/navigation-AP-header-control-root-catalog-review-v1/sealed-files.json':
        '92406f56aff1a845cd18d41d869ed207a87b2693a200d5a0ccbab5f21a33dead',
    'staging/navigation-AP-header-control-root-catalog-exact-reparse-v1/sealed-files.json':
        '9a91365b0f4779cdb64aaada260034c5d774a92798de9e5d56bbae902c499002',
    LEAF+'own-summary-audit-and-bound.json': '85c4aadfa553d12d790fc83c43c09bbc2265352ae0a8666046a2b78bcab36a4c',
    LEAF+'actual-file-handle-closure.json': '4c6c2e762af5b32f2f711715225ed6112403a676daaf8d8daba3f425daceea4d',
    LEAF+'scope-summary.json': '66d15883e22a1a70d04d4b9b3b451a775ba652b38bef3b16e259989a589eb001',
    LEAF+'conditional-capacity-bound-proof.json': '970c4fbd16d295e3c2df971010fc5df25af2526bbd26ed0633158e749694e5e4',
    LEAF+'sealed-files.json': '3199149e5763c45abd90a76e5a54affeb74ebc41bccfd19d7472de11b4e0f778',
    AUDIT+'audit.json': 'fb459394c90631748e23c0975b7b30ee632fc015603e22cf5fdbffbdf7573a38',
    AUDIT+'proof.json': 'd8ccf275dd73d1e72c78810152454d781bcee676d2326a31be29609eaa345da2',
    AUDIT+'sealed-files.json': '1d86aa68693ac206f1976eb8ef8a1e5871a07a548bf81cf594757ef4b760feb7',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    docs = {}
    for path, pin in PINS.items():
        raw = (ROOT/path).read_bytes()
        require(len(raw) <= 32768 and sha(raw) == pin, 'Fixed small prerequisite '+path)
        if path.endswith('.json'):
            docs[path] = json.loads(raw)
    materializer = docs[MAT+'proof.json']
    bound = docs[LEAF+'own-summary-audit-and-bound.json']
    handles = docs[LEAF+'actual-file-handle-closure.json']
    audit = docs[AUDIT+'audit.json']
    require(materializer['all_assigned_checks_passed'] and
            materializer['tests']['actual_exit_code'] == 0 and materializer['tests']['methods'] == 17,
            'Closed synthetic writer checks')
    require(not materializer['real_materialization_executed'] and not materializer['installable'],
            'Production materialization and acceptance remain unverified')
    require(bound['actual_universal_predicate_all_v3_groups_have_stockhit0'] is False and
            bound['actual_allstockmatched_group_rows'] == 22,
            'Preserve the two counterexamples')
    capacity = bound['wholegroup_optimistic_savings_bound']
    require(capacity['sum'] == 10772 and capacity['required'] == 71359 and capacity['insufficient'],
            'Restricted whole-group savings bound')
    require(handles['actual_state']['completed'] and handles['all_handles_closed'] and
            handles['all_source_stats_unchanged'], 'Actual completed leaf-stream handle closure')
    before = {name:(ROOT/name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[4]])
    require(state == public['deep_research'] and
            state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair'],
            'Canonical state equality before publication')
    require(sha(before[FILES[3]]) == audit['report_snapshot_sha256'], 'Reviewed exact report revision')
    require(all(x['goal_status'] == 'active' and not x['goal_complete'] for x in [state,task,public,web]),
            'Goal remains active and incomplete')
    require(not state['attended_testing']['user_present'] and state['attended_testing']['no_pending_question']
            and not state['audio']['audible_tests_allowed'], 'Away and silent scope')
    require(task['user_away'] is False and public['research_goal_status'] == 'paused' and
            web['current_physical_test_requested'] is True and web['user_away_for_class'] is False,
            'Exact known stale current fields')
    svc = service()
    require(http(web['url'])[0] == before[FILES[3]], 'Current HTTP body equals local report')
    old_app, old_audio = copy.deepcopy(state['native_app_music']), copy.deepcopy(state['audio'])
    nav = state['navigation_repair']
    old_device = copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    checkpoint = dict(updated_utc=now.isoformat(), prerequisite_pins=PINS,
        writer_synthetic_actual_terminal='396f0a EXIT0', writer_synthetic_test_methods=17,
        writer_synthetic_receipt_cases=24, writer_actual_saved_file_readback_verified_on_synthetic_inputs=True,
        writer_corrupt_partial_refusal_and_no_overwrite_verified=True,
        writer_post_publication_fsync_failure_reports_verified_published_final=True,
        actual_root_metadata_cli_terminal='d33396 EXIT0', root_metadata_catalog_read_bytes=11217,
        root_metadata_statpin_precision_corrected_from_original_saved_stdout=True,
        production_Python_catalog_integer_pins_unchanged=True,
        metadata_mode_source_IMG_stat_or_open=False, production_materialization_run=False,
        leaf_artifact_actual_terminal='175368 EXIT0', leaf_emitted_groups_streamed=29866,
        leaf_v3_complete_groups=4676, mixed_new_content_groups=4674,
        all_stockmatched_group_exceptions=2, all_stockmatched_exception_rows=22,
        universal_all_groups_excluded_hypothesis=False,
        restricted_complete_group_reuse_optimistic_savings_upper_bound=10772,
        restricted_complete_group_reuse_rows_required=71359,
        restricted_complete_group_reuse_capacity_plan_insufficient=True,
        unrestricted_compaction_or_device_capacity_limit_proven=False,
        original_declared_capacity_not_assumed_hardware_limit=True,
        all_new_addresses_preserved=True, actual_leaf_source_handles_closed=True,
        current_HTML_guidance_conflicts_fixed=2, current_structured_fields_fixed=4,
        historical_records_preserved=True, strict_rollback_binding_followup='active_preflight_and_host_adapter',
        device_IO=False, new_full_IMG_saved=False, installable=False,
        checksum_algorithm_verified=False, road_loss_rootcause_proven=False,
        renderer_UI_route_verified=False, full_Taiwan_update_complete=False,
        native_App_complete=False, direct_phone_A2DP_complete=False, full_goal_complete=False)
    nav['materializer_and_group_checkpoint_v1'] = copy.deepcopy(checkpoint)
    prior = nav['header_and_leaf_frontier_checkpoint_v1']
    prior['candidate_materializer'] = 'closed_synthetic_validation_production_generation_not_run'
    prior['L6_group_feasibility_followup'] = 'complete_group_only_savings_upper_bound_insufficient'
    nav['next'] = ('完成保留全部門牌的標頭對照之嚴格還原綁定，核對實際候選檔後再準備實測包；'
                   '完整群組沿用的容量方案已證明不足，但原宣告容量不是已證硬體上限。'
                   '目前正常v2＋Search v2保持，使用者返回前繼續離線驗證，不詢問在場或要求接線。')
    phases = nav['native_country_address_update_progress']['phases']
    phases.extend([
        '候選產生工具完成17項小型合成測試、24筆程序紀錄，核對原檔完整雜湊、預期輸出雜湊及已存檔的實際讀回雜湊；損毀拒絕、不覆寫、失敗清理與發布後fsync錯誤處理通過。Root另實跑--list，只讀11217 bytes小型目錄證據，不讀或產生真IMG。',
        '完整讀取29866個封閉群組紀錄後，4676個新L6群組中4674含原廠未有的記錄；另2組共22筆是反例，不能聲稱全部都不可沿用。即使假設原v2尾段10750筆與這22筆全部可省，完整群組沿用上限10772仍小於容量所需71359；只排除這個受限方案，保留所有新門牌。',
        '目前報告兩處v3用語及四個狀態欄位已修正，保留歷史安裝、道路消失及還原紀錄；車機現用v2、使用者在外、無待答實機問題、goal維持active。下一步準備嚴格綁定的還原介面，不把標頭虛擬雜湊或小型工具測試當作實機修復。',
    ])
    nav['updated_utc'] = now.isoformat()
    nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    work = state['offline_24h_work_order']
    work['latest_completed_materializer_group_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['navigation'] = nav['next']
    turn = dict(classification='progress', validated_utc=now.isoformat(), goal_status='active',
        full_goal_complete=False, required_work_remaining=True, device_files_written=False,
        reason='Host candidate writer tests and bounded complete-group feasibility completed; current report guidance corrected.')
    state.update(updated_utc=now.isoformat(), last_goal_turn=copy.deepcopy(turn))
    for key in ['updated_utc','navigation_repair','offline_24h_work_order','last_goal_turn']:
        task[key] = copy.deepcopy(state[key])
    task['user_away'] = True
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav),
        offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn),
        native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']),
        research_goal_status=state['research_goal_status'])
    public['research_progress']['research_updated_utc'] = now.isoformat()
    report = before[FILES[3]].decode()
    for finding in audit['HTML_findings']:
        require(report.count(finding['replace_exact']) == 1, 'Exactly one reviewed current phrase')
        report = report.replace(finding['replace_exact'], finding['replace_with'], 1)
    paragraph = ('<p id="offline-frontier-latest-v1">最新：候選檔產生工具的17項小型測試已通過，包含完整雜湊、存檔後讀回、損毀拒絕與不覆寫；'
        '尚未產生新實機檔。完整群組沿用即使樂觀估算也最多省10772筆，少於所需71359筆，這條容量方案不足；'
        '並不代表原宣告容量就是硬體上限。接著完成保留全部門牌的封裝對照與嚴格還原綁定。'
        '車機維持已實測正常的門牌v2＋Search v2，舊v3下載已撤下；全台更新、Garmin原機App與手機直接藍牙音樂仍未完成。</p>')
    report,count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>',lambda _:paragraph,report,count=1,flags=re.S)
    require(count == 1, 'Unique current frontier paragraph')
    report,count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>',
        lambda _:'<h3>已完成</h3><ul>'+''.join('<li>'+x+'</li>' for x in phases)+'</ul>',report,count=1,flags=re.S)
    require(count == 1, 'Unique navigation completed-detail list')
    for ident in ['navigation-address-updated-time','report-updated-time','research-updated-time']:
        report,count = re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>',
            lambda _:f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',report,count=1)
        require(count == 1, 'Unique current time '+ident)
    require(nav['latest_country_v2_comparison_checkpoint'] == old_device and
            state['native_app_music'] == old_app and state['audio'] == old_audio, 'Device/App/audio history preserved')
    require(nav['native_country_address_update_progress']['estimate_percent'] == 75,
            'No percentage increase from synthetic writer tests')
    out = ROOT/'staging'/('materializer-group-publication-'+now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for name,raw in before.items():
        with (out/(name.replace('/','__')+'.gz')).open('xb') as f:
            f.write(gzip.compress(raw,mtime=0)); f.flush(); os.fsync(f.fileno())
    for name,value in zip(FILES[:4],[state,task,public,report]):
        replace(name,value)
    served,response = http(web['url'])
    require(served == report.encode() and service() == svc, 'Fresh HTTP exact bytes and original live service')
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
        served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
        current_physical_test_requested=False, user_away_for_class=True,
        materializer_and_group_checkpoint_v1=copy.deepcopy(checkpoint),
        header_and_leaf_frontier_checkpoint_v1=copy.deepcopy(prior),
        offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web['progress_display_verified'].update(report_updated_time=local.isoformat(timespec='seconds'),
        research_updated_time=local.isoformat(timespec='seconds'),navigation_repair_estimate_percent=75)
    replace(FILES[4],web)
    fresh = [json.loads((ROOT/p).read_bytes()) for p in [FILES[0],FILES[1],FILES[2],FILES[4]]]
    require(all(x['goal_status'] == 'active' and not x['goal_complete'] for x in fresh), 'Goal stays active')
    require(fresh[0] == fresh[2]['deep_research'] and
            fresh[0]['navigation_repair'] == fresh[1]['navigation_repair'] == fresh[2]['navigation_repair'],
            'Fresh canonical equality')
    require(fresh[1]['user_away'] and fresh[2]['research_goal_status'] == 'active_offline' and
            not fresh[3]['current_physical_test_requested'] and fresh[3]['user_away_for_class'],
            'All four stale current fields corrected')
    create(out/'fresh-readback.json',dict(all_passed=True, prerequisite_pins=PINS, service=svc,
        report_sha256=sha(served), navigation_estimate=75, native_App_estimate=40, overall_estimate=37,
        goal_status='active', user_away=True, device_IO=False, full_goal_complete=False))
    print(json.dumps(dict(all_passed=True, checkpoint=str(out.relative_to(ROOT)), report_url=web['url'],
        updated_at_Taiwan=local.isoformat(timespec='seconds'), device_IO=False)))


if __name__ == '__main__':
    main()
