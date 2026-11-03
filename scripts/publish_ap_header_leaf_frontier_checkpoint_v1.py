"""Publish scoped data results and retire the known regressing package link."""
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
L5 = 'staging/navigation-v3-exclusive-stock-L5-reuse-feasibility-v1/'
L6 = 'staging/navigation-v3-L6-exact-record-reuse-upper-bound-v1/'
HEAD = 'staging/navigation-AP-coherent-geometry-virtual-controls-v2/'
RETIRE = 'staging/navigation-v3-download-retirement-v1/'
REVIEW = 'staging/navigation-AP-coherent-geometry-controls-independent-review-v1/'
PINS = {
    L5+'scope-summary.json': '3b68757d856d0efbd9cc1d3cd7ad33ba80c92a438cd2a969057690c466680d4a',
    L5+'sealed-files.json': '3470bc9131486b71a3e661c95d9a85399c6e44c7aef72bc7f475d2b4a125ceba',
    L6+'proof.json': '4afaafa7acddd900b63d648eedc22f1af0ac418ff4325051032b8758ad676a12',
    L6+'result-summary.json': '4315cbbeb88143b9efe75748b165fa6a8e6da95dfcd833544378e9d7c8fab814',
    L6+'sealed-files.json': 'f116357618c853f8b50628cc290035c2fe4dcfd0b98439590155a2c82348888d',
    HEAD+'proof.json': 'dace2db29b3a7d36dc74e775b78501bbe0d9673da77e8f524a05fe7b662e7683',
    HEAD+'prepared-control-plan.json': 'dc636ce504acb7ef3a8b0980d4f91b796f05fc6f07dcbb52aed9d73c6740f655',
    HEAD+'sealed-files.json': 'b3365a9aa57c0181adcbebf80ce3ac3c58463706b9e773280db3433e9eba67da',
    REVIEW+'proof.json': '317f65d79a8efd8196a4973ce0e0bb439c9499bb0c30c3892a641b8a22ad2853',
    REVIEW+'sealed-files.json': 'e48fe6bef2619e61f0c4e0de7c633f451caec17cc80162ab18959ae6cb933e6c',
    RETIRE+'actual-deployment-live-checks.json': '91d1b709dad719c88ca0f46eca0f7c6ab632c2fdba9ebe24417cd8abd2a12359',
    RETIRE+'sealed-files.json': 'd5b70da4c460a54c255d5b23b817d1b510852cbdec7c6601f8ca0dbf7511e727',
    'staging/navigation-v3-exclusive-stock-L4-plan-independent-review-v1/proof.json':
        'a1123cc1eed0cade119061eb33f94c94dda92463e50980a090552d4d627d2bb4',
    'staging/navigation-v3-exclusive-stock-L5-plan-independent-review-v1/proof.json':
        '2152d64c368482207b1834e8087f969937aeec1bfb19d6aca68c1309103a8f9e',
    'staging/navigation-v3-stock-L5-reuse-capacity-threshold-review-v1/proof.json':
        '398d8b0539aeef6d072005754434c6f70a42f614260c5b599c4b7ec9c506b298',
}


def main():
    docs = {}
    for path, pin in PINS.items():
        raw = (ROOT/path).read_bytes()
        assert len(raw) <= 20000 and sha(raw) == pin
        docs[path] = json.loads(raw)
    l5, l6 = docs[L5+'scope-summary.json'], docs[L6+'proof.json']
    header, reviewed = docs[HEAD+'proof.json'], docs[REVIEW+'proof.json']
    retirement = docs[RETIRE+'actual-deployment-live-checks.json']
    assert l5['actual_terminal']['exit_code'] == 0 and l5['L5_rows_compared_and_discardable'] == 38734
    assert l5['combined_arithmetic']['full6components_IMG_bytes'] == 134828032
    assert l6['all_assigned_checks_passed'] and l6['optimistic_L6_savings_upper_bound'] == 73772
    assert l6['exact_L6_capacity_savings_required'] == 71359 and not l6['safe_actual_group_reuse_or_compactor_ready']
    assert header['all_assigned_checks_completed'] and header['total_actual_IMG_bytes_read'] == 306683904
    assert reviewed['independent_full512_and_arithmetic_passed']
    assert retirement['all_live_checks_passed'] and retirement['restart_calls_total'] == 1
    before = {path:(ROOT/path).read_bytes() for path in FILES}
    state, task, public = [json.loads(before[path]) for path in FILES[:3]]
    web = json.loads(before[FILES[4]])
    assert state == public['deep_research']
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    assert all(x['goal_status'] == 'active' and not x['goal_complete'] for x in [state,task,public,web])
    assert not state['attended_testing']['user_present'] and state['attended_testing']['no_pending_question']
    assert not state['audio']['audible_tests_allowed']
    svc = service(); assert http(web['url'])[0] == before[FILES[3]]
    old_app, old_audio = copy.deepcopy(state['native_app_music']), copy.deepcopy(state['audio'])
    nav = state['navigation_repair']; old_device = copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
    now = datetime.now(timezone.utc); local = now.astimezone(ZoneInfo('Asia/Taipei'))
    checkpoint = dict(updated_utc=now.isoformat(), prerequisite_pins=PINS,
        actual_L5_comparison_terminal='28762d EXIT0', L5_groups=1636, additional_L5_rows_reusable=38734,
        combined_L4_L5_projected_IMG_bytes=134828032, combined_plan_remaining_excess_bytes=610304,
        L4_L5_finite_plan_reviews_completed=True, independent_whole_rows_or_full_graph_recomputed=False,
        actual_L6_read_terminal='1736c0 EXIT0', L6_actual_IMG_read_bytes=17604590,
        L6_full_key_bits=68, L6_optimistic_reusable_rows=73772, L6_rows_required_for_capacity=71359,
        L6_safe_complete_groups_confirmed=False, L6_group_feasibility_followup='active_artifact_preflight',
        actual_header_control_terminal='9b63ea EXIT0', full_virtual_control_source_read_bytes=306683904,
        header_control_names=list(header['controls']),
        changed_header_byte_counts={'eightK_end_mirror':1,'expanded_fourK_geometry':5},
        all_nonheader_bytes_unchanged=True, all_188870_supplements_inherited_content_unchanged=True,
        full_hashes_source_reverified_and_virtual_computed=True,
        independent_header_arithmetic_review_completed=True, independent_full_virtual_hash_recomputed=False,
        source_and_candidate_geometry_inconsistencies_observed=True, original_declared_capacity_not_proven_device_limit=True,
        candidate_materializer='active_development_synthetic_tests_only',
        known_regressing_v3_download_withdrawn=True, v3_download_live_GET_HEAD_status=410,
        v2_download_live_HEAD_status=200, v3_research_archive_preserved=True,
        device_IO=False, new_full_IMG_saved=False, installable=False, checksum_algorithm_verified=False,
        road_loss_rootcause_proven=False, renderer_UI_route_verified=False,
        full_Taiwan_update_complete=False, native_App_complete=False, full_goal_complete=False)
    nav['header_and_leaf_frontier_checkpoint_v1'] = copy.deepcopy(checkpoint)
    nav['exclusive_stock_L4_reuse_checkpoint_v1']['L5_followup_status'] = 'actual_comparison_completed_still_over_capacity'
    nav['exclusive_stock_L4_reuse_checkpoint_v1']['independent_L4_plan_review_status'] = 'finite_data_review_completed_not_full_raw_graph_recomputation'
    nav['next'] = ('完整內容保留的兩個標頭對照已離線核對，實機道路恢復尚未證明；L4＋L5沿用計畫仍超610304 bytes，'
                   'L6逐筆相同數量足夠但整組沿用尚待核對。繼續群組前置與候選檔產生工具，保留全部新增門牌；'
                   '已撤下會讓道路消失的舊v3下載，正常v2保持，不要求使用者在外操作。')
    phases = nav['native_country_address_update_progress']['phases']
    phases.extend([
        'L5沿用實際核對1636群組、38734筆，保留全部126bit中非指標欄位；L4＋L5計畫預估134828032 bytes，仍超原宣告容量610304 bytes。L4與L5計畫的獨立有限資料審查完成，並不代表全部raw rows或incoming graph重新驗證。',
        '完整L6資料一次實讀後，89455個新增區段key全唯一，73772筆與原stock完整68bit相同；容量至少需省71359筆。這是忽略群組連續性與引用限制的樂觀上界，尚未證明可整組沿用；新增門牌保留，未產生壓縮IMG。',
        '實際標頭比對顯示正常v2的容量與結尾欄位一致，v3與較大4K控制有不一致。完成1-byte與5-byte兩個僅標頭虛擬對照，重新核對兩個原檔完整SHA並計算新虛擬SHA，所有非標頭內容相同；獨立512byte及算術審查通過。未驗證checksum政策、Garmin接受度、道路顯示或根因。',
        '已部署下載頁修正：已知實機會令Search v2道路消失的舊v3包GET與HEAD都回410，研究zip仍保留；v2下載HEAD200。只重啟下載服務一次，報告PID357833保持，未碰車機與音訊。',
    ])
    nav['updated_utc'] = now.isoformat(); nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    work = state['offline_24h_work_order']
    work['latest_completed_header_leaf_frontier_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['navigation'] = nav['next']
    turn = dict(classification='progress', validated_utc=now.isoformat(), goal_status='active',
                full_goal_complete=False, required_work_remaining=True, device_files_written=False,
                reason='New L5/L6 data evidence and content-preserving header controls completed; known regressing download withdrawn.')
    state.update(updated_utc=now.isoformat(), last_goal_turn=copy.deepcopy(turn))
    for key in ['updated_utc','navigation_repair','offline_24h_work_order','last_goal_turn']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav),
        offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn),
        native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    report = before[FILES[3]].decode()
    paragraph = ('<p id="offline-frontier-latest-v1">最新：找到容量／結尾欄位不一致，已完成保留全部新版內容的兩個標頭對照與離線核對；'
        '尚未證明它就是道路消失原因，也未做實機驗收。L4＋L5索引沿用計畫仍差約610KB；最底層有73772筆完全相同記錄，'
        '正在確認群組能否實際沿用。舊v3試驗包已撤下下載，研究檔保留；車機維持已實測正常的門牌v2＋Search v2。'
        '全台更新包、Garmin原機App與手機直接藍牙音樂仍未完成。</p>')
    report,count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>',lambda _:paragraph,report,count=1,flags=re.S); assert count == 1
    report,count = re.subn(r'<a\b[^>]*href="http://172\.16\.60\.187:8767/Garmin-2565RT-lane-address-test-v3\.zip"[^>]*>.*?</a>',
        '<span data-download-status="withdrawn">舊v3試驗包已撤下下載：實機會讓新版道路消失；修正版仍在核對。</span>',report,count=1,flags=re.S); assert count == 1
    report,count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>',lambda _:'<h3>已完成</h3><ul>'+''.join('<li>'+x+'</li>' for x in phases)+'</ul>',report,count=1,flags=re.S); assert count == 1
    for ident in ['navigation-address-updated-time','report-updated-time','research-updated-time']:
        report,count = re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>',
            lambda _:f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',report,count=1); assert count == 1
    assert nav['latest_country_v2_comparison_checkpoint'] == old_device
    assert state['native_app_music'] == old_app and state['audio'] == old_audio
    assert nav['native_country_address_update_progress']['estimate_percent'] == 75
    out = ROOT/'staging'/('header-leaf-frontier-publication-'+now.strftime('%Y%m%dT%H%M%S%fZ')); out.mkdir(mode=0o700)
    for path,raw in before.items():
        with (out/(path.replace('/','__')+'.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw,mtime=0));stream.flush();os.fsync(stream.fileno())
    for path,value in zip(FILES[:4],[state,task,public,report]): replace(path,value)
    served,response = http(web['url']); assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
        served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
        header_and_leaf_frontier_checkpoint_v1=copy.deepcopy(checkpoint),
        offline_24h_work_order=copy.deepcopy(work), last_goal_turn=copy.deepcopy(turn))
    web['progress_display_verified'].update(report_updated_time=local.isoformat(timespec='seconds'),
        research_updated_time=local.isoformat(timespec='seconds'),navigation_repair_estimate_percent=75)
    replace(FILES[4],web)
    fresh = [json.loads((ROOT/path).read_bytes()) for path in [FILES[0],FILES[1],FILES[2],FILES[4]]]
    assert all(x['goal_status']=='active' and not x['goal_complete'] for x in fresh)
    assert fresh[0] == fresh[2]['deep_research']
    assert fresh[0]['navigation_repair'] == fresh[1]['navigation_repair'] == fresh[2]['navigation_repair']
    create(out/'fresh-readback.json',dict(all_passed=True,prerequisite_pins=PINS,service=svc,report_sha256=sha(served),
        nav_estimate=75,app_estimate=40,overall_estimate=37,goal_status='active',user_away=True,device_IO=False,full_goal_complete=False))
    print(json.dumps(dict(all_passed=True,checkpoint=str(out.relative_to(ROOT)),report_url=web['url'],
        updated_at_Taiwan=local.isoformat(timespec='seconds'),device_IO=False)))


if __name__=='__main__':
    main()
