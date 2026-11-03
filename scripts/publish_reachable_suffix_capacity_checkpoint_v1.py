"""Publish completed data calculations, preserving current physical v2."""
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
BASE = 'staging/navigation-v3-reachable-suffix-compaction-dependency-preflight-v5/'
MATH = 'staging/navigation-v3-compaction-capacity-independent-review-v1/'
PINS = {
    BASE+'proof.json': 'ca6e4225536d9240b58c7424934f49f1c86c58c23dd956b5c8f1c223500f4d82',
    BASE+'feasibility-summary.json': '8cf117b560852b26e8fdadd8270987a3cdd5df0177c20364e34e4fb787b67fe5',
    BASE+'sealed-files.json': '228acf76f416a8f00b3996c19b35cc5f144d842e37adf7b274edb2f0b618dcea',
    BASE+'actual-output-closure-proof.json': '299328334645176ee18875d3f8d2350f7e8ec0ae850622306ba399a3375982bb',
    MATH+'proof.json': '628c7e508b9d5f82bd6afd4263a1835dfb67422a231787cba0db2e82f58765f2',
    MATH+'sealed-files.json': '76cfcdbb94e877633bcd615b940d6f6aef9c93714cc82395013573686267b047',
    'staging/navigation-v3-compaction-data-algorithm-readonly-review-v1/proof.json':
        '38a7c969f90ba7f6129bdfe1cd5cdf30ede055ab04db9f62741865c6db3bb060',
    'staging/navigation-v3-nontable-lowerref-provenance-review-v1/proof.json':
        '3d86738a0d3a6aaee496ad1c9b8e5ad453426311dba720ea1702cb35eaca5d28',
}


def main():
    docs = {}
    for path, pin in PINS.items():
        raw = (ROOT/path).read_bytes()
        assert len(raw) <= 100000 and sha(raw) == pin
        docs[path] = json.loads(raw)
    proof, summary, math = docs[BASE+'proof.json'], docs[BASE+'feasibility-summary.json'], docs[MATH+'proof.json']
    stock, v2 = summary['stock_prefix_plus_active'], summary['current_v2_prefix_plus_active']
    assert proof['all_assigned_data_feasibility_checks_completed'] and math['all_assigned_checks_passed']
    assert proof['actual_IMG_read_bytes'] == 149290500 and proof['one_actual_MDR_stream_bytes'] == 149220356
    assert proof['actual_MDR_hash_matches_sealed_complete_readback']
    assert not stock['invalid_or_unclassified_child_encoding_counts']
    assert not stock['any_unknown_or_invalid_encoding_forced_all_lower_suffix_retention']
    assert stock['arithmetic']['projected_conservative_4K_IMG_bytes'] == math['stock_active_plan_4K_bytes'] == 137170944
    assert v2['arithmetic']['projected_conservative_4K_IMG_bytes'] == 153337856
    assert math['stock_active_shortage_bytes'] == 2953216
    assert math['exact_additional_L4_rows_needed_if_only128bit_L4_shrinks'] == 184273
    assert not stock['arithmetic']['fits_4K_capacity_arithmetic'] and not v2['arithmetic']['fits_4K_capacity_arithmetic']
    before = {p:(ROOT/p).read_bytes() for p in FILES}
    state, task, public = [json.loads(before[p]) for p in FILES[:3]]
    web = json.loads(before[FILES[4]])
    assert state == public['deep_research']
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    assert all(x['goal_status']=='active' and not x['goal_complete'] for x in [state,task,public,web])
    assert not state['attended_testing']['user_present'] and state['attended_testing']['no_pending_question']
    assert not state['audio']['audible_tests_allowed']
    svc = service()
    served, _ = http(web['url'])
    assert served == before[FILES[3]]
    now = datetime.now(timezone.utc); local = now.astimezone(ZoneInfo('Asia/Taipei'))
    nav = state['navigation_repair']
    old_device = copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
    old_app, old_audio = copy.deepcopy(state['native_app_music']), copy.deepcopy(state['audio'])
    checkpoint = dict(updated_utc=now.isoformat(), prerequisite_pins=PINS,
        actual_success_terminal='c4d30e EXIT0', actual_IMG_read_bytes=149290500,
        actual_MDR_stream_bytes=149220356, actual_complete_MDR_SHA_guard_passed=True,
        actual_current_mm_peak_KiB=105872, current_mm_budget_KiB=393216,
        prior_failed_v4_IMG_read_bytes=149290500, known_v4_v5_combined_IMG_reads=298581000,
        extracted_helper_dependency_preflight_passed=True,
        preserved_original_lower_ID_prefixes=True, actual_all_47870_L3_roots_examined=True,
        structurally_unreferenced_poststock_records=stock['structurally_unreferenced_postprefix_records'],
        lower_table_logical_bytes_removable=16158456,
        stock_prefix_and_active_plan_IMG_bytes=137170944,
        original_declared_4K_capacity_bytes=134217728, stock_plan_over_capacity_bytes=2953216,
        complete_v2_prefix_plan_IMG_bytes=153337856, both_plans_fit_original_declared_capacity=False,
        parent_first_fields_requiring_remap=36617, L3_roots_requiring_remap=19077,
        independent_numeric_review_passed=True, exact_additional_L4_only_rows_needed=184273,
        minimum_row_saving_is_not_deletion_permission=True,
        original_declared_capacity_is_not_proven_native_platform_limit=True,
        original_unknown_prefix_body_range=[772,4195100],
        five_other_components_stock_copy_provenance_reviewed=True,
        copied_bytes_do_not_prove_external_lower_ID_reference_absence=True,
        stock_root_pointer_only_reuse_feasibility_status='pending_actual_data_analysis',
        device_IO=False, compact_IMG_created=False, installable=False,
        road_loss_rootcause_proven=False, renderer_UI_route_verified=False,
        full_Taiwan_update_complete=False, native_App_complete=False, full_goal_complete=False)
    nav['reachable_suffix_capacity_checkpoint_v1'] = copy.deepcopy(checkpoint)
    nav['next'] = ('完整v3未引用索引回收計算已完成，仍比原4K宣告容量多2953216 bytes；'
        '接著核對獨占原廠L4群組能否沿用原編號、只更新子項指標，保留全部新增門牌。'
        '完整更新包與道路消失修復仍未完成，正常v2保持；使用者回來會自行通知。')
    phases = nav['native_country_address_update_progress']['phases']
    phases.extend([
        '完整v3 MDR實際串流與雜湊核對後，完成兩種保留範圍的圖關係、指標重排及容量計算；主機峰值105872KiB低於原384MiB預算。原廠索引＋使用中地址鏈計畫可回收1006407筆L4與3552筆L5，約16.16MB；只產生小型計畫，未重寫IMG。',
        '回收後預估137170944 bytes，仍超出原4K宣告容量2953216 bytes；保留完整v2索引則需153337856 bytes。獨立整數核對確認兩者都不符合該容量；若只減少128-bit L4，至少還需184273筆，這是容量門檻，不代表可刪門牌或可安裝。',
        '唯讀来源鏈結核對確認五個非MDR元件、未知prefix body與L1/L2 payload延續原廠資料；header DIR offset及table positions有變動。相同bytes不能證明沒有未知lower-ID、table-offset或cache引用，這些限制保留。',
    ])
    nav['updated_utc'] = now.isoformat()
    nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    work = state['offline_24h_work_order']
    work['latest_completed_reachable_suffix_capacity_checkpoint'] = copy.deepcopy(checkpoint)
    work['current_offline_line_status']['navigation'] = nav['next']
    state['updated_utc'] = now.isoformat()
    for key in ['updated_utc','navigation_repair','offline_24h_work_order']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(),deep_research=copy.deepcopy(state),navigation_repair=copy.deepcopy(nav),
        offline_24h_work_order=copy.deepcopy(work),
        native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    report = before[FILES[3]].decode()
    paragraph = ('<p id="offline-frontier-latest-v1">最新：完整v3門牌索引的容量回收計算與獨立整數核對完成。'
        '保留原廠索引編號與使用中的地址鏈，可回收約16.16MB，但預估仍超原4K宣告容量約2.95MB；'
        '完整保留v2索引的版本也放不下。正檢查能否沿用獨占的原廠索引位置、只更新子項指標。'
        '這是離線計算，尚未產生新的完整可安裝圖資，也未證明道路消失根因。'
        '車機維持已實測正常的Address Point v2＋Search v2；原機App／手機直接藍牙音樂仍未完成。</p>')
    report, count = re.subn(r'<p id="offline-frontier-latest-v1">.*?</p>',lambda _:paragraph,report,count=1,flags=re.S)
    assert count == 1
    report, count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>',
        lambda _:'<h3>已完成</h3><ul>'+''.join('<li>'+x+'</li>' for x in phases)+'</ul>',report,count=1,flags=re.S)
    assert count == 1
    for ident in ['navigation-address-updated-time','report-updated-time','research-updated-time']:
        report, count = re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>',
            lambda _:f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',report,count=1)
        assert count == 1
    assert nav['latest_country_v2_comparison_checkpoint'] == old_device
    assert state['native_app_music'] == old_app and state['audio'] == old_audio
    assert nav['native_country_address_update_progress']['estimate_percent'] == 75
    out = ROOT/'staging'/('reachable-suffix-capacity-publication-'+now.strftime('%Y%m%dT%H%M%S%fZ'))
    out.mkdir(mode=0o700)
    for path, raw in before.items():
        with (out/(path.replace('/','__')+'.gz')).open('xb') as f:
            f.write(gzip.compress(raw,mtime=0));f.flush();os.fsync(f.fileno())
    for path,value in zip(FILES[:4],[state,task,public,report]):replace(path,value)
    served,response = http(web['url'])
    assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(),HTTP_status=response['status'],local_report_sha256=sha(served),
        served_report_sha256=sha(served),report_bytes=len(served),service_not_restarted=True,
        reachable_suffix_capacity_checkpoint_v1=checkpoint,offline_24h_work_order=copy.deepcopy(work))
    replace(FILES[4],web)
    fresh = [json.loads((ROOT/p).read_bytes()) for p in [FILES[0],FILES[1],FILES[2],FILES[4]]]
    assert all(x['goal_status']=='active' and not x['goal_complete'] for x in fresh)
    assert fresh[0] == fresh[2]['deep_research']
    assert fresh[0]['navigation_repair'] == fresh[1]['navigation_repair'] == fresh[2]['navigation_repair']
    assert fresh[0]['native_app_music'] == fresh[1]['native_app_music'] == old_app
    create(out/'fresh-readback.json',dict(all_passed=True,prerequisite_pins=PINS,service=svc,
        report_sha256=sha(served),nav_estimate=75,app_estimate=40,overall_estimate=37,
        goal_status='active',user_away=True,device_IO=False,full_goal_complete=False))
    print(json.dumps(dict(all_passed=True,checkpoint=str(out.relative_to(ROOT)),report_url=web['url'],
        updated_at_Taiwan=local.isoformat(timespec='seconds'),device_IO=False)))


if __name__ == '__main__':
    main()
