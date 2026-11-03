"""Publish finite offline progress without promoting it to device acceptance."""
import argparse
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

OUT = ROOT / 'staging/navigation-new-street-subnumber-publication-v1'
FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json',
         'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']
FIXED_SEALS = {
    'staging/navigation-native-label-relocation-v1/sealed-files.json':
        '5c42d72fd02635993ac138c7eba8aad34340c6fd784a5c83556392b285fb9bb4',
    'staging/navigation-native-subnumber-branch-v1/sealed-files.json':
        'f262d5beddc26ce219cc697338ad7a0d03df79e2ec907d0ff5baf4b95d0aa71d',
    'staging/navigation-native-new-street-source-example-v1/sealed-files.json':
        'a7f469ff3b4c9acc562ba92560f4645f77977ccc234a379fdb9f88b11d8c58d3',
    'staging/navigation-native-new-street-family-payload-v1/sealed-files.json':
        '59efa3b3c3fd8ba5c78c6a0f04d2d2de7e4185f24ae5918d6b4027283edd9bfa',
}


def proof_from_seal(path, expected, filename):
    raw = (ROOT / path).read_bytes()
    assert sha(raw) == expected
    seal = json.loads(raw)
    item = next(row for row in seal['files'] if row['path'].endswith('/' + filename))
    data = (ROOT / item['path']).read_bytes()
    assert len(data) == item['bytes'] and sha(data) == item['sha256']
    return json.loads(data), dict(seal=path, seal_sha256=expected, proof=item)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--jai-seal-sha256', required=True)
    parser.add_argument('--payload-cpu-seal-sha256', required=True)
    args = parser.parse_args()
    assert not OUT.exists()
    label, label_pin = proof_from_seal('staging/navigation-native-label-relocation-v1/sealed-files.json',
                                       FIXED_SEALS['staging/navigation-native-label-relocation-v1/sealed-files.json'],
                                       'actual-relocation-proof.json')
    sub, sub_pin = proof_from_seal('staging/navigation-native-subnumber-branch-v1/sealed-files.json',
                                  FIXED_SEALS['staging/navigation-native-subnumber-branch-v1/sealed-files.json'], 'proof.json')
    source, source_pin = proof_from_seal('staging/navigation-native-new-street-source-example-v1/sealed-files.json',
                                        FIXED_SEALS['staging/navigation-native-new-street-source-example-v1/sealed-files.json'], 'candidate.json')
    payload, payload_pin = proof_from_seal('staging/navigation-native-new-street-family-payload-v1/sealed-files.json',
                                          FIXED_SEALS['staging/navigation-native-new-street-family-payload-v1/sealed-files.json'], 'proof.json')
    jai, jai_pin = proof_from_seal('staging/navigation-native-jai-new-street-plan-v1/sealed-files.json',
                                  args.jai_seal_sha256, 'sandbox-proof.json')
    cpu, cpu_pin = proof_from_seal('staging/navigation-native-new-street-payload-cpu-v1/sealed-files.json',
                                  args.payload_cpu_seal_sha256, 'proof.json')
    assert label['all_passed'] and label['labels_are_synthetic_format_fixtures']
    assert sub['all_assigned_checks_passed'] and sub['new_numeric_callback_body_comparison_count'] == 21
    assert source['streettext'] == '敦富六街' and not source['admissibility']['install_candidate']
    assert payload['all_passed'] and payload['current_family_records_copied_verbatim'] == 441
    assert jai['all_assigned_checks_passed'] and not jai['full_newstreet_writer_complete']
    assert cpu['all_assigned_checks_passed']
    before = {name: (ROOT / name).read_bytes() for name in FILES}
    state, task, public = [json.loads(before[name]) for name in FILES[:3]]
    web = json.loads(before[FILES[-1]])
    svc = service()
    served, _ = http(web['url'])
    assert served == before[FILES[3]] and state == public['deep_research']
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    app = copy.deepcopy(state['native_app_music'])
    nav = state['navigation_repair']
    package_before = copy.deepcopy(nav['lane_tree_cow_candidate_v3'])
    assert nav['native_country_address_update_progress']['estimate_percent'] == 65
    now = datetime.now(timezone.utc)
    local = now.astimezone(ZoneInfo('Asia/Taipei'))
    checkpoint = dict(updated_utc=now.isoformat(), status='finite_offline_prototypes_not_installable',
        proofs=[label_pin, sub_pin, source_pin, payload_pin, jai_pin, cpu_pin],
        original_numeric_body_pairs=21, original_subnumber_prefix_records=20,
        source_example=dict(street='敦富六街', house='368號', source_ids=source['source_ids'],
                            city_geometry_checked=True, district_polygon_checked=False, historical_aliases_checked=False),
        JAI_one_family_host_FTS3_sandbox_passed=True, current_v3_family_records_preserved=441,
        new_street_ID=48312, proposed_family_payload_native_prefix_verified=True,
        proposed_directory_and_memory_frames_used=True, actual_new_candidate_IMG_read=False,
        new_prefix_segment_writer_complete=False, complete_MDR_GMP_IMG_composition_ready=False,
        complete_getter_query_UI_verified=False, device_IO=False, installable=False,
        full_Taiwan_update_complete=False)
    nav['new_street_subnumber_checkpoint_v1'] = checkpoint
    nav['updated_utc'] = now.isoformat()
    nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    details = [
        '新街道：北屯區441個原街名的搜尋索引搬移原型通過本機FTS3查詢；現有街名、ID及原搜尋詞記錄保留。',
        '來源示例敦富六街368號通過完整台中市的來源點／量化點檢查；區界及歷史別名未驗，僅供離線原型。',
        '新街名／門牌／父區記錄和中文字引用已產小型payload，441個街道保留現有v3門牌範圍；在明示的候選索引與記憶體框架中，原韌體3筆記錄及1個新街名字標籤片段通過，尚未整張圖資載入。',
        '之號：20筆原紀錄與21組原數字比較驗證，樣本順序為1之1號、1之2號、1之3號、1號；raw13不是專用子號旗標。',
        '仍缺新街道prefix/segment搜尋、完整圖資與還原整合、完整前端及實機驗收；這些原型不放入可安裝v3包。']
    nav['new_street_subnumber_checkpoint_v1']['details'] = details
    nav['native_country_address_update_progress']['phases'].append(
        '新街道整組索引搬移、中文字引用及之號原數字比較取得有限離線驗證；完整新街道搜尋前端仍未完成。')
    state.update(updated_utc=now.isoformat(), required_work_remaining=True, goal_complete=False)
    state['last_goal_turn'] = dict(classification='progress', validated_utc=now.isoformat(),
        goal_status=state['goal_status'], full_goal_complete=False, required_work_remaining=True,
        device_files_written=False, reason='New finite JAI/name/payload/subnumber prototypes verified; installed map and v3 package unchanged; physical and prefix/segment integration remain.')
    for key in ['navigation_repair', 'updated_utc', 'last_goal_turn', 'required_work_remaining', 'goal_complete']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert nav['lane_tree_cow_candidate_v3'] == package_before and state['native_app_music'] == app
    report = before[FILES[3]].decode()
    marker = '<h3>接著處理</h3>'
    assert report.count(marker) == 1
    card = '<h3 id="new-street-subnumber-checkpoint-v1">新街道與之號：離線前置驗證</h3><ul>' + ''.join('<li>' + d + '</li>' for d in details) + '</ul>'
    report = report.replace(marker, card + marker, 1)
    for identifier in ['navigation-address-updated-time', 'report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="' + identifier + r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{identifier}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        assert count == 1
    assert '<progress id="navigation-country-address-progress" max="100" value="65">65%</progress>' in report
    OUT.mkdir()
    for name, raw in before.items():
        with (OUT / (name.replace('/', '__') + '.gz')).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0))
            stream.flush(); os.fsync(stream.fileno())
    for name, value in zip(FILES[:4], [state, task, public, report]):
        replace(name, value)
    served, response = http(web['url'])
    assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'],
        local_report_sha256=sha(served), served_report_sha256=sha(served),
        report_bytes=len(served), service_not_restarted=True)
    replace(FILES[-1], web)
    assert read(FILES[0]) == read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    create(OUT / 'fresh-readback.json', dict(all_passed=True, service=svc, report_sha256=sha(served),
        engineering_estimate_percent=65, latest_install_package_unchanged=True,
        device_files_written=False, full_goal_complete=False, checkpoint=checkpoint))
    print(json.dumps(dict(all_passed=True, report_url=web['url'], engineering_estimate_percent=65,
                          v3_package_unchanged=True, device_files_written=False)))


if __name__ == '__main__':
    main()
