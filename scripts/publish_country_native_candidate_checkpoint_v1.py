#!/usr/bin/env python3
"""Publish the actual structural country supplement, with acceptance pending."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

OUT = ROOT/'staging/navigation-country-native-candidate-publication-v1'
FILES = ['evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json',
    'reports/nuvi2565RT.html', 'evidence/report-web-latest.json']


def main():
    assert not OUT.exists()
    before = {n:(ROOT/n).read_bytes() for n in FILES}
    state, task, public = [json.loads(before[n]) for n in FILES[:3]]
    web = json.loads(before[FILES[-1]])
    svc = service(); served, _ = http(web['url']); assert served == before[FILES[3]]
    assert state == public['deep_research']
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    candidate = read('staging/navigation-country-native-candidate-v1/proof.json')
    merge = read('staging/navigation-country-native-house-merge-v1/proof.json')
    rollback = read('staging/navigation-country-layout-restore-v1/proof.json')
    join = read('staging/navigation-country-address-ready-join-v1/proof.json')
    assert candidate['all_assigned_checks_passed'] and merge['all_assigned_checks_passed'] and rollback['all_assigned_checks_passed']
    assert candidate['candidate_bytes'] == 121823232 and candidate['new_integer_house_records'] == 111608
    assert candidate['updated_original_streets'] == 15679 and not candidate['device_installed']
    assert rollback['candidate_sha256'] == candidate['candidate_sha256']
    app = copy.deepcopy(state['native_app_music'])
    now = datetime.now(timezone.utc); local = now.astimezone(ZoneInfo('Asia/Taipei'))
    nav = state['navigation_repair']
    evidence = ['staging/navigation-country-address-ready-join-v1/proof.json',
        'staging/navigation-country-native-house-merge-v1/proof.json',
        'staging/navigation-country-native-house-merge-v1/output-readback-proof.json',
        'staging/navigation-native-multilevel-mdr-writer-v1/file-seal-v1.json',
        'staging/navigation-country-native-candidate-v1/proof.json',
        'staging/navigation-country-layout-restore-v1/proof.json']
    nav['country_existing_street_candidate'] = dict(status='structural_readback_passed_independent_and_native_CPU_pending',
        candidate_path=candidate['candidate_path'], bytes=candidate['candidate_bytes'], sha256=candidate['candidate_sha256'],
        new_integer_houses=111608, existing_streets_updated=15679,
        new_houses_by_leaf_level={'4':74455, '5':35183, '6':1970},
        original_records_cloned_with_significant_bits_preserved=1463478,
        original_4K_geometry_and_other_five_components_unchanged=True,
        all_47870_parent_fields_and_15679_merged_groups_readback_verified=True,
        compact_restore_recipe_bytes=rollback['recipe_bytes'], exact_original_hash_stream_reconstructed=True,
        device_installed=False, device_search_verified=False, native_CPU_verified=False,
        independent_source_review_verified=False, install_package_ready=False,
        full_Taiwan_update_complete=False, evidence=evidence)
    progress = nav['native_country_address_update_progress']
    progress.update(estimate_percent=40, updated_utc=now.isoformat(), source_exact_ready_groups=2120618,
        source_ready_groups_are_not_new_house_count=True, full_Taiwan_native_address_update_complete=False,
        phases=['全台來源規劃及原廠街道／文字對照完成；212萬組精確可配對來源仍需查原記錄是否已有。',
            '跨縣市既有街道候選已寫出：111,608筆新整數門牌／15,679街道，L4／L5／L6三層整合及完整讀回通過。',
            '原檔精確串流還原通過；獨立來源核對、原韌體有界讀取及候選安裝包繼續準備。',
            '台中較大測試包已可下載，實機待接；新街道、巷弄、子號、行政區字串及座標矛盾仍未完成。'])
    actions = [state['next_actions'][0],
        '完成跨縣市門牌候選的獨立來源核對、原指令讀取及安裝／還原封裝；目前未安裝車機。',
        '核對完整巷弄路徑與高雄可用區界，續處理新街道／行政區、子號、缺文字與座標矛盾。',
        state['next_actions'][3]]
    state['next_actions'] = actions; nav['remaining_next_actions'] = copy.deepcopy(actions)
    nav['next'] = actions[0]; nav['updated_utc'] = now.isoformat()
    nav['execution_status'] = 'country_candidate_offline_validation_in_progress_Taichung_package_waits_for_USB'
    nav['goal_complete'] = False; nav['required_work_remaining'] = True
    state['updated_utc'] = now.isoformat()
    state['last_goal_turn'] = dict(classification='progress', validated_utc=now.isoformat(),
        goal_status=state['goal_status'], historical_goal_API_status_not_changed=True,
        country_structural_candidate_ready=True, full_goal_complete=False, required_work_remaining=True,
        device_files_written=False, reason='Actual multilevel candidate readback and exact stock restoration passed; native/source/physical acceptance remain pending.')
    for key in ['navigation_repair', 'updated_utc', 'next_actions', 'last_goal_turn']:
        task[key] = copy.deepcopy(state[key])
    public.update(updated=now.isoformat(), deep_research=copy.deepcopy(state), navigation_repair=copy.deepcopy(nav))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert state['native_app_music'] == app
    archive = nav['taichung_larger_candidate']['package']['download_url']
    card = f'''<section class="card" id="navigation-repair-checkpoint-v2"><h2>跨縣市原生門牌補充候選已寫出；實機待測</h2>
<p>全台更新工程估計 <strong>40%</strong>。這是工作進度估計，不是地址覆蓋率。</p>
<progress id="navigation-country-address-progress" max="100" value="40">40%</progress>
<p>更新：<time id="navigation-address-updated-time" datetime="{local.isoformat(timespec='seconds')}">{local.strftime('%Y/%m/%d %H:%M:%S')}</time>（台灣時間）</p>
<h3>已完成</h3><ul><li>全台來源整理為4,630,959組規劃資料；2,120,618組來源可精確對上原有街道與門牌文字，這不是新增門牌數。</li>
<li>跨縣市候選補入111,608筆原廠缺少的整數門牌，更新15,679條既有街道；保留原有記錄、座標與相對順序。</li>
<li>真正約122 MB圖資已寫出；三層門牌表、全部街道父記錄和合併組讀回核對，原4K圖資格式、其他五個元件、原生地址索引與授權均保留。</li>
<li>精確還原工具已從候選串流重建原檔，雜湊與唯一備份相同；沒有新增完整備份。</li>
<li>111,608筆為跨縣市候選的離線結果，尚未安裝，正在獨立核對來源與原韌體讀取；尚未完成跨縣市實機搜尋／路線驗收。</li></ul>
<h3>可用測試包與既有實測</h3><p><a href="{archive}" download>下載台中擴大完整測試包（約145 MB）</a>：11,002筆新增整數門牌／1,693條街道，包含AP、Search v2道路、校驗及精確還原工具。封裝、區網完整下載與安裝／還原35項控制通過，尚未安裝。</p>
<p>先前民權路9筆補充試驗的限定里程碑100%：6、150、184號皆找到且無逾時，6、150號位置合理且路線都算出。這不代表较大候選或全台更新已完成。<a href="http://172.16.60.187:8767/Garmin-2565RT-address-test-v1.zip" download>原已抽測包</a>保留。</p>
<h3>接著處理</h3><ol>''' + ''.join(f'<li>{a}</li>' for a in actions) + '''</ol>
<h3>資料限制</h3><p>新街道、完整巷弄路徑、子號、缺少的文字、行政區字串和座標矛盾仍需處理。高雄缺兩段市界，這批先保留原資料；正核對可完整驗證的各區界。原有同名門牌座標保留，未聲稱所有2016門牌都已更新到2026。</p>
<p>原廠圖也會刷新慢／短暫破圖，簡略稍微改善；依使用者指示停止效能測試，未宣稱CPU根因或刷新問題已修復。導航地址驗證後恢復音樂／App研究。</p></section>'''
    report = before[FILES[3]].decode()
    report, count = re.subn(r'<section class="card" id="navigation-repair-checkpoint-v2">.*?</section>',
        lambda _:card, report, count=1, flags=re.S); assert count == 1
    for identifier in ['report-updated-time', 'research-updated-time']:
        report, count = re.subn(r'<time id="'+identifier+r'" datetime="[^"]+">[^<]+</time>',
            lambda _:f'<time id="{identifier}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>', report, count=1)
        assert count == 1
    OUT.mkdir()
    for name, data in before.items():
        with (OUT/(name.replace('/','__')+'.gz')).open('xb') as f:
            f.write(gzip.compress(data, mtime=0)); f.flush(); os.fsync(f.fileno())
    create(OUT/'actual-root-operation-receipts.json', dict(all_assigned_checks_passed=True,
        builder=dict(command='python3 -B scripts/build_country_native_address_candidate_v1.py',
            session_id=77241, initial_chunk='da2784', terminal_chunk='00ad5c', exit_code=0),
        restore=dict(command='python3 -B scripts/prepare_country_layout_restore_v1.py',
            terminal_chunk='fcd7e1', exit_code=0),
        candidate_sha256=candidate['candidate_sha256'], device_IO=False))
    for name, value in zip(FILES[:4], [state, task, public, report]): replace(name, value)
    served, response = http(web['url']); assert served == report.encode() and service() == svc
    web.update(updated_utc=now.isoformat(), HTTP_status=response['status'], local_report_sha256=sha(served),
        served_report_sha256=sha(served), report_bytes=len(served), service_not_restarted=True,
        country_candidate_structural_checkpoint_evidence='staging/navigation-country-native-candidate-v1/proof.json')
    replace(FILES[-1], web)
    assert read(FILES[0]) == read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair'] == read(FILES[1])['navigation_repair'] == read(FILES[2])['navigation_repair']
    create(OUT/'fresh-readback.json', dict(all_passed=True, HTTP=response, report_sha256=sha(served), service=svc,
        candidate_sha256=candidate['candidate_sha256'], engineering_estimate_percent=40,
        country_candidate_device_installed=False, full_goal_complete=False))
    print(json.dumps(dict(all_passed=True, report_url=web['url'], engineering_estimate_percent=40,
        new_integer_houses=111608, device_installed=False), ensure_ascii=False))


if __name__ == '__main__': main()
