#!/usr/bin/env python3
"""Publish actual broader native-address preparation, with scoped progress."""
import copy
import gzip
import html
import json
import os
import re
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT,create,http,read,replace,service,sha

OUT=ROOT/'staging/navigation-country-address-preparation-publication-v1'
FILES=['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json',
    'reports/nuvi2565RT.html','evidence/report-web-latest.json']
PROOFS=[
    'staging/navigation-taiwan-address-ingestion-v1/ingestion-summary.json',
    'staging/navigation-address-house-join-v1/proof.json',
    'staging/navigation-native-general-writer-corrected-source-v2/corrected-original-L3-writer-source-proof-v2.json',
    'staging/navigation-native-mdr-rewrite-v1/MDR-streaming-suffix-writer-proof-v1.json',
    'staging/navigation-taichung-address-merge-v1/proof.json',
    'staging/navigation-taichung-merge-review-v1/proof.json',
    'staging/navigation-taichung-native-candidate-v1/proof.json',
    'staging/navigation-taichung-native-cpu-v1/actual-Taichung-candidate-original-CPU-proof-v1.json',
    'staging/navigation-taichung-layout-restore-v1/proof.json',
    'staging/navigation-country-city-geometry-v1/proof.json',
    'staging/navigation-native-deeper-address-plan-v1/deeper-address-plan.json',
]


def main():
    assert not OUT.exists()
    before={name:(ROOT/name).read_bytes()for name in FILES}
    state,task,public=[json.loads(before[name])for name in FILES[:3]]
    web=json.loads(before[FILES[-1]])
    assert public['deep_research']==state
    assert state['navigation_repair']==task['navigation_repair']==public['navigation_repair']
    svc=service();served,_=http(web['url']);assert served==before[FILES[3]]
    binding=[]
    for name in PROOFS:
        data=(ROOT/name).read_bytes();binding.append(dict(path=name,bytes=len(data),sha256=sha(data)))
    merge=read(PROOFS[4]);review=read(PROOFS[5]);candidate=read(PROOFS[6]);cpu=read(PROOFS[7]);restore=read(PROOFS[8])
    assert all(item['all_assigned_checks_passed']for item in [merge,review,candidate,cpu,restore])
    assert merge['counts']['actual_new_integer_house_records']==review['source_new_integer_records']==candidate['actual_new_integer_house_records']==11002
    assert cpu['exact_native_record_prefix_count']==18 and cpu['exact_new_leaf_count']==14
    assert not cpu['device_IO'] and not candidate['device_installed']
    now=datetime.now(timezone.utc);local=now.astimezone(ZoneInfo('Asia/Taipei'));stamp=local.isoformat(timespec='seconds')
    app=copy.deepcopy(state['native_app_music']);previous_progress=copy.deepcopy(public['research_progress'])
    full=dict(estimate_percent=30,scope='全台原生門牌更新的工程估計；不是門牌覆蓋率或完成率量測。',
        updated_utc=now.isoformat(),source_prepared_groups=4630959,
        original_named_streets=47853,original_cities=22,original_districts=343,
        source_snapshot_utc='2026-10-01T20:22:06Z',
        full_country_source_planning_ready=True,full_Taiwan_native_address_update_complete=False,
        phases=['全台來源分組與既有街道／文字對照完成。',
            '原廠格式串流寫入工具與台中擴大候選已產出，原指令有限讀取通過。',
            '全台分層門牌整合、新街道／行政區、缺文字、座標矛盾與巷弄仍在處理。',
            '較大候選安裝／還原工具準備中；尚未實機驗收。'])
    larger=dict(status='local_image_readback_and_bounded_native_CPU_passed_installation_tools_in_preparation',
        candidate_path=candidate['candidate_path'],bytes=candidate['candidate_bytes'],sha256=candidate['candidate_sha256'],
        new_integer_houses=11002,existing_streets_updated=1693,
        existing_exact_houses_kept=merge['counts']['source_exact_house_labels_already_in_original'],
        new_subnumber_groups_deferred=merge['counts']['subnumber_or_other_house_deferred'],
        source_coordinate_review_groups=8421,header_geometry_unchanged=True,
        other_five_components_unchanged=True,host_full_readback_passed=True,
        independent_new_merge_review_passed=True,bounded_native_CPU_records=18,
        bounded_native_CPU_new_leaves=14,compact_restore_recipe_bytes=restore['recipe_bytes'],
        exact_original_hash_stream_reconstructed=True,additional_full_backup_created=False,
        device_installed=False,device_search_verified=False,full_Taiwan_update_complete=False,
        evidence=PROOFS[4:9])
    actions=['完成較大台中候選的安裝／還原工具及驗證，方便時再安排實機抽測。',
        '擴大全台來源與既有原生next4／next5／next6門牌合併，保留原有階層及flags。',
        '處理新街道／行政區、之號／巷弄、缺文字與座標矛盾；不猜名稱或任意第一個位置。',
        '畫面刷新效能測試依使用者指示停止；導航地址需求驗證完成後恢復手機音樂／App。']
    nav=state['navigation_repair']
    nav.update(updated_utc=now.isoformat(),native_country_address_update_progress=full,
        taichung_larger_candidate=larger,execution_status='larger_Taichung_candidate_ready_country_address_update_in_progress',
        navigation_repair_status='single_street_trial_accepted_larger_candidate_awaits_physical_acceptance',
        remaining_next_actions=actions,next=actions[0],required_work_remaining=True,goal_complete=False,
        remaining_physical_checks=['較大台中候選工具準備完成後，再安排USB安裝及新增門牌位置／路線抽測。'])
    nav['sources']['country_address_preparation']=str((OUT/'proof-bindings.json').relative_to(ROOT))
    state.update(updated_utc=now.isoformat(),current_priority=actions[1],next_actions=actions,
        goal_complete=False,required_work_remaining=True)
    state['last_goal_turn']=dict(classification='progress',validated_utc=now.isoformat(),goal_status=state['goal_status'],
        full_goal_complete=False,required_work_remaining=True,device_IO=False,
        checkpoint='Broader native Taichung missing-house candidate with fullreadback, independentreview, bounded CPU and compact rollback; fullcountry update ongoing.')
    for key in ['navigation_repair','updated_utc','current_priority','next_actions','last_goal_turn','goal_complete','required_work_remaining']:
        task[key]=copy.deepcopy(state[key])
    public.update(updated=now.isoformat(),deep_research=copy.deepcopy(state),navigation_repair=copy.deepcopy(nav),
        required_work_remaining=True,goal_complete=False,native_country_address_update_progress=copy.deepcopy(full))
    public['research_progress']['research_updated_utc']=now.isoformat()
    assert state['native_app_music']==app
    for key in ['estimate_percent','weighted_estimate_percent','phases','completed']:
        assert public['research_progress'][key]==previous_progress[key]
    report=before[FILES[3]].decode()
    old_start=report.index('<section class="card" id="navigation-repair-checkpoint-v2">')
    old_end=report.index('</section>',old_start)+len('</section>')
    card=f'''<section class="card" id="navigation-repair-checkpoint-v2"><h2>全台原生門牌更新進行中；台中擴大候選已產出</h2>
<p>全台更新工程估計 <strong>30%</strong>。這是工作進度估計，不是地址覆蓋率。</p>
<progress id="navigation-country-address-progress" max="100" value="30">30%</progress>
<p>更新：<time datetime="{stamp}">{local.strftime('%Y/%m/%d %H:%M:%S')}</time>（台灣時間）</p>
<h3>已完成的較大範圍成果</h3><ul>
<li>全台来源整理成4,630,959組門牌規劃資料；對照原廠22縣市、343區與47,853筆具名街道。</li>
<li>台中候選補入11,002筆原廠缺少的整數門牌，涵蓋1,693條既有街道；207,287筆已存在門牌保留。</li>
<li>實際IMG {candidate['candidate_bytes']:,} bytes（約101 MB）已完整讀回；其他五個元件、原標頭／配置格式、JAI與授權檔保留。</li>
<li>獨立審查全數新增資料／來源／欄位；原廠指令有限讀取4條街、14筆新門牌及標籤通過。完整搜尋UI與實機接受仍待驗證。</li>
<li>864,491 bytes還原資料已用串流重建原廠完整SHA；沒有另外留一份完整車機備份。</li>
</ul><h3>既有實機抽測</h3><p>先前民權路9筆補充試驗的限定里程碑為100%：6、150、184號皆找到且無逾時，6、150號位置合理且路線都算出。這項驗收不代表較大台中候選或全台更新已完成。</p>
<p><a href="http://172.16.60.187:8767/Garmin-2565RT-address-test-v1.zip" download>既有民權路測試包</a>；新的較大更新包仍在準備。</p>
<h3>接著處理</h3><ol>{''.join('<li>'+html.escape(a)+'</li>'for a in actions)}</ol>
<h3>資料與實機限制</h3><p>本批未新增64,285組之號等子號，8,421組座標待查資料已隔離。仍需處理全台其他街道、next5／next6、完整巷弄階層與新街道索引；台中候選尚未安裝。高雄來源行政邊界不完整，先不以缺件多邊形判定地址位置。</p>
<p>原廠圖也會刷新慢／短暫破圖，简略稍微改善；依使用者指示停止效能測試，未宣稱CPU根因或刷新問題已修復。</p></section>'''
    report=report[:old_start]+card+report[old_end:]
    for identifier in ['report-updated-time','research-updated-time']:
        report,count=re.subn(r'<time id="'+identifier+r'" datetime="[^"]+">[^<]+</time>',
            lambda _:f'<time id="{identifier}" datetime="{stamp}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',report,count=1)
        assert count==1
    OUT.mkdir()
    for name,data in before.items():
        with (OUT/(name.replace('/','__')+'.gz')).open('xb')as f:f.write(gzip.compress(data,mtime=0));f.flush();os.fsync(f.fileno())
    create(OUT/'proof-bindings.json',dict(proofs=binding,focused_only=True,old_closed_suites_replayed=False,
        root_L3_v1_original_source_claim_withdrawn_corrected_v2_used=True,full_goal_complete=False))
    for name,value in zip(FILES[:4],[state,task,public,report]):replace(name,value)
    served,response=http(web['url']);assert served==report.encode()and service()==svc
    web.update(updated_utc=now.isoformat(),HTTP_status=response['status'],local_report_sha256=sha(served),
        served_report_sha256=sha(served),report_bytes=len(served),service_not_restarted=True,
        latest_native_country_address_checkpoint=str(OUT.relative_to(ROOT)),native_country_address_estimate_percent=30)
    replace(FILES[-1],web)
    assert read(FILES[0])==read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair']==read(FILES[1])['navigation_repair']==read(FILES[2])['navigation_repair']
    create(OUT/'fresh-readback.json',dict(all_passed=True,HTTP=response,report_sha256=sha(served),service=svc,
        native_country_estimate_percent=30,larger_candidate_installed=False,full_goal_complete=False))
    print(json.dumps(dict(all_passed=True,report_url=web['url'],full_country_estimate_percent=30,
        new_Taichung_houses=11002,full_goal_complete=False),ensure_ascii=False))


if __name__=='__main__':main()
