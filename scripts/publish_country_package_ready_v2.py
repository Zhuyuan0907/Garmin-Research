#!/usr/bin/env python3
"""Publish a verified v2 package while preserving physical and full-goal gaps."""
import copy
import gzip
import json
import os
import re
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT,create,http,read,replace,service,sha

OUT=ROOT/'staging/navigation-country-package-publication-v2'
FILES=['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json',
       'reports/nuvi2565RT.html','evidence/report-web-latest.json']

def main():
    assert not OUT.exists()
    before={n:(ROOT/n).read_bytes() for n in FILES}
    state,task,public=[json.loads(before[n]) for n in FILES[:3]]
    web=json.loads(before[FILES[-1]]);svc=service();served,_=http(web['url'])
    assert served==before[FILES[3]] and state==public['deep_research']
    assert state['navigation_repair']==task['navigation_repair']==public['navigation_repair']
    package=read('staging/navigation-country-address-package-v2/package-result.json')
    download=read('staging/navigation-country-v2-download-publication/download-verification.json')
    host=read('staging/navigation-country-native-candidate-v2/proof.json')
    cpu=read('staging/navigation-country-native-cpu-v2/proof.json')
    review=read('staging/navigation-country-v2-rebase-review/proof.json')
    restore=read('staging/navigation-country-layout-restore-v2/proof.json')
    tests=read('staging/navigation-country-address-package-v2/validation/country-v2-binding-results.json')
    manifest=read('staging/navigation-country-address-package-v2/manifest.json')
    lane_raw=(ROOT/'staging/navigation-country-lane-absent-source-join-v1/proof.json').read_bytes()
    assert sha(lane_raw)=='4b44c17242fe2ef4ac179d4c7c8aafc2750d401e1fb9be263c359959722bd9dd'
    lane=json.loads(lane_raw)
    assert lane['all_assigned_checks_passed'] and lane['counts']['ready_targets']==58233 and not lane['native_write_ready']
    assert package['all_passed'] and download['all_passed']
    assert all(p['all_assigned_checks_passed'] for p in (host,cpu,review,restore,tests))
    assert package['bytes']==download['served_bytes'] and package['sha256']==download['served_sha256']
    assert package['new_houses']==review['all_new_rows_reviewed']==130637
    assert package['existing_streets']==review['all_selected_parents_reviewed']==18823
    assert tests['controls_passed']==7 and review['omitted_exact_outlier_count']==1
    now=datetime.now(timezone.utc);local=now.astimezone(ZoneInfo('Asia/Taipei'))
    nav=state['navigation_repair'];app=copy.deepcopy(state['native_app_music'])
    nav['country_existing_street_candidate_v1']=copy.deepcopy(nav['country_existing_street_candidate'])
    evidence=['staging/navigation-country-native-candidate-v2/proof.json',
      'staging/navigation-country-v2-rebase-review/proof.json','staging/navigation-country-native-cpu-v2/proof.json',
      'staging/navigation-country-layout-restore-v2/proof.json','staging/navigation-country-address-package-v2/package-result.json',
      'staging/navigation-country-address-package-v2/validation/country-v2-binding-results.json',
      'staging/navigation-country-v2-download-publication/download-verification.json']
    nav['country_existing_street_candidate']=dict(status='packaged_validated_waiting_for_USB',
      candidate_path=host['candidate_path'],bytes=host['candidate_bytes'],sha256=host['candidate_sha256'],
      new_integer_houses=130637,existing_streets_updated=18823,
      new_houses_by_leaf_level=manifest['new_houses_by_leaf_level'],
      original_records_cloned_with_significant_bits_preserved=1854236,
      original_4K_geometry_and_other_five_components_unchanged=True,
      all_47870_parent_fields_and_18823_merged_groups_readback_verified=True,
      compact_restore_recipe_bytes=restore['recipe_bytes'],exact_original_hash_stream_reconstructed=True,
      native_CPU_verified=True,native_CPU_parent_records=cpu['exact_parent_count'],
      native_CPU_new_leaf_records=cpu['exact_new_leaf_count'],native_CPU_candidate_read_bytes=cpu['total_actual_candidate_bytes_read'],
      native_CPU_verification_scope='Finite actual new candidate parser/directory/packed prefixes/LBL; complete search/UI/route not executed',
      independent_source_review_verified=True,independent_new_rows_checked=130637,
      exact_three_source_rebase_verified=True,omitted_new_quantized_city_edge_outliers=1,
      inherited_source_geometry_review_separate=True,Kaohsiung_individual_complete_districts=37,
      flat_cities_native_district_verified=False,flat_cities_original_city_to_street_structure_preserved=True,
      install_package_ready=True,package=package,new_binding_controls_passed=7,
      inherited_transaction_controls_referenced=35,download_HTTP_full_readback_verified=True,
      physical_device_installation_pending=True,device_installed=False,device_search_verified=False,
      full_Taiwan_update_complete=False,evidence=evidence)
    if 'source_extensions_checkpoint' in nav:
        checkpoint=nav['source_extensions_checkpoint']
        checkpoint['lane_path_matching'].update(coordinates_and_complete_source_IDs_join_pending=False,
          source_join_complete=True,geometry_qualified_integer_targets=58233,held_targets=18616,
          native_tree_overlay_pending=True,native_write_ready=False)
        checkpoint['next_composition'].update(country_v2_in_progress=False,candidate_complete=True,
          native_CPU_pending=False,package_pending=False,device_installation_pending=True)
        checkpoint['kaohsiung_prepared_append'].update(IMG_composition_pending=False,in_v2_package=True)
        checkpoint['flat_city_geometry'].update(address_merge_pending=False,new_integer_houses=4500,
          existing_streets_updated=889,in_v2_package=True)
    nav['lane_missing_house_source_join']=dict(counts=lane['counts'],ready_actual_parent_count=20613,
      source_provenance_and_geometry_planning_verified=True,native_tree_overlay_pending=True,native_write_ready=False,
      device_installed=False,evidence='staging/navigation-country-lane-absent-source-join-v1/proof.json')
    nav['native_country_address_update_progress'].update(estimate_percent=50,updated_utc=now.isoformat(),
      phases=['全台來源規劃及完整巷弄精確階層比對完成，門牌／座標矛盾與子號仍分別處理。',
        '130,637新整數門牌／18,823既有街道，三源合併、實際讀回與完整新葉重排核對通過。',
        '原韌體有限讀取、精確原檔還原、新安裝綁定與整包ZIP／區網下載校驗通過；實機尚待。',
        '繼續巷弄缺項的原生樹狀索引、新街道／行政区、子號及完整實機搜尋／路線驗收。'])
    actions=['最新v2整合門牌包已完成；USB隨身碟模式接Pi後安裝讀回，再測民權控制及新增直接／巷弄門牌搜尋、位置與路線。',
      '完整巷弄的缺項來源須完成原生父子樹及位寬／容量處理，不能只追加葉而保留舊父指標。',
      '繼續新街道／行政區、子號與矛盾資料，保留原地址搜尋選單；全台完整更新尚未完成。',
      state['next_actions'][3]]
    state['next_actions']=actions;nav['remaining_next_actions']=copy.deepcopy(actions);nav['next']=actions[0]
    nav['remaining_physical_checks']=['最新v2安裝／讀回後，再依序抽測民權路控制與新增L4／L5／L6、部分高雄／原生無區層城市的搜尋位置路線。']
    nav['execution_status']='country_v2_package_waits_for_USB_and_lane_tree_source_work_continues'
    nav['updated_utc']=now.isoformat();state['updated_utc']=now.isoformat()
    state['last_goal_turn']=dict(classification='progress',validated_utc=now.isoformat(),goal_status=state['goal_status'],
      country_v2_partial_package_complete=True,full_goal_complete=False,required_work_remaining=True,device_files_written=False,
      reason='Three-source partial country candidate fully packaged with new native/source/restore bindings; physical/full dataset gaps remain.')
    for key in ['navigation_repair','updated_utc','next_actions','last_goal_turn']:task[key]=copy.deepcopy(state[key])
    public.update(updated=now.isoformat(),deep_research=copy.deepcopy(state),navigation_repair=copy.deepcopy(nav))
    public['research_progress']['research_updated_utc']=now.isoformat();assert state['native_app_music']==app
    report=before[FILES[3]].decode()
    report=report.replace('全台更新工程估計 <strong>45%</strong>','全台更新工程估計 <strong>50%</strong>',1)
    report=report.replace('<progress id="navigation-country-address-progress" max="100" value="45">45%</progress>',
      '<progress id="navigation-country-address-progress" max="100" value="50">50%</progress>',1)
    marker='<h3>可用測試包與既有實測</h3>';assert report.count(marker)==1
    mb=package['bytes']/1000000
    text=(f'<p><a href="{package["download_url"]}" download>下載最新跨縣市門牌測試包 v2（約{mb:.0f} MB）</a>：130,637筆新整數門牌／18,823條既有街道，含高雄完整個別區界及四個原生無區層城市的補充。三源合併、全新葉來源重排核對、原韌體有限讀取及精確還原通過，7項新安裝綁定控制與ZIP／區網完整下載校驗一致；尚未實機安裝。前版1筆原生座標量化跨市界的新門牌已排除，原廠資料保留。</p>')
    report=report.replace(marker,marker+text,1)
    report=report.replace('下載最新跨縣市完整測試包（約153 MB）','下載前版跨縣市測試包 v1（約153 MB）',1)
    report,count=re.subn(r'<h3>最新來源核對進度</h3><p>.*?</p>',
      lambda _:'<h3>最新來源核對進度</h3><p>完整巷弄有1,806,069組精確階層匹配，其中1,729,220組原廠已有門牌；其餘76,849組已回查完整來源及座標，留下58,233筆整數門牌規劃候選、18,616組暫留。這批仍需更新原生父子樹，尚未寫入图資。高雄14,530筆與四個原生無區層城市4,500筆已併入最新v2。原街道／原地址選單保留，新街道、子號、矛盾資料及完整實機驗收仍未完成。</p>',report,count=1,flags=re.S)
    assert count==1
    report,count=re.subn(r'<h3>接著處理</h3><ol>.*?</ol>',
      lambda _:'<h3>接著處理</h3><ol>'+''.join(f'<li>{a}</li>' for a in actions)+'</ol>',report,count=1,flags=re.S)
    assert count==1
    for identifier in ['navigation-address-updated-time','report-updated-time','research-updated-time']:
        report,count=re.subn(r'<time id="'+identifier+r'" datetime="[^"]+">[^<]+</time>',
          lambda _:f'<time id="{identifier}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',report,count=1)
        assert count==1
    OUT.mkdir()
    for name,raw in before.items():
        with (OUT/(name.replace('/','__')+'.gz')).open('xb') as f:f.write(gzip.compress(raw,mtime=0));f.flush();os.fsync(f.fileno())
    for name,value in zip(FILES[:4],[state,task,public,report]):replace(name,value)
    served,response=http(web['url']);assert served==report.encode() and service()==svc
    web.update(updated_utc=now.isoformat(),HTTP_status=response['status'],local_report_sha256=sha(served),
      served_report_sha256=sha(served),report_bytes=len(served),service_not_restarted=True,latest_country_partial_package=package)
    replace(FILES[-1],web)
    assert read(FILES[0])==read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair']==read(FILES[1])['navigation_repair']==read(FILES[2])['navigation_repair']
    create(OUT/'fresh-readback.json',dict(all_passed=True,HTTP=response,report_sha256=sha(served),service=svc,
      package=package,download_service=download['service'],engineering_estimate_percent=50,
      device_installed=False,full_goal_complete=False))
    print(json.dumps(dict(all_passed=True,report_url=web['url'],download_url=package['download_url'],
      engineering_estimate_percent=50,device_installed=False),ensure_ascii=False))

if __name__=='__main__':main()
