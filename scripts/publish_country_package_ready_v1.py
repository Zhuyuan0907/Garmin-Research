#!/usr/bin/env python3
"""Publish sealed partial-country package and honest offline/physical scopes."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

OUT = ROOT/'staging/navigation-country-package-publication-v1'
FILES = ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json',
    'reports/nuvi2565RT.html','evidence/report-web-latest.json']


def main():
    assert not OUT.exists()
    before={n:(ROOT/n).read_bytes() for n in FILES}
    state,task,public=[json.loads(before[n]) for n in FILES[:3]]
    web=json.loads(before[FILES[-1]]);svc=service();served,_=http(web['url'])
    assert served==before[FILES[3]] and state==public['deep_research']
    assert state['navigation_repair']==task['navigation_repair']==public['navigation_repair']
    package=read('staging/navigation-country-address-package-v1/package-result.json')
    download=read('staging/navigation-country-download-publication-v1/download-verification.json')
    native=read('staging/navigation-country-native-cpu-v1/proof.json')
    review=read('staging/navigation-country-merge-independent-review-v1/proof.json')
    tests=read('staging/navigation-country-address-package-v1/validation/country-binding-results.json')
    preflight=read('staging/navigation-country-address-package-v1/validation/root-readonly-preflight.json')
    assert package['all_passed'] and download['all_passed']
    assert native['all_assigned_checks_passed'] and review['all_assigned_checks_passed'] and tests['all_assigned_checks_passed']
    assert package['bytes']==download['served_bytes'] and package['sha256']==download['served_sha256']
    assert tests['controls_passed']==12 and preflight['state']=='waiting_for_usb' and not preflight['device_files_written']
    assert len(review['quantized_point_city_membership_outliers'])==1
    now=datetime.now(timezone.utc);local=now.astimezone(ZoneInfo('Asia/Taipei'))
    app=copy.deepcopy(state['native_app_music']);nav=state['navigation_repair'];current=nav['country_existing_street_candidate']
    current.update(status='packaged_validated_waiting_for_USB',native_CPU_verified=True,
        native_CPU_verification_scope='8 parent /11 new leaf /19 LBL fragments; complete search/UI/route not executed',
        native_CPU_candidate_read_bytes=73315,independent_source_review_verified=True,
        independent_new_rows_checked=111608,independent_old_groups_checked=30,
        native_grid_city_edge_outliers=copy.deepcopy(review['quantized_point_city_membership_outliers']),
        source_points_all_inside_expected_city=True,native_grid_membership_distinct_from_source_policy=True,
        install_package_ready=True,package=package,new_binding_controls_passed=12,
        inherited_transaction_controls_referenced=35,download_HTTP_full_readback_verified=True,
        physical_device_present_at_preflight=False,device_installed=False,device_search_verified=False,
        native_source_package_evidence=['staging/navigation-country-native-cpu-v1/proof.json',
            'staging/navigation-country-merge-independent-review-v1/proof.json',
            'staging/navigation-country-address-package-v1/package-result.json',
            'staging/navigation-country-address-package-v1/validation/country-binding-results.json',
            'staging/navigation-country-download-publication-v1/download-verification.json'])
    progress=nav['native_country_address_update_progress']
    progress.update(estimate_percent=45,updated_utc=now.isoformat(),
        phases=['全台來源規劃、精確街道／門牌文字配對與三層補充候選完成。',
            '111,608新整數門牌／15,679既有街道：整張圖資讀回、獨立來源核對、原韌體有限讀取及精確還原通過。',
            '約153 MB整合測試包已封裝並區網讀回；12新綁定控制及既有35項交易控制證據具備，實機尚待。',
            '繼續完整巷弄匹配、高雄37可驗證區、四個原生無區層城市、新街道／子號與矛盾資料處理。'])
    actions=['最新跨縣市門牌測試包已完成；接Pi USB隨身碟模式後安裝，再測民權路及新增L4／L5／L6門牌的搜尋、位置與路線。',
        '沿原階層串流比對完整巷弄名稱，區分已有門牌與真正缺少記錄，仍不猜名稱／位置。',
        '整合高雄可完整驗證的37區，以及四個原生無區層城市的來源區界；再處理新街道、子號和矛盾資料。',
        state['next_actions'][3]]
    state['next_actions']=actions;nav['remaining_next_actions']=copy.deepcopy(actions);nav['next']=actions[0]
    nav['remaining_physical_checks']=['最新跨縣市包：USB安裝／讀回後，抽測民權6/150/184及北屯一新一街1、三光巷35、仁美九巷92的位置／搜尋／路線。']
    nav['execution_status']='country_source_extensions_continue_latest_package_waits_for_USB'
    nav['updated_utc']=now.isoformat();state['updated_utc']=now.isoformat()
    state['last_goal_turn']=dict(classification='progress',validated_utc=now.isoformat(),goal_status=state['goal_status'],
        country_partial_package_complete=True,full_goal_complete=False,required_work_remaining=True,
        device_files_written=False,physical_device_present=False,
        reason='Actual partial country candidate packaged/readback/native/source verified; full dataset and physical acceptance remain pending.')
    for key in ['navigation_repair','updated_utc','next_actions','last_goal_turn']:task[key]=copy.deepcopy(state[key])
    public.update(updated=now.isoformat(),deep_research=copy.deepcopy(state),navigation_repair=copy.deepcopy(nav))
    public['research_progress']['research_updated_utc']=now.isoformat();assert state['native_app_music']==app
    report=before[FILES[3]].decode()
    report=report.replace('全台更新工程估計 <strong>40%</strong>','全台更新工程估計 <strong>45%</strong>',1)
    report=report.replace('<progress id="navigation-country-address-progress" max="100" value="40">40%</progress>',
        '<progress id="navigation-country-address-progress" max="100" value="45">45%</progress>',1)
    old='111,608筆為跨縣市候選的離線結果，尚未安裝，正在獨立核對來源與原韌體讀取；尚未完成跨縣市實機搜尋／路線驗收。'
    new='111,608筆新記錄已獨立核對來源及實際packed資料；原韌體有限讀取8父街道／11新門牌／19標籤片段通過。尚未安裝，完整實機搜尋／路線未驗收。'
    assert report.count(old)==1;report=report.replace(old,new)
    marker='<h3>可用測試包與既有實測</h3>'
    paragraph=f'<p><a href="{package["download_url"]}" download>下載最新跨縣市完整測試包（約153 MB）</a>：111,608筆新增整數門牌，包含AP、Search v2道路、校驗與精確還原工具；17個ZIP成員及區網完整下載校驗一致。新安裝綁定12項控制通過，實機USB預檢仍未偵測到車機。</p>'
    assert report.count(marker)==1;report=report.replace(marker,marker+paragraph)
    report,count=re.subn(r'<h3>接著處理</h3><ol>.*?</ol>',lambda _:'<h3>接著處理</h3><ol>'+''.join(f'<li>{a}</li>' for a in actions)+'</ol>',report,count=1,flags=re.S);assert count==1
    for identifier in ['navigation-address-updated-time','report-updated-time','research-updated-time']:
        report,count=re.subn(r'<time id="'+identifier+r'" datetime="[^"]+">[^<]+</time>',
            lambda _:f'<time id="{identifier}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',report,count=1);assert count==1
    note='來源位置均在指定市內；另有1筆市界附近的原生24-bit量化點跨界，已在包内独立核對記錄明列，未自動改來源坐標。實機目的地與路線仍待確認。'
    report=report.replace('<h3>資料限制</h3>', '<h3>資料限制</h3><p>'+note+'</p>',1)
    OUT.mkdir()
    for name,data in before.items():
        with (OUT/(name.replace('/','__')+'.gz')).open('xb') as f:f.write(gzip.compress(data,mtime=0));f.flush();os.fsync(f.fileno())
    for name,value in zip(FILES[:4],[state,task,public,report]):replace(name,value)
    served,response=http(web['url']);assert served==report.encode() and service()==svc
    web.update(updated_utc=now.isoformat(),HTTP_status=response['status'],local_report_sha256=sha(served),
        served_report_sha256=sha(served),report_bytes=len(served),service_not_restarted=True,latest_country_partial_package=package)
    replace(FILES[-1],web)
    assert read(FILES[0])==read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair']==read(FILES[1])['navigation_repair']==read(FILES[2])['navigation_repair']
    create(OUT/'publication-operation-receipts.json',dict(all_passed=True,
        package=dict(session_id=48916,initial_chunk='b08e8c',terminal_chunk='489ffa',exit_code=0),
        download_server_copy=dict(terminal_chunk='4ecdbb',exit_code=0),
        download_service_restart=dict(terminal_chunk='2ef8c1',exit_code=0),
        download_full_HTTP_readback=dict(terminal_chunk='cd1438',exit_code=0)))
    create(OUT/'fresh-readback.json',dict(all_passed=True,HTTP=response,report_sha256=sha(served),service=svc,
        package=package,download_service=download['service'],engineering_estimate_percent=45,
        device_installed=False,full_goal_complete=False))
    print(json.dumps(dict(all_passed=True,report_url=web['url'],download_url=package['download_url'],
        engineering_estimate_percent=45,device_installed=False),ensure_ascii=False))


if __name__=='__main__':main()
