#!/usr/bin/env python3
"""Publish the checked single package and the actual USB availability."""
import copy
import gzip
import json
import os
import re
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT,create,http,read,replace,service,sha

OUT=ROOT/'staging/navigation-taichung-package-publication-v1'
FILES=['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json',
    'reports/nuvi2565RT.html','evidence/report-web-latest.json']


def main():
    assert not OUT.exists()
    before={n:(ROOT/n).read_bytes()for n in FILES};state,task,public=[json.loads(before[n])for n in FILES[:3]]
    web=json.loads(before[FILES[-1]]);svc=service();served,_=http(web['url']);assert served==before[FILES[3]]
    assert state==public['deep_research']and state['navigation_repair']==task['navigation_repair']==public['navigation_repair']
    package=read('staging/navigation-taichung-address-package-v1/package-result.json')
    tests=read('staging/navigation-taichung-address-package-v1/validation/new-transaction-results.json')
    available=read('staging/navigation-taichung-address-package-v1/validation/root-readonly-preflight.json')
    download=read('staging/navigation-taichung-download-publication-v1/download-verification.json')
    assert package['all_passed']and tests['all_assigned_checks_passed']and download['all_passed']
    assert tests['controls_passed']==35 and available['state']=='waiting_for_usb'and not available['device_files_written']
    assert package['sha256']==download['served_sha256']and package['bytes']==download['served_bytes']
    app=copy.deepcopy(state['native_app_music']);now=datetime.now(timezone.utc);local=now.astimezone(ZoneInfo('Asia/Taipei'))
    nav=state['navigation_repair'];larger=nav['taichung_larger_candidate']
    larger.update(status='packaged_validated_waiting_for_USB',package=package,installer_controls_passed=35,
        physical_device_present_at_preflight=False,physical_preflight_evidence='staging/navigation-taichung-address-package-v1/validation/root-readonly-preflight.json',
        device_installed=False,download_HTTP_full_readback_verified=True)
    old_action=state['next_actions'][0]
    action='較大台中候選已完整封裝、安裝／還原工具驗證通過；目前未偵測到USB，方便時再安排實機安裝與抽測。'
    for owner in [state,task]:owner['next_actions'][0]=action
    nav['remaining_next_actions'][0]=action;nav['next']=action
    nav['remaining_physical_checks']=['較大台中候選：接Pi USB隨身碟模式安裝，再以北屯／沙鹿／石岡新增門牌及民權舊例測位置、搜尋與路線。']
    nav['execution_status']='country_update_in_progress_Taichung_package_ready_waiting_for_USB'
    nav['updated_utc']=now.isoformat();state['updated_utc']=now.isoformat()
    state['last_goal_turn']=dict(classification='progress',validated_utc=now.isoformat(),goal_status=state['goal_status'],
        package_complete=True,full_goal_complete=False,required_work_remaining=True,device_files_written=False,
        physical_device_present=False,reason='Larger candidate packaged and LAN readback verified; full-country merge work continues while USB absent.')
    for key in ['navigation_repair','updated_utc','next_actions','last_goal_turn']:task[key]=copy.deepcopy(state[key])
    public.update(updated=now.isoformat(),deep_research=copy.deepcopy(state),navigation_repair=copy.deepcopy(nav))
    public['research_progress']['research_updated_utc']=now.isoformat();assert state['native_app_music']==app
    report=before[FILES[3]].decode();old='<p><a href="http://172.16.60.187:8767/Garmin-2565RT-address-test-v1.zip" download>既有民權路測試包</a>；新的較大更新包仍在準備。</p>'
    new=f'<p><a href="{package["download_url"]}" download>下載台中擴大完整測試包（約145 MB）</a>，包含較大AP、Search v2道路圖、校驗與精確還原工具。ZIP18個成員已讀回，區網完整下載雜湊一致。</p><p><a href="http://172.16.60.187:8767/Garmin-2565RT-address-test-v1.zip" download>既有已抽測民權路包</a>仍保留。</p><p>新尺寸安裝／還原35項控制通過；目前USB唯讀預檢未偵測到車機，尚未安裝較大候選。</p>'
    assert report.count(old)==1;report=report.replace(old,new);assert report.count(old_action)==1;report=report.replace(old_action,action)
    for identifier in ['report-updated-time','research-updated-time']:
        report,count=re.subn(r'<time id="'+identifier+r'" datetime="[^"]+">[^<]+</time>',
            lambda _:f'<time id="{identifier}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',report,count=1);assert count==1
    OUT.mkdir()
    for n,data in before.items():
        with (OUT/(n.replace('/','__')+'.gz')).open('xb')as f:f.write(gzip.compress(data,mtime=0));f.flush();os.fsync(f.fileno())
    for n,value in zip(FILES[:4],[state,task,public,report]):replace(n,value)
    served,response=http(web['url']);assert served==report.encode()and service()==svc
    web.update(updated_utc=now.isoformat(),HTTP_status=response['status'],local_report_sha256=sha(served),served_report_sha256=sha(served),
        report_bytes=len(served),service_not_restarted=True,latest_Taichung_package=package)
    replace(FILES[-1],web)
    assert read(FILES[0])==read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair']==read(FILES[1])['navigation_repair']==read(FILES[2])['navigation_repair']
    create(OUT/'fresh-readback.json',dict(all_passed=True,HTTP=response,report_sha256=sha(served),service=svc,
        download=download,package_members_verified=18,device_installed=False,full_goal_complete=False))
    print(json.dumps(dict(all_passed=True,report_url=web['url'],download_url=package['download_url'],state='waiting_for_USB'),ensure_ascii=False))


if __name__=='__main__':main()
