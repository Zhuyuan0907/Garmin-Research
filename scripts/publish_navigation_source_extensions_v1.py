#!/usr/bin/env python3
"""Publish completed source preparation without upgrading device claims."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

OUT = ROOT/'staging/navigation-source-extension-checkpoint-v1'
FILES = ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json',
         'reports/nuvi2565RT.html','evidence/report-web-latest.json']
PINS = {
 'staging/navigation-country-lane-path-match-v1/proof.json':
 '174739c4a3866d98ac2ff1d79af9c981f311525f2029e951dccffa5752112ee1',
 'staging/navigation-kaohsiung-native-house-merge-v1/proof.json':
 '5c8502e617ed4b178237dd9d9228a7d84a1c8a995cd3311658237a31896c9704',
 'staging/navigation-flat-city-district-geometry-v1/proof.json':
 'd9961345335eea3b8ff0ff41f4aff6283d7053ecf367b6ce900f79ab9106186c'}

def main():
    assert not OUT.exists()
    evidence=[]
    for path, expected in PINS.items():
        raw=(ROOT/path).read_bytes()
        assert sha(raw)==expected
        proof=json.loads(raw)
        passed_key = ('all_assigned_preparation_checks_passed'
          if path.endswith('navigation-flat-city-district-geometry-v1/proof.json')
          else 'all_assigned_checks_passed')
        assert proof[passed_key]
        evidence.append(dict(path=path,sha256=expected,bytes=len(raw)))
    before={n:(ROOT/n).read_bytes() for n in FILES}
    state,task,public=[json.loads(before[n]) for n in FILES[:3]]
    web=json.loads(before[FILES[-1]])
    svc=service();served,_=http(web['url'])
    assert served==before[FILES[3]] and state==public['deep_research']
    assert state['navigation_repair']==task['navigation_repair']==public['navigation_repair']
    app=copy.deepcopy(state['native_app_music'])
    now=datetime.now(timezone.utc);local=now.astimezone(ZoneInfo('Asia/Taipei'))
    nav=state['navigation_repair']
    nav['source_extensions_checkpoint']={
      'updated_utc':now.isoformat(),
      'lane_path_matching':dict(source_groupkeys_checked=2278269,matched_groupkeys=1806069,
        actual_parents=122040,source_house_already_present=1729220,source_house_absent=76849,
        coordinates_and_complete_source_IDs_join_pending=True,native_write_ready=False),
      'kaohsiung_prepared_append':dict(new_integer_house_records=14530,updated_existing_streets=2255,
        original_records_retained=248612,complete_individual_districts=37,
        city_boundary_still_incomplete=True,source_and_exact_raw24_same_district_verified=True,
        IMG_composition_pending=True,device_installed=False),
      'flat_city_geometry':dict(cities=['臺北市','基隆市','新竹市','嘉義市'],source_districts=24,
        original_native_district_records=0,source_district_geometry_prerequisite_only=True,
        address_merge_pending=True,native_district_verified=False),
      'next_composition':dict(country_v2_in_progress=True,source_v1_and_KH_seals_immutable=True,
        omit_one_new_quantized_city_edge_outlier=True,native_CPU_pending=True,package_pending=True),
      'evidence':evidence,'device_files_written':False,'full_country_update_complete':False}
    # Keep the completed v1 package as the current installable artifact until
    # the new candidate has its own CPU, rollback and transaction bindings.
    assert nav['country_existing_street_candidate']['install_package_ready']
    assert not nav['country_existing_street_candidate']['device_installed']
    assert nav['native_country_address_update_progress']['estimate_percent']==45
    nav['updated_utc']=now.isoformat();state['updated_utc']=now.isoformat()
    state['last_goal_turn']=dict(classification='progress',validated_utc=now.isoformat(),
      goal_status=state['goal_status'],full_goal_complete=False,required_work_remaining=True,
      device_files_written=False,
      reason='Full lane-path matching and Kaohsiung append preparation completed; new source joins and candidate composition continue.')
    for key in ['navigation_repair','updated_utc','last_goal_turn']:task[key]=copy.deepcopy(state[key])
    public.update(updated=now.isoformat(),deep_research=copy.deepcopy(state),navigation_repair=copy.deepcopy(nav))
    public['research_progress']['research_updated_utc']=now.isoformat()
    assert state['native_app_music']==app
    report=before[FILES[3]].decode()
    marker='<h3>接著處理</h3>'
    assert report.count(marker)==1
    text='<h3>最新來源核對進度</h3><p>完整巷弄沿原廠階層比對完成：1,806,069組找到精確父項，1,729,220組原廠已有門牌；其餘76,849組正在回查來源座標與完整編號，尚不等於可新增數量。高雄37個完整區界已核對，14,530筆新增門牌及2,255條原街道的增量資料已讀回封存，正在組成下一版，尚未安裝。臺北、基隆、新竹、嘉義共24個來源區界也已準備，但原廠這四市沒有區層，仍按原搜尋結構處理。</p>'
    report=report.replace(marker,text+marker,1)
    for identifier in ['navigation-address-updated-time','report-updated-time','research-updated-time']:
        report,count=re.subn(r'<time id="'+identifier+r'" datetime="[^"]+">[^<]+</time>',
          lambda _:f'<time id="{identifier}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',
          report,count=1)
        assert count==1
    OUT.mkdir()
    for name,raw in before.items():
        with (OUT/(name.replace('/','__')+'.gz')).open('xb') as f:
            f.write(gzip.compress(raw,mtime=0));f.flush();os.fsync(f.fileno())
    for name,value in zip(FILES[:4],[state,task,public,report]):replace(name,value)
    served,response=http(web['url'])
    assert served==report.encode() and service()==svc
    web.update(updated_utc=now.isoformat(),HTTP_status=response['status'],local_report_sha256=sha(served),
      served_report_sha256=sha(served),report_bytes=len(served),service_not_restarted=True)
    replace(FILES[-1],web)
    assert read(FILES[0])==read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair']==read(FILES[1])['navigation_repair']==read(FILES[2])['navigation_repair']
    create(OUT/'publisher-attempts.json',dict(first_attempt_exit_code=1,first_attempt_chunk='c2f3b6',
      reason='Preparation proof uses a distinct success-key; corrected exact key before any canonical mutation.',
      first_attempt_canonical_mutations=False))
    create(OUT/'fresh-readback.json',dict(all_passed=True,evidence=evidence,HTTP=response,
      service=svc,report_sha256=sha(served),engineering_estimate_percent=45,device_files_written=False,
      current_v1_package_unchanged=True,full_goal_complete=False))
    print(json.dumps(dict(all_passed=True,report_url=web['url'],estimate_percent=45,device_files_written=False)))

if __name__=='__main__':main()
