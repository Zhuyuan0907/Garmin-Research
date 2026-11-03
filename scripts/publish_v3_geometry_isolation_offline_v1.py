"""Publish a noninstallable geometry experiment, preserving device/goal scope."""
import copy
import gzip
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

FILES = ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json',
         'reports/nuvi2565RT.html','evidence/report-web-latest.json']


def main():
    folder = ROOT/'staging/navigation-v3-expanded4k-offline-isolation-v1'
    raw = (folder/'proof.json').read_bytes()
    assert sha(raw) == '7b5315087aebfda01db11d72bc206aaba23780031d90b92edcfcee3c0188c41a'
    p = json.loads(raw)
    assert p['all_assigned_checks_passed'] and p['all_six_logical_components_byte_identical_to_v3']
    assert not p['installable'] and not p['live_device_IO'] and not p['current_display_bug_fixed']
    assert p['output_bytes'] == 153337856 and len(p['complete_actual_logical_component_readback']) == 6
    now = datetime.now(timezone.utc); local = now.astimezone(ZoneInfo('Asia/Taipei'))
    before = {n:(ROOT/n).read_bytes() for n in FILES}
    state,task,public = [json.loads(before[n]) for n in FILES[:3]];web = json.loads(before[FILES[4]])
    assert state == public['deep_research'] and state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    assert state['goal_status'] == 'active' and not state['attended_testing']['user_present']
    assert state['attended_testing']['no_pending_question']
    svc = service(); served,_ = http(web['url']); assert served == before[FILES[3]]
    app = copy.deepcopy(state['native_app_music'])
    nav = state['navigation_repair'];current_v2 = copy.deepcopy(nav['latest_country_v2_comparison_checkpoint'])
    checkpoint = dict(updated_utc=now.isoformat(),proof=str((folder/'proof.json').relative_to(ROOT)),proof_sha256=sha(raw),
        actual_terminal='cbed67 EXIT0; exec session1111', output=p['output'],output_bytes=p['output_bytes'],output_sha256=p['output_sha256'],
        all_six_logical_components_preserved=True,only_explicit_4K_capacity_header_changes=True,
        opaque_checksum_and_CHS_preserved_but_acceptance_unknown=True,installable=False,device_IO=False,
        actual_AP_renderer_executed=False,current_display_bug_fixed=False,
        current_device_candidate='verified_country_AP_v2_4K',full_Taiwan_update_complete=False)
    nav['v3_expanded4K_offline_isolation_checkpoint'] = checkpoint
    phases = nav['native_country_address_update_progress']['phases']
    phases[:] = [x for x in phases if not x.startswith('v3離線4K隔離')]
    phases.append('v3離線4K隔離：153,337,856-byte實驗封裝完整讀回，六個實際元件與v3逐byte相同；僅改容量宣告／配置，未知checksum／CHS與原繪圖接受度仍未解，檔案不可安裝。')
    nav['native_country_address_update_progress']['updated_utc'] = now.isoformat()
    nav['updated_utc'] = now.isoformat();state['updated_utc'] = now.isoformat()
    state['offline_24h_work_order']['latest_completed_offline_checkpoint'] = copy.deepcopy(checkpoint)
    state['navigation_repair'] = nav
    for k in ['updated_utc','navigation_repair','offline_24h_work_order']:
        task[k] = copy.deepcopy(state[k])
    public.update(updated=now.isoformat(),deep_research=copy.deepcopy(state),navigation_repair=copy.deepcopy(nav),
        native_country_address_update_progress=copy.deepcopy(nav['native_country_address_update_progress']),
        offline_24h_work_order=copy.deepcopy(state['offline_24h_work_order']))
    public['research_progress']['research_updated_utc'] = now.isoformat()
    assert state['native_app_music'] == app and nav['latest_country_v2_comparison_checkpoint'] == current_v2
    assert nav['native_country_address_update_progress']['estimate_percent'] == 75
    report = before[FILES[3]].decode()
    paragraph = ('<p id="v3-expanded4k-offline-result">最新離線結果：已把v3六個元件完整重新封裝到4K區塊，'
                 '153 MB實驗檔讀回內容一致，188,870筆補充門牌資料未變；checksum／CHS及原機繪圖接受度仍未知，'
                 '目前只供隔離問題研究，不可安裝。車機繼續保留已通過限定實測的v2。</p>')
    if 'id="v3-expanded4k-offline-result"' in report:
        report,count = re.subn(r'<p id="v3-expanded4k-offline-result">.*?</p>',paragraph,report,count=1,flags=re.S);assert count==1
    else:
        marker = '<section class="card" id="offline-research-24h">'
        assert report.count(marker)==1;report=report.replace(marker,marker+paragraph,1)
    report,count = re.subn(r'<h3>已完成</h3><ul>.*?</ul>',lambda _: '<h3>已完成</h3><ul>'+''.join('<li>'+x+'</li>' for x in phases)+'</ul>',report,count=1,flags=re.S);assert count==1
    for ident in ['navigation-address-updated-time','report-updated-time','research-updated-time']:
        report,count = re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>',
            lambda _: f'<time id="{ident}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',report,count=1);assert count==1
    out=ROOT/'staging'/('v3-geometry-offline-publication-'+now.strftime('%Y%m%dT%H%M%S%fZ'));out.mkdir()
    for name,data in before.items():
        with (out/(name.replace('/','__')+'.gz')).open('xb') as f:f.write(gzip.compress(data,mtime=0));f.flush();os.fsync(f.fileno())
    for name,value in zip(FILES[:4],[state,task,public,report]):replace(name,value)
    served,response=http(web['url']);assert served==report.encode() and service()==svc
    web.update(updated_utc=now.isoformat(),HTTP_status=response['status'],local_report_sha256=sha(served),
        served_report_sha256=sha(served),report_bytes=len(served),service_not_restarted=True,
        v3_expanded4K_offline_isolation_checkpoint=checkpoint,
        offline_24h_work_order=copy.deepcopy(state['offline_24h_work_order']))
    replace(FILES[4],web)
    assert read(FILES[0]) == read(FILES[2])['deep_research']
    assert read(FILES[0])['navigation_repair']==read(FILES[1])['navigation_repair']==read(FILES[2])['navigation_repair']
    assert read(FILES[2])['native_country_address_update_progress']==read(FILES[0])['navigation_repair']['native_country_address_update_progress']
    create(out/'fresh-readback.json',dict(all_passed=True,service=svc,report_sha256=sha(served),
        native_country_engineering_estimate_percent=75,installable=False,device_IO=False,full_goal_complete=False))
    print(json.dumps(dict(all_passed=True,checkpoint=str(out.relative_to(ROOT)),report_url=web['url'],installable=False)))


if __name__=='__main__':
    main()
