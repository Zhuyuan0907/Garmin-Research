#!/usr/bin/env python3
"""Honor the user's decision to stop display-speed experiments."""
import copy
import gzip
import json
import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from publish_navigation_native_basis_checkpoint_v1 import ROOT, create, http, read, replace, service, sha

OUT = ROOT / 'staging/navigation-rendering-deferred-publication-v1'
EV = 'evidence/navigation-rendering-deferred-20261007-v1.json'
FILES = ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json',
         'reports/nuvi2565RT.html','evidence/report-web-latest.json']


def main():
    assert not OUT.exists() and not (ROOT/EV).exists()
    before = {n:(ROOT/n).read_bytes() for n in FILES}
    state,task,public = [json.loads(before[n]) for n in FILES[:3]]
    latest = json.loads(before[FILES[-1]])
    assert public['deep_research'] == state
    assert state['navigation_repair'] == task['navigation_repair'] == public['navigation_repair']
    svc=service(); raw,_=http(latest['url']); assert raw == before[FILES[3]]
    app=copy.deepcopy(state['native_app_music']); progress=copy.deepcopy(public['research_progress'])
    now=datetime.now(timezone.utc); local=now.astimezone(ZoneInfo('Asia/Taipei'))
    create(ROOT/EV,dict(recorded_utc=now.isoformat(),user_quote='沒事，應該也沒辦法改善，因為是機器本身就慢 這2011年的機器',
        interpreted_instruction='停止刷新效能測試，繼續全台地址更新。',
        north_up_test_result_provided=False,CPU_cause_proven=False,rendering_fixed=False,
        prior_simpler_detail_result='slight improvement',full_goal_complete=False))
    nav=state['navigation_repair']
    nav['rendering_issue'].update(status='deferred_by_user',user_stopped_further_testing=True,
        disposition_evidence=EV,north_up_comparison_pending=False,corrected=False)
    actions=['完成全台地址來源與原生街道對照，擴大原廠格式地址更新；完整全台更新尚未完成。',
        '保留原資料與精確還原，候選產出後再驗證新增地址、位置與路線。',
        '刷新測試依使用者指示停止；簡略稍微改善，未宣稱已修復或確認CPU瓶頸。',
        '導航搜尋與地址更新驗證完成後，再恢復手機音樂／App研究。']
    nav.update(updated_utc=now.isoformat(),next=actions[0],remaining_next_actions=actions,
        execution_status='expanding_native_addresses_rendering_tests_deferred',
        navigation_repair_status='single_street_trial_accepted_full_update_in_progress',
        remaining_physical_checks=['後續較大範圍地址候選實機驗證'])
    nav['known_limits'][2]='刷新慢與短暫破圖在原廠圖也會，簡略稍微改善；使用者已停止進一步效能測試。'
    state.update(updated_utc=now.isoformat(),current_priority=actions[0],next_actions=actions)
    state['last_goal_turn']=dict(classification='progress',validated_utc=now.isoformat(),goal_status=state['goal_status'],
        user_steering_evidence=EV,device_IO=False,full_goal_complete=False,required_work_remaining=True)
    for k in ['navigation_repair','updated_utc','current_priority','next_actions','last_goal_turn']: task[k]=copy.deepcopy(state[k])
    public.update(updated=now.isoformat(),deep_research=copy.deepcopy(state),navigation_repair=copy.deepcopy(nav))
    public['research_progress']['research_updated_utc']=now.isoformat()
    assert state['native_app_music']==app
    for k in ['estimate_percent','weighted_estimate_percent','phases','completed']: assert public['research_progress'][k]==progress[k]
    report=before[FILES[3]].decode()
    edits={
        '民權路補充抽測已驗收；全台更新與刷新改善繼續':'民權路補充抽測已驗收；繼續全台地址更新',
        'CPU原因尚未確認，正在比較北方向上與圖資顯示量。':'依使用者指示停止進一步刷新測試；未確認CPU瓶頸。',
        '保持簡略，將地圖畫面改北方向上，固定圖層以相同方式比較刷新；等待使用者回覆。':actions[0],
        '準備保留道路與地址處理的建物顯示減量候選，先驗證再安排實機比較。':actions[2],
        '整體導航搜尋、地址更新及刷新需求驗證完成後，再恢復手機音樂／App研究。':actions[3],
        '刷新慢與短暫破圖在原廠圖也會，簡略只稍微改善；根因與修復尚未完成。':nav['known_limits'][2],
    }
    for old,new in edits.items(): assert report.count(old)==1; report=report.replace(old,new)
    import re
    for identifier in ['report-updated-time','research-updated-time']:
        report,count=re.subn(r'<time id="'+identifier+r'" datetime="[^"]+">[^<]+</time>',
            lambda _:f'<time id="{identifier}" datetime="{local.isoformat(timespec="seconds")}">{local.strftime("%Y/%m/%d %H:%M:%S")}</time>',report,count=1)
        assert count==1
    OUT.mkdir()
    for n,data in before.items():
        with (OUT/(n.replace('/','__')+'.gz')).open('xb') as f: f.write(gzip.compress(data,mtime=0)); f.flush();os.fsync(f.fileno())
    for n,value in zip(FILES[:4],[state,task,public,report]): replace(n,value)
    served,response=http(latest['url']); assert served==report.encode() and service()==svc
    latest.update(updated_utc=now.isoformat(),HTTP_status=response['status'],local_report_sha256=sha(served),
        served_report_sha256=sha(served),report_bytes=len(served),service_not_restarted=True,
        rendering_tests_deferred_by_user=True,latest_rendering_disposition=EV)
    replace(FILES[-1],latest)
    assert read(FILES[2])['deep_research']==read(FILES[0])
    assert read(FILES[0])['navigation_repair']==read(FILES[1])['navigation_repair']==read(FILES[2])['navigation_repair']
    create(OUT/'fresh-readback.json',dict(all_passed=True,HTTP=response,report_sha256=sha(served),service=svc,
        user_further_rendering_test_pending=False,full_goal_complete=False))
    print(json.dumps(dict(all_passed=True,report_url=latest['url'],rendering_tests='deferred_by_user'),ensure_ascii=False))


if __name__=='__main__': main()
