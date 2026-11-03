#!/usr/bin/env python3
"""Check exact LAN report, preserving native and host evidence scopes."""
from datetime import datetime,timezone
import hashlib,json,re,subprocess,urllib.request
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()

def main():
    latest=read('evidence/report-web-latest.json');previous=read('staging/native-player-independent-signal/previous-checkpoint.json')
    path='evidence/firmware-analysis/native-independent-signal-checkpoint-audit.json';audit=read(path)
    assert audit['all_passed']and len(audit['scope_checks'])==28
    for key,p in [('state_sha256','evidence/deep-research-state.json'),('report_sha256','reports/nuvi2565RT.html')]:assert audit[key]==sha(p)
    result=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1)for line in result.stdout.splitlines()if'='in line)
    assert service['ActiveState']=='active'and service['SubState']=='running'and service['UnitFileState']=='enabled'and int(service['MainPID'])>0
    with urllib.request.urlopen(latest['url'],timeout=10)as response:
        content=response.read();status=response.status;cache=response.headers.get('Cache-Control','')
    assert status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes()and'no-store'in cache
    report=content.decode();assert all(s in report for s in ['原廠菜單回呼與播放控制器','二十七組主機控制測試通過','目前還沒有能安裝到車機的整合 App'])
    assert not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)and'REDACTED_PRIVATE_ID'not in report
    history=latest['historical_offline_checkpoint_audits'];key='prior_native_task_runtime_checkpoint'
    entry=dict(audit=previous['audit']['path'],audit_sha256=previous['audit']['sha256'],state_snapshot=previous['state']['path'],
        state_snapshot_sha256=previous['state']['sha256'],fresh_revalidation_scopes=20,all_passed=True,
        reason='Fresh20-scope101-finding checkpoint retained before independent original Signal callback-entry proof and separate ARM control component tests.')
    if key in history:assert history[key]==entry
    else:history[key]=entry
    for row in previous.values():assert sha(row['path'])==row['sha256']
    latest.pop('current_native_task_runtime_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(content).hexdigest(),
        served_latest_report=True,report_bytes=len(content),service=service,service_not_restarted=True,cache_control=cache,
        current_native_independent_signal_checkpoint=path,checkpoint_sha256={path:sha(path)},
        goal_status='active',full_goal_complete=False,no_MAC_in_report=True,user_explicitly_returned=True,current_physical_test_requested=False)
    latest['complete_current_offline_run']=dict(checkpoint_scope_count=28,prior_checkpoint_scope_count=20,
        checkpoint_all_scope_checks_passed=True,device_io=False,sounds_emitted=False,
        native_frozen_suites_revalidated=39,native_unique_exact_dependencies=430,
        native_and_control_source_dependencies_protected=435,
        complete_native_independent_signal_callback_entry_groups=4,callback_runtime_session=66913,
        full_scoped_callback_entry_and_live_endpoint_memory_guards_passed=True,callback_body_executed=False,
        separate_ARM_control_component_host_groups=27,separate_ARM_component_native_runtime_verified=False,
        no_combined_UI_direct_music_device_candidate=True,general_Menu_foreground_or_visible_device_App_verified=False,
        scope='Original independent80-byte Signal constructor/register/queue reaches405340 callback entry on actual Dispatcher through native vtables/adapter.4 scoped controls include exact ownership/recursion/ALL/ready/timed-node/active-stack-RAII/event2/resident-frames/full-memory guards; original cleanup Signal/Thread retained. Callback body not run. New ARM relocatable Start/Stop component passes27 ASan/UBSan host adapter groups; it is not linked to original worker/GUI/radio/audio. Static19 join and20 foreground-prerequisite CFGs guide next cold MainMenu body. No physical IRQ/GUI/App/direct-phone music, accepted package or safe unload proof.')
    latest['progress_display_verified'].update(estimate_percent=32,completed_items=79,
        report_updated_time=re.search(r'<time id="report-updated-time" datetime="([^"]+)"',report)[1],
        research_updated_time=re.search(r'<time id="research-updated-time" datetime="([^"]+)"',report)[1],
        callback_entry_before_body_and_host_only_control_component_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(url=latest['url'],HTTP_status=status,report_bytes=len(content),report_sha256=latest['local_report_sha256'],
        service=service,checkpoint_scopes=28,prior_scopes=20,served_exact_report=True)))

if __name__=='__main__':main()
