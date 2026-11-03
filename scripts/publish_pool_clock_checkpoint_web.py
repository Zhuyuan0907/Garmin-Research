#!/usr/bin/env python3
"""Verify live LAN bytes for the pool-clock / partial dispatcher checkpoint."""
from datetime import datetime,timezone
import hashlib,json,re,subprocess,urllib.request
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()

def main():
    latest=read('evidence/report-web-latest.json')
    previous=read('staging/native-player-pool-clock/previous-checkpoint.json')
    path='evidence/firmware-analysis/native-pool-clock-checkpoint-audit.json';audit=read(path)
    assert audit['all_passed'] and len(audit['scope_checks'])==19
    assert audit['state_sha256']==sha('evidence/deep-research-state.json')
    assert audit['report_sha256']==sha('reports/nuvi2565RT.html')
    result=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1) for line in result.stdout.splitlines() if '='in line)
    assert service['ActiveState']=='active' and service['SubState']=='running' and service['UnitFileState']=='enabled' and int(service['MainPID'])>0
    with urllib.request.urlopen(latest['url'],timeout=10) as response:
        content=response.read();status=response.status;cache=response.headers.get('Cache-Control','')
    assert status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes() and 'no-store'in cache
    report=content.decode();assert '原廠首頁控制器與同步流程'in report and '六項控制完成五項'in report
    assert not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID' not in report
    history=latest['historical_offline_checkpoint_audits']
    key='prior_native_mainmenu_constructor_user_present_checkpoint'
    assert key not in history
    history[key]=dict(audit=previous['audit']['path'],audit_sha256=previous['audit']['sha256'],
        state_snapshot=previous['state']['path'],state_snapshot_sha256=previous['state']['sha256'],
        fresh_revalidation_scopes=15,all_passed=True,
        reason='Fresh15-scope complete constructor/current-user-present checkpoint preserved before five pool clock controls and failed dispatcher research.')
    for row in previous.values():assert sha(row['path'])==row['sha256']
    latest.pop('current_native_mainmenu_constructor_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(content).hexdigest(),
        served_latest_report=True,report_bytes=len(content),service=service,service_not_restarted=True,cache_control=cache,
        current_native_pool_clock_checkpoint=path,checkpoint_sha256={path:sha(path)},
        goal_status='active',full_goal_complete=False,no_MAC_in_report=True,
        user_explicitly_returned=True,current_physical_test_requested=False)
    latest['complete_current_offline_run']=dict(
        checkpoint_scope_count=19,checkpoint_all_scope_checks_passed=True,device_io=False,sounds_emitted=False,
        general_Menu_controller_or_visible_device_App_verified=False,
        prior_metadata_controls=dict(session_id=7075,exit_code=0,case_count=5,source_artifact_count=94,all_scoped_final_guards_passed=True),
        prior_loaded_player_general_Menu_constructor=dict(session_id=70973,exit_code=0,case_count=3,source_artifact_count=101,all_scoped_final_guards_passed=True,frame=[0,0,0,0],visibility=[0,0]),
        complete_pool_clock_controls=dict(session_id=31358,exit_code=0,case_count=5,source_artifact_count=98,all_scoped_final_guards_passed=True),
        latest_controller_development_run=dict(session_id=15754,exit_code=1,root_registration_entered=True,root_registration_completed=False,original_controller_returned=False,full_scoped_final_guards_passed=False),
        latest_dispatcher_development_run=dict(session_id=73611,exit_code=1,planned_groups=6,completed_groups=5,original_singleton_constructor_returned=False,full_scoped_final_guards_passed=False,native_fatal_code='0x6e5d8016',native_fatal_caller='0x3ec5ea'),
        scope='Complete pool clock+1000/u32/repeated-call controls and exact native failure/unlock, with full guards. Earlier metadata and loaded-player MainMenu constructor remain frozen. Controller now entered root registration but did not finish; six-control dispatcher run remains failed at native condition owner gate with five partial cases. Heap/clock/kernel inputs remain explicit fixtures. No foreground/device App/direct audio/accepted loading or safe lifetime proof.')
    latest['progress_display_verified'].update(estimate_percent=32,completed_items=63,
        report_updated_time=re.search(r'<time id="report-updated-time" datetime="([^"]+)"',report)[1],
        research_updated_time=re.search(r'<time id="research-updated-time" datetime="([^"]+)"',report)[1],
        complete_pool_clock_and_failed_dispatcher_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(url=latest['url'],HTTP_status=status,report_bytes=len(content),report_sha256=latest['local_report_sha256'],service=service,checkpoint_scopes=19,pool_groups=5,served_exact_report=True)))

if __name__=='__main__':main()
