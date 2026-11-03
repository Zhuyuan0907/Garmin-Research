#!/usr/bin/env python3
"""Verify the live LAN report for complete mutex-owner / partial dispatcher work."""
from datetime import datetime,timezone
import hashlib,json,re,subprocess,urllib.request
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()

def main():
    latest=read('evidence/report-web-latest.json');previous=read('staging/native-player-mutex-owner/previous-checkpoint.json')
    path='evidence/firmware-analysis/native-mutex-owner-checkpoint-audit.json';audit=read(path)
    assert audit['all_passed']and len(audit['scope_checks'])==22
    assert audit['state_sha256']==sha('evidence/deep-research-state.json')and audit['report_sha256']==sha('reports/nuvi2565RT.html')
    result=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1)for line in result.stdout.splitlines()if'='in line)
    assert service['ActiveState']=='active'and service['SubState']=='running'and service['UnitFileState']=='enabled'and int(service['MainPID'])>0
    with urllib.request.urlopen(latest['url'],timeout=10)as response:
        content=response.read();status=response.status;cache=response.headers.get('Cache-Control','')
    assert status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes()and'no-store'in cache
    report=content.decode();assert '原廠鎖定與同步初始化已驗證'in report and '解鎖時因擁有者欄位缺失而中止'in report
    assert not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)and'REDACTED_PRIVATE_ID'not in report
    key='prior_native_pool_clock_user_present_checkpoint';history=latest['historical_offline_checkpoint_audits']
    expected=dict(audit=previous['audit']['path'],audit_sha256=previous['audit']['sha256'],
        state_snapshot=previous['state']['path'],state_snapshot_sha256=previous['state']['sha256'],
        fresh_revalidation_scopes=19,all_passed=True,
        reason='Fresh19-scope pool clock/partial bootstrap checkpoint retained before five complete original owner controls and partial45010.')
    if key in history:assert history[key]==expected
    else:history[key]=expected
    for row in previous.values():assert sha(row['path'])==row['sha256']
    latest.pop('current_native_pool_clock_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(content).hexdigest(),
        served_latest_report=True,report_bytes=len(content),service=service,service_not_restarted=True,cache_control=cache,
        current_native_mutex_owner_checkpoint=path,checkpoint_sha256={path:sha(path)},
        goal_status='active',full_goal_complete=False,no_MAC_in_report=True,
        user_explicitly_returned=True,current_physical_test_requested=False)
    latest['complete_current_offline_run']=dict(checkpoint_scope_count=22,checkpoint_all_scope_checks_passed=True,
        device_io=False,sounds_emitted=False,general_Menu_controller_or_visible_device_App_verified=False,
        complete_mutex_owner_controls=dict(session_id=28332,exit_code=0,case_count=5,source_artifact_count=99,all_scoped_final_guards_passed=True),
        original_mutex_static=dict(complete_CFGs=5,mixed_ARM_Thumb_functions=3,mode_transitions=12),
        latest_dispatcher_development_run=dict(session_id=45010,exit_code=1,owner_gate_passed=True,
            wait_return_observed_in_recent=True,original_singleton_returned=False,full_scoped_final_guards_passed=False,
            native_fatal_code='0x6e5d800b',native_fatal_caller='0x3008e0',native_reacquire_caller='0x3ec692',
            reacquire_fallback_inferred_from_source_and_CFG=True),
        earlier_complete_pool_clock_controls=dict(session_id=31358,exit_code=0,case_count=5,source_artifact_count=98,all_scoped_final_guards_passed=True),
        earlier_general_Menu_constructor=dict(session_id=70973,exit_code=0,case_count=3,source_artifact_count=101,all_scoped_final_guards_passed=True),
        scope='Complete original immediate/recursive mutex owner/list/unlink and condition constructor IRQ/LR-return controls on explicitly fictional96-byte TCB. Owner fields written by original instructions. Original thread globals restored and all scoped final guards pass. Dispatcher45010 passes native owner gate then fails unowned unlock;3EC692 reacquire still falls into counter-only fixture. Equal fictional thread identity/native wake boundary do not establish real wait/event/scheduler. No complete dispatcher/controller/foreground/device App/direct audio/accepted loading or safe lifetime proof.')
    latest['progress_display_verified'].update(estimate_percent=32,completed_items=65,
        report_updated_time=re.search(r'<time id="report-updated-time" datetime="([^"]+)"',report)[1],
        research_updated_time=re.search(r'<time id="research-updated-time" datetime="([^"]+)"',report)[1],
        complete_native_owner_controls_and_failed_reacquire_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(url=latest['url'],HTTP_status=status,report_bytes=len(content),report_sha256=latest['local_report_sha256'],
        service=service,checkpoint_scopes=22,owner_groups=5,served_exact_report=True)))

if __name__=='__main__':main()
