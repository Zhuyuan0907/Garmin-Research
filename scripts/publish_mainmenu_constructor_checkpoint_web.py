#!/usr/bin/env python3
"""Verify live LAN report bytes and retain preceding settings checkpoint."""
from datetime import datetime,timezone
import hashlib,json,re,subprocess,urllib.request
from analyze_native_sections import ROOT

def read(p): return json.loads((ROOT/p).read_text())
def sha(p): return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()

def main():
    latest=read('evidence/report-web-latest.json')
    previous=read('staging/native-player-mainmenu-metadata/previous-checkpoint.json')
    path='evidence/firmware-analysis/native-mainmenu-constructor-checkpoint-audit.json';audit=read(path)
    assert audit['all_passed']and len(audit['scope_checks'])==15 and audit['state_sha256']==sha('evidence/deep-research-state.json')
    assert audit['report_sha256']==sha('reports/nuvi2565RT.html')
    out=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1)for line in out.stdout.splitlines()if'='in line)
    assert service['ActiveState']=='active'and service['SubState']=='running'and service['UnitFileState']=='enabled'and int(service['MainPID'])>0
    with urllib.request.urlopen(latest['url'],timeout=10)as response:
        content=response.read();status=response.status;cache=response.headers.get('Cache-Control','')
    assert status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes()and'no-store'in cache
    report=content.decode();assert '播放器已接入原廠首頁初始化'in report and '頁面目前仍是隱藏、零尺寸'in report
    key='prior_native_settings_writer_checkpoint';history=latest['historical_offline_checkpoint_audits']
    if key not in history:
        history[key]=dict(audit=previous['audit'],audit_sha256=sha(previous['audit']),state_snapshot=previous['state'],
            state_snapshot_sha256=sha(previous['state']),original_current_audit_location='evidence/firmware-analysis/native-settings-writer-checkpoint-audit.json',
            fresh_revalidation_scopes=12,all_passed=True,reason='Settings checkpoint freshly revalidated before metadata/Main work; exact snapshots retained.')
    assert history[key]['audit_sha256']==sha(previous['audit'])and history[key]['state_snapshot_sha256']==sha(previous['state'])
    returned_path=ROOT/'evidence/user-return-20261004-latest.json'
    if returned_path.exists():
        returned=read(str(returned_path.relative_to(ROOT)));archive=read(returned['prior_night_checkpoint'])
        for row in archive.values():assert sha(row['snapshot'])==row['sha256']
        nightkey='prior_native_mainmenu_constructor_night_checkpoint'
        if nightkey not in history:
            old=archive['evidence/firmware-analysis/native-mainmenu-constructor-checkpoint-audit.json']
            oldstate=archive['evidence/deep-research-state.json']
            history[nightkey]=dict(audit=old['snapshot'],audit_sha256=old['sha256'],state_snapshot=oldstate['snapshot'],
                state_snapshot_sha256=oldstate['sha256'],fresh_revalidation_scopes=14,all_passed=True,
                reason='Completed14-scope night checkpoint preserved before recording explicit user return; research findings unchanged.')
        latest['user_explicitly_returned']=True
        latest['current_physical_test_requested']=False
    latest.pop('current_native_settings_writer_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,local_report_sha256=sha('reports/nuvi2565RT.html'),
        served_report_sha256=hashlib.sha256(content).hexdigest(),served_latest_report=True,report_bytes=len(content),service=service,
        service_not_restarted=True,cache_control=cache,current_native_mainmenu_constructor_checkpoint=path,checkpoint_sha256={path:sha(path)},
        goal_status='active',full_goal_complete=False,no_MAC_in_report=not bool(re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)))
    latest['complete_current_offline_run']=dict(
        checkpoint_scope_count=15,all_scoped_final_guards_passed=True,device_io=False,sounds_emitted=False,
        general_Menu_controller_or_visible_device_App_verified=False,
        metadata_controls=dict(session_id=7075,exit_code=0,case_count=5,source_artifact_count=94,all_scoped_final_guards_passed=True),
        loaded_player_general_Menu_constructor=dict(session_id=70973,exit_code=0,case_count=3,source_artifact_count=101,
            original_ctor_returned=True,all_scoped_final_guards_passed=True,frame=[0,0,0,0],visibility=[0,0]),
        earlier_general_menu_development_run=dict(session_id=21207,exit_code=0,original_constructor_returned=True,
            all_scoped_final_guards_passed=False,compiled_player_loaded_by_original_loader=False),
        earlier_SQL_guard_assertion_run=dict(session_id=36971,exit_code=1,completed_groups=3,all_scoped_final_guards_passed=False),
        latest_controller_development_run=dict(session_id=49765,exit_code=1,original_controller_returned=False,
            root_registration_reached=False,full_scoped_final_guards_passed=False,native_clock_fixture=180,native_wait_argument=1180,
            next_focus='Verify original clock-result-plus1000 request instead of inherited fixed1000 lower boundary; no arbitrary timeout or successful audio stub.'),
        scope='Five original metadata/lookup/driver/fallback controls plus three original loaded-player general-menu constructor controls. Fifteen-row Grid contains Pi player; native121E default write/readback and full scoped guards pass. Lower storage/heap/kernel/GPS/boot inputs remain explicit fixtures; Page hidden/zero-size. Controller/root/foreground/recreation/safe lifetime/accepted loading/device App/direct audio remain open.')
    latest['progress_display_verified'].update(estimate_percent=32,completed_items=61,
        report_updated_time=re.search(r'<time id="report-updated-time" datetime="([^"]+)"',report)[1],
        research_updated_time=re.search(r'<time id="research-updated-time" datetime="([^"]+)"',report)[1],
        current_five_metadata_three_general_constructor_controls_and_hidden_page_limits_visible=True,
        visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(url=latest['url'],HTTP_status=status,report_bytes=len(content),report_sha256=latest['local_report_sha256'],
        service=service,checkpoint_scopes=15,metadata_groups=5,constructor_groups=3,served_exact_report=True)))

if __name__=='__main__': main()
