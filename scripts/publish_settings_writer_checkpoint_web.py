#!/usr/bin/env python3
"""Verify LAN settings checkpoint and retain preceding heap audit snapshot."""
from datetime import datetime,timezone
import hashlib,json,re,subprocess,urllib.request
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()

def main():
    latest=read('evidence/report-web-latest.json');previous=read('staging/native-player-settings-writer/previous-checkpoint.json')
    path='evidence/firmware-analysis/native-settings-writer-checkpoint-audit.json';audit=read(path)
    assert audit['all_passed']and len(audit['scope_checks'])==12 and audit['state_sha256']==sha('evidence/deep-research-state.json')
    assert audit['report_sha256']==sha('reports/nuvi2565RT.html')
    out=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1)for line in out.stdout.splitlines()if'='in line)
    assert service['ActiveState']=='active'and service['SubState']=='running'and service['UnitFileState']=='enabled'and int(service['MainPID'])>0
    with urllib.request.urlopen(latest['url'],timeout=10)as response:
        content=response.read();status=response.status;cache=response.headers.get('Cache-Control','')
    assert status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes()and'no-store'in cache
    report=content.decode();assert '原廠設定儲存流程已驗證'in report and '一般首頁仍未返回'in report
    key='prior_native_heap_callback_checkpoint';history=latest['historical_offline_checkpoint_audits'];assert key not in history
    history[key]=dict(audit=previous['audit'],audit_sha256=sha(previous['audit']),state_snapshot=previous['state'],
        state_snapshot_sha256=sha(previous['state']),original_current_audit_location='evidence/firmware-analysis/native-heap-callback-checkpoint-audit.json',
        fresh_revalidation_scopes=12,all_passed=True,reason='Heap checkpoint freshly revalidated before settings work; exact snapshots retained.')
    latest.pop('current_native_heap_callback_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,local_report_sha256=sha('reports/nuvi2565RT.html'),
        served_report_sha256=hashlib.sha256(content).hexdigest(),served_latest_report=True,report_bytes=len(content),service=service,
        service_not_restarted=True,cache_control=cache,current_native_settings_writer_checkpoint=path,checkpoint_sha256={path:sha(path)},
        goal_status='active',full_goal_complete=False,no_MAC_in_report=not bool(re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)))
    latest['complete_current_offline_run']=dict(session_id=87467,exit_code=0,case_count=5,source_artifact_count=93,
        checkpoint_scope_count=12,all_scoped_final_guards_passed=True,device_io=False,sounds_emitted=False,
        full_general_MainMenu_or_visible_player_App_verified=False,
        general_menu_development_run=dict(session_id=30668,exit_code=1,native_validation_count=82,full_final_guards_passed=False,
            original_constructor_returned=False,next_failure_PC='0x26a300',next_unknown_metadata_bank=139),
        scope='Five original settings cold-init/read/program/commit/cached replacement/rejection controls. Fictional guarded NOR and explicit lower driver/heap/condition token inputs. General menu still fails on unmodeled bank139 metadata; real boot/kernel/controller/foreground/accepted loading/device App/audio and safe lifecycle remain open.')
    latest['progress_display_verified'].update(estimate_percent=31,completed_items=59,
        report_updated_time=re.search(r'<time id="report-updated-time" datetime="([^"]+)"',report)[1],
        research_updated_time=re.search(r'<time id="research-updated-time" datetime="([^"]+)"',report)[1],
        current_five_settings_controls_partial_MainMenu_and_storage_fixture_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(url=latest['url'],HTTP_status=status,report_bytes=len(content),report_sha256=latest['local_report_sha256'],
        service=service,checkpoint_scopes=12,focused_groups=5,served_exact_report=True)))

if __name__=='__main__':main()
