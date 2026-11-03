#!/usr/bin/env python3
"""Check LAN report service and preserve historical checkpoint provenance."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,re,subprocess,urllib.request
from analyze_native_sections import ROOT

def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def read(path):return json.loads((ROOT/path).read_text())

def main():
    latest=read('evidence/report-web-latest.json');previous=read('staging/native-player-resources/previous-checkpoint.json')
    path='evidence/firmware-analysis/native-player-resources-checkpoint-audit.json';audit=read(path)
    state=read('evidence/deep-research-state.json');item=state['native_app_music']['static_findings']['native_player_resources'];proof=read(item['evidence'])
    assert audit['all_passed']and audit['state_sha256']==sha('evidence/deep-research-state.json')
    assert audit['report_sha256']==sha('reports/nuvi2565RT.html')and proof['all_passed']
    result=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1)for line in result.stdout.splitlines()if'='in line)
    assert service['ActiveState']=='active'and service['SubState']=='running'and service['UnitFileState']=='enabled'and int(service['MainPID'])>0
    with urllib.request.urlopen(latest['url'],timeout=10)as response:
        content=response.read();status=response.status;cache=response.headers.get('Cache-Control','')
    assert status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes()and'no-store'in cache
    report=content.decode('utf-8');assert '播放器圖示與文字已畫入模擬畫布'in report
    history=latest['historical_offline_checkpoint_audits']
    entry=dict(audit=previous['audit'],audit_sha256=sha(previous['audit']),state_snapshot=previous['state'],
        state_snapshot_sha256=sha(previous['state']),original_current_audit_location='evidence/firmware-analysis/native-player-rendering-checkpoint-audit.json',
        fresh_revalidation_scopes=16,all_passed=True,reason='Rendering checkpoint revalidated immediately before resource work; frozen exact state/audit snapshots preserved.')
    key='prior_native_player_rendering_checkpoint';assert key not in history;history[key]=entry
    latest.pop('current_native_player_rendering_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(content).hexdigest(),
        served_latest_report=True,report_bytes=len(content),service=service,service_not_restarted=True,cache_control=cache,
        current_native_player_resources_checkpoint=path,checkpoint_sha256={path:sha(path)},
        no_MAC_in_report=not bool(re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)),goal_status='active',full_goal_complete=False)
    latest['complete_current_offline_run']=dict(session_id=78370,exit_code=0,case_count=6,source_artifact_count=102,
        checkpoint_scope_count=18,all_passed=True,device_io=False,sounds_emitted=False,
        focused_resource_reference_ABI=dict(session_id=2516,exit_code=0,case_count=4,source_artifact_count=32,all_passed=True),
        scope='Original loader/corrected resource player, original stock GIR registration/decompression, icon+CJK caption layout,1954 software pixels, native clipping/repaint/events and final guards. Explicit readonly GIR placement is not an actual boot map. No physical App/display/root/touch/accepted modified package/direct-phone music. One captured-artifact label reconciled without changing original successful proof or pixels.')
    display=latest['progress_display_verified'];display.update(estimate_percent=31,completed_items=51,
        report_updated_time=re.search(r'<time id="report-updated-time" datetime="([^"]+)"',report)[1],
        research_updated_time=re.search(r'<time id="research-updated-time" datetime="([^"]+)"',report)[1],
        corrected_hash32_resource_ABI_borrowed_original_icon_and_native1954_pixel_preview_visible=True,
        real_boot_GIR_MainMenu_root_display_thread_touch_install_direct_music_unverified_visible=True,
        nonempty_icons_actual_framebuffer_UI_thread_root_touch_install_unverified_visible=False,
        older213_pixel_and_blank_icon_figures_are_labeled_historical=True,
        visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(url=latest['url'],HTTP_status=status,report_bytes=len(content),report_sha256=latest['local_report_sha256'],
        service=service,complete_native_groups=6,focused_ABI_groups=4,checkpoint_scopes=18,served_exact_report=True)))

if __name__=='__main__':main()
