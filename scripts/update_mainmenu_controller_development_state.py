#!/usr/bin/env python3
"""Retain partial controller evidence and explicit user return/availability."""
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import hashlib,html,json,re
from analyze_native_sections import ROOT

def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def write(p,d):(ROOT/p).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')

def main():
    prefix='staging/native-player-mainmenu-controller/'
    staticpath=prefix+'controller-static-preflight.json';static=read(staticpath)
    metapath=prefix+'clock-argument-failure-metadata.json';meta=read(metapath);probe=read(meta['probe'])
    deadlinepath=prefix+'audio-pool-clock-argument-preflight.json';deadline=read(deadlinepath)
    indexpath=prefix+'preserved-development-evidence-index.json';index=read(indexpath)
    assert static['complete_bounded_CFG_count']==4 and meta['terminal_exit_code']==1 and not probe['completed']
    for p,s in index['source_artifact_sha256'].items():assert sha(p)==s,p
    state,task,public=read('evidence/deep-research-state.json'),read('evidence/task-state.json'),read('reports/findings.json')
    assert not state['user_resting']and state['attended_testing']['user_present']and not task['user_away']
    app=state['native_app_music'];assert len(app['static_findings'])==91
    key='general_MainMenu_controller_advancing_clock_development';assert key not in app['development_observations']
    app['development_observations'][key]=dict(
        static_evidence=staticpath,static_evidence_sha256=sha(staticpath),complete_bounded_CFG_count=4,
        terminal_metadata=metapath,terminal_metadata_sha256=sha(metapath),
        development_evidence=meta['probe'],development_evidence_sha256=sha(meta['probe']),
        preserved_development_evidence=indexpath,preserved_development_evidence_sha256=sha(indexpath),
        clock_argument_evidence=deadlinepath,clock_argument_evidence_sha256=sha(deadlinepath),
        original_controller_lookup_name='PageMainMenu',original_controller_entered=True,original_general_ctor_entered=True,
        original_controller_returned=False,original_root_registration_reached=False,full_scoped_final_guards_passed=False,
        native_failure_PC='0x3ec6aa',native_clock_word_fixture=180,native_wait_argument=1180,
        original_wait_argument_equals_original_clock_result_plus1000=True,
        inherited_fixed_clock_boundary_accepts_only1000=True,
        underlying_condition_mutex_owner_and_actual_kernel_time_units_unverified=True,
        device_io=False,sounds_emitted=False)
    actions=state['next_actions']
    actions[0]='Recover original3B4BA8 clock-result-plus1000 wait argument now exposed by advancing virtual time: controller49765 stopped at3EC6AA because old fixed-clock fixture expects1000, native argument is1180 from clock180. New scoped subclass/control must observe original3B4BB0 result, verify exact native argument and mutex inventory, retain declared absent-pool failure and execute original rejection/unlock. Do not alter frozen VMs, native code, arbitrary timeout acceptance or fake successful audio. Then rerun original405340 controller/root38E696 with full guards; this partial run entered40434C but never reached root registration.'
    actions[-1]='User explicitly returned and is available for future physical tests. Current work remains offline; no physical test needed or requested yet. Prepare/verify audio and pairing agent first when needed, and immediately prioritize any pairing request. Goal active/no-achieve.'
    app['remaining_work']=actions[:4]
    now=datetime.now(timezone.utc)
    state.update(updated_utc=now.isoformat())
    state['last_goal_turn'].update(validated_utc=now.isoformat(),next_focus=actions[0],
        latest_controller_development_evidence=meta['probe'],latest_controller_development_evidence_sha256=sha(meta['probe']),
        latest_controller_run_returned=False,latest_controller_run_root_registration_reached=False,
        latest_controller_run_full_scoped_final_guards_passed=False)
    state['last_goal_turn']['reasons'].append('Four original controller/name-lookup/post-registration CFGs recovered. Advancing-clock controller probe49765 failed before root registration on scoped fixed1000 boundary while native clock180 plus1000 gives1180; serializer failure19309 preserved with outcome unknown. No physical device fault or controller success claim.')
    state['latest_user_instruction'].update(instruction='使用者已返回並願意協助未來實機測試；目前繼續離線原生播放器／首頁控制器研究，有具體實機測試時告知步驟，配對立即優先。麥克風取消、音質精修擱置、AA後、Maps延後與不標記goal完成偏好保留。',recorded_utc=now.isoformat())
    state['attended_testing'].update(user_instruction='好的，如果有任何需要實際車機接入讓我嘗試的東西，也請再告訴我',recorded_utc=now.isoformat(),user_available_for_future_physical_tests=True,current_attended_test='No current physical test needed. Original controller stopped at a scoped advancing-clock wait-argument fixture; continue offline controls.')
    for k in ['updated_utc','next_actions','latest_user_instruction','attended_testing','last_goal_turn']:task[k]=state[k]
    public.update(deep_research=state,updated=now.isoformat());progress=public['research_progress']
    assert progress['estimate_percent']==32 and len(progress['completed'])==61
    progress.update(research_updated_utc=now.isoformat(),next='先修正模擬環境的等待值檢查，再重跑原廠首頁控制器、頁面掛接與前景顯示；之後驗證安全清理、實機 App 及手機直接藍牙音樂。')
    progress['phases'][4]['next']='首頁初始化已通過離線整合；修正前進時鐘下的等待值檢查，再接控制器、前景顯示、安全清理與原機載入。'
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    anchor='<p><strong>頁面目前仍是隱藏、零尺寸；實機 App 尚未完成。</strong>'
    assert report.count(anchor)==1
    paragraph='<p>最新控制器測試已進入原廠首頁建立流程，但尚未返回或進入頁面掛接。加入前進的模擬時鐘後，原廠等待值會跟著增加；既有測試介面只接受固定值，因此拒絕這次請求。已核對原始計算流程，下一步修正模擬介面並驗證。這不是實機故障，也沒有進行車機安裝或音訊測試。</p>'
    report=report.replace(anchor,paragraph+anchor,1)
    report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda m:'<p><strong>下一步：</strong>'+html.escape(progress['next'])+' 使用者已返回，目前無需操作實機；現場配對要求立即優先。</p>',report,count=1);assert n==1
    report,n=re.subn(r'(<tr><td>原生 App 入口與功能整合</td><td>10%</td><td>).*?(</td></tr>)',lambda m:m[1]+html.escape(progress['phases'][4]['next'])+m[2],report,count=1);assert n==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds');display=local.strftime('%Y/%m/%d %H:%M:%S')
    for ident in ['report-updated-time','research-updated-time']:
        report,n=re.subn(r'<time id="'+ident+r'" datetime="[^"]+">[^<]+</time>','<time id="'+ident+'" datetime="'+iso+'">'+display+'</time>',report,count=1);assert n==1
    write('evidence/deep-research-state.json',state);write('evidence/task-state.json',task);write('reports/findings.json',public)
    (ROOT/'reports/nuvi2565RT.html').write_text(report)
    print(json.dumps(dict(findings=91,estimate_percent=32,completed_items=61,user_present=True,controller_partial_terminal_exit1=True,updated_Taiwan=iso)))

if __name__=='__main__':main()
