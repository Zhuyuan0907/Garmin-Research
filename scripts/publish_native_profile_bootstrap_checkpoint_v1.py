#!/usr/bin/env python3
"""Publish the newly completed bounded native profile bootstrap evidence."""
import json, hashlib, importlib.util, re, html, urllib.request
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('frozen_warm_publisher',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
read=P.read;sha=P.sha;create=P.create;write=P.write
B='staging/native-audio-profile-bootstrap-checkpoint/'
G='staging/native-audio-profile-bootstrap/'
OLD='evidence/firmware-analysis/native-warm-probe-ROOT-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-profile-bootstrap-ROOT-checkpoint-audit.json'
SOURCE='scripts/publish_native_profile_bootstrap_checkpoint_v1.py'

def main():
    assert not(ROOT/B).exists() and not(ROOT/OUT).exists(),'Preserve earlier attempts; use new namespace'
    previous=read(OLD);assert previous['all_passed'] and previous['current_findings']==249
    assert len(previous['protected_sources'])==3237
    assert all(sha(p)==h for p,h in previous['canonical_after_sha256'].items())
    protected=dict(previous['protected_sources']);verified={}
    def register(entries):
        for p,h in entries.items():
            if p not in verified:verified[p]=sha(p)
            assert verified[p]==h,p
            assert p not in protected or protected[p]==h,p
            protected[p]=h
    # Revalidate once before publication; canonical readback below never uses
    # this immutable-source cache.
    register(previous['protected_sources'])
    for name in ('static-v1-terminal-tool-receipt.json','guest-v1-terminal-tool-receipt.json','FILE-v1-terminal-tool-receipt.json'):
        r=read(G+name);assert r['terminal'] and r['actual_terminal_result']['exit_code']==0
        assert 'session_id' not in r['actual_terminal_result']
    static=read(G+'original-cold-profile-sentinel-contract-v1.json')
    guest=read(G+'original-profile-bootstrap-v1-proof.json')
    files=read(G+'ROOT-profile-bootstrap-file-proof-v1.json')
    assert all(x['all_passed'] and not x['device_IO'] for x in (static,guest,files))
    assert guest['case_count']==files['case_count']==1 and guest['tag']==files['tag']=='WFFE'
    assert len(guest['full_original_profile_returns'])==18
    assert files['original_sentinel_CPU_writes']==files['original_callback_CPU_writes']==18
    assert files['selected_original_setup_CPU_stores']==1476 and files['diagnostic_CPU_stores']==332 and files['native_reads']==83
    assert not guest['native_condition_and_Timer_constructed'] and not files['VM_import_or_execution']
    register(files['source_sha256'])
    for p in (ROOT/G).rglob('*'):
        if p.is_file() and '__pycache__' not in p.parts:
            rel=str(p.relative_to(ROOT)); register({rel:sha(rel)})
    for name in (SOURCE,OLD,'staging/native-player-warm-probe-checkpoint/publication-v1-terminal-tool-receipt.json',
                 'staging/native-player-warm-probe-checkpoint/postpublication-loopback-check-failure.json'):
        register({name:sha(name)})
    state,task,public=[read(p) for p in P.CANONICAL[:3]]
    app=state['native_app_music'];progress=public['research_progress']
    assert state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining']
    assert not app['native_app_running'] and not app['direct_phone_music_verified']
    assert len(app['static_findings'])==249 and len(progress['completed'])==218
    assert progress['estimate_percent']==33 and progress['phases'][4]['estimate_percent']==20
    old_details=list(progress['completed']);old_next=progress['phases'][4]['next']
    latest=read('evidence/report-web-latest.json');before_service=P.service_now()
    with urllib.request.urlopen(latest['url'],timeout=10) as r:
        before_html=r.read();assert r.status==200 and 'no-store' in r.headers.get('Cache-Control','')
    assert hashlib.sha256(before_html).hexdigest()==sha(P.CANONICAL[3])
    (ROOT/B).mkdir();snapshots=[]
    for original,name in [(OLD,'previous-audit.json')]+list(zip(P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
        target=B+name;(ROOT/target).write_bytes((ROOT/original).read_bytes())
        snapshots.append(dict(original=original,snapshot=target,sha256=sha(target)));register({target:sha(target)})
    now=datetime.now(timezone.utc)
    focus='Verify actual warm condition/Timer and channel ownership, then bind the resident native player; cold profile callback construction alone is insufficient.'
    next_text='下一步查完整等待物件／Timer與正常模式的音訊所有權；使用者回來先確認原語音2.10，再測只讀Wxxx診斷碼。原生App菜單與手機直接音樂尚未完成。'
    findings=[('native_cold_profile_sentinel_provenance',G+'original-cold-profile-sentinel-contract-v1.json','Exact original269ED6 cold sentinel2 writer; no warm initializer claim.'),
              ('native_cold_profile_bootstrap_ROOT',G+'original-profile-bootstrap-v1-proof.json','One new bounded original loop:18 full profile returns, WFFE observation; hardware tail/condition/Timer excluded.'),
              ('native_cold_profile_bootstrap_FILE_ROOT',G+'ROOT-profile-bootstrap-file-proof-v1.json','FILE-only1476 original setup stores and332 diagnostic stores; two selected writer GP inputs,83 reads,12 zones; no full control-flow or independent-agent claim.')]
    for key,path,scope in findings:
        assert key not in app['static_findings']
        app['static_findings'][key]=dict(evidence=path,evidence_sha256=sha(path),scope=scope,evidence_type='ROOT bounded offline evidence',device_io=False,physical_App_or_audio_verified=False)
    details=[
        '找到原廠建立音訊回呼的前置步驟：冷初始化迴圈先在每個通道寫入特殊值2，再呼叫原設定函式。這解釋了先前只呼叫設定函式可能回傳成功但未建立回呼的原因；十八通道冷重設仍不能用於正常模式的App。',
        '新增一組原始指令離線驗證，十八次設定呼叫都完整返回，實際寫入十八個初始化值及十八個原廠音訊回呼。程式停在硬體流程前，等待物件與Timer沒有建立。新診斷程式讀出WFFE，僅表示這組已知輸入的狀態。',
        'ROOT由檔案重建1476次原廠初始化寫入、332次診斷寫入及83次只讀取樣，十二個完整區域與音訊快照一致；兩個指定寫入器的暫存器／位址／數值另經核對。沒有新的獨立agent或完整控制流程證明。車機原檔保持已還原，新診斷檔仍只放在Pi，待使用者回來確認。']
    state.update(updated_utc=now.isoformat(),current_priority=focus)
    state['next_actions']=[focus,'Recover real native SEP publication and accepted Configure/Start; native heap and callback lifetime remain pending.',
                           'Integrate the native menu and resident music player after native warm lifetime/hardware closure.',
                           'Attended later: original Aud Ver2.10 control, then reversible single-file Wxxx trial and rollback. User away; no pending question.']
    app['remaining_work']=state['next_actions'][:3]
    app['development_observations']['native_cold_profile_bootstrap_ROOT']=dict(proof=findings[1][1],FILE=findings[2][1],case_count=1,profile_returns=18,tag='WFFE',condition_or_Timer=False,physical_App=False)
    state['last_goal_turn'].update(validated_utc=now.isoformat(),classification='progress',focused_evidence=findings[1][1],focused_evidence_sha256=sha(findings[1][1]),
        previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',next_focus=focus,
        reasons=['Original sentinel provenance recovered and original18-channel cold profile loop actually executed to exact pre-hardware boundary.','New diagnostic WFFE and ROOT FILE replay completed; warm condition/Timer/native hardware/App remain pending.'],
        new_bounded_original_profile_execution=True,device_IO=False,device_calls_or_sound=False,complete_native_App_or_phone_audio=False,goal_status='active',full_goal_complete=False)
    for key in ('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
    task.update(user_away=True,current_device_connection_verified=False,current_connection_not_rechecked_this_offline_turn=True)
    public.update(updated=now.isoformat(),deep_research=state)
    progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
    progress.update(research_updated_utc=now.isoformat(),next=next_text);progress['phases'][4]['next']=next_text
    assert len(app['static_findings'])==252 and len(progress['completed'])==221 and progress['completed'][:218]==old_details
    report=before_html.decode()
    card='<div class="card"><h2>最新進展：找到原廠建立音訊回呼的前置步驟</h2>'
    card+='<p>原廠冷初始化會先在通道寫入特殊值，再設定回呼。新離線測試執行了真正的初始化迴圈，十八次設定都完整返回並建立回呼，診斷程式讀出WFFE；這是特定輸入的快照，不能當成暖機播放器已就緒。</p>'
    card+='<p>ROOT檔案核對1476次原廠寫入、332次診斷寫入與83次讀取，十二個完整區域一致，兩個指定寫入器的暫存器與位址亦通過核對。未涵蓋全部控制流程，也沒有新的獨立agent審查。</p>'
    card+='<p>目前尚未建立完整等待物件與Timer、硬體播放及正常模式所有權；原生App菜單和手機直接音樂仍未完成。不能在正常模式直接重設十八個音訊通道。</p>'
    card+='<p>實機原始美玲語音已還原，新只讀診斷候選僅在Pi準備。使用者目前不在車機旁，回來先確認Aud Ver2.10，再安排單檔Wxxx測試與還原。本輪未改寫車機、沒有來電或聲音。</p>'
    card+='<p>整體估計33%、App整合20%，研究繼續。配對第一優先，麥克風取消、音質擱置，Android Auto排後、Google Maps暫緩。</p></div>'
    report,count=re.subn(r'<div class="card"><h2>最新進展：實機音訊狀態診斷檔已在 Pi 準備完成</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert count==1
    old_row='<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(old_next)+'</td></tr>';assert report.count(old_row)==1
    report=report.replace(old_row,'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(next_text)+'</td></tr>',1)
    report,count=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda x:x[1]+x[2]+''.join('<li>'+html.escape(d)+'</li>' for d in details)+x[3],report,count=1,flags=re.S);assert count==1
    report,count=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>',report,count=1);assert count==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
    for name in ('report-updated-time','research-updated-time'):
        report,count=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert count==1
    assert report.count('datetime="'+iso+'"')==2 and 'REDACTED_PRIVATE_ID' not in report
    assert task['last_goal_turn']==state['last_goal_turn'] and public['deep_research']==state
    for row in snapshots:assert sha(row['original'])==row['sha256']
    create(B+'publication-inputs.json',dict(all_passed=True,source_sha256=protected,new_findings=findings,details=details,device_IO=False,guest_rerun=False))
    register({B+'publication-inputs.json':sha(B+'publication-inputs.json')})
    for p,d in zip(P.CANONICAL[:3],(state,task,public)):write(p,d)
    (ROOT/P.CANONICAL[3]).write_text(report);after={p:sha(p) for p in P.CANONICAL}
    with urllib.request.urlopen(urllib.request.Request(latest['url'],headers={'Cache-Control':'no-cache'}),timeout=10) as r:
        served=r.read();assert r.status==200 and 'no-store' in r.headers.get('Cache-Control','')
    assert served==report.encode() and hashlib.sha256(served).hexdigest()==after[P.CANONICAL[3]]
    assert {p:sha(p) for p in P.CANONICAL}==after
    assert P.service_now()==before_service
    audit=dict(previous,updated_utc=now.isoformat(),all_passed=True,previous_checkpoint=B+'previous-audit.json',protected_sources=protected,
               canonical_after_sha256=after,current_state_sha256=after[P.CANONICAL[0]],report_sha256=after[P.CANONICAL[3]],
               local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],current_findings=252,current_public_details=221,
               selected_native_profile_bootstrap_scopes=[dict(guest=findings[1][1],FILE=findings[2][1],case_count=1,profile_returns=18,tag='WFFE',warm_condition_constructed=False)],
               prior_warm_diagnostic8_and_embedded_reader1_preserved=True,new_independent_agent_review=False,device_IO_this_turn=False,
               scope_checks=dict(previous['scope_checks'],original_sentinel_writer_and18_callback_returns_verified=True,
                                 new_ROOT_FILE_two_selected_GP_writers_verified=True,condition_Timer_hardware_and_warm_ownership_not_claimed=True,
                                 canonical_and_served_uncached_exact=True,old3237_sources_revalidated_once=True))
    create(OUT,audit)
    latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_warm_probe_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),current_native_profile_bootstrap_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},
                  local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,
                  current_physical_test_requested=False,user_away_for_class=True,service_not_restarted=True,canonical_hash_readback_uncached=True)
    write('evidence/report-web-latest.json',latest)
    print(json.dumps(dict(all_passed=True,findings=252,details=221,protected_sources=len(protected),new_original_profile_scopes=1,
                          original_profiles_returned=18,tag='WFFE',estimate_percent=33,App_estimate_percent=20,
                          updated_Taiwan=iso,report_bytes=len(served),served_sha256=after[P.CANONICAL[3]],goal_status='active',device_IO=False)),flush=True)

if __name__=='__main__':main()
