#!/usr/bin/env python3
"""Publish the new original-wire reply/Start prototype, no guest/device action."""
import json,hashlib,re,html,urllib.request,importlib.util
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('warm_publication_helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
read=P.read;sha=P.sha;create=P.create;write=P.write
B='staging/native-avdtp-reply-admission-checkpoint/'
G='staging/native-avdtp-reply-admission/'
OLD='evidence/firmware-analysis/native-profile-bootstrap-ROOT-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-reply-admission-ROOT-checkpoint-audit.json'
SOURCE='scripts/publish_native_reply_admission_checkpoint_v1.py'
def main():
    assert not(ROOT/B).exists()and not(ROOT/OUT).exists(),'Keep earlier attempts immutable'
    previous=read(OLD);assert previous['all_passed']and previous['current_findings']==252
    assert len(previous['protected_sources'])==3258
    assert all(sha(p)==h for p,h in previous['canonical_after_sha256'].items())
    protected=dict(previous['protected_sources']);verified={}
    def register(entries):
        for p,h in entries.items():
            if p not in verified:verified[p]=sha(p)
            assert verified[p]==h,p
            assert p not in protected or protected[p]==h,p
            protected[p]=h
    register(previous['protected_sources'])
    seal_path=G+'ROOT-native-reply-admission-terminal-seal-v1.json';seal=read(seal_path)
    assert seal['all_passed']and seal['case_count']==8 and seal['completed_exit1_prefix_cases']==2 and seal['new_exit0_cases']==6
    assert seal['false_native_TX_return0_inference_corrected']and seal['accepted_stream_generation_binding_still_required']
    assert not seal['direct_phone_PCM_App_or_warm_ownership_or_physical_verified']
    register(seal['source_sha256'])
    for p in (SOURCE,OLD,seal_path,G+'seal-v1-terminal-tool-receipt.json',
              'staging/native-audio-profile-bootstrap-checkpoint/publication-v1-terminal-tool-receipt.json',
              'staging/native-audio-profile-bootstrap-checkpoint/web-latest-historical-key-cleanup.json'):
        register({p:sha(p)})
    receipt=read(G+'seal-v1-terminal-tool-receipt.json');assert receipt['terminal']and receipt['actual_terminal_result']['exit_code']==0
    assert 'session_id'not in receipt['actual_terminal_result']
    state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress']
    assert state['goal_status']=='active'and not state['goal_complete']and state['required_work_remaining']
    assert not app['native_app_running']and not app['direct_phone_music_verified']
    assert len(app['static_findings'])==252 and len(progress['completed'])==221
    old_details=list(progress['completed']);old_next=progress['phases'][4]['next']
    assert progress['estimate_percent']==33 and progress['phases'][4]['estimate_percent']==20
    latest=read('evidence/report-web-latest.json');service=P.service_now()
    with urllib.request.urlopen(latest['url'],timeout=10)as r:
        before_html=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
    assert hashlib.sha256(before_html).hexdigest()==sha(P.CANONICAL[3])
    (ROOT/B).mkdir();snapshots=[]
    for original,name in [(OLD,'previous-audit.json')]+list(zip(P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
        target=B+name;(ROOT/target).write_bytes((ROOT/original).read_bytes())
        snapshots.append(dict(original=original,snapshot=target,sha256=sha(target)));register({target:sha(target)})
    findings=[('native_reply_start_admission_build',G+'build-v3.json','Compiled selected reply byte witness and Start/Suspend gates; VM-only placement/prologue/table bindings.'),
              ('native_reply_start_admission_eight_scopes',G+'ROOT-selected-eight-wire-scopes-v2.json','Two completed failed-suite prefixes plus six new controls; Config state2 is preserved, not rolled back.'),
              ('native_reply_start_admission_ROOT_FILE',G+'ROOT-native-reply-admission-file-proof-v2.json','ROOT FILE opcode/preimage/37 wire scopes222 zones with6055 CPU stores plus42 explicit service writes. No GP/nonstore CFG or independent-agent proof.')]
    for key,path,scope in findings:
        assert key not in app['static_findings']
        app['static_findings'][key]=dict(evidence=path,evidence_sha256=sha(path),scope=scope,evidence_type='ROOT bounded offline evidence',device_io=False,physical_App_or_audio_verified=False)
    details=[
        '新增原生藍牙接收流程原型，透過真正的原廠封包派送器進入新的設定、開始與暫停閘門；命令關聯由編譯程式自行建立，沒有由測試主機逐封包指定。成功回覆另外核對原L2CAP實際寫入的兩個資料位元組。',
        '已阻止原廠的錯誤播放狀態：Open尚未完成時，原版成功排入拒絕Start回覆後仍會切到state8並呼叫event17；新版本送出相同拒絕回覆，保持state2／pending2且沒有播放回呼。正常Start、Suspend、resume、capabilities與原媒體回呼有保留；此輪沒有解碼手機音樂或接到Source音訊佇列。',
        '八組新情境由兩個已完成失敗套件前綴加六個新控制組成，共十四個VM對照。ROOT由檔案核對6055次CPU寫入、42個明示服務寫入、37次封包呼叫及222個完整區域；其餘暫存器有效位址與全部控制流程並未重建，也沒有新的獨立agent審查。',
        '更正先前回傳值判讀：上層接收函式回傳0不能代表傳送成功；本輪傳送失敗在底層有非零錯誤，未證明底層會以0回報未寫入資料。Configure本來就在送出回覆前設定state2，失敗後仍保持state2，因此還需要把已接受Configure／Start與同一遠端協商世代綁定。所有錯誤推論與腳本失敗均保留；實機原檔已還原，新診斷候選仍只在Pi。']
    now=datetime.now(timezone.utc)
    focus='Bind accepted Configure/Start and native five-argument media callback identity to the same remote generation, then connect to the existing Source/SBC/FIFO pipeline; retain warm ownership and physical-readiness checks.'
    next_text='下一步把已接受的Configure／Start、端點與同一手機協商世代綁定，再接到現有Source／SBC／音訊FIFO。正常模式所有權、heap與完整退出仍待驗證；使用者回來先確認原語音2.10，再測只讀Wxxx診斷。'
    state.update(updated_utc=now.isoformat(),current_priority=focus)
    state['next_actions']=[focus,'Verify warm audio condition/Timer/channel ownership and native heap; do not reset all18 channels from a resident App.',
                           'Integrate native menu and resident player after dispatcher/callback/hardware lifetime closure; full STOP_DONE remains unverified.',
                           'Attended later: original Aud Ver2.10, reversible single-file Wxxx diagnostic and rollback. User away; no pending question.']
    app['remaining_work']=state['next_actions'][:3]
    app['development_observations']['native_reply_Start_gate_ROOT']=dict(seal=seal_path,case_count=8,totals=seal['totals'],rejected_Start_false_transition_blocked=True,
        command_generation_is_not_remote_generation=True,native_TX_zero_short_write_not_proven=True,Config_state2_not_rollback=True,native_Source_pipeline_connected=False)
    state['last_goal_turn'].update(validated_utc=now.isoformat(),classification='progress',focused_evidence=findings[2][1],focused_evidence_sha256=sha(findings[2][1]),
        previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',next_focus=focus,
        reasons=['New compiled gates entered through original native dispatcher and prevented real reject-Start state8/event17 false positive.','Eight scopes reconstructed; upper receive return vs actual TX error corrected, original Configure pre-reply state2 is retained.','Actual accepted remote generation/native media→Source bridge and warm physical App still pending.'],
        new_bounded_original_reply_Start_execution=True,device_IO=False,device_calls_or_sound=False,complete_native_App_or_phone_audio=False,goal_status='active',full_goal_complete=False)
    for key in ('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
    public.update(updated=now.isoformat(),deep_research=state);progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
    progress.update(research_updated_utc=now.isoformat(),next=next_text);progress['phases'][4]['next']=next_text
    assert len(app['static_findings'])==255 and len(progress['completed'])==225 and progress['completed'][:221]==old_details
    report=before_html.decode()
    card='<div class="card"><h2>最新進展：原生藍牙接收閘門阻止錯誤播放狀態</h2>'
    card+='<p>新編譯原型透過真正的原廠封包派送器處理設定、開始與暫停。Open尚未完成時，原版送出拒絕Start後仍會轉為播放狀態並發出播放回呼；新版本送出相同拒絕回覆，保持原狀態且沒有播放回呼。正常開始、暫停、恢復與原媒體回呼有保留。</p>'
    card+='<p>八組情境含兩個完整失敗套件前綴及六個新控制。ROOT檔案核對6055次CPU寫入、42個明示服務寫入、37次封包呼叫及222個完整區域。沒有新的獨立agent、完整暫存器有效位址或全部控制流程證明。</p>'
    card+='<p>更正：上層接收回傳0並不代表底層傳送成功，測得的底層失敗有非零錯誤；未證明底層以0回報未寫入資料。Configure在回覆前先設定state2，失敗後仍保留，不能單靠狀態判定協商成立。原型核對成功回覆實際排入的兩個資料位元組，但尚未將接受紀錄綁到同一遠端協商世代。</p>'
    card+='<p>下一步才是把正確協商與原生五參數媒體回呼接到現有Source／SBC／音訊FIFO。此輪沒有手機音樂解碼或實機播放，原生App菜單、正常模式所有權、heap與完整退出仍未完成。測試鎖、配置器、memcpy、傳輸與事件服務等條件皆保留為明示模擬邊界。</p>'
    card+='<p>原始美玲語音已還原，新只讀Wxxx候選仍在Pi，未寫入車機。使用者回來先確認2.10。整體估計33%、App20%，研究持續；配對第一優先，麥克風取消、音質擱置，Android Auto排後、Google Maps暫緩。</p></div>'
    report,count=re.subn(r'<div class="card"><h2>最新進展：找到原廠建立音訊回呼的前置步驟</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert count==1
    old_row='<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(old_next)+'</td></tr>';assert report.count(old_row)==1
    report=report.replace(old_row,'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(next_text)+'</td></tr>',1)
    report,count=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda x:x[1]+x[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+x[3],report,count=1,flags=re.S);assert count==1
    report,count=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>',report,count=1);assert count==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
    for name in ('report-updated-time','research-updated-time'):
        report,count=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert count==1
    assert report.count('datetime="'+iso+'"')==2 and 'REDACTED_PRIVATE_ID'not in report
    for row in snapshots:assert sha(row['original'])==row['sha256']
    create(B+'publication-inputs.json',dict(all_passed=True,protected_sources=protected,new_findings=findings,details=details,guest_rerun=False,device_IO=False))
    register({B+'publication-inputs.json':sha(B+'publication-inputs.json')})
    for p,d in zip(P.CANONICAL[:3],(state,task,public)):write(p,d)
    (ROOT/P.CANONICAL[3]).write_text(report);after={p:sha(p)for p in P.CANONICAL}
    with urllib.request.urlopen(urllib.request.Request(latest['url'],headers={'Cache-Control':'no-cache'}),timeout=10)as r:
        served=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
    assert served==report.encode() and hashlib.sha256(served).hexdigest()==after[P.CANONICAL[3]]
    assert {p:sha(p)for p in P.CANONICAL}==after and P.service_now()==service
    audit=dict(previous,updated_utc=now.isoformat(),all_passed=True,previous_checkpoint=B+'previous-audit.json',protected_sources=protected,
               canonical_after_sha256=after,current_state_sha256=after[P.CANONICAL[0]],report_sha256=after[P.CANONICAL[3]],
               local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],current_findings=255,current_public_details=225,
               selected_native_reply_admission_scopes=[dict(selection=seal['selected_scopes'],ROOT_FILE=seal['ROOT_FILE'],case_count=8,completed_prefix_exit1=2,new_exit0=6)],
               native_reply_admission_totals=seal['totals'],new_independent_agent_review=False,device_IO_this_turn=False,
               accepted_remote_generation_native_media_to_Source_or_phone_App_verified=False,
               scope_checks=dict(previous['scope_checks'],new_rejected_Start_state_false_positive_blocked=True,
                                 upper_receive_vs_TX_false_inference_corrected=True,native_Config_state2_retained=True,
                                 native_command_generation_not_remote_generation=True,old3258_sources_revalidated_once=True))
    create(OUT,audit)
    old_key='current_native_profile_bootstrap_ROOT_checkpoint';assert latest[old_key]==OLD
    latest.pop(old_key)
    latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_profile_bootstrap_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),current_native_reply_admission_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},
                  local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,
                  current_physical_test_requested=False,user_away_for_class=True,service_not_restarted=True,canonical_hash_readback_uncached=True)
    write('evidence/report-web-latest.json',latest)
    print(json.dumps(dict(all_passed=True,findings=255,details=225,protected_sources=len(protected),new_wire_cases=8,totals=seal['totals'],
                          estimate_percent=33,App_estimate_percent=20,updated_Taiwan=iso,report_bytes=len(served),served_sha256=after[P.CANONICAL[3]],goal_status='active',device_IO=False)),flush=True)
if __name__=='__main__':main()
