#!/usr/bin/env python3
"""Publish scoped native pause/resume evidence to the existing LAN report."""
import json,hashlib,re,html,importlib.util,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('report_helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
G='staging/native-player-remote-pause/'
B='staging/native-player-remote-pause-checkpoint/'
OLD='evidence/firmware-analysis/native-remote-binding-ROOT-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-remote-pause-ROOT-checkpoint-audit.json'
def main():
 assert not(ROOT/B).exists()and not(ROOT/OUT).exists()
 prior=read(OLD);assert prior['all_passed']and prior['current_findings']==258 and prior['current_public_details']==229
 assert all(sha(p)==h for p,h in prior['canonical_after_sha256'].items())
 protected=dict(prior['protected_sources']);verified={}
 def register(entries):
  for p,h in entries.items():
   if p not in verified:verified[p]=sha(p)
   assert verified[p]==h and (p not in protected or protected[p]==h),p
   protected[p]=h
 register(protected.copy())
 fileproof=read(G+'ROOT-remote-pause-file-proof-v3.json');guest=read(G+'remote-pause-v1-proof.json')
 assert fileproof['all_passed']and guest['all_passed']and fileproof['case_count']==len(guest['cases'])==6
 assert guest['completed_exit1_prefix']==guest['new_exit0_cases']==3 and not guest['whole_guest_v1_suite_passed']
 assert fileproof['native_Suspend_resume_same_config_supported']and fileproof['reconnect_STOP_DONE_unload_warm_ownership_unimplemented']
 assert not fileproof['phone_or_speaker_or_App_or_warm_install_verified']
 for name in ('guest-v3','file-v3'):
  receipt=read(G+name+'-terminal-tool-receipt.json');assert receipt['terminal']and receipt['actual_terminal_result']['exit_code']==0
 register(fileproof['source_sha256'])
 for p in sorted((ROOT/G).rglob('*')):
  if p.is_file():register({str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT)))})
 for p in (OLD,'scripts/publish_native_remote_pause_checkpoint_v1.py','staging/native-remote-source-binding-checkpoint/publication-v1-terminal-tool-receipt.json'):register({p:sha(p)})
 state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress']
 assert state['goal_status']=='active'and not state['goal_complete']and not app['native_app_running']and not app['direct_phone_music_verified']
 assert len(app['static_findings'])==258 and len(progress['completed'])==229
 latest=read('evidence/report-web-latest.json');service=P.service_now()
 with urllib.request.urlopen(latest['url'],timeout=10)as r:before=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert hashlib.sha256(before).hexdigest()==sha(P.CANONICAL[3])
 (ROOT/B).mkdir();snapshots=[]
 for p,name in [(OLD,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]+list(zip(P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
  target=B+name;(ROOT/target).write_bytes((ROOT/p).read_bytes());h=sha(target)
  register({target:h});snapshots.append(dict(original=p,snapshot=target,sha256=h))
 findings=[('native_remote_Source_pause_build',G+'source-build-v2.json','Resident Source private pause/epoch and silent reader preserve PCM/codec/anchor; no stock message13-as-Pause assumption. Compile-only artifact.'),
  ('native_remote_Suspend_Start_resume_six_scopes',G+'remote-pause-v1-proof.json','Three completed failed-suite prefixes plus three fresh successful scopes; native Suspend/accepted Start/first F1 resumes same Source. Full FIFO/failed Start/profile rewrite/disconnect covered.'),
  ('native_remote_pause_ROOT_FILE',G+'ROOT-remote-pause-file-proof-v3.json','Saved opcode/preimage/full RW/RX and selected GP/ABI/retained FIFO checks. Same live VM slice boundaries preserved. No complete nonstore CFG/store effective-address/independent-agent/warm physical proof.')]
 for key,p,scope in findings:
  assert key not in app['static_findings'];app['static_findings'][key]=dict(evidence=p,evidence_sha256=sha(p),scope=scope,evidence_type='ROOT bounded offline evidence',device_io=False,physical_App_or_audio_verified=False)
 details=[
  '原生媒體橋接新增暫停與恢復：原廠Suspend關閉新資料接收，由真正Source工作設定私有暫停狀態，原生讀取器輸出靜音並保留PCM、解碼狀態、anchor及工作身分。成功Start完整返回後，第一個有效媒體回呼要求同一Source恢復，不需要因暫停重建音源。這仍是离線整合。',
  '六組已完成情境涵蓋连续兩次暫停／恢復、Start傳送失敗後保留資料再重試、首包之前暫停、四個PCM緩衝滿載且有待解碼封包、原廠profile改寫，以及暫停時斷線。滿載恢復由真正原生mixer讀取容量通知喚醒Source，六包連續輸出與參考音訊相符；profile被改寫後拒絕恢復資料，斷線仍關閉接收及要求Stop。',
  '選取三個已完成失敗套件前綴與三個新成功控制，沒有重跑已完成guest。ROOT保存檔案核對完整區域、原生回呼與FIFO保持不變；這不是全指令流程或新的獨立agent審查。更正舊測試上限判讀：同時設有指令數與時間上限，失敗紀錄不能區分先到哪個；新版同一live VM分段接續，滿載恢復共585066觀察指令、兩段後完整返回，未還原CPU上下文或由Python調度工作。',
  '暫停／恢復已在離線原型中完成；斷線重連、新設定復用、完整STOP_DONE、模組卸載、正常模式ownership、真正配置／載入位址及App菜單仍待研究。已在硬體緩衝的音訊不由私有Pause狀態回收，不能宣稱瞬間硬體靜音。此輪沒有車機改寫、電話或聲音；使用者回來先確認原語音2.10，再安排Wxxx診斷。']
 now=datetime.now(timezone.utc);old_next=progress['phases'][4]['next']
 focus='Prepare resident load/relocation and warm Source initialization/menu integration, replacing synthetic fixed Source imports with loader-resolved exports. Recover durable warm channel ownership and heap. Native reconnect/full STOP_DONE/hardware validation remain; user away, original2.10 and Wxxx test pending.'
 next_text='下一步處理原機載入／重定位、正常模式Source初始化與App菜單，把模擬用固定位址改成載入器提供的函式連接；持續查warm ownership、heap、斷線重連及STOP_DONE。回來先確認原語音2.10，再測只讀Wxxx。'
 audio_next='同一次協商的原生Suspend／Start暫停恢復已離線完成；接下來處理真正載入、正常模式音訊資源、導航共存與斷線重連，再安排實機。'
 state.update(updated_utc=now.isoformat(),current_priority=focus)
 state['next_actions']=[focus,'Recover actual warm channel ownership/profile/condition/Timer and heap, without global18-channel resets.',
  'Complete reconnect/new configuration and full hardware/native STOP_DONE retirement; integrate native player menu and current phone.',
  'Later attended original Aud Ver2.10 then reversible Wxxx. User away/no pending question; pairing first when present. Android Auto later, offline Maps deferred.']
 app['remaining_work']=state['next_actions'][:3]
 app['development_observations']['native_remote_pause_lifecycle_ROOT']=dict(ROOT_FILE=findings[2][1],guest=findings[1][1],totals=fileproof['totals'],native_Suspend_Start_resume_same_configuration_offline=True,
  real_warm_App_or_phone_or_speaker=False,reconnect_or_STOP_DONE_or_module_unload=False,per_call_bound_cause_not_proven=True,VM_slice_no_context_restore=True)
 state['attended_testing'].update(user_present=False,waiting_for_user_return=True,no_pending_question=True,recorded_utc=now.isoformat())
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',
  focused_evidence=findings[2][1],focused_evidence_sha256=sha(findings[2][1]),next_focus=focus,reasons=['Native Suspend/full Start/valid F1 now pauses and resumes the same Source with retained PCM and decoder.',
  'Six scopes cover failed resume, full FIFO capacity wake, before-first-input pause, profile replacement and disconnection.',
  'Saved-file reconstruction complete; live VM slicing finishes bounded work without context restoration. Warm loader/menu/ownership/reconnect/full STOP_DONE remain incomplete.'],
  device_IO=False,device_calls_or_sound=False,complete_native_App_or_phone_audio=False,goal_status='active',full_goal_complete=False)
 for key in ('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
 public.update(updated=now.isoformat(),deep_research=state);progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
 progress['phases'][1].update(estimate_percent=60,next=audio_next);progress['phases'][4]['next']=next_text
 weighted=sum(p['weight']*p['estimate_percent']/100 for p in progress['phases']);assert weighted==35.5
 progress.update(estimate_percent=int(weighted+0.5),weighted_estimate_percent=weighted,research_updated_utc=now.isoformat(),next=next_text)
 assert len(app['static_findings'])==261 and len(progress['completed'])==233 and progress['phases'][4]['estimate_percent']==25
 report=before.decode()
 card='<div class="card"><h2>最新進展：離線原生播放器已能暫停與恢復</h2>'
 card+='<p>原廠Suspend先關閉新資料接收，真正Source工作設定暫停；原生讀取器輸出靜音，保留音訊緩衝、解碼狀態、音源anchor及工作身分。成功Start完整返回後，第一個有效媒體回呼恢復同一播放工作。同一次協商的暫停不再需要重建音源。</p>'
 card+='<p>六個完成情境含連續兩次暫停／恢復、恢復請求失敗再重試、第一包之前暫停、四個緩衝滿載與待解碼封包、原廠音訊通道改寫及斷線。滿載恢復由原生容量通知喚醒解碼，六包連續音訊与參考輸出相符；通道被改寫時拒絕恢復，斷線保持停止。ROOT另核對保存區域與回呼，未由Python還原CPU或調度工作。</p>'
 card+='<p><strong>仍是離線原型：</strong>真手機、實機喇叭、正常模式ownership、配置／載入位址及App菜單尚未完成。斷線後重新連接、新設定復用、完整STOP_DONE與模組卸載仍待研究；硬體內既有音訊不由此Pause回收，不宣稱瞬間靜音。radio、BTmutex、配置器與硬體輸出仍有明示fixture。</p>'
 card+='<p>舊測試同時有指令数与时间限制，保存紀錄不能判定先到哪項；新版保持同一live VM分段接續，滿載流程完整返回。使用者不在車機旁，原語音已還原，本輪未改寫車機或發出聲音。回來先確認Aud Ver2.10，再安排只讀Wxxx。整體約36%、App25%，研究持續；配對優先、麥克風取消、Android Auto排後、Maps暫緩。</p></div>'
 report,n=re.subn(r'<div class="card"><h2>最新進展：原廠藍牙媒體回呼已接入原生音訊流程</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
 report,n=re.subn(r'(<div class="progress-total">約 <strong>)35(%</strong>)',r'\g<1>36\2',report,count=1);assert n==1
 report,n=re.subn(r'(<progress id="research-progress" max="100" value=")35("[^>]*>)35(%</progress>)',r'\g<1>36\g<2>36\3',report,count=1);assert n==1
 old='<tr><td>原生 App 入口與功能整合</td><td>25%</td><td>'+html.escape(old_next)+'</td></tr>';assert report.count(old)==1
 report=report.replace(old,'<tr><td>原生 App 入口與功能整合</td><td>25%</td><td>'+html.escape(next_text)+'</td></tr>',1)
 report,n=re.subn(r'<tr><td>原生音訊與元件原型</td><td>55%</td><td>.*?</td></tr>',lambda _:'<tr><td>原生音訊與元件原型</td><td>60%</td><td>'+html.escape(audio_next)+'</td></tr>',report,count=1);assert n==1
 report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda x:x[1]+x[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+x[3],report,count=1,flags=re.S);assert n==1
 report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>',report,count=1);assert n==1
 local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
 for name in ('report-updated-time','research-updated-time'):
  report,n=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert n==1
 assert not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',report)and 'REDACTED_PRIVATE_ID'not in report
 for row in snapshots:assert sha(row['original'])==row['sha256']
 create(B+'publication-inputs.json',dict(all_passed=True,protected_sources=protected,new_findings=findings,details=details,VM=False,device_IO=False));register({B+'publication-inputs.json':sha(B+'publication-inputs.json')})
 for p,d in zip(P.CANONICAL[:3],(state,task,public)):write(p,d)
 (ROOT/P.CANONICAL[3]).write_text(report);after={p:sha(p)for p in P.CANONICAL}
 with urllib.request.urlopen(urllib.request.Request(latest['url'],headers={'Cache-Control':'no-cache'}),timeout=10)as r:
  served=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert served==report.encode()and P.service_now()==service and {p:sha(p)for p in P.CANONICAL}==after
 audit=dict(prior,all_passed=True,updated_utc=now.isoformat(),previous_checkpoint=B+'previous-audit.json',protected_sources=protected,canonical_after_sha256=after,
  current_state_sha256=after[P.CANONICAL[0]],report_sha256=after[P.CANONICAL[3]],local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],
  current_findings=261,current_public_details=233,estimate_percent=36,weighted_estimate_percent=35.5,App_estimate_percent=25,
  selected_native_remote_pause_scopes=guest['cases'],completed_pause_exit1_prefix_scopes=3,new_pause_exit0_scopes=3,native_remote_pause_totals=fileproof['totals'],
  new_independent_agent_review=False,device_IO_this_turn=False,native_Suspend_resume_same_configuration_offline=True,physical_phone_App_warm_ownership_reconnect_STOP_DONE_verified=False,
  scope_checks=dict(prior['scope_checks'],six_new_pause_resume_scopes=True,old3485_sources_preserved=True,Pause_does_not_retire_Source_and_Disconnect_does=True,
   bounded_call_instruction_vs_timeout_cause_not_proven=True,live_report_36_App25_visible=True))
 create(OUT,audit)
 oldkey='current_native_remote_binding_ROOT_checkpoint';assert latest.pop(oldkey)==OLD
 latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_remote_binding_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),current_native_remote_pause_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},
  local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,current_physical_test_requested=False,
  user_away_for_class=True,canonical_hash_readback_uncached=True,service_not_restarted=True)
 latest['progress_display_verified'].update(estimate_percent=36,completed_items=233,report_updated_time=iso,research_updated_time=iso,native_pause_resume_offline_scope_visible=True,
  current_native_pause_retires_instance=False,Disconnect_requires_restart_still_visible=True)
 write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=261,details=233,protected_sources=len(protected),updated_Taiwan=iso,estimate_percent=36,App_estimate_percent=25,totals=fileproof['totals'],
  report_bytes=len(served),served_sha256=after[P.CANONICAL[3]],goal_status='active',device_IO=False)),flush=True)
if __name__=='__main__':main()
