#!/usr/bin/env python3
"""Update existing LAN report from frozen same-VM native media bridge evidence.
No guest/device/BT action or report service restart.
"""
import json,hashlib,re,html,importlib.util,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('report_helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
G='staging/native-remote-source-binding/'
B='staging/native-remote-source-binding-checkpoint/'
OLD='evidence/firmware-analysis/native-reply-admission-ROOT-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-remote-binding-ROOT-checkpoint-audit.json'
def main():
 assert not(ROOT/B).exists()and not(ROOT/OUT).exists()
 prior=read(OLD);assert prior['all_passed']and prior['current_findings']==255 and prior['current_public_details']==225
 assert all(sha(p)==h for p,h in prior['canonical_after_sha256'].items())
 protected=dict(prior['protected_sources']);verified={}
 def register(entries):
  for p,h in entries.items():
   if p not in verified:verified[p]=sha(p)
   assert verified[p]==h and (p not in protected or protected[p]==h),p
   protected[p]=h
 register(protected.copy())
 fileproof=read(G+'ROOT-remote-binding-file-proof-v1.json');guest=read(G+'remote-binding-v1-proof.json')
 assert fileproof['all_passed']and guest['all_passed']and fileproof['case_count']==len(guest['cases'])==4
 assert fileproof['same_VM_native_F1_to_existing_Source_SBC_FIFO']and not fileproof['phone_or_speaker_or_App_or_warm_install_verified']
 assert fileproof['totals']['native_callbacks']==21 and fileproof['totals']['SBC_full_returns']==8 and fileproof['totals']['native_full_returns']==31
 assert fileproof['one_stream_per_boot_resume_restart_STOP_DONE_unload_unimplemented']
 for name in ('guest-v3','file-v1'):
  result=read(G+name+'-terminal-tool-receipt.json')['actual_terminal_result'];assert result['exit_code']==0 and 'session_id'not in result
 register(fileproof['source_sha256'])
 for p in sorted((ROOT/G).rglob('*')):
  if p.is_file():register({str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT)))})
 register({OLD:sha(OLD),'scripts/publish_native_remote_binding_checkpoint_v1.py':sha('scripts/publish_native_remote_binding_checkpoint_v1.py'),
  'staging/native-avdtp-reply-admission-checkpoint/publication-v1-terminal-tool-receipt.json':sha('staging/native-avdtp-reply-admission-checkpoint/publication-v1-terminal-tool-receipt.json')})
 state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress']
 assert state['goal_status']=='active'and not state['goal_complete']and not app['native_app_running']and not app['direct_phone_music_verified']
 assert len(app['static_findings'])==255 and len(progress['completed'])==225
 latest=read('evidence/report-web-latest.json');service=P.service_now()
 with urllib.request.urlopen(latest['url'],timeout=10)as r:before=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert hashlib.sha256(before).hexdigest()==sha(P.CANONICAL[3])
 (ROOT/B).mkdir();snapshots=[]
 for p,name in [(OLD,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]+list(zip(P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
  target=B+name;(ROOT/target).write_bytes((ROOT/p).read_bytes());h=sha(target)
  register({target:h});snapshots.append(dict(original=p,snapshot=target,sha256=h))
 findings=[('native_remote_generation_Source_bridge_build',G+'build-v1.json','Resident private-ABI bridge with accepted Configure, full-return Start and five-argument callback identity; exact existing Source ELF imports. VM-only placement, no installer.'),
  ('native_remote_generation_Source_same_VM',G+'remote-binding-v1-proof.json','Four new scopes: real original F1 callback enters existing ingress, Source/kernel/SBC/FIFO/mixer. BT mutex, heap, PSM, radio and output/DMA remain declared fixtures.'),
  ('native_remote_generation_Source_ROOT_FILE',G+'ROOT-remote-binding-file-proof-v1.json','ROOT opcode/preimage/whole128 RW and16 RX reconstruction with21 complete native callbacks,8 SBC and31 original audio returns. Full nonstore CFG/all store effective addresses and physical App not proved.')]
 for key,p,scope in findings:
  assert key not in app['static_findings'];app['static_findings'][key]=dict(evidence=p,evidence_sha256=sha(p),scope=scope,evidence_type='ROOT bounded offline evidence',device_io=False,physical_App_or_audio_verified=False)
 details=[
  '新增並完成原生藍牙媒體橋接的離線整合：由原廠封包處理器真正呼叫五參數媒體回呼，再進入既有Source工作、SBC解碼器、PCM FIFO與原生mixer；不再由測試主機直接呼叫四參數輸入捷徑。設定與Start接受紀錄、端點、手機身分、codec、媒體通道及本地MTU由編譯程式核對。',
  '四組新控制已完成：正常兩包音訊、設定回覆傳送失敗、斷線，以及真正原廠profile重寫。傳送失敗後原廠仍保持state2，但新橋接沒有接受協商或開始解碼；event17仍在pending4期間出現，橋接直到完整Start返回、pending清空才允許資料。暫停與斷線會關閉接收並要求既有Source Stop，原廠音訊通道被改寫後也無新解碼。',
  'ROOT檔案核對141729次CPU寫入與474個明示fixture寫入、128個完整RW區與16個RX區；21次原生回呼、8次解碼及31次原生音訊完整返回。參考音樂PCM共744bytes，原生軟體輸出7168bytes含缺資料時的靜音。這是保存檔案的核對，沒有新的獨立agent或完整非寫入指令流程證明。',
  '目前橋接限定每次啟動一段協商，暫停或斷線後不提供resume／restart；原生STOP_DONE、模組卸載、正常模式音訊ownership、heap、App菜單、真手機與實機喇叭仍未完成。BT mutex、配置器、PSM、radio與硬體輸出仍為明示模擬條件；原始語音已還原，使用者不在車機旁，本輪沒有裝置改寫或聲音。']
 now=datetime.now(timezone.utc);old_next=progress['phases'][4]['next']
 focus='Close warm audio ownership and resident bridge initialization, then integrate the native App/menu. Complete Suspend/resume/reconnect retirement and native STOP_DONE before a physical direct-phone receiver. User away; original2.10 control and Wxxx diagnostic pending.'
 next_text='接著確認正常模式音訊資源與持續ownership，把新的原生媒體橋接接到真正的App入口；補齊暫停恢復、重新連線與STOP_DONE。使用者回來先確認原語音2.10，再安排只讀Wxxx診斷。'
 audio_next='原廠媒體回呼已接到Source／SBC／FIFO的離線整合；下一步處理正常模式資源、導航共存、恢復播放與重新連線，再做實機測試。'
 state.update(updated_utc=now.isoformat(),current_priority=focus)
 state['next_actions']=[focus,'Recover actual warm channel ownership/profile/condition/Timer and native heap, without resetting all18 channels.',
  'Provide full resident player menu, pause/resume/reconnect and hardware retirement; no native STOP_DONE/unload yet.',
  'Later attended: original Aud Ver2.10 then reversible Wxxx diagnostic. User away, no pending question. Pairing takes first priority when present.']
 app['remaining_work']=state['next_actions'][:3]
 app['development_observations']['native_remote_source_binding_ROOT']=dict(ROOT_FILE=findings[2][1],guest=findings[1][1],totals=fileproof['totals'],
  accepted_configuration_full_Start_native_F1_existing_Source_pipeline_connected_offline=True,one_stream_per_boot=True,resume_restart_supported=False,
  native_ownership_heap_STOP_DONE_real_phone_App_or_speaker=False)
 state['attended_testing'].update(user_present=False,waiting_for_user_return=True,no_pending_question=True,recorded_utc=now.isoformat())
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',
  focused_evidence=findings[2][1],focused_evidence_sha256=sha(findings[2][1]),next_focus=focus,
  reasons=['Original native five-argument F1 callback now enters existing Source/SBC/FIFO/mixer in one new VM.',
  'Accepted configuration/full Start identity and failed Configure, Suspend, disconnect and real profile replacement controls verified.',
  'ROOT saved-file reconstruction complete; warm ownership, resume/reconnect/native STOP_DONE and physical App/phone remain incomplete.'],
  device_IO=False,device_calls_or_sound=False,complete_native_App_or_phone_audio=False,goal_status='active',full_goal_complete=False)
 for key in ('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
 public.update(updated=now.isoformat(),deep_research=state);progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
 progress['phases'][1].update(estimate_percent=55,next=audio_next);progress['phases'][4].update(estimate_percent=25,next=next_text)
 weighted=sum(p['weight']*p['estimate_percent']/100 for p in progress['phases']);assert weighted==34.5
 progress.update(estimate_percent=int(weighted+0.5),weighted_estimate_percent=weighted,research_updated_utc=now.isoformat(),next=next_text)
 assert len(app['static_findings'])==258 and len(progress['completed'])==229
 report=before.decode()
 card='<div class="card"><h2>最新進展：原廠藍牙媒體回呼已接入原生音訊流程</h2>'
 card+='<p>新的離線整合已跑通原廠封包處理器 → 五參數媒體回呼 → Source工作 → SBC解碼 → PCM佇列 → 原生mixer。成功設定與完整Start返回後才接收資料，並核對端點、手機身分、codec、媒體通道與MTU。軟體輸出與參考音訊相符。</p>'
 card+='<p>四組控制已完成：正常兩包音訊、設定回覆傳送失敗、斷線及原廠音訊profile改寫。暫停／斷線關閉接收並要求Source Stop；傳送失敗與通道被改寫後沒有新的解碼。共21次完整原生回呼、8次SBC解碼返回、31次原生音訊返回，ROOT另核對完整保存區域。</p>'
 card+='<p><strong>尚未可安裝：</strong>這是Pi上的離線VM整合，radio、BT mutex、配置器、PSM與硬體輸出仍有明示fixture，沒有真手機或喇叭測試。原型限定每次啟動一段協商，暫停或斷線後仍需重啟；恢復播放、重新連線、正常模式資源ownership、heap、STOP_DONE與App菜單尚未完成。</p>'
 card+='<p>使用者目前不在車機旁；原始語音已還原，本輪沒有改寫裝置或發出聲音。回來先確認Aud Ver2.10，再安排只讀Wxxx診斷。整體約35%、原生App整合25%，屬里程碑估計；研究持續，配對優先、麥克風取消、Android Auto排後、Google Maps暫緩。</p></div>'
 report,n=re.subn(r'<div class="card"><h2>最新進展：原生藍牙接收閘門阻止錯誤播放狀態</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
 report,n=re.subn(r'(<div class="progress-total">約 <strong>)33(%</strong>)',r'\g<1>35\2',report,count=1);assert n==1
 report,n=re.subn(r'(<progress id="research-progress" max="100" value=")33("[^>]*>)33(%</progress>)',r'\g<1>35\g<2>35\3',report,count=1);assert n==1
 old='<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(old_next)+'</td></tr>';assert report.count(old)==1
 report=report.replace(old,'<tr><td>原生 App 入口與功能整合</td><td>25%</td><td>'+html.escape(next_text)+'</td></tr>',1)
 report,n=re.subn(r'<tr><td>原生音訊與元件原型</td><td>50%</td><td>.*?</td></tr>',lambda _:'<tr><td>原生音訊與元件原型</td><td>55%</td><td>'+html.escape(audio_next)+'</td></tr>',report,count=1);assert n==1
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
 audit=dict(prior,all_passed=True,updated_utc=now.isoformat(),previous_checkpoint=B+'previous-audit.json',protected_sources=protected,
  canonical_after_sha256=after,current_state_sha256=after[P.CANONICAL[0]],report_sha256=after[P.CANONICAL[3]],local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],
  current_findings=258,current_public_details=229,estimate_percent=35,weighted_estimate_percent=34.5,App_estimate_percent=25,
  selected_native_remote_binding_scopes=guest['cases'],native_remote_binding_totals=fileproof['totals'],new_independent_agent_review=False,device_IO_this_turn=False,
  native_remote_F1_existing_Source_SBC_FIFO_connected_offline=True,physical_phone_App_warm_ownership_STOP_DONE_verified=False,
  scope_checks=dict(prior['scope_checks'],four_new_native_media_to_Source_scopes=True,old3409_sources_preserved=True,one_stream_per_boot_limit_visible=True,live_report_time_and_35_App25_visible=True))
 create(OUT,audit)
 oldkey='current_native_reply_admission_ROOT_checkpoint';assert latest.pop(oldkey)==OLD
 latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_reply_admission_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),current_native_remote_binding_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},
  local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,current_physical_test_requested=False,
  user_away_for_class=True,canonical_hash_readback_uncached=True,service_not_restarted=True)
 latest['progress_display_verified'].update(estimate_percent=35,completed_items=229,report_updated_time=iso,research_updated_time=iso,native_media_Source_bridge_offline_scope_visible=True,one_stream_per_boot_limit_visible=True)
 write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=258,details=229,protected_sources=len(protected),updated_Taiwan=iso,estimate_percent=35,App_estimate_percent=25,report_bytes=len(served),served_sha256=after[P.CANONICAL[3]],goal_status='active',device_IO=False)),flush=True)
if __name__=='__main__':main()
