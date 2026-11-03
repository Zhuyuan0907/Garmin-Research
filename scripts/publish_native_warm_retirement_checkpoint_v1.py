#!/usr/bin/env python3
"""Publish frozen scoped warm native retirement evidence; no device or guest operations."""
import json,hashlib,re,html,importlib.util,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('warm_retirement_report_helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
G='staging/native-player-warm-retirement/'
B='staging/native-player-warm-retirement-checkpoint/'
OLD='evidence/firmware-analysis/native-warm-physical-route-ROOT-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-warm-retirement-ROOT-checkpoint-audit.json'
def main():
 assert not(ROOT/B).exists() and not(ROOT/OUT).exists(),'Preserve attempted publications'
 prior=read(OLD);assert prior['all_passed'] and prior['current_findings']==275 and prior['current_public_details']==251
 assert all(sha(p)==h for p,h in prior['canonical_after_sha256'].items())
 protected=dict(prior['protected_sources']);verified={}
 def register(entries):
  for p,h in entries.items():
   if p not in verified:verified[p]=sha(p)
   assert verified[p]==h and(p not in protected or protected[p]==h),p
   protected[p]=h
 register(protected.copy())
 build,selected,files=[read(G+p)for p in('build-v1.json','ROOT-selected-warm-retirement-six-scopes-v1.json','ROOT-warm-retirement-file-proof-v2.json')]
 assert all(d['all_passed']for d in(build,selected,files)) and selected['case_count']==files['case_count']==6
 assert selected['completed_prefix_not_rerun'] and selected['v1_whole_suite_not_claimed_successful'] and files['FILE_v1_incomplete_suite_not_claimed_successful']
 assert [c['guest_suite_terminal_exit']for c in selected['cases']]==[130,130,130,0,0,0]
 assert files['totals']['store_opcodes_checked']==928503 and files['totals']['full_Stop_ACK_returns']==files['totals']['full_one_node_removals']==4
 assert files['totals']['original_retirement_full_returns']==24 and files['totals']['actual_Mixer_borrow_deferrals']==4
 assert not selected['device_IO'] and not files['device_IO'] and not files['native_STOP_DONE_yield_unload_all_writers_App_phone_or_device_verified']
 for name,code in(('prepare-v1',0),('build-v1',0),('guest-v1',130),('guest-v2',0),('file-v1',1),('file-v2',0)):
  r=read(G+name+'-terminal-tool-receipt.json')['actual_terminal'];assert r['exit_code']==code and 'session_id'not in r
 register(files['source_sha256'])
 for p in sorted((ROOT/G).rglob('*')):
  if p.is_file():register({str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT)))})
 for p in(OLD,'scripts/publish_native_warm_retirement_checkpoint_v1.py','staging/native-player-warm-physical-route-checkpoint/publication-v1-terminal-tool-receipt.json','staging/native-player-warm-physical-route-checkpoint/post-publication-live-readback-v1.json'):
  register({p:sha(p)})
 state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress']
 assert state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining']
 assert not app['native_app_running'] and not app['direct_phone_music_verified']
 assert len(app['static_findings'])==275 and len(progress['completed'])==251
 latest=read('evidence/report-web-latest.json');service=P.service_now()
 with urllib.request.urlopen(urllib.request.Request(latest['url'],headers={'Cache-Control':'no-cache'}),timeout=10)as r:
  before=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert hashlib.sha256(before).hexdigest()==sha(P.CANONICAL[3])
 (ROOT/B).mkdir();snapshots=[]
 for p,name in[(OLD,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]+list(zip(P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
  target=B+name
  with(ROOT/target).open('xb')as f:f.write((ROOT/p).read_bytes())
  h=sha(target);register({target:h});snapshots.append(dict(original=p,snapshot=target,sha256=h))
 findings=[
  ('native_warm_single_image_retirement_integration',G+'build-v1.json','Warm single loaded image now includes native_stop_scoped_v1 and Source registration capture/binding/Stop retry, with selected five route gates and no global eighteen-channel reset. EMULATION ONLY, no VPM/candidate/device install.'),
  ('native_warm_retirement_six_completed_scopes',G+'ROOT-selected-warm-retirement-six-scopes-v1.json','Six completed cases: three preserved prefixes from deliberately storage-interrupted EXIT130 suite, plus three gzip cases from EXIT0 suite. Normal, pre-input, full queues, actual borrowed Mixer, paused Disconnect, foreign head preservation. Entire EXIT130 suite is not successful.'),
  ('native_warm_Stop_ACK_full_remove_retains_cleanup_hold',G+'ROOT-warm-retirement-file-proof-v2.json','Four positive cases execute six original cleanup helpers/full returns each. Source waits actual Stop ACK, removes exact one-node source fully, then releases compiled session anchor and ready PCM. Early notice23 still has count1. Foreign actor rejected; actual borrow defers four times. Guard/claim/TCBs stay resident; STOP_DONE/unload/all writers not proven.'),
  ('native_warm_retirement_ROOT_FILE_reconstruction',G+'ROOT-warm-retirement-file-proof-v2.json','ROOT reconstructed928503 saved CPU stores across six loader/playback zones,180 gate full returns,50 foreign gate rejections,24 full cleanup returns. JSON/gzip encoded and decoded hashes checked; completed FILE prefix retained. No guest rerun or independent-agent review; heap/radio/output/DMA remain explicit fixtures.')]
 for key,p,scope in findings:
  assert key not in app['static_findings'];app['static_findings'][key]=dict(evidence=p,evidence_sha256=sha(p),scope=scope,evidence_type='ROOT bounded offline evidence',device_io=False,physical_App_or_audio_verified=False)
 details=[
  '已把原生停止與音源移除流程接進同一份暖啟動播放器映像。Source記錄原廠實際註冊節點及選定音源，停止時關閉新資料入口、等待正在使用的資料歸還，再要求原混音程式清理。這份大型播放器仍只在離線環境執行，尚未安裝到車機。',
  '六種停止情境的紀錄已完成：播放後停止、尚未收到音樂就停止、PCM及壓縮資料佇列塞滿時停止、混音任務仍借用資料時停止、暫停後由原Disconnect觸發停止，以及外部更動音源節點時拒絕回收。外部更動節點的情境會拒絕回收，保留原資料。',
  '四個可回收情境均保留清理鎖，收到原廠Stop完整回覆後才完整移除一個音源節點；之後才釋放播放器資料及取消剩餘待播放PCM。共24次原廠清理函式完整返回，混音仍借用資料時延後四次。通知23出現時節點數仍是1，不能拿它當移除完成；另兩個占用通道的head與count保持不變。',
  'ROOT從保存的JSON及壓縮JSON核對928503筆CPU寫入、180次入口完整返回與50次其他任務遭拒的請求。六次載入各有37個完整區域，播放各有34個可寫區域與3個不變程式區域。初次guest因儲存空間主動中斷，已完成的三項保留；後三項改保存為壓縮檔，沒有重跑已完成項目。FILE檢查亦修正未收到音樂前混音任務尚未建立的假設。',
  '停止後仍保留模組、原廠任務與私人通道claim；尚未完成全體寫入入口的保護、STOP_DONE／安全卸載、重新連線、實機MAIN與cache安裝、App菜單及手機直接播放。原語音2.10實機還原確認已完成；本輪沒有USB寫入、藍牙配對、來電或聲音，暫時不需要操作車機。']
 now=datetime.now(timezone.utc);old_next=progress['phases'][4]['next']
 focus='Warm single loaded image now executes scoped native Stop/ACK/full one-node removal before session-anchor/FIFO release in four positive cases; six saved-file scopes verified. Guard/claim/TCBs remain pinned. Next guard remaining pool reset/free/configuration/alias writers, then STOP_DONE/yield/reconnect, actual MAIN/cache installation, native heap and visible App. Physical diagnostic2.10/WFFF/2.10 remains complete; no new device test requested.'
 next_text='補齊尚未涵蓋的原生音源重設、釋放與設定入口，研究停止後重新連線及安全交還通道；再驗證實機載入、記憶體與App菜單。目前大型播放器未安裝，無新的實體測試要求。'
 state.update(updated_utc=now.isoformat(),current_priority=focus)
 state['next_actions']=[focus,'Current five gates are selected-entry barriers, not protection of all pool/reset/free/alias writers or durable native ownership. Native ownership witness remains-200.','Keep original voice restored. Pairing immediately first when user resumes it; microphone canceled, fidelity deferred, Android Auto later, Google Maps deferred. No USB/Bluetooth required for current offline work.']
 app['remaining_work']=state['next_actions'][:2]
 app['development_observations']['native_warm_retirement']=dict(build=G+'build-v1.json',selected_scopes=G+'ROOT-selected-warm-retirement-six-scopes-v1.json',ROOT_FILE=G+'ROOT-warm-retirement-file-proof-v2.json',totals=files['totals'],resident_not_STOP_DONE_or_unload=True,physical_installed=False)
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',focused_evidence=G+'ROOT-warm-retirement-file-proof-v2.json',focused_evidence_sha256=sha(G+'ROOT-warm-retirement-file-proof-v2.json'),next_focus=focus,reasons=[x[2]for x in findings],physical_new_warm_candidate_tested=False,physical_2_10_control_pending=False,rollback_Aud_Ver_2_10_pending=False,device_io=False,device_IO=False,device_files_written=False,diagnostic_voice_file_written=False,native_firmware_or_research_package_written=False,native_firmware_flashed=False,device_calls_or_sound=False,automatic_calls_or_sound=False,attended_calls_or_sound=False,complete_native_App_or_phone_audio=False,physical_App_or_audio_verified=False,goal_status='active',full_goal_complete=False)
 state['attended_testing'].update(no_pending_question=True,current_attended_test='Completed original2.10/WFFF/original2.10; no new physical test requested.',USB_or_Bluetooth_required_for_current_offline_work=False,next_attended_test_not_requested_yet=True)
 for key in('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
 task.update(current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False,physical_diagnostic_and_rollback_complete=True)
 public.update(updated=now.isoformat(),deep_research=state);progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
 progress['phases'][4]['next']=next_text;progress['phases'][1]['next']='暖啟動播放器的限定Stop與音源移除已通過離線核對；接著處理其餘音源入口、重新連線與正常導航共存，再測原生手機音樂。'
 progress.update(research_updated_utc=now.isoformat(),next=next_text)
 assert len(app['static_findings'])==279 and len(progress['completed'])==256
 assert progress['estimate_percent']==37 and progress['phases'][4]['estimate_percent']==35 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==36.5
 report=before.decode()
 card='<div class="card"><h2>最新進展：原生播放器停止與音源回收</h2><p>同一份暖啟動播放器已接入原廠停止流程。六種情境的保存紀錄完成核對；四種可回收情境會等待混音任務歸還資料、收到完整Stop回覆、完整移除音源，之後才釋放播放器資料。包含暫停後藍牙Disconnect、佇列塞滿及播放中的停止；音源被外部更動時保留資料、不誤刪。</p><p>ROOT核對928503筆保存CPU寫入、24次原廠清理函式完整返回、180次保護入口返回。這是使用精確韌體備份的限定離線驗證，記憶體服務、無線電及喇叭輸出仍有明示模擬邊界。</p><p><strong>尚未完成：</strong>模組與任務仍保留，所有音源寫入入口、安全卸載及重連、實機載入、App菜單與手機直接播放尚待驗證。估計維持整體37%、App35%。此前實機原版2.10 → WFFF → 原版2.10已確認，原美玲語音已恢復；這輪沒有車機寫入或音訊播放，目前不需要USB或藍牙連線。</p></div>'
 report,n=re.subn(r'<div class="card"><h2>最新進展：實機 WFFF 診斷與還原完成</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
 old='<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>'+html.escape(old_next)+'</td></tr>';assert report.count(old)==1
 report=report.replace(old,'<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>'+html.escape(next_text)+'</td></tr>',1)
 report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda x:x[1]+x[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+x[3],report,count=1,flags=re.S);assert n==1
 report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>',report,count=1);assert n==1
 local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
 for name in('report-updated-time','research-updated-time'):
  report,n=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert n==1
 assert not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',report)and 'REDACTED_PRIVATE_ID'not in report
 for row in snapshots:assert sha(row['original'])==row['sha256']
 create(B+'publication-inputs.json',dict(all_passed=True,protected_sources=protected,new_findings=findings,details=details,guest_rerun=False,publication_does_device_IO=False));register({B+'publication-inputs.json':sha(B+'publication-inputs.json')})
 for p,d in zip(P.CANONICAL[:3],(state,task,public)):write(p,d)
 (ROOT/P.CANONICAL[3]).write_text(report);after={p:sha(p)for p in P.CANONICAL}
 with urllib.request.urlopen(urllib.request.Request(latest['url'],headers={'Cache-Control':'no-cache'}),timeout=10)as r:
  served=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert served==report.encode() and P.service_now()==service and {p:sha(p)for p in P.CANONICAL}==after
 audit=dict(prior,all_passed=True,updated_utc=now.isoformat(),previous_checkpoint=B+'previous-audit.json',protected_sources=protected,canonical_after_sha256=after,current_state_sha256=after[P.CANONICAL[0]],report_sha256=after[P.CANONICAL[3]],local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],current_findings=279,current_public_details=256,native_warm_retirement_scopes=selected['cases'],native_warm_retirement_totals=files['totals'],device_IO_this_turn=False,durable_warm_native_ownership_or_navigation_App_phone=False,new_independent_agent_review=False,scope_checks=dict(prior['scope_checks'],old4117_sources_preserved=True,resident_retirement_not_STOP_DONE_or_unload=True,six_retirement_saved_file_scopes=True,live_report_37_App35_visible=True))
 create(OUT,audit)
 assert latest.pop('current_native_warm_physical_route_ROOT_checkpoint')==OLD
 latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_warm_physical_route_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),current_native_warm_retirement_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,current_physical_test_requested=False,canonical_hash_readback_uncached=True,service_not_restarted=True)
 latest['progress_display_verified'].update(completed_items=256,report_updated_time=iso,research_updated_time=iso,native_warm_retirement_scope_visible=True,durable_ownership_not_claimed=True)
 write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=279,details=256,protected_sources=len(protected),updated_Taiwan=iso,estimate_percent=37,App_estimate_percent=35,totals=files['totals'],report_bytes=len(served),served_sha256=after[P.CANONICAL[3]],goal_status='active',publication_device_IO=False)),flush=True)
if __name__=='__main__':main()
