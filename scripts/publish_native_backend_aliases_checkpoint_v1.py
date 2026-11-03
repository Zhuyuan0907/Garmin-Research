#!/usr/bin/env python3
"""Publish frozen selected backend-alias evidence; no guest or device operations."""
import json,hashlib,re,html,importlib.util,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('backend_report_helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
G='staging/native-player-backend-aliases/'
B='staging/native-player-backend-aliases-checkpoint/'
OLD='evidence/firmware-analysis/native-provider-entries-ROOT-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-backend-aliases-ROOT-checkpoint-audit.json'
def main():
 assert not(ROOT/B).exists() and not(ROOT/OUT).exists(),'Preserve attempted publications'
 prior=read(OLD);assert prior['all_passed'] and prior['current_findings']==283 and prior['current_public_details']==261
 assert len(prior['protected_sources'])==4280 and all(sha(p)==h for p,h in prior['canonical_after_sha256'].items())
 protected=dict(prior['protected_sources']);verified={}
 def register(entries):
  for p,h in entries.items():
   if p not in verified:verified[p]=sha(p)
   assert verified[p]==h and(p not in protected or protected[p]==h),p
   protected[p]=h
 register(protected.copy())
 build,selected,files=[read(G+p)for p in('build-v1.json','backend-alias-v4-proof.json','ROOT-backend-alias-file-proof-v3.json')]
 assert all(d['all_passed']for d in(build,selected,files)) and selected['case_count']==files['case_count']==1
 totals=files['totals'];assert totals['backend_alias_foreign_rejections']==18 and totals['backend_alias_racer_runs']==3 and totals['interior_clear_rejections']==3
 assert totals['backend_alias_full_returns']==selected['backend_alias_full_returns'] and totals['original_retirement_full_returns']==6
 assert totals['fixed_clear_ARM_entries']==8 and totals['original_null_backend_branches']==3 and totals['original_valid_config_fallbacks']==1
 assert totals['provider_foreign_rejections']==18 and totals['music_PCM_bytes']==186 and files['cases'][0]['other_original_config_return']==65535
 assert not selected['device_IO'] and not files['device_IO'] and not files['all_EA_CFG_leaf_writers_STOP_DONE_heap_App_phone_or_device']
 for name,code in(('build-v1',0),('build-v2',1),('build-v3',1),('guest-v1',1),('guest-v2',1),('guest-v3',1),('guest-v4',0),('file-v3',0)):
  r=read(G+name+'-terminal-tool-receipt.json');r=r.get('actual_terminal',r)
  assert r['exit_code']==code and 'session_id'not in r,(name,r)
 register(files['source_sha256'])
 for p in sorted((ROOT/G).rglob('*')):
  if p.is_file():register({str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT)))})
 for p in(OLD,'scripts/publish_native_backend_aliases_checkpoint_v1.py','staging/native-player-provider-entries-checkpoint/publication-v1-terminal-tool-receipt.json','staging/native-player-provider-entries-checkpoint/post-publication-live-readback-v1.json'):
  register({p:sha(p)})
 state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress']
 assert state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining']
 assert not app['native_app_running'] and not app['direct_phone_music_verified']
 assert len(app['static_findings'])==283 and len(progress['completed'])==261
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
  ('native_five_backend_aliases_single_loaded_image',G+'build-v1.json','Five additional backend aliases protected in same stock-loaded DLL: config, stop, start/read, seek and clear. Exact private receiver and typed actual Mixer grant required; interior pointer rejected. Selected aliases only; other direct leaf writers remain.'),
  ('native_eight_byte_clear_overlap_bridge',G+'ROOT-backend-alias-file-proof-v3.json','Eight-byte native clear entry uses overlapping Thumb BX-r3 and literal pointing at fixed ARM entry inside the original DLL. Complete original leaf relocated, next function prologue preserved; eight actual fixed-bridge transitions and two original leaf stores checked. Explicit DLL padding mapping is not physical MMU/heap proof.'),
  ('native_backend_actual_kernel_racer_and_controls',G+'backend-alias-v4-proof.json','Native kernel competitor performs six attempts at each of three stages: five aliases and interior clear pointer, eighteen rejected requests. Original music and all six cleanup helpers return. Other-object config fallback returns original error, three safe null branches and standalone clear execute; null config is invalid original input.'),
  ('native_backend_ROOT_FILE_reconstruction',G+'ROOT-backend-alias-file-proof-v3.json','ROOT file replay checks whole loader/playback zones, CPU store opcodes/preimages, five entry literals, full alias ABI returns, actual native-kernel racer and private retirement provenance. Failed loader-gap, null-config and missing-linker-symbol controls retained. No guest rerun, independent-agent claim, complete CFG/all writers, physical App or phone claim.')]
 for key,p,scope in findings:
  assert key not in app['static_findings'];app['static_findings'][key]=dict(evidence=p,evidence_sha256=sha(p),scope=scope,evidence_type='ROOT bounded offline evidence',device_io=False,physical_App_or_audio_verified=False)
 details=[
  '離線播放器新增五個底層音源入口保護：設定、停止、啟動／讀取、seek及clear。即使繞過上層六個音源入口，仍須符合私人槽位與真正混音任務的授權；指向私人物件內部的錯位指標也會拒絕。這些攔截尚未安裝到車機，也未涵蓋全部直接寫入。',
  '原kernel建立的測試任務在音源綁定後、等待Stop回覆時、回收後，各嘗試五個別名及一次錯位clear，共十八次都被拒，私人資料未變。原混音任務仍播放186bytes音樂PCM並完成六個原廠清理函式；既有十八次上層音源攔截也保留。',
  '原clear函式只有八個bytes，直接使用一般跳轉會覆蓋下一個函式。新原型讓Thumb跳轉指令與目標位址共用部分bytes，跳到同一份DLL內的ARM入口；核對八次實際跳轉、完整原clear body及下一函式prologue。載入器空白區由明示模擬映射補足，不能當作實機MMU或heap證據。',
  '原設定函式的空指標分支仍寫入receiver+524，不能用NULL驗證正常返回。改以完整測試物件且無callback，原程式清除mode並回傳原廠錯誤；另核對停止、讀取、seek三個安全NULL分支及其他物件clear。原設定錯誤65535仍不算設定成功；四參數讀取入口保留第四參數。',
  f"ROOT核對{totals['store_opcodes_checked']}筆CPU寫入、{totals['backend_alias_full_returns']}次底層入口完整返回、十八次底層拒絕及六次原生清理返回。失敗紀錄及所有4280個既有保護檔保留。接著追查仍可直接設定／消耗音源的leaf入口，再研究重連、安全歸還資源、實機載入與App菜單；原美玲2.10還原已由使用者確認，本輪沒有車機寫入或播放。"]
 now=datetime.now(timezone.utc);old_next=progress['phases'][4]['next']
 focus='Five selected backend aliases now guarded with eighteen real-kernel rejections and complete original music/Stop returns. Eight-byte clear overlap bridge stays inside stock-loaded image; DLL padding backing is declared fixture. Next cover direct setup5E759E/consume5E75BA and confirm seek writer entry; then reconnect/yield, actual MAIN/cache, native heap and visible App. Original voice2.10 restored; no new physical test.'
 next_text='追查底層直接設定與消耗音源的入口，再處理重連、安全歸還資源、實機載入與App菜單。五個新增底層入口只在離線驗證，大型播放器未安裝；目前無新的實體測試要求。'
 state.update(updated_utc=now.isoformat(),current_priority=focus,latest_user_instruction='User confirms original Aud Ver restored to2.10; continue authorized offline native audio/App research.')
 state['next_actions']=[focus,'Sixteen selected route/provider/backend barriers are not all direct leaf writers. Native ownership witness remains-200; guard/claim/TCBs stay resident; full STOP_DONE/reconnect/yield/unload incomplete.','Pairing first when user resumes it; microphone canceled, fidelity deferred, Android Auto later, Maps deferred. No USB/Bluetooth needed for current offline work.']
 app['remaining_work']=state['next_actions'][:2]
 app['development_observations']['native_backend_alias_protection']=dict(build=G+'build-v1.json',selected_scopes=G+'backend-alias-v4-proof.json',ROOT_FILE=G+'ROOT-backend-alias-file-proof-v3.json',totals=totals,not_all_leaf_writers_or_physical_MMU=True,resident_not_STOP_DONE_or_unload=True,physical_installed=False)
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',focused_evidence=G+'ROOT-backend-alias-file-proof-v3.json',focused_evidence_sha256=sha(G+'ROOT-backend-alias-file-proof-v3.json'),next_focus=focus,reasons=[x[2]for x in findings],physical_new_warm_candidate_tested=False,physical_2_10_control_pending=False,rollback_Aud_Ver_2_10_pending=False,device_io=False,device_IO=False,device_files_written=False,diagnostic_voice_file_written=False,native_firmware_or_research_package_written=False,native_firmware_flashed=False,device_calls_or_sound=False,automatic_calls_or_sound=False,attended_calls_or_sound=False,complete_native_App_or_phone_audio=False,physical_App_or_audio_verified=False,goal_status='active',full_goal_complete=False)
 state['attended_testing'].update(no_pending_question=True,current_attended_test='Completed original2.10/WFFF/original2.10; no new physical test requested.',USB_or_Bluetooth_required_for_current_offline_work=False,next_attended_test_not_requested_yet=True)
 for key in('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
 task.update(current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False,physical_diagnostic_and_rollback_complete=True)
 public.update(updated=now.isoformat(),deep_research=state);progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
 progress['phases'][4]['next']=next_text;progress['phases'][1]['next']='五個新增底層音源入口保護已離線核對，接著追查直接leaf寫入及重連，再測原生手機音樂。'
 progress.update(research_updated_utc=now.isoformat(),next=next_text)
 assert len(app['static_findings'])==287 and len(progress['completed'])==266
 assert progress['estimate_percent']==37 and progress['phases'][4]['estimate_percent']==35 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==36.5
 report=before.decode()
 card='<div class="card"><h2>最新進展：五個底層音源入口保護</h2><p>離線播放器新增設定、停止、啟動／讀取、seek及clear五個底層入口保護。原kernel測試任務在音源綁定後、等待Stop回覆時與回收後，嘗試五個入口及錯位指標，共十八次被拒，私人資料保持相同；原混音任務仍完成音樂播放與六個原廠停止清理函式。</p><p>八bytes的原clear入口透過指令與位址重疊，跳到同一份DLL內的ARM入口；完整原clear及下一函式入口保留。原設定函式的NULL輸入會寫入無效位址，已改用完整測試物件驗證原廠錯誤返回；其他三個安全NULL分支與清理也核對。載入器空白區是明示模擬映射，不能當作實機MMU或heap證據。</p><p><strong>尚未完成：</strong>其他直接設定／消耗音源的leaf入口、安全歸還與重連、實機載入、App菜單及手機直接音樂。估計維持整體37%、App35%。原版2.10 → WFFF → 原版2.10實機對照已完成；本輪無車機寫入或播放，目前不需要保持USB或藍牙連線。</p></div>'
 report,n=re.subn(r'<div class="card"><h2>最新進展：六個音源管理入口保護</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
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
 audit=dict(prior,all_passed=True,updated_utc=now.isoformat(),previous_checkpoint=B+'previous-audit.json',protected_sources=protected,canonical_after_sha256=after,current_state_sha256=after[P.CANONICAL[0]],report_sha256=after[P.CANONICAL[3]],local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],current_findings=287,current_public_details=266,native_backend_alias_scopes=selected['cases'],native_backend_alias_totals=totals,device_IO_this_turn=False,durable_warm_native_ownership_or_navigation_App_phone=False,new_independent_agent_review=False,scope_checks=dict(prior['scope_checks'],old4280_sources_preserved=True,backend_alias_protection_not_all_leaf_writers_or_unload=True,eight_byte_clear_bridge_in_original_DLL=True,DLL_padding_backing_not_physical_MMU=True,one_backend_saved_file_scope=True,live_report_37_App35_visible=True))
 create(OUT,audit)
 assert latest.pop('current_native_provider_entries_ROOT_checkpoint')==OLD
 latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_provider_entries_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),current_native_backend_aliases_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,current_physical_test_requested=False,canonical_hash_readback_uncached=True,service_not_restarted=True)
 latest['progress_display_verified'].update(completed_items=266,report_updated_time=iso,research_updated_time=iso,native_backend_alias_scope_visible=True,durable_ownership_not_claimed=True)
 write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=287,details=266,protected_sources=len(protected),updated_Taiwan=iso,estimate_percent=37,App_estimate_percent=35,totals=totals,report_bytes=len(served),served_sha256=after[P.CANONICAL[3]],goal_status='active',publication_device_IO=False)),flush=True)
if __name__=='__main__':main()
