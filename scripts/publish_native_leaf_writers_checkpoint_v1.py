#!/usr/bin/env python3
"""Publish frozen selected memory-writer evidence; no guest or device operations."""
import json,hashlib,re,html,importlib.util,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('backend_report_helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
G='staging/native-player-leaf-writers/'
B='staging/native-player-leaf-writers-checkpoint/'
OLD='evidence/firmware-analysis/native-backend-aliases-ROOT-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-leaf-writers-ROOT-checkpoint-audit.json'
def main():
 assert not(ROOT/B).exists() and not(ROOT/OUT).exists(),'Preserve attempted publications'
 prior=read(OLD);assert prior['all_passed'] and prior['current_findings']==287 and prior['current_public_details']==266
 assert len(prior['protected_sources'])==4393 and all(sha(p)==h for p,h in prior['canonical_after_sha256'].items())
 protected=dict(prior['protected_sources']);verified={}
 def register(entries):
  for p,h in entries.items():
   if p not in verified:verified[p]=sha(p)
   assert verified[p]==h and(p not in protected or protected[p]==h),p
   protected[p]=h
 register(protected.copy())
 build,selected,files=[read(G+n)for n in('build-v2.json','leaf-writer-v1-proof.json','ROOT-leaf-writer-file-proof-v3.json')]
 assert all(d['all_passed']for d in(build,selected,files))and selected['case_count']==files['case_count']==1
 totals=files['totals'];assert totals['leaf_writer_rejections']==24 and totals['leaf_writer_native_task_runs']==3 and totals['leaf_wrong_receiver_rejections']==6
 assert totals['leaf_writer_full_returns']==selected['leaf_writer_full_returns']==52 and totals['backend_alias_full_returns']==selected['backend_alias_full_returns']==32
 assert totals['original_retirement_full_returns']==6 and totals['fixed_clear_ARM_entries']==9 and totals['other_original_memory_controls']==24 and totals['other_memory_snapshots_reconstructed']==48
 assert totals['original_other_memory_successful_configurations']==1 and totals['original_memory_callback_pointer_stores']==8 and totals['foreign_writer_native_pool_CPU_stores']==0
 assert totals['provider_foreign_rejections']==18 and totals['backend_alias_foreign_rejections']==18 and totals['music_PCM_bytes']==186 and files['cases'][0]['other_original_config_return']==65535
 assert not selected['device_IO']and not files['device_IO']and not files['all_EA_CFG_leaf_writers_STOP_DONE_heap_App_phone_or_device']
 for name,code in(('build-v1',1),('build-v2',0),('guest-v1',0),('file-v1',1),('file-v2',1),('file-v3',0)):
  r=read(G+name+'-terminal-tool-receipt.json');r=r.get('actual_terminal',r);assert r['exit_code']==code and 'session_id'not in r,(name,r)
 register(files['source_sha256'])
 for p in sorted((ROOT/G).rglob('*')):
  if p.is_file():register({str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT)))})
 for p in(OLD,'scripts/publish_native_leaf_writers_checkpoint_v1.py','staging/native-player-backend-aliases-checkpoint/publication-v1-terminal-tool-receipt.json','staging/native-player-backend-aliases-checkpoint/post-publication-live-readback-v1.json'):
  register({p:sha(p)})
 state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress']
 assert state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining']
 assert not app['native_app_running'] and not app['direct_phone_music_verified']
 assert len(app['static_findings'])==287 and len(progress['completed'])==266
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
  ('native_memory_six_writer_barriers',G+'build-v2.json','Same stock-loaded image adds generic write and true generic seek plus direct memory setup/read/write/seek. Original function-table argument12 selects memory callbacks. Earlier 4CAF2E alias labeled seek is actually type selector; 5E752E belongs to other layout. Six selected barriers do not cover all other source kinds or arbitrary writers.'),
  ('native_memory_real_kernel_competitor',G+'leaf-writer-v1-proof.json','Native kernel writer task makes eight attempts at binding, Stop ACK wait and retirement;24 rejected calls, including6 interior receiver attempts,52 full writer ABI returns. Actual music and6 cleanup helpers return. Older PG18 and AL18 requests also rejected in this new case; no universal ownership or hardware proof.'),
  ('native_original_memory_backend_positive_controls',G+'ROOT-leaf-writer-file-proof-v3.json','Original kind selector publishes8 callbacks and original config returns0 and stores mode2 for complete standalone object.24 controls cover generic/direct reads and writes with fourth argument, absolute/relative/end seek, bounds/EOF/unprepared and two safe null branches. Object/data backing is declared BSS input, not native heap/navigation/device proof; original failed slot1 configuration still returns65535.'),
  ('native_memory_ROOT_FILE_reconstruction',G+'ROOT-leaf-writer-file-proof-v3.json','Whole loader/playback CPU stores/opcodes/preimages and48 control snapshots reconstructed; independent memory semantics checked. Actual native setter stores separate from prior zeroing. Kind12 is selector input, not a stored tag beyond560-byte clear. Failed build/padding and two FILE assumptions preserved; no guest rerun/independent-agent/full CFG/App/phone claim.')]
 for key,p,scope in findings:
  assert key not in app['static_findings'];app['static_findings'][key]=dict(evidence=p,evidence_sha256=sha(p),scope=scope,evidence_type='ROOT bounded offline evidence',device_io=False,physical_App_or_audio_verified=False)
 details=[
  '修正原廠函式名稱：先前標成seek的4CAF2E實際選擇音源類型；真正的通用seek是4CAEA8，記憶體音源seek是5E7622。5E752E屬另一種物件結構。原廠選擇參數12會發布記憶體音源的八個回呼，沒有在初始化範圍外寫入kind tag。',
  '同一份離線播放器新增六個入口保護：通用寫入、真正的通用seek，以及直接設定、讀取、寫入、seek。原kernel測試任務在綁定後、等Stop回覆時與回收後，分別嘗試八次，共二十四次全部拒絕；其中六次故意使用錯位receiver。私人音源沒有這個任務造成的CPUstores；原音樂與六個原廠停止清理返回仍正常。',
  '新增有成功結果的原廠音源操作：原type selector發布八個callback，原設定函式回傳0並寫入mode2，接著真正完成通用／直接讀寫。使用count乘width驗證第四參數；二十四組操作涵蓋absolute／relative／end seek、越界、EOF、未準備音源與兩個安全NULL入口。使用完整獨立BSS測試物件與明示資料，不代表原生heap、導航語音或實機已正常。',
  f"ROOT逐筆核對{totals['store_opcodes_checked']}筆CPUstores、52次新writer與32次底層alias完整返回；從CPU及明示輸入紀錄重建48個操作前後快照，另核對讀寫內容與位置／錯誤語意。新read入口有自己的保護patch；八bytes clear並未越界覆蓋它，不能宣稱新版仍保留未修改的read prologue。",
  '第一個build漏補未對齊write入口的兩bytes padding，已保留失敗並修正。FILE初版誤以為kind12會存在object+560，實際原callback是no-op且初始化止於560bytes；次版把先清零的stores也算入八個callback發布，已改核實際setter CPUstores。最終guest及FILE通過，所有4393個舊保護檔保持。大型播放器未安裝，原美玲2.10還原已確認；接著研究其他音源類型與生命週期，再處理重連、實機載入與App菜單。']
 now=datetime.now(timezone.utc);old_next=progress['phases'][4]['next']
 focus='Six memory-writer barriers and24 actual-kernel rejections pass with original music/Stop. True seek labels corrected; original selector argument12 publishes memory callbacks and original config succeeds for explicit standalone object. Next assess other-kind writes and required lifetime/ownership, reconnect/yield, native heap, actual MAIN/cache and visible App. No device test pending.'
 next_text='追查其他音源類型與播放器生命週期，再完成重連、資源歸還、原生heap、實機載入與App菜單。原廠記憶體音源的讀寫成功仍是離線測試物件；大型播放器尚未安裝，目前無新實體測試要求。'
 state.update(updated_utc=now.isoformat(),current_priority=focus,latest_user_instruction='User confirms original Aud Ver restored to2.10; continue authorized offline native audio/App research.')
 state['next_actions']=[focus,'Twenty-two selected route/provider/backend/memory barriers do not cover all other-kind direct writers or universal ownership. Native ownership witness remains-200; guard/claim/TCBs stay resident; full STOP_DONE/reconnect/yield/unload incomplete.','Pairing first when user resumes it; microphone canceled, fidelity deferred, Android Auto later, Maps deferred. No USB/Bluetooth needed for current offline work.']
 app['remaining_work']=state['next_actions'][:2]
 app['development_observations']['native_memory_writer_protection']=dict(build=G+'build-v2.json',selected_scopes=G+'leaf-writer-v1-proof.json',ROOT_FILE=G+'ROOT-leaf-writer-file-proof-v3.json',totals=totals,standalone_memory_object_not_native_heap=True,not_all_other_kind_writers_or_physical_MMU=True,resident_not_STOP_DONE_or_unload=True,physical_installed=False)
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',focused_evidence=G+'ROOT-leaf-writer-file-proof-v3.json',focused_evidence_sha256=sha(G+'ROOT-leaf-writer-file-proof-v3.json'),next_focus=focus,reasons=[x[2]for x in findings],physical_new_warm_candidate_tested=False,physical_2_10_control_pending=False,rollback_Aud_Ver_2_10_pending=False,device_io=False,device_IO=False,device_files_written=False,diagnostic_voice_file_written=False,native_firmware_or_research_package_written=False,native_firmware_flashed=False,device_calls_or_sound=False,automatic_calls_or_sound=False,attended_calls_or_sound=False,complete_native_App_or_phone_audio=False,physical_App_or_audio_verified=False,goal_status='active',full_goal_complete=False)
 state['attended_testing'].update(no_pending_question=True,current_attended_test='Completed original2.10/WFFF/original2.10; no new physical test requested.',USB_or_Bluetooth_required_for_current_offline_work=False,next_attended_test_not_requested_yet=True)
 for key in('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
 task.update(current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False,physical_diagnostic_and_rollback_complete=True)
 public.update(updated=now.isoformat(),deep_research=state);progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
 progress['phases'][4]['next']=next_text;progress['phases'][1]['next']='原廠記憶體音源讀寫與六個新入口保護已離線核對；接著研究其他類型、生命週期與重連，再測原生手機音樂。'
 progress.update(research_updated_utc=now.isoformat(),next=next_text)
 assert len(app['static_findings'])==291 and len(progress['completed'])==271
 assert progress['estimate_percent']==37 and progress['phases'][4]['estimate_percent']==35 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==36.5
 report=before.decode()
 card='<div class="card"><h2>最新進展：原廠記憶體音源讀寫與入口保護</h2><p>離線測試已用原廠流程建立記憶體音源，設定成功後完成讀取、寫入與移動位置。二十四組操作涵蓋通用及直接函式、越界、檔案尾端、未準備狀態；操作前後四十八個資料快照已從執行紀錄重建。這使用完整BSS測試物件與明示資料，尚未驗證車機的原生記憶體分配或喇叭。</p><p>新增通用寫入、真正的seek，以及直接設定／讀取／寫入／seek六個入口保護；原kernel測試任務在三個階段共二十四次呼叫被拒，私人音源不變，原音樂及六個停止清理函式仍完整返回。也修正名稱：先前4CAF2E是音源類型選擇，真正的通用seek在另一處。</p><p><strong>尚未完成：</strong>其他音源類型、生命週期與資源歸還、重連、實機載入、App菜單與手機直接音樂。估計維持整體37%、App35%。原美玲2.10已還原並確認；本輪沒有車機寫入或播放，目前不需要USB或藍牙保持連線。</p></div>'
 report,n=re.subn(r'<div class="card"><h2>最新進展：五個底層音源入口保護</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
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
 audit=dict(prior,all_passed=True,updated_utc=now.isoformat(),previous_checkpoint=B+'previous-audit.json',protected_sources=protected,canonical_after_sha256=after,current_state_sha256=after[P.CANONICAL[0]],report_sha256=after[P.CANONICAL[3]],local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],current_findings=291,current_public_details=271,native_leaf_writer_scopes=selected['cases'],native_leaf_writer_totals=totals,device_IO_this_turn=False,durable_warm_native_ownership_or_navigation_App_phone=False,new_independent_agent_review=False,scope_checks=dict(prior['scope_checks'],old4393_sources_preserved=True,memory_writer_protection_not_all_other_kind_writers_or_unload=True,prior_kind_selector_and_true_seek_corrected=True,original_memory_config_success_and48_snapshots=True,eight_byte_clear_bridge_in_original_DLL=True,DLL_padding_backing_not_physical_MMU=True,one_memory_writer_saved_file_scope=True,live_report_37_App35_visible=True))
 create(OUT,audit)
 assert latest.pop('current_native_backend_aliases_ROOT_checkpoint')==OLD
 latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_backend_aliases_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),current_native_leaf_writers_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,current_physical_test_requested=False,canonical_hash_readback_uncached=True,service_not_restarted=True)
 latest['progress_display_verified'].update(completed_items=271,report_updated_time=iso,research_updated_time=iso,native_memory_writer_scope_visible=True,durable_ownership_not_claimed=True)
 write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=291,details=271,protected_sources=len(protected),updated_Taiwan=iso,estimate_percent=37,App_estimate_percent=35,totals=totals,report_bytes=len(served),served_sha256=after[P.CANONICAL[3]],goal_status='active',publication_device_IO=False)),flush=True)
if __name__=='__main__':main()
