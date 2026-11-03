#!/usr/bin/env python3
"""Publish frozen six-provider-entry evidence; no device or guest operations."""
import json,hashlib,re,html,importlib.util,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('warm_retirement_report_helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
G='staging/native-player-provider-entries/'
B='staging/native-player-provider-entries-checkpoint/'
OLD='evidence/firmware-analysis/native-warm-retirement-ROOT-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-provider-entries-ROOT-checkpoint-audit.json'
def main():
 assert not(ROOT/B).exists() and not(ROOT/OUT).exists(),'Preserve attempted publications'
 prior=read(OLD);assert prior['all_passed'] and prior['current_findings']==279 and prior['current_public_details']==256
 assert all(sha(p)==h for p,h in prior['canonical_after_sha256'].items())
 protected=dict(prior['protected_sources']);verified={}
 def register(entries):
  for p,h in entries.items():
   if p not in verified:verified[p]=sha(p)
   assert verified[p]==h and(p not in protected or protected[p]==h),p
   protected[p]=h
 register(protected.copy())
 build,selected,files=[read(G+p)for p in('build-v3.json','provider-entry-v4-proof.json','ROOT-provider-entry-file-proof-v2.json')]
 assert all(d['all_passed']for d in(build,selected,files)) and selected['case_count']==files['case_count']==1
 assert selected['provider_gate_full_returns']==26 and selected['provider_foreign_racer_runs']==3 and selected['provider_foreign_rejections']==18
 assert files['totals']['store_opcodes_checked']==155749 and files['totals']['original_retirement_full_returns']==6
 assert files['totals']['provider_gate_full_returns']==26 and files['totals']['provider_foreign_rejections']==18
 assert files['cases'][0]['other_original_config_return']==65535
 assert not selected['device_IO'] and not files['device_IO'] and not files['all_effective_addresses_CFG_backend_aliases_all_writers_STOP_DONE_App_phone_or_device']
 for name,code in(('build-v1',1),('build-v2',0),('build-v3',0),('guest-v1',1),('guest-v2',1),('guest-v3',1),('guest-v4',0),('file-v1',1),('file-v2',0)):
  r=read(G+name+'-terminal-tool-receipt.json')['actual_terminal'];assert r['exit_code']==code and 'session_id'not in r
 register(files['source_sha256'])
 for p in sorted((ROOT/G).rglob('*')):
  if p.is_file():register({str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT)))})
 for p in(OLD,'scripts/publish_native_provider_entries_checkpoint_v1.py','staging/native-player-warm-retirement-checkpoint/publication-v1-terminal-tool-receipt.json','staging/native-player-warm-retirement-checkpoint/post-publication-live-readback-v1.json'):
  register({p:sha(p)})
 state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress']
 assert state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining']
 assert not app['native_app_running'] and not app['direct_phone_music_verified']
 assert len(app['static_findings'])==279 and len(progress['completed'])==256
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
  ('native_six_provider_entries_single_loaded_image',G+'build-v3.json','Single loaded warm image adds six public provider barriers: start, stop, void free, configuration, whole reset, seek. Actual private allocation captured within IRQ exclusion, retained through retirement. No device package, installed hooks, backend-alias/all-writer exclusivity or ownership witness.'),
  ('native_provider_actual_kernel_racer_and_other_callers',G+'provider-entry-v4-proof.json','Original native kernel provider racer tries six public entries after binding, during Source Stop ACK wait, and after retirement: eighteen rejected requests with private bytes preserved. Original music/Stop still completes; unclaimed allocator and void free work. Other-provider configuration forwards three writes and original error65535, not successful configuration.'),
  ('native_provider_reset_loop_and_retired_reservation',G+'ROOT-provider-entry-file-proof-v2.json','Entire native five-slot reset loop relocated to avoid entry patch covering internal loop header. Actual five original-equivalent byte clears verified; equivalent Thumb ADD forms explicitly checked. IRQ-scoped scanner temporarily reserves retired private slot, native scanner selects another slot, exact private busy byte restored.'),
  ('native_provider_ROOT_FILE_reconstruction',G+'ROOT-provider-entry-file-proof-v2.json','ROOT reconstructed155749 CPU stores across whole loader/playback zones,26 provider and40 previous gate full returns,6 full native cleanup returns,18 provider rejections. All six PC-relative entry literals checked including unaligned Stop fix; no guest rerun/new independent agent/all effective-address or complete CFG claim.')]
 for key,p,scope in findings:
  assert key not in app['static_findings'];app['static_findings'][key]=dict(evidence=p,evidence_sha256=sha(p),scope=scope,evidence_type='ROOT bounded offline evidence',device_io=False,physical_App_or_audio_verified=False)
 details=[
  '同一份離線播放器新增六個原生音源管理入口保護：啟動／讀取、停止、直接釋放、設定、全域重設及seek。音源分配器真正標記占用後，在IRQ保護內記錄私人槽位；保留到停止完成之後。尚未涵蓋底層別名入口與所有直接寫入，也沒有安裝到車機。',
  '高優先任務由原kernel建立並POST，在音源綁定後、Source等待原Stop回覆時、原生回收完成後，各嘗試六個入口；十八次全部被拒，五個音源槽及私人通道狀態不變。free與reset是void函式，測試標記只表示已呼叫，不將任意r0數值當作成功。原混音任務仍可播放186bytes音樂PCM及完成六個原廠清理函式，STOP_DONE仍未達成。',
  '未保留的槽位仍交回原程式：原分配器使用slot1、原free清除slot1的占用byte。設定測試確實執行三個原廠format寫入，但所用測試參數回傳原廠錯誤65535，不能算完整設定成功。停止後的私人slot0仍保留，分配器在IRQ保護內暫時標記它、挑選slot1，再恢復私人busy byte，沒有誤用剛回收的私人槽。',
  '全域reset的入口patch會覆蓋內部loop header，因此搬移整個原廠loop，實際完成五個槽位byte寫入。ROOT核對155749筆CPUstores（載入114155、執行41594）、37載入區域、34完整可寫區域及3個不變程式區域；26次新入口及40次既有入口完整返回、六次原廠清理返回。重定位後的兩種Thumb加一編碼已明示核對；不是字節完全相同或所有指令路徑證明。',
  '第一個guest抓到未對齊Stop入口的PC-relative literal計算錯誤，已修復；後續修正觀察器把其他槽位free誤判為私人清理，以及結果保存參數缺漏。失敗紀錄保留，最終整合guest及FILE核對通過。下一步保護底層callback別名與其餘音源寫入，再研究重連、通道歸還、實機載入與App菜單；原語音2.10已還原，本輪無車機寫入或聲音。']
 now=datetime.now(timezone.utc);old_next=progress['phases'][4]['next']
 focus='Six additional public provider barriers now protect private reserved slot, including actual whole-reset relocation and post-retirement allocator exclusion. Three real-kernel competitor runs reject eighteen provider attempts while original music/Stop and other allocator/free remain functional. Other-provider test configuration forwards but returns original error65535. Next guard backend aliases4CAE18/4CAE44/4CAE6C/4CAF2E/5E75B2 and other writers; then reconnect/yield, actual MAIN/cache installation, native heap and visible App. No new device test.'
 next_text='補齊底層音源callback別名與其他直接寫入，再處理重連、安全交還通道、實機載入與App菜單。六個新增入口只在離線映像驗證，大型播放器未安裝；目前無新的實體測試要求。'
 state.update(updated_utc=now.isoformat(),current_priority=focus)
 state['next_actions']=[focus,'Eleven selected public entry barriers do not protect all backend aliases or direct writers. Native ownership witness remains-200; guard/claim/TCBs stay resident, full STOP_DONE/reconnect/yield/unload incomplete.','Keep original voice restored. Pairing immediately first when user resumes it; microphone canceled, fidelity deferred, Android Auto later, Google Maps deferred. No USB/Bluetooth required for current offline work.']
 app['remaining_work']=state['next_actions'][:2]
 app['development_observations']['native_provider_entry_protection']=dict(build=G+'build-v3.json',selected_scopes=G+'provider-entry-v4-proof.json',ROOT_FILE=G+'ROOT-provider-entry-file-proof-v2.json',totals=files['totals'],resident_not_STOP_DONE_or_unload=True,physical_installed=False)
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',focused_evidence=G+'ROOT-provider-entry-file-proof-v2.json',focused_evidence_sha256=sha(G+'ROOT-provider-entry-file-proof-v2.json'),next_focus=focus,reasons=[x[2]for x in findings],physical_new_warm_candidate_tested=False,physical_2_10_control_pending=False,rollback_Aud_Ver_2_10_pending=False,device_io=False,device_IO=False,device_files_written=False,diagnostic_voice_file_written=False,native_firmware_or_research_package_written=False,native_firmware_flashed=False,device_calls_or_sound=False,automatic_calls_or_sound=False,attended_calls_or_sound=False,complete_native_App_or_phone_audio=False,physical_App_or_audio_verified=False,goal_status='active',full_goal_complete=False)
 state['attended_testing'].update(no_pending_question=True,current_attended_test='Completed original2.10/WFFF/original2.10; no new physical test requested.',USB_or_Bluetooth_required_for_current_offline_work=False,next_attended_test_not_requested_yet=True)
 for key in('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
 task.update(current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False,physical_diagnostic_and_rollback_complete=True)
 public.update(updated=now.isoformat(),deep_research=state);progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
 progress['phases'][4]['next']=next_text;progress['phases'][1]['next']='六個新增音源入口及限定Stop已通過離線核對；接著處理底層別名、重連與正常導航共存，再測原生手機音樂。'
 progress.update(research_updated_utc=now.isoformat(),next=next_text)
 assert len(app['static_findings'])==283 and len(progress['completed'])==261
 assert progress['estimate_percent']==37 and progress['phases'][4]['estimate_percent']==35 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==36.5
 report=before.decode()
 card='<div class="card"><h2>最新進展：六個音源管理入口保護</h2><p>離線播放器新增啟動、停止、直接釋放、設定、全域重設與seek六個入口保護。原廠音源真正分配後，在IRQ保護內記錄私人槽位；原kernel任務在綁定後、等待Stop回覆時與回收後，各嘗試六個入口，十八次都被拒。播放器仍完成音樂播放及原廠停止清理。</p><p>其他槽位仍交回原程式分配與釋放；設定試驗確實執行原格式寫入，但回傳原廠錯誤65535，未當作設定成功。全域重設搬移整個原loop，避免覆蓋loop header；停止後保留私人槽位，分配器選用其他槽並還原busy byte。ROOT核對155749筆CPU寫入、26次新入口完整返回及六個原生清理完整返回。</p><p><strong>尚未完成：</strong>這仍是指定公開入口的離線保護，底層callback別名與所有寫入、安全交還及重連、實機載入、App菜單與手機直接播放尚待驗證。估計維持整體37%、App35%。此前原版2.10 → WFFF → 原版2.10實機對照已完成；本輪沒有車機寫入或播放，不需要保持USB或藍牙連線。</p></div>'
 report,n=re.subn(r'<div class="card"><h2>最新進展：原生播放器停止與音源回收</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
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
 audit=dict(prior,all_passed=True,updated_utc=now.isoformat(),previous_checkpoint=B+'previous-audit.json',protected_sources=protected,canonical_after_sha256=after,current_state_sha256=after[P.CANONICAL[0]],report_sha256=after[P.CANONICAL[3]],local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],current_findings=283,current_public_details=261,native_provider_entry_scopes=selected['cases'],native_provider_entry_totals=files['totals'],device_IO_this_turn=False,durable_warm_native_ownership_or_navigation_App_phone=False,new_independent_agent_review=False,scope_checks=dict(prior['scope_checks'],old4182_sources_preserved=True,provider_entry_protection_not_all_writers_or_unload=True,one_provider_saved_file_scope=True,live_report_37_App35_visible=True))
 create(OUT,audit)
 assert latest.pop('current_native_warm_retirement_ROOT_checkpoint')==OLD
 latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_warm_retirement_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),current_native_provider_entries_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,current_physical_test_requested=False,canonical_hash_readback_uncached=True,service_not_restarted=True)
 latest['progress_display_verified'].update(completed_items=261,report_updated_time=iso,research_updated_time=iso,native_provider_entry_scope_visible=True,durable_ownership_not_claimed=True)
 write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=283,details=261,protected_sources=len(protected),updated_Taiwan=iso,estimate_percent=37,App_estimate_percent=35,totals=files['totals'],report_bytes=len(served),served_sha256=after[P.CANONICAL[3]],goal_status='active',publication_device_IO=False)),flush=True)
if __name__=='__main__':main()
