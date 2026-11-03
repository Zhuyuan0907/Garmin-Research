#!/usr/bin/env python3
"""Publish bounded stock task-index evidence, preserving earlier scope."""
import json,hashlib,re,html,importlib.util,urllib.request,shutil
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('frozen_report_helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
G='staging/native-os20-task-index-v2/';B='staging/native-os20-task-index-checkpoint-v1/'
OLD='evidence/firmware-analysis/garminos-storage-cleanup-checkpoint-audit.json';OUT='evidence/firmware-analysis/native-os20-task-index-checkpoint-audit.json'
def main():
 assert not(ROOT/B).exists()and not(ROOT/OUT).exists()
 old=read(OLD);assert old['all_passed']and old['current_findings']==297 and old['current_public_details']==279 and len(old['protected_sources'])==4619
 assert all(sha(p)==h for p,h in old['canonical_after_sha256'].items())
 static,guest,files=[read(G+p)for p in('static-bridge-proof.json','guest-proof.json','ROOT_FILE-proof-v2.json')]
 assert all(d['all_passed']for d in(static,guest,files))and guest['case_count']==files['case_count']==9
 assert guest['full_returns']==8 and guest['error_callsite_stops']==1 and files['totals']==dict(CPU_stores=32,pool_stores=3,whole_zones=18,instructions=876,lookup_field_reads=96,full_returns=8,error_boundaries=1)
 assert len(static['graphs'])==6 and static['adapter_records']==15 and static['stride']==64 and static['not_entire_OS_task_count']and not files['actual_task_creation_or_allocator_contract_or_live_pool_proven']
 for p,exitcode in[('staging/native-os20-task-index-v1/terminal-tool-receipt.json',1),(G+'terminal-tool-receipt.json',0),(G+'FILE-v1-terminal-tool-receipt.json',1),(G+'FILE-v2-terminal-tool-receipt.json',0)]:
  r=read(p)['actual_terminal_result'];assert r['exit_code']==exitcode and 'session_id'not in r
 protected=dict(old['protected_sources']);new_verified={}
 def register(p,h=None):
  actual=sha(p);assert h is None or h==actual,p;assert p not in protected or protected[p]==actual,p;protected[p]=actual;new_verified[p]=actual
 for data in(static,guest,files):
  for p,h in data['source_sha256'].items():register(p,h)
 for dirname in ('staging/native-os20-task-index-v1/',G,'native/os20-task-bridge/'):
  for p in sorted((ROOT/dirname).rglob('*')):
   if p.is_file():register(str(p.relative_to(ROOT)))
 for p in(OLD,'scripts/probe_os20_task_index_v1.py','scripts/probe_os20_task_index_v2.py','scripts/verify_os20_task_index_files_v1.py','scripts/verify_os20_task_index_files_v2.py','scripts/publish_os20_task_index_checkpoint_v1.py','staging/garminos-storage-cleanup-checkpoint-v1/publication-terminal-tool-receipt.json','staging/garminos-storage-cleanup-checkpoint-v1/fresh-live-readback.json'):register(p)
 state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress'];latest=read('evidence/report-web-latest.json');service=P.service_now()
 assert state['goal_status']=='active'and not state['goal_complete']and state['required_work_remaining']and not app['native_app_running']and not app['direct_phone_music_verified']and len(app['static_findings'])==297 and len(progress['completed'])==279
 with urllib.request.urlopen(urllib.request.Request(latest['url'],headers={'Cache-Control':'no-cache'}),timeout=10)as r:before=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert hashlib.sha256(before).hexdigest()==sha(P.CANONICAL[3]);(ROOT/B).mkdir();snapshots=[]
 for p,name in[(OLD,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]+list(zip(P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
  target=B+name
  with(ROOT/target).open('xb')as f:f.write((ROOT/p).read_bytes())
  register(target);snapshots.append(dict(original=p,snapshot=target,sha256=sha(target)))
 findings=[
  ('native_os20_deferred_task_bridge_static',G+'static-bridge-proof.json','Six exact bounded stock bridge CFGs identify15x64 adapter records, current-task lookup, task create calls, callback root and argument forwarding. Allocator nonnull guarantee, index-table bounds, constructor argument5 and native task lifecycle remain unknown. Static create is not actual task creation.'),
  ('native_os20_index_helpers_bounded_guest',G+'guest-proof.json','Nine explicit pool/current/stack input cases:8 stock full returns, one full-pool stop before original assertion. Existing, free, unknown and lazy-current registration execute original code and IRQ save/restore; exactly3 pool field stores, no allocation/task create/device proof.'),
  ('native_os20_index_ROOT_FILE_replay',G+'ROOT_FILE-proof-v2.json','32 exact CPU store preimages and18 whole zones,96 original effective lookup reads/results,8 saved helper ABI returns and876 instructions checked. Syntax-checked64byte C view records recovered offsets; static signature not SDK. Conditional-branch CFG and push-store verifier errors preserved and corrected, no scope rerun.')]
 for key,p,scope in findings:
  assert key not in app['static_findings'];app['static_findings'][key]=dict(evidence=p,evidence_sha256=sha(p),scope=scope,evidence_type='ROOT bounded stock-code evidence',device_io=False,physical_App_or_audio_verified=False)
 details=[
  '找到原OS20橋接的延後工作候選路徑：原建立函式521E5E透過兩個配置入口取得descriptor／workspace，再建立原TCB、填入工作索引並POST。原入口521E44經索引呼叫user callback，參數取自record+16。已恢復六個有界靜態CFG及參數／欄位，沒有執行任務建立、配置器或user callback。',
  '原索引容量為十五筆、每筆64bytes，比對+48的native task word；這是适配層容量，不是全OS只有十五個工作。非零task找不到正常返回0；找空槽但表已滿會到原診斷呼叫，含Out of OS20 tasks與原建置檔路徑。沒有把該診斷呼叫假設成可安全返回。',
  '九組新離線情境涵蓋首／中／末task、首／末空槽、未知task、滿表，以及原current helper既有／新登記。八组完整返回、一组在原錯誤呼叫前停止。新登記僅寫三個索引欄位，原IRQ save／restore真正執行；索引與current TCB是明示輸入，沒有實機空槽或新工作證明。',
  'FILE核對32筆CPUstores、18個完整區域、96次索引讀取的實際地址與值、8次ABI完整返回、876條原指令。首版CFG把條件分支誤當未知PC寫入，首版FILE漏接受push的堆疊stores；兩次工具失敗保留，修正版通過。原建立流程在恢復的本體內未先檢查空配置／空槽就寫指標，原配置器保证仍未確認；實機需先查CPU／模式與記憶體，再考慮安全延後啟動App。新紀錄用gzip，沒有複製MAIN。']
 now=datetime.now(timezone.utc);old_next=progress['phases'][4]['next'];focus='Stock OS20 adapter create/root route recovered, but only index/current helpers executed over explicit fixtures. Await optional user CPU-diagnostic USB readiness; then actual heap/capacity/mode and legal deferred GUI launch. Native music/direct A2DP/menu and full Android Auto/Maps scope remain open.'
 next_text='現場方便時先用只讀CPU診斷取得實機代碼；持續核實原OS20配置器保證、空槽與GUI就緒時點，將播放器延後到合法任務中啟動。原建立API尚未實機執行；正常音訊所有權、App菜單、手機直接A2DP及生命週期仍待完成。'
 state.update(updated_utc=now.isoformat(),current_priority=focus,latest_user_instruction='User requests continuous research and reduced duplicate storage; original full scope preserved. Optional attended CPU probe question pending; no answer or new USB volume observed.')
 state['next_actions']=[focus,'Recover original create allocator nonnull/error contract and caller priority/constructor inputs before using it. Fifteen adapter records are not the whole OS task inventory.','Continue native ownership/lifetime, real SEP and direct phone/music/UI integration; pairing FIRST when offered; mic canceled, fidelity deferred, Android Auto later, Maps deferred.','Preserve sole original disk image, RO view and shared immutable content; gzip new large traces and never alter shared source in place.']
 app['remaining_work']=state['next_actions'][:3];app['development_observations']['OS20_task_bridge']=dict(static=G+'static-bridge-proof.json',guest=G+'guest-proof.json',ROOT_FILE=G+'ROOT_FILE-proof-v2.json',typed_view='native/os20-task-bridge/recovered_abi.h',totals=files['totals'],actual_create_allocator_or_root_callback_executed=False,live_adapter_slot_availability_unmeasured=True)
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',focused_evidence=G+'ROOT_FILE-proof-v2.json',focused_evidence_sha256=sha(G+'ROOT_FILE-proof-v2.json'),next_focus=focus,reasons=[f[2]for f in findings],device_IO=False,device_io=False,device_files_written=False,diagnostic_voice_file_written=False,native_firmware_flashed=False,physical_new_platform_candidate_tested=False,physical_CPU_identified=False,complete_native_App_or_phone_audio=False,goal_status='active',full_goal_complete=False)
 state['attended_testing'].update(no_pending_question=False,current_attended_test='Optional user availability question: connect Garmin in USB mass-storage for prepared CPU-only diagnostic. No reply received; no transfer.',next_attended_test_not_requested_yet=False,physical_test_availability_question_pending=True,physical_candidate_installed=False,current_real_USB_volume_observed=False,backup_loop_is_not_live_Garmin=True)
 for key in('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing'):task[key]=state[key]
 task.update(current_device_connection_verified=False,current_real_USB_volume_observed=False)
 public.update(updated=now.isoformat(),deep_research=state);progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details);progress['phases'][4]['next']=next_text;progress.update(research_updated_utc=now.isoformat(),next=next_text)
 assert len(app['static_findings'])==300 and len(progress['completed'])==283 and progress['estimate_percent']==37 and progress['phases'][4]['estimate_percent']==35
 card='<div class="card"><h2>最新進展：原廠OS20工作橋接路徑</h2><p>找到可讓原核心啟動user callback的工作建立／入口路徑；六個有界CFG與欄位已恢復，建立API與配置器尚未執行。原索引15筆是適配層容量，不能當全OS任務數。</p><p>原索引／current helper九個離線情境：八個完整返回，一個在滿表的原診斷呼叫前停止。新登記實際只寫三個欄位。FILE核對32筆CPUstores、18完整區域、96次地址／值讀取及876條指令；輸入是模型，沒有實機空槽、建立任務或App聲音證明。</p><p><strong>下一步：</strong>只讀CPU診斷已備妥，現場可用性回覆待確認；續查配置保證、GUI就緒與合法延後啟動。原語音2.10保持還原，候選未傳入。整體37%、App35%；本輪只新增約100KiB紀錄，沒有複製MAIN或新增完整備份。</p></div>'
 report,n=re.subn(r'<div class="card"><h2>最新進展：GarminOS空間整理與研究專案</h2>.*?</div>',lambda _:card,before.decode(),count=1,flags=re.S);assert n==1
 # Retain a visible workspace download after replacing the latest card.
 download='<p><a href="'+html.escape(latest['workspace_download_url'],quote=True)+'">下載VS Code研究專案（207檔，約27.4MiB；原廠完整原始碼未取得）</a>。前輪已釋放1.81GiB；完整備份只保留sda.img，原讀取路徑為唯讀視圖。</p>'
 report=report.replace(card,card+download,1)
 oldrow='<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>'+html.escape(old_next)+'</td></tr>';assert report.count(oldrow)==1;report=report.replace(oldrow,'<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>'+html.escape(next_text)+'</td></tr>',1)
 report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda x:x[1]+x[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+x[3],report,count=1,flags=re.S);assert n==1
 report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>',report,count=1);assert n==1
 local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
 for name in('report-updated-time','research-updated-time'):
  report,n=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert n==1
 assert 'REDACTED_PRIVATE_ID'not in report and not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',report)
 for row in snapshots:assert sha(row['original'])==row['sha256']
 create(B+'publication-inputs.json',dict(all_passed=True,protected_sources=protected,new_sources_verified=new_verified,previous4619_sources_inherited_not_fresh_full_rehash=True,new_findings=findings,details=details,guest_rerun=False,device_IO=False));register(B+'publication-inputs.json')
 for p,d in zip(P.CANONICAL[:3],(state,task,public)):write(p,d)
 (ROOT/P.CANONICAL[3]).write_text(report);after={p:sha(p)for p in P.CANONICAL}
 with urllib.request.urlopen(urllib.request.Request(latest['url'],headers={'Cache-Control':'no-cache'}),timeout=10)as r:served=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert served==report.encode()and P.service_now()==service
 audit=dict(old,all_passed=True,updated_utc=now.isoformat(),previous_checkpoint=B+'previous-audit.json',protected_sources=protected,canonical_after_sha256=after,current_state_sha256=after[P.CANONICAL[0]],report_sha256=after[P.CANONICAL[3]],local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],current_findings=300,current_public_details=283,OS20_task_bridge_totals=files['totals'],OS20_adapter_slots_not_entire_OS_count=True,actual_Task_create_allocator_root_callback_executed=False,prior_full_source_rehash_repeated_this_turn=False,current_focused_sources_sha256=new_verified,scope_checks=dict(old['scope_checks'],os20_adapter_helper_only_bounded_scope=True,os20_full_pool_assertion_not_executed=True,no_complete_Task_create_or_App_claim=True))
 create(OUT,audit);assert latest.pop('current_garminos_storage_cleanup_checkpoint')==OLD;latest.setdefault('historical_offline_checkpoint_audits',{})['prior_garminos_storage_cleanup_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.update(updated_utc=now.isoformat(),current_native_os20_task_index_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,current_physical_test_requested=True,canonical_hash_readback_uncached=True,service_not_restarted=True)
 latest['progress_display_verified'].update(completed_items=283,report_updated_time=iso,research_updated_time=iso,OS20_bridge_bounded_helper_scope_visible=True);write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=300,details=283,protected_sources=len(protected),report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),updated_Taiwan=iso,free_bytes=shutil.disk_usage(ROOT).free,goal_status='active',device_IO=False)),flush=True)
if __name__=='__main__':main()
