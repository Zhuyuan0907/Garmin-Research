#!/usr/bin/env python3
"""Publish diagnostic + requested VS Code archive evidence; no VM/device work."""
import json,hashlib,re,html,importlib.util,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('frozen_publication_helper',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
G='staging/native-platform-readonly-probe/';W='staging/garminos-vscode-workspace-v1/';B='staging/native-platform-readonly-probe-checkpoint/'
OLD='evidence/firmware-analysis/native-leaf-writers-ROOT-checkpoint-audit.json';OUT='evidence/firmware-analysis/native-platform-readonly-probe-ROOT-checkpoint-audit.json'
def main():
 assert not(ROOT/B).exists()and not(ROOT/OUT).exists()
 prior=read(OLD);assert prior['all_passed']and prior['current_findings']==291 and prior['current_public_details']==271 and len(prior['protected_sources'])==4486
 assert all(sha(p)==h for p,h in prior['canonical_after_sha256'].items())
 protected=dict(prior['protected_sources']);verified={}
 def register(entries):
  for p,h in entries.items():
   if p not in verified:verified[p]=sha(p)
   assert verified[p]==h and(p not in protected or protected[p]==h),p
   protected[p]=h
 register(protected.copy());print(json.dumps(dict(old4486_sources_verified=True)),flush=True)
 micro=read(G+'ROOT-platform-micro-file-bundle-v1.json');reader=read(G+'ROOT-platform-reader-file-proof-v1.json');guest=read(G+'platform-candidate-reader-v1-proof.json');bundle=read(G+'local-platform-probe-bundle-v1.json');export=read(W+'export-verification.json');download=read(W+'download-live-verification.json')
 assert micro['all_passed']and micro['case_count']==44 and micro['totals']['MRC']==8 and micro['totals']['full_ABI_returns']==44
 assert reader['all_passed']and reader['case_count']==guest['case_count']==2 and reader['totals']==dict(CPU_stores=903,whole_zones=24,MRC_reads=2,sample_full_returns=1)
 assert guest['all_passed']and guest['new_probe_CP15_writes']==0 and not guest['physical_candidate_acceptance_CPU_or_Main_permission_or_App_proven']
 assert export['all_passed']and export['files']==207 and not export['original_source_recovered']and export['full_MAIN_bytes_included']and export['verified_kernel_CFGs']==5 and export['linear_previews']==11
 assert download['all_passed']and download['archive_sha256']==export['archive_sha256']==sha(export['archive_path'])and download['download_service']['MainPID']=='639766'
 assert bundle['candidate_sha256']=='e12dd6b6f4c1821405b20edd2accf8a59e75e1d5ae36513117d92ad526ec4292'
 for data in(micro,reader,export):register(data['source_sha256'])
 for p in sorted((ROOT/G).rglob('*')):
  if p.is_file():register({str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT)))})
 for p in [OLD,'scripts/publish_platform_probe_workspace_checkpoint_v1.py','scripts/stage_native_platform_probe_voice.py','scripts/serve_workspace_download.py','services/garmin-workspace-download.service',W+'export-verification.json',W+'export-terminal-tool-receipt.json',W+'download-live-verification.json',export['archive_path'],'staging/native-player-leaf-writers-checkpoint/publication-v1-terminal-tool-receipt.json','staging/native-player-leaf-writers-checkpoint/post-publication-live-readback-v1.json']:register({p:sha(p)})
 for p in [G+'reader-v1-terminal-tool-receipt.json',G+'reader-file-v1-terminal-tool-receipt.json',W+'export-terminal-tool-receipt.json']:
  terminal=read(p)['actual_terminal_result'];assert terminal['exit_code']==0 and 'session_id'not in terminal,p
 state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress'];latest=read('evidence/report-web-latest.json');service=P.service_now()
 assert state['goal_status']=='active'and not state['goal_complete']and state['required_work_remaining']and not app['native_app_running']and not app['direct_phone_music_verified']
 assert len(app['static_findings'])==291 and len(progress['completed'])==271
 with urllib.request.urlopen(urllib.request.Request(latest['url'],headers={'Cache-Control':'no-cache'}),timeout=10)as r:before=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert hashlib.sha256(before).hexdigest()==sha(P.CANONICAL[3])
 (ROOT/B).mkdir();snapshots=[]
 for p,name in[(OLD,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]+list(zip(P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
  target=B+name
  with(ROOT/target).open('xb')as f:f.write((ROOT/p).read_bytes())
  h=sha(target);register({target:h});snapshots.append(dict(original=p,snapshot=target,sha256=h))
 findings=[
  ('native_platform_readonly_register_probe',G+'platform-probe-source-contract-v1.json','New v4T freestanding sampler reads CPSR, and MIDR/SCTLR only in SVC/System; no new MSR/MCR or table access. Four display units preserve original getter. Tag is cached init snapshot and controlM meaning depends on actual CPU.'),
  ('native_platform_micro44_FILE_replay',G+'ROOT-platform-micro-file-bundle-v1.json','Two explicit model CPUs across six modes plus32 formatter cases:44 full returns,12 MRS,8 MRC and88 stores reconstructed;8 modes skipped CP15, no actual physical CPU identified.'),
  ('native_platform_candidate_reader2_FILE_replay',G+'ROOT-platform-reader-file-proof-v1.json','Exact candidate original embedded reader and allfive native callbacks: positive cached repeat0B76 and wrong outer path retains2.10.903 stores/24 whole zones and one sampler ABI return reconstructed. Storage/heap/TCB fixtures remain; model register values not physical measurements.'),
  ('garminos_requested_VS_Code_workspace',W+'export-verification.json','User-requested207-file editable research workspace with exact MAIN/BOOT/voice DLL, five verified kernel CFGs,11 linear previews, C sources and portable tools. Integrity, byte-exact .byte/incbin assembly and our probe rebuild pass. Not original complete source or installable OS; LGPL source/notices retained.'),
  ('garminos_workspace_LAN_download',W+'download-live-verification.json','One named28,704,271-byte ZIP served on dedicatedLAN8766; HEAD/GET and complete SHA verified, unrelated paths404. Report service357833 remains. Firmware strings GarminOS/OS20 and official25xx link filenames2585 are distinct provenance; exact kernel vendor/full composition unproven.')]
 for key,p,scope in findings:
  assert key not in app['static_findings'];app['static_findings'][key]=dict(evidence=p,evidence_sha256=sha(p),scope=scope,evidence_type='ROOT bounded offline evidence and requested workspace export',device_io=False,physical_App_or_audio_verified=False)
 details=[
  '完成新的只讀CPU診斷：讀取CPSR，只有Supervisor／System一般任務模式讀取MIDR／SCTLR；User與例外模式跳過。沒有新增系統暫存器寫入、MMU表存取或音訊操作。四位代碼沿用原Aud Ver字串長度，表示CPU part與當下控制位元；它是初始化快照，不能證明MAIN可寫或播放器資源已就緒。',
  '兩種模擬CPU、六種模式與三十二個純格式組合，共四十四個微測試及FILE核對通過；四個允許的sampler共讀取八次CP15，八個sampler跳過。完整返回、八十八次CPUstores及七百條指令均核對。ARM926／ARM1176是模型輸入，尚未取得實機CPU資訊。',
  '新的單檔語音候選已經原廠容器與五個原檔案回呼離線載入；正向取得0B76，重複進入保留快照不重新取樣；路徑不符保持2.10。兩個載入器情境及FILE核對完成，重建九百零三次CPUstores、二十四個完整區域與一次sampler返回；沒有新增音訊區域讀寫。候選與原檔還原包只在Pi，未寫車機。',
  '依使用者要求匯出VS Code研究工作區，共207檔。包含完整原MAIN／BOOT二進位、原語音DLL、五個已驗證核心CFG、十一個明示線性預覽、研究C／組合語言、可攜式工具及來源說明。原廠完整C/C++原始碼沒有取得；語意模型與byte表示不能稱作原廠原始碼復原。',
  '工作區完整性、反組譯工具、原韌體.byte／.incbin重組與診斷程式建置通過；ZIP逐檔雜湊核對通過，約27.4MiB。已提供同區網下載8766，HTTP完整下載SHA相同，無關路徑404；原報告8765服務沒有重啟。',
  '本機韌體存在GarminOS、OS20任務路徑與OS20_root_task_ws，搭配原任務切換指令，較支持原生GarminOS／OS20環境；exact核心供應商／版本與全機組成尚未確認。官方Linux頁的nuvi25xx連結檔名實為nuvi_2585_tw的3.20／4.50，不能套用到本台HWID1352 8.00。原美玲2.10已確認；持續原生App／音訊研究，整體37%、App35%不因檔案匯出提高。']
 now=datetime.now(timezone.utc);old_next=progress['phases'][4]['next']
 focus='Requested editable VS Code research archive and LAN download completed; readonly CPU/mode probe prepared and exact candidate reader verified. Next attended CPU result, then actual memory/loader/menu integration and native direct phone music. Source reconstruction is not original complete source. Full goal active.'
 next_text='方便現場測試時用新的只讀Aud Ver診斷取得實機CPU／模式代碼，再完成真正的記憶體載入、原生音訊及App菜單。完整播放器與手機直接A2DP尚未驗證；VS Code研究專案已可下載。'
 state.update(updated_utc=now.isoformat(),current_priority=focus,latest_user_instruction='User confirms restored2.10 and requests complete GarminOS source for VS Code. Export verified firmware/research workspace with explicit limits; continue full authorized research.')
 state['next_actions']=[focus,'Native lifetime/ownership, reconnect/yield, heap, original cache/MMU permissions and installed menu remain; all22 selected barriers are bounded, no universal exclusion/unload proof.','Pairing FIRST when user offers BT test; mic canceled, fidelity deferred, Android Auto later, Google Maps deferred. No current USB/BT action or availability question pending.']
 app['remaining_work']=state['next_actions'][:2]
 app['development_observations']['native_platform_readonly_probe']=dict(candidate_bundle=G+'local-platform-probe-bundle-v1.json',micro_FILE=G+'ROOT-platform-micro-file-bundle-v1.json',reader_FILE=G+'ROOT-platform-reader-file-proof-v1.json',micro_totals=micro['totals'],reader_totals=reader['totals'],physical_CPU_identified=False,physical_candidate_installed=False,cached_initialization_snapshot=True)
 app['development_observations']['requested_VS_Code_workspace']=dict(export=W+'export-verification.json',download=W+'download-live-verification.json',archive_url=download['archive_url'],archive_sha256=export['archive_sha256'],files=207,original_full_source_recovered=False,working_copy_editable_not_frozen=True,immutable_export_zip_protected=True)
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',focused_evidence=G+'ROOT-platform-reader-file-proof-v1.json',focused_evidence_sha256=sha(G+'ROOT-platform-reader-file-proof-v1.json'),next_focus=focus,reasons=[x[2]for x in findings],device_io=False,device_IO=False,device_files_written=False,diagnostic_voice_file_written=False,native_firmware_flashed=False,device_calls_or_sound=False,physical_CPU_identified=False,physical_new_platform_candidate_tested=False,complete_native_App_or_phone_audio=False,goal_status='active',full_goal_complete=False)
 state['attended_testing'].update(no_pending_question=True,current_attended_test='Original Aud Ver2.10 confirmed; NEW CPU-only candidate prepared locally, no availability request yet.',USB_or_Bluetooth_required_for_current_offline_work=False,next_attended_test_not_requested_yet=True)
 for key in('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
 task.update(current_connection_not_rechecked_this_offline_turn=True,current_device_connection_verified=False,physical_diagnostic_and_rollback_complete=True)
 public.update(updated=now.isoformat(),deep_research=state);progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details);progress['phases'][4]['next']=next_text
 progress['phases'][1]['next']='實機CPU診斷準備完成；持續真正藍牙接收／正常模式音訊資源與App整合。原生手機音樂尚未實機驗證。';progress.update(research_updated_utc=now.isoformat(),next=next_text)
 assert len(app['static_findings'])==296 and len(progress['completed'])==277 and progress['estimate_percent']==37 and progress['phases'][4]['estimate_percent']==35 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==36.5
 report=before.decode();link=html.escape(download['archive_url'],quote=True)
 card='<div class="card"><h2>最新進展：CPU診斷與VS Code研究專案</h2><p>新的只讀CPU／模式診斷完成44組微測試與2組原廠候選讀取器情境，FILE核對通過。模擬結果0B76不是實機CPU識別；候選只在Pi，沒有寫入車機。原美玲語音已確認回到2.10。</p><p><a href="'+link+'">下載VS Code研究專案（207檔，約27.4MiB）</a>，解壓後開啟GarminOS-research.code-workspace。包含原韌體、反組譯、研究C程式與工具；<strong>原廠完整原始碼未取得</strong>，不是可直接刷入的OS。</p><p>本機韌體有GarminOS／OS20任務字串與原核心切換指令；官方25xx開源套件連結實際是2585，不能直接套用到此台2565RT。<strong>尚未完成：</strong>實機載入、正常模式音訊所有權、手機直接A2DP、App菜單、重連及安全卸載。估計保持整體37%、App35%。</p></div>'
 report,count=re.subn(r'<div class="card"><h2>最新進展：原廠記憶體音源讀寫與入口保護</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert count==1
 old='<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>'+html.escape(old_next)+'</td></tr>';assert report.count(old)==1
 report=report.replace(old,'<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>'+html.escape(next_text)+'</td></tr>',1)
 report,count=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda x:x[1]+x[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+x[3],report,count=1,flags=re.S);assert count==1
 report,count=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>',report,count=1);assert count==1
 local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
 for name in('report-updated-time','research-updated-time'):
  report,count=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert count==1
 assert 'REDACTED_PRIVATE_ID'not in report and not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',report)
 for row in snapshots:assert sha(row['original'])==row['sha256']
 create(B+'publication-inputs.json',dict(all_passed=True,protected_sources=protected,new_findings=findings,details=details,guest_rerun=False,device_IO=False));register({B+'publication-inputs.json':sha(B+'publication-inputs.json')})
 for p,d in zip(P.CANONICAL[:3],(state,task,public)):write(p,d)
 (ROOT/P.CANONICAL[3]).write_text(report);after={p:sha(p)for p in P.CANONICAL}
 with urllib.request.urlopen(urllib.request.Request(latest['url'],headers={'Cache-Control':'no-cache'}),timeout=10)as r:served=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert served==report.encode()and P.service_now()==service and {p:sha(p)for p in P.CANONICAL}==after
 audit=dict(prior,all_passed=True,updated_utc=now.isoformat(),previous_checkpoint=B+'previous-audit.json',protected_sources=protected,canonical_after_sha256=after,current_state_sha256=after[P.CANONICAL[0]],report_sha256=after[P.CANONICAL[3]],local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],current_findings=296,current_public_details=277,native_platform_probe_micro_totals=micro['totals'],native_platform_probe_reader_totals=reader['totals'],requested_workspace_export=export['archive_path'],requested_workspace_archive_sha256=export['archive_sha256'],requested_workspace_download=download['archive_url'],device_IO_this_turn=False,physical_CPU_or_Main_permissions_identified=False,original_Garmin_full_source_recovered=False,new_independent_agent_review=False,scope_checks=dict(prior['scope_checks'],old4486_sources_preserved=True,platform_registers_model_not_unit_measurements=True,platform_snapshot_not_Main_permissions=True,requested207_file_workspace_not_complete_original_source=True,immutable_zip_not_editable_working_copy_protected=True,live_report_37_App35_visible=True))
 create(OUT,audit);assert latest.pop('current_native_leaf_writers_ROOT_checkpoint')==OLD
 latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_leaf_writers_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),current_native_platform_readonly_probe_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,current_physical_test_requested=False,canonical_hash_readback_uncached=True,service_not_restarted=True,workspace_download_url=download['archive_url'])
 latest['progress_display_verified'].update(completed_items=277,report_updated_time=iso,research_updated_time=iso,platform_probe_and_requested_VS_Code_export_visible=True,original_full_source_not_claimed=True);write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=296,details=277,protected_sources=len(protected),updated_Taiwan=iso,estimate_percent=37,App_estimate_percent=35,report_bytes=len(served),served_sha256=after[P.CANONICAL[3]],workspace_download_url=download['archive_url'],goal_status='active',device_IO=False)),flush=True)
if __name__=='__main__':main()
