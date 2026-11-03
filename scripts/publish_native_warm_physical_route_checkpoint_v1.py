#!/usr/bin/env python3
"""Publish attended WFFF/rollback and scoped offline native-entry protection.
No device operation, guest execution, sound, daemon restart or goal completion.
"""
import json,hashlib,re,html,importlib.util,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('warm_physical_report_helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
G='staging/native-player-route-entries/'
B='staging/native-player-warm-physical-route-checkpoint/'
OLD='evidence/firmware-analysis/native-warm-entry-ROOT-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-warm-physical-route-ROOT-checkpoint-audit.json'
CONTROL='evidence/native-marker-physical-original-control-20261005T044607Z.json'
STAGE='evidence/native-warm-probe-physical-stage-20261005T044711Z.json'
POSITIVE='evidence/native-warm-probe-physical-positive-20261005T045004Z.json'
RESTORE='evidence/native-warm-probe-physical-original-restore-20261005T045115Z.json'
FINAL='evidence/native-warm-probe-physical-final-control-20261005T045419Z.json'
def main():
 assert not(ROOT/B).exists()and not(ROOT/OUT).exists()
 prior=read(OLD);assert prior['all_passed']and prior['current_findings']==271 and prior['current_public_details']==246
 assert all(sha(p)==h for p,h in prior['canonical_after_sha256'].items())
 protected=dict(prior['protected_sources']);verified={}
 def register(entries):
  for p,h in entries.items():
   if p not in verified:verified[p]=sha(p)
   assert verified[p]==h and(p not in protected or protected[p]==h),p
   protected[p]=h
 register(protected.copy())
 original,stage,positive,restore,final=[read(p)for p in(CONTROL,STAGE,POSITIVE,RESTORE,FINAL)]
 candidate='1fa09e3258ac9e571f8e2ca6d824c5edd305d2f00e7c956c1d6b33df5a3226ba'
 rollback='b5f132ae4b073d6e804f7a7b639a60b1055573f9fbb65144f18f3b2198a5de68'
 assert original['physical_original_Aud_Ver_2_10_confirmed']and positive['user_answer_verbatim']=='WFFF'and positive['sample_mask']==4095
 assert final['physical_A_B_A_sequence_complete']and final['sequence']==['2.10','WFFF','2.10']and final['no_pending_physical_question']
 for d,h,size in((stage,candidate,20136960),(restore,rollback,20133888)):
  assert d['operation']['installed_sha256']==h and d['operation']['bytes']==size and d['operation']['readback_verified']and d['safely_unmounted']
  assert d['operation']['target']=='Voice/Chinese_Big5_MeiLing.vpm'and not d['operation']['other_files_written']and not d['operation']['firmware_flashed']
 assert sha(stage['operation']['fresh_backup'])==rollback and sha(restore['operation']['fresh_backup'])==candidate
 for d in(stage,restore):
  p=d['operation']['fresh_backup'];register({p:sha(p)})
  p=str(Path(p).parent/'operation.json');register({p:sha(p)})
 assert not positive['native_durable_channel_ownership_or_phone_music_proven']and not final['native_App_or_direct_phone_audio_proven']
 build,guest,files=[read(G+p)for p in('build-v2.json','route-entry-v5-proof.json','ROOT-route-entry-file-proof-v1.json')]
 assert all(d['all_passed']for d in(build,guest,files))and not build['device_IO']and not build['durable_native_ownership']
 assert guest['selected_native_entry_barriers']==5 and guest['true_kernel_interference_runs']==2 and guest['target_rejections']==10
 assert files['totals']['native_gate_full_returns']==34 and files['totals']['original_native_mutexes_held_at_claim']==3 and files['totals']['store_opcodes_checked']==164666
 for name in('prepare-v2','build-v2','guest-v5','file-v1'):
  receipt=read(G+name+'-terminal-tool-receipt.json');r=receipt['actual_terminal']
  assert r['exit_code']==0 and 'session_id'not in r
 register(files['source_sha256'])
 for p in sorted((ROOT/G).rglob('*')):
  if p.is_file():register({str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT)))})
 for p in(CONTROL,STAGE,POSITIVE,RESTORE,FINAL,OLD,'scripts/stage_native_warm_probe_voice.py','scripts/publish_native_warm_physical_route_checkpoint_v1.py','staging/native-player-warm-entry-checkpoint/publication-v1-terminal-tool-receipt.json'):
  register({p:sha(p)})
 state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress']
 assert state['goal_status']=='active'and not state['goal_complete']and state['required_work_remaining']
 assert not app['native_app_running']and not app['direct_phone_music_verified']
 assert len(app['static_findings'])==271 and len(progress['completed'])==246
 latest=read('evidence/report-web-latest.json');service=P.service_now()
 with urllib.request.urlopen(latest['url'],timeout=10)as r:before=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert hashlib.sha256(before).hexdigest()==sha(P.CANONICAL[3])
 (ROOT/B).mkdir();snapshots=[]
 for p,name in[(OLD,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]+list(zip(P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
  target=B+name
  with (ROOT/target).open('xb')as f:f.write((ROOT/p).read_bytes())
  h=sha(target);register({target:h});snapshots.append(dict(original=p,snapshot=target,sha256=h))
 findings=[
  ('physical_original_and_W_diagnostic_A_B_A',FINAL,'Attended user-reported Aud Ver2.10 -> WFFF -> restored2.10. Exact single-file backup/readback and safe unmount are recorded. Original marker rollback control is also closed; no MAIN/BOOT flash or player installation.',True),
  ('physical_WFFF_audio_initialization_snapshot',POSITIVE,'Exact diagnostic candidate ran on the actual device and displayedWFFF. Twelve defined initialization-time conditions are true; this is a cached snapshot, not live monitoring, durable ownership, a native menu App or phone/speaker playback.',True),
  ('native_five_entry_barriers_real_kernel_racer',G+'route-entry-v5-proof.json','Corrected eight-byte allocator patch preserves native loop back-edge. Five selected route gates reject ten attempts by a real kernel task at warm attach and established playback; unclaimed profile/provider calls still forward. Three actual native mutexes held at claim. Boot-pinned claim is not all-writer exclusivity or Stop/yield.',False),
  ('native_route_entry_ROOT_file_reconstruction',G+'ROOT-route-entry-file-proof-v1.json','164666 actual CPU stores reconstructed across loader and playback zones;34 gate returns,2 real-kernel interference runs,10 rejections, original allocator selects free slot1 and leaves private slot0 intact. ROOT FILE, no guest rerun or new independent-agent review.',False)]
 for key,p,scope,physical in findings:
  assert key not in app['static_findings'];app['static_findings'][key]=dict(evidence=p,evidence_sha256=sha(p),scope=scope,evidence_type='attended user-reported physical diagnostic'if physical else'ROOT bounded offline evidence',device_io=physical,physical_diagnostic_observed=physical,physical_App_or_audio_verified=False)
 details=[
  '使用者回到現場，冷重開機選中文－美玲並確認原版本2.10；安裝只讀音訊診斷後顯示WFFF，再還原原檔並重開機確認2.10。原版→診斷版→原版的實機畫面對照完成，先前M7Q9還原後的2.10確認也已補齊。',
  '實機WFFF表示十二項定義條件在語音初始化快照全部符合：原condition標記、通道識別、原廠callback、profile、空list與節點數、未prepared的provider、清空methods、空globalhead、inactive mixer、至少一個可用音源槽，以及mapping。Aud Ver讀取快取結果，不能當即時監視、長期獨占或已能播手機音樂的證明。',
  '本輪只替換Voice/Chinese_Big5_MeiLing.vpm。每次寫入前保存現場檔並核對，安裝與還原後讀回SHA一致且安全卸載；原檔20133888bytes已恢復。未寫MAIN／BOOT、未安裝大型播放器、未改圖資，也未發起電話或音訊播放。',
  '離線播放器新增五個原生入口保護，涵蓋profile、直接queue、selector、provider準備與音源分配；啟動時真正取得三個原廠mutex。高優先任務由原kernel POST搶占Source，在建立私人狀態前及播放後各嘗試五個入口，十次被拒；其他通道profile與其他caller音源分配仍正常。這只是指定入口保護，直接pool reset／free／alias等旁路與完整Stop／yield仍未閉合。',
  '修正十二byte allocator掛鉤覆蓋原內部loop target的錯誤，改用八byte patch保留原loop與回跳；原分配器實際選到另一個空slot1，播放器slot0保持不變。ROOT由保存檔重建164666筆CPUstores（載入101868、播放62798）、37載入區域、34可寫區域與3不變程式區域，核對34次gate完整返回、4次SBC及15次原生音訊返回。兩包372bytes音樂PCM相符，3584bytes總輸出另含靜音；不是新agent審查或實機喇叭播放。']
 now=datetime.now(timezone.utc);old_next=progress['phases'][4]['next']
 focus='Attended physical diagnostic sequence2.10/WFFF/2.10 is complete and original voice restored. Corrected five selected native entry barriers passed two real-kernel interference runs and saved-file replay offline. Next close remaining pool reset/free/alias writers and Stop/yield, actual MAIN/cache gate installation, resident lifetime/native heap and menu App. Direct phone music and installed App remain unverified.'
 next_text='繼續補齊音訊通道使用與釋放：處理尚未涵蓋的原生旁路、Stop與資源歸還，再驗證實機載入保護、記憶體與App菜單。這次WFFF實機觀察與還原已完成；大型播放器仍未安裝。'
 state.update(updated_utc=now.isoformat(),current_priority=focus,latest_user_instruction='User returned to the device and completed attended original2.10/WFFF/original2.10; continue native music/App research with pairing first when needed.')
 state['next_actions']=[focus,'Close direct pool reset/free/alias and all native audio writers; current claim remains boot-pinned, mcs ownership witness remains-200, full STOP_DONE/yield/unload incomplete.','Verify actual MAIN/cache patch installation and voice-selector lifetime, native resident allocation and visible menu App.','No further physical test currently requested; user may leave Garmin in normal mode, no USB or Bluetooth connection required for offline work. Pairing first when resumed; microphone canceled, Android Auto later, Google Maps deferred.']
 app['remaining_work']=state['next_actions'][:3]
 app['development_observations']['physical_warm_diagnostic']=dict(initial_original_control=CONTROL,positive=POSITIVE,restore=RESTORE,final_control=FINAL,sequence=['2.10','WFFF','2.10'],all12_initialization_snapshot_conditions_true=True,original_restored_readback_and_physical_confirmed=True,live_readiness_ownership_App_phone=False)
 app['development_observations']['native_route_entry_protection']=dict(build=findings[2][1].replace('route-entry-v5-proof.json','build-v2.json'),guest=findings[2][1],ROOT_FILE=findings[3][1],totals=files['totals'],boot_pinned_not_full_ownership_Stop_yield=True,physical_installed=False)
 app['local_warm_audio_observation_bundle'].update(prepared_local_only=False,physical_installation_performed=True,physical_installed=False,physical_2_10_control_pending=False,physical_new_W_tag_test_pending=False,physical_observation='WFFF',original_restored_verified=True,physical_sequence_complete=True)
 attended=state['attended_testing'];attended.update(user_present=True,waiting_for_user_return=False,user_available_for_future_physical_tests=True,no_pending_question=True,recorded_utc=now.isoformat(),user_instruction='User returned and completed the attended diagnostic and rollback.',current_attended_test='Completed2.10/WFFF/2.10; no next physical test requested.',USB_or_Bluetooth_required_for_current_offline_work=False,next_attended_test_not_requested_yet=True)
 attended['native_marker_code_test'].update(Aud_Ver_2_10_pending=False,physical_rollback_2_10_confirmed=True)
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',focused_evidence=FINAL,focused_evidence_sha256=sha(FINAL),next_focus=focus,
  reasons=['Attended exact diagnostic candidate displayedWFFF, original2.10 controls before and after confirmed; original voice restored.','Corrected native allocator loop patch;five selected barriers reject ten real-kernel competitor attempts while other native callers continue.','ROOT reconstructed164666 saved CPU stores,34 gate full returns and all scoped regions; durable full ownership/App/phone remains incomplete.'],
  physical_new_warm_candidate_tested=True,physical_2_10_control_pending=False,rollback_Aud_Ver_2_10_pending=False,device_io=True,device_IO=True,device_files_written=True,diagnostic_voice_file_written=True,native_firmware_or_research_package_written=True,native_firmware_flashed=False,device_calls_or_sound=False,automatic_calls_or_sound=False,attended_calls_or_sound=False,complete_native_App_or_phone_audio=False,physical_App_or_audio_verified=False,goal_status='active',full_goal_complete=False)
 for key in('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
 task.update(user_away=False,current_connection_not_rechecked_this_offline_turn=False,current_device_connection_verified=False,latest_USB_transfer_device_identity_verified=True,physical_diagnostic_and_rollback_complete=True)
 public.update(updated=now.isoformat(),deep_research=state);progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
 progress['phases'][4]['next']=next_text;progress['phases'][1]['next']='實機音訊初始化快照WFFF已確認；接著閉合音訊旁路與資源釋放、正常導航共存，再測原生手機音樂。'
 progress.update(research_updated_utc=now.isoformat(),next=next_text)
 assert len(app['static_findings'])==275 and len(progress['completed'])==251
 assert progress['estimate_percent']==37 and progress['phases'][4]['estimate_percent']==35 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==36.5
 report=before.decode()
 card='<div class="card"><h2>最新進展：實機 WFFF 診斷與還原完成</h2><p>本次實機完整確認 <strong>原版2.10 → 診斷版WFFF → 還原2.10</strong>。WFFF表示十二項音訊初始化觀察全部符合預期，包括原廠callback、空閒目標通道及可用音源槽。原始美玲語音檔已讀回核對並恢復，只有這個語音檔曾被替換。</p><p>離線播放器的五個音訊入口保護已通過真kernel任務搶占測試：啟動與播放期間共十次競爭請求被拒，其他通道及音源分配仍正常。原音源分配loop掛鉤錯誤已修正；ROOT核對164666筆保存CPU寫入、34次gate完整返回及兩包連續音訊。</p><p><strong>尚未完成：</strong>WFFF是載入當下的快取快照；指定入口保護不是所有音訊寫入的長期獨占。原生旁路、Stop／資源歸還、實機MAIN／cache安裝、App菜單及手機直接連車機播放仍待研究。大型播放器未安裝，這輪未打電話或播放聲音。估計維持整體37%、App35%；目前不需要你保持USB或藍牙連線。</p></div>'
 report,n=re.subn(r'<div class="card"><h2>最新進展：播放器啟動已移除全通道重設</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
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
 assert served==report.encode()and P.service_now()==service and {p:sha(p)for p in P.CANONICAL}==after
 audit=dict(prior,all_passed=True,updated_utc=now.isoformat(),previous_checkpoint=B+'previous-audit.json',protected_sources=protected,canonical_after_sha256=after,
  current_state_sha256=after[P.CANONICAL[0]],report_sha256=after[P.CANONICAL[3]],local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],current_findings=275,current_public_details=251,
  physical_original_WFFF_original_sequence=final,physical_positive=positive,selected_native_route_entry_scopes=guest['cases'],native_route_entry_totals=files['totals'],device_IO_this_turn=True,only_voice_file_written_and_restored=True,
  durable_warm_native_ownership_or_navigation_App_phone=False,new_independent_agent_review=False,
  scope_checks=dict(prior['scope_checks'],old4019_sources_preserved=True,physical_2_10_WFFF_2_10_observed=True,original_voice_restored=True,five_route_barriers_not_all_writers_or_Stop_yield=True,live_report_37_App35_visible=True))
 create(OUT,audit)
 assert latest.pop('current_native_warm_entry_ROOT_checkpoint')==OLD
 latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_warm_entry_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),current_native_warm_physical_route_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,current_physical_test_requested=False,user_away_for_class=False,user_explicitly_returned=True,physical_sequence_complete=True,canonical_hash_readback_uncached=True,service_not_restarted=True)
 latest['progress_display_verified'].update(completed_items=251,report_updated_time=iso,research_updated_time=iso,physical_WFFF_and_exact_rollback_visible=True,durable_ownership_not_claimed=True)
 write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=275,details=251,protected_sources=len(protected),updated_Taiwan=iso,estimate_percent=37,App_estimate_percent=35,physical_sequence=['2.10','WFFF','2.10'],totals=files['totals'],report_bytes=len(served),served_sha256=after[P.CANONICAL[3]],goal_status='active',publication_device_IO=False)),flush=True)
if __name__=='__main__':main()
