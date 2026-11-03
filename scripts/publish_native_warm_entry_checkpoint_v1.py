#!/usr/bin/env python3
"""Publish selective warm attach evidence; preserve exact physical limits."""
import json,hashlib,re,html,importlib.util,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('warm_entry_report_helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
G='staging/native-player-warm-entry/'
B='staging/native-player-warm-entry-checkpoint/'
OLD='evidence/firmware-analysis/native-reserved-tail-ROOT-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-warm-entry-ROOT-checkpoint-audit.json'
def main():
 assert not(ROOT/B).exists()and not(ROOT/OUT).exists()
 prior=read(OLD);assert prior['all_passed']and prior['current_findings']==268 and prior['current_public_details']==242
 assert all(sha(p)==h for p,h in prior['canonical_after_sha256'].items())
 protected=dict(prior['protected_sources']);verified={}
 def register(entries):
  for p,h in entries.items():
   if p not in verified:verified[p]=sha(p)
   assert verified[p]==h and(p not in protected or protected[p]==h),p
   protected[p]=h
 register(protected.copy())
 build=read(G+'build-v1.json');guest=read(G+'warm-entry-v1-proof.json');files=read(G+'ROOT-warm-entry-file-proof-v1.json')
 assert all(x['all_passed']for x in(build,guest,files))
 assert guest['negative_controls']==8 and guest['native_F1_packets']==2
 assert guest['all_other17_records_unchanged_at_attach']and guest['no_global_reset_in_warm_Source']
 assert not guest['durable_native_ownership_or_actual_navigation_App_phone_hardware']
 assert files['totals']['original_condition_constructors']==36 and files['totals']['original_profile_callbacks']==18
 assert not build['durable_native_ownership']and not build['device_IO']
 for name in('build-v1','guest-v1','file-v1'):
  r=read(G+name+'-terminal-tool-receipt.json');assert r['terminal']and r['actual_terminal_result']['exit_code']==0
 register(files['source_sha256'])
 for p in sorted((ROOT/G).rglob('*')):
  if p.is_file():register({str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT)))})
 for p in(OLD,'scripts/publish_native_warm_entry_checkpoint_v1.py','staging/native-player-reserved-tail-checkpoint/publication-v1-terminal-tool-receipt.json'):register({p:sha(p)})
 state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress']
 assert state['goal_status']=='active'and not state['goal_complete']and state['required_work_remaining']
 assert not app['native_app_running']and not app['direct_phone_music_verified']
 assert len(app['static_findings'])==268 and len(progress['completed'])==242
 latest=read('evidence/report-web-latest.json');service=P.service_now()
 with urllib.request.urlopen(latest['url'],timeout=10)as r:before=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert hashlib.sha256(before).hexdigest()==sha(P.CANONICAL[3])
 (ROOT/B).mkdir();snapshots=[]
 for p,name in[(OLD,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]+list(zip(P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
  target=B+name;(ROOT/target).write_bytes((ROOT/p).read_bytes());h=sha(target)
  register({target:h});snapshots.append(dict(original=p,snapshot=target,sha256=h))
 findings=[
  ('native_selective_warm_Source_build',G+'build-v1.json','Current reserved-tail player relinked with selective Source admission. No all18-channel reset, mapping reset or profile rewrite in warm Stage1. Checks structural preconditions and acquires actual original profile mutex; durable ownership remains unproven.'),
  ('native_preexisting_audio_warm_attach_eight_rejections',G+'warm-entry-v1-proof.json','Original pre-App channel/condition/profile bodies construct18 records with external boot boundaries explicit. Warm Source attaches, preserves all other17 records and18heads;8 negatives rejected, native F1 two packets play. Other-channel busy inputs are fixtures, not running navigation.'),
  ('native_warm_entry_ROOT_saved_file_reconstruction',G+'ROOT-warm-entry-file-proof-v1.json','151758 loader/playback CPUstores and full zones reconstructed. Actual36 condition constructor stores,18 stock callback publications and Source native profile-lock acquisition/release verified. Two continuous PCM outputs; no rerun/independent-agent claim.')]
 for key,p,scope in findings:
  assert key not in app['static_findings'];app['static_findings'][key]=dict(evidence=p,evidence_sha256=sha(p),scope=scope,evidence_type='ROOT bounded offline evidence',device_io=False,physical_App_or_audio_verified=False)
 details=[
  '新播放器啟動版本移除Source的全18通道重設、channel mapping重設與profile重寫。它先檢查既有通道結構，短暫取得原廠profile mutex，再建立播放器私人狀態和安裝queue callback；不把idle欄位、空pool或callback交換當作長期獨占。映像仍在既有reserved tail，沒有製作或安裝VPM。',
  '新離線情境先由原廠音訊物件與profile程式建立18份既有通道，36次原始condition constructor和18次原始callback發布由實際CPU寫入核對；Timer TCB由原程式建立但未排程，後續五個外部boot服務是明示fixture。再啟動新版Source，啟動時其他17份record及18個global heads完整保持不變；兩個其他通道的busy輸入只作不重設控制，不冒稱正在播放導航語音。',
  '八項warm拒絕控制通過：condition標記缺失、不同callback、目標list非空、mixer已active、provider已prepared、原channel狀態非idle、IRQ marker、原廠mutex已由Timer TCB持有。最後一項透過真正原mutex取得與ownership transfer建立，而非預填owner token。拒絕後音訊語意狀態不變；成功接入後原F1／Source／SBC／mixer連續兩包音訊相符。',
  'ROOT保存檔案重建151758筆CPU寫入；原載入37個完整區域，後段34個完整可寫區域及3個不變程式區域。核對Source實際執行原mutex取得／釋放、5次原生回呼、2次Source接收、4次SBC返回、15次完整原生音訊返回；372bytes是音樂PCM，總3584bytes另含靜音。下一步處理callback檢查後的搶占／直接原queue與provider旁路，取得可維持的ownership，再實機安裝與App菜單。']
 now=datetime.now(timezone.utc);old_next=progress['phases'][4]['next']
 focus='Selective warm Source attachment now works offline after actual pre-App audio constructors, without18-channel reset. Next audit durable target-channel ownership, profile/direct queue/provider bypass and native competition during attach/Start; then actual MAIN/cache patch installation, native menu/heap, reconnect/full STOP_DONE. Actual navigation, phone, speaker and App remain unverified; original2.10/Wxxx await user return.'
 next_text='下一步補上音訊資源的長期ownership與競態：檢查profile重設、原queue／provider直接呼叫能否搶用；再處理實機MAIN／cache保護安裝、App菜單與heap。離線新版啟動已不重設全部18通道，但正常導航共存尚未實測。回來先確認2.10，再安排觀測測試。'
 state.update(updated_utc=now.isoformat(),current_priority=focus)
 state['next_actions']=[focus,
  'Audit validation-to-install competition and direct native queue277C6A/provider48EE68 bypass. Selective warm admission holds native profile mutex only during setup; do not infer a durable ownership witness. Existing mcs_native_ownership_snapshot remains-200.',
  'Recover real MAIN writable/cache and reader gate installation, full voice-selector concurrency, native menu/heap and reconnect/full STOP_DONE.',
  'Wait for explicit user return for originalAudVer2.10 then read-only warm observation. Pairing first, microphone canceled, Android Auto later, Google Maps deferred.']
 app['remaining_work']=state['next_actions'][:3]
 app['development_observations']['native_selective_warm_Source']=dict(build=findings[0][1],guest=findings[1][1],ROOT_FILE=findings[2][1],totals=files['totals'],
  preexisting_native_constructor_structural_warm_attach_offline=True,other17_records_unchanged_at_attach=True,no18channel_reset=True,
  busy_other_channel_inputs_are_declared_not_actual_navigation=True,durable_native_ownership_actual_navigation_App_phone=False,modified_VPM_generated=False,device_IO=False)
 state['attended_testing'].update(user_present=False,waiting_for_user_return=True,no_pending_question=True,recorded_utc=now.isoformat())
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',
  focused_evidence=findings[2][1],focused_evidence_sha256=sha(findings[2][1]),next_focus=focus,
  reasons=['Compiled selective warm Source initialization instead of global18-channel reset.',
   'Original pre-App constructors/profile loops then warm attach: other17 records preserved,8 negative controls and2 native media packets pass.',
   'Saved complete-region/store reconstruction and original constructor/mutex provenance verified; durable warm ownership/actual navigation remain incomplete.'],
  device_IO=False,device_calls_or_sound=False,complete_native_App_or_phone_audio=False,goal_status='active',full_goal_complete=False)
 for key in('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
 public.update(updated=now.isoformat(),deep_research=state)
 progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
 progress['phases'][4]['next']=next_text
 progress['phases'][1]['next']='新版選擇性warm啟動已離線接通，未重設其他17個通道；接下來取得長期ownership、處理原生旁路與導航共存，再實機測試。'
 weighted=sum(p['weight']*p['estimate_percent']/100 for p in progress['phases']);assert weighted==36.5
 progress.update(research_updated_utc=now.isoformat(),next=next_text)
 assert progress['estimate_percent']==37 and progress['phases'][4]['estimate_percent']==35
 assert len(app['static_findings'])==271 and len(progress['completed'])==246
 report=before.decode()
 card='<div class="card"><h2>最新進展：播放器啟動已移除全通道重設</h2>'
 card+='<p>新增選擇性啟動版本：檢查既有目標音訊通道、取得原廠profile mutex，再初始化播放器。Source啟動不再清空18個通道、不重建mapping、不重寫profile。在離線情境中，啟動時其他17份通道record和18個global heads完整保持不變；兩包原生F1／Source／SBC／mixer音訊相符。</p>'
 card+='<p>八種異常或忙碌狀態都被拒絕，包含目標音源仍忙碌、callback不同、原廠mutex已由其他TCB持有。原廠程式實際建立36個condition並發布18個profile callback；ROOT已核對原mutex的取得／釋放及151758筆保存寫入。</p>'
 card+='<p><strong>仍是離線進展：</strong>預先執行的原音訊建構程式仍使用明示kernel啟動、未排程Timer和五個外部boot服務邊界；其他通道busy值為測試輸入，未證明導航語音正在運作。短暫持有profile mutex和idle檢查不是長期ownership，原queue／provider旁路與搶占競態仍須處理。MAIN修改／cache／安裝、App菜單／heap及真手機／喇叭仍未驗證。</p>'
 card+='<p>估計維持整體37%、App35%。372bytes為音樂PCM，3584bytes總輸出另含靜音；本輪沒有車機改寫、來電或聲音，未製作VPM。下一步長期音訊ownership與導航共存，再安排實機；先確認原語音Aud Ver2.10。配對優先、麥克風取消、Android Auto排後、Google Maps暫緩。</p></div>'
 report,n=re.subn(r'<div class="card"><h2>最新進展：共享載入區保護已離線接通</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
 old='<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>'+html.escape(old_next)+'</td></tr>';assert report.count(old)==1
 report=report.replace(old,'<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>'+html.escape(next_text)+'</td></tr>',1)
 report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda x:x[1]+x[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+x[3],report,count=1,flags=re.S);assert n==1
 report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>',report,count=1);assert n==1
 local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
 for name in('report-updated-time','research-updated-time'):
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
  current_findings=271,current_public_details=246,selected_native_warm_entry_scopes=guest['cases'],native_warm_entry_totals=files['totals'],
  selective_warm_Source_no18channel_reset_offline=True,durable_warm_native_ownership_or_navigation_App_phone=False,new_independent_agent_review=False,device_IO_this_turn=False,
  scope_checks=dict(prior['scope_checks'],old3982_sources_preserved=True,actual_original_pre_App_constructor_stores_verified=True,
   selective_warm_attach_preserves_other17_records=True,eight_warm_rejections=True,short_mutex_and_busy_fixtures_not_durable_navigation_ownership=True,live_report_37_App35_visible=True))
 create(OUT,audit)
 assert latest.pop('current_native_reserved_tail_ROOT_checkpoint')==OLD
 latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_reserved_tail_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),current_native_warm_entry_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},
  local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,current_physical_test_requested=False,
  user_away_for_class=True,canonical_hash_readback_uncached=True,service_not_restarted=True)
 latest['progress_display_verified'].update(completed_items=246,report_updated_time=iso,research_updated_time=iso,
  selective_warm_no_reset_scope_visible=True,durable_ownership_not_claimed=True)
 write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=271,details=246,protected_sources=len(protected),updated_Taiwan=iso,estimate_percent=37,App_estimate_percent=35,
  totals=files['totals'],report_bytes=len(served),served_sha256=after[P.CANONICAL[3]],goal_status='active',device_IO=False)),flush=True)
if __name__=='__main__':main()
