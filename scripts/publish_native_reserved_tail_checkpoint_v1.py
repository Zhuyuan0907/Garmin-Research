#!/usr/bin/env python3
"""Publish native reserved-tail reader protection and continuous-media scope."""
import json,hashlib,re,html,importlib.util,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('tail_report_helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
G='staging/native-player-reserved-tail/'
B='staging/native-player-reserved-tail-checkpoint/'
OLD='evidence/firmware-analysis/native-loaded-image-ROOT-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-reserved-tail-ROOT-checkpoint-audit.json'
def main():
 assert not(ROOT/B).exists()and not(ROOT/OUT).exists()
 prior=read(OLD);assert prior['all_passed']and prior['current_findings']==265 and prior['current_public_details']==238
 assert all(sha(p)==h for p,h in prior['canonical_after_sha256'].items())
 protected=dict(prior['protected_sources']);verified={}
 def register(entries):
  for p,h in entries.items():
   if p not in verified:verified[p]=sha(p)
   assert verified[p]==h and (p not in protected or protected[p]==h),p
   protected[p]=h
 register(protected.copy())
 build=read(G+'build-v2.json');guest=read(G+'reserved-tail-integration-v2-proof.json');files=read(G+'ROOT-reserved-tail-file-proof-v1.json')
 assert all(x['all_passed']for x in (build,guest,files))
 assert files['case_count']==len(guest['cases'])==1
 assert guest['three_original_native_DLL_reloads_preserve_current_player']and guest['oversize_file_rejected_before_copy']and guest['oversize_RAM_rejected_before_execute']
 assert guest['shared_capacity_rewrite_does_not_raise_private_limit']and guest['continuous_original_F1_Source_SBC_mixer_packets']==6
 assert guest['guarded_native_reader_full_returns']==5 and guest['full_selector_concurrency_actual_patch_warm_ownership_or_phone_or_App_not_verified']
 assert build['private_caller_descriptor_capacity']and not build['live_patch_or_cache_or_safe_unload_or_warm_owner']
 for receipt in ('build-v2','guest-v2','file-v1'):
  d=read(G+receipt+'-terminal-tool-receipt.json');assert d['terminal']and d['actual_terminal_result']['exit_code']==0
 register(files['source_sha256'])
 for p in sorted((ROOT/G).rglob('*')):
  if p.is_file():register({str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT)))})
 for p in (OLD,'scripts/publish_native_reserved_tail_checkpoint_v1.py','staging/native-player-loaded-image-checkpoint/publication-v1-terminal-tool-receipt.json'):register({p:sha(p)})
 state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress']
 assert state['goal_status']=='active'and not state['goal_complete']and state['required_work_remaining']
 assert not app['native_app_running']and not app['direct_phone_music_verified']
 assert len(app['static_findings'])==265 and len(progress['completed'])==238
 latest=read('evidence/report-web-latest.json');service=P.service_now()
 with urllib.request.urlopen(latest['url'],timeout=10)as r:before=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert hashlib.sha256(before).hexdigest()==sha(P.CANONICAL[3])
 (ROOT/B).mkdir();snapshots=[]
 for p,name in [(OLD,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]+list(zip(P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
  target=B+name;(ROOT/target).write_bytes((ROOT/p).read_bytes());h=sha(target)
  register({target:h});snapshots.append(dict(original=p,snapshot=target,sha256=h))
 findings=[
  ('native_player_reserved_DLL_tail_build',G+'build-v2.json','Current player linked beyond all3 original voice RAM footprints within stock3MiB DLL reservation. Compiled reader gate uses caller-local52-byte descriptor and exact8-byte relocated reader prologue. No VPM/live patch.'),
  ('native_loader_private_limit_three_voices_continuous_media',G+'reserved-tail-integration-v2-proof.json','One fresh integration scope:3 native original voice reloads preserve current player; file4 rejected before copy and RAM9 before execute, even under explicit shared-capacity rewrite. Six F1 packets/12SBC returns. Whole selector concurrency/hardware/warm owner untested.'),
  ('native_reserved_tail_ROOT_saved_file_reconstruction',G+'ROOT-reserved-tail-file-proof-v1.json','Loader37zones plus playback34RW incl mutable TTS and3unchangedRX,299766CPUstores, selected callback/gateABI and6 referencePCM outputs. No guest rerun, all nonstoreCFG/storeEA or independent-agent claim.')]
 for key,p,scope in findings:
  assert key not in app['static_findings'];app['static_findings'][key]=dict(evidence=p,evidence_sha256=sha(p),scope=scope,evidence_type='ROOT bounded offline evidence',device_io=False,physical_App_or_audio_verified=False)
 details=[
  '播放器已重新連結到原廠3MiB DLL區較後方，在三份已備份原廠語音的RAM範圍之後；模組總RAM2557068bytes。新增讀取保護使用每次呼叫的52-byte私人descriptor，將檔案與宣告RAM上限限制在播放器之前，避免其他INIT改寫共享上限時影響此次檢查。這是每次開機保留的區域，尚未實機安裝，也不是卸載協定。',
  '一組新離線整合情境已實際依序透過原廠INIT／reader／原始語音bootstrap載入中文（大陸）美玲、英文Jill、中文（台灣）美玲，三次均完整返回11，且播放器code／狀態／PCM／Source stack整段保持不變。每次重新載入後繼續接收原生五參數F1並播放下一包，同一協商共六包連續參考PCM相符。這只驗證DLL載入路徑，完整語音選單與硬體時序仍待實機。',
  '兩項拒絕控制通過：超過保留範圍的整合映像在複製之前由原reader返回4；小檔案宣告過大的RAM則在執行前返回9。明示改寫共享descriptor的3MiB上限仍不能改變此次私人上限。兩次拒絕後播放器仍完整保留並能繼續解碼播放；不能宣稱任意並行語音切換或真手機／喇叭已完成。',
  'ROOT保存檔案重建299766筆CPU写入，載入37個完整區域、播放34個可寫區域與3個不變程式區域；原始TTS與其padding為明示可變的可執行區，不冒稱全部DLL均不可寫。五次reader保護完整返回、9次原生回呼、6次Source接收、12次SBC返回與43次完整原生音訊返回已核對；1116bytes是真正音樂PCM，總10752bytes輸出另含underrun靜音。下一步正常導航初始化、真正RAM patch／cache、ownership／heap與App菜單。']
 now=datetime.now(timezone.utc);old_next=progress['phases'][4]['next']
 focus='Recover actual warm audio initialization/ownership without global18-channel reset, and writable MAIN/cache/native installation boundaries for the reserved-tail reader gate. Direct native DLL reload protection now works offline across3 original voices and2 rejects, but full voice-selector concurrency/UI, permanent storage lifetime and actual hardware are unverified. Integrate native menu/heap and reconnect/full STOP_DONE; no device calls, original2.10/Wxxx pending until user returns.'
 next_text='下一步改用正常導航的音訊初始化與真正ownership，避免重設全部18個通道；確認實機MAIN RAM修改／cache及保護安裝，再整合App菜單與heap。完整語音選單、斷線重連／STOP_DONE仍待驗證；回來先確認2.10，再安排Wxxx。'
 state.update(updated_utc=now.isoformat(),current_priority=focus)
 state['next_actions']=[focus,
  'Source stage1 currently calls277E20 plus18 channel resets; replace only after recovering warmed channel mutex/condition/Timer/callback ownership, never infer ownership from profile0 or empty pool.',
  'Audit MAIN writable RAM/cache and pre-read gate installation; protect native known DLL reloads, but do not claim full GUI voice-selection concurrency/unload.',
  'Integrate native menu/heap and reconnect/full STOP_DONE. Later original2.10/Wxxx with user present; pairing first, mic canceled, Android Auto later, Maps deferred.']
 app['remaining_work']=state['next_actions'][:3]
 app['development_observations']['native_reserved_tail_reader_protection']=dict(build=findings[0][1],guest=findings[1][1],ROOT_FILE=findings[2][1],totals=files['totals'],
  known_original_voice_DLL_reload_preserves_player_offline=True,caller_private_descriptor_capacity=True,permanent_boot_reservation_not_unload_protocol=True,
  physical_patch_cache_warm_ownership_full_voice_selector_or_App_phone=False,modified_VPM_generated=False,device_IO=False)
 state['attended_testing'].update(user_present=False,waiting_for_user_return=True,no_pending_question=True,recorded_utc=now.isoformat())
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',
  focused_evidence=findings[2][1],focused_evidence_sha256=sha(findings[2][1]),next_focus=focus,
  reasons=['Relinked the current native player beyond all3 installed original voice RAM footprints and compiled a caller-private reader capacity guard.',
   'Original INIT/reader/bootstrap reloads3 voices while preserving player; original file/RAM rejection controls leave music functional even after shared-capacity perturbation.',
   'Whole saved-region/store and callback/gate ABI reconstruction complete. Next movement is actual warm initialization/ownership and MAIN/cache/menu installation.'],
  device_IO=False,device_calls_or_sound=False,complete_native_App_or_phone_audio=False,goal_status='active',full_goal_complete=False)
 for key in ('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
 public.update(updated=now.isoformat(),deep_research=state)
 progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
 progress['phases'][4].update(estimate_percent=35,next=next_text)
 weighted=sum(p['weight']*p['estimate_percent']/100 for p in progress['phases']);assert weighted==36.5
 progress.update(estimate_percent=37,weighted_estimate_percent=weighted,research_updated_utc=now.isoformat(),next=next_text)
 assert len(app['static_findings'])==268 and len(progress['completed'])==242
 report=before.decode()
 card='<div class="card"><h2>最新進展：共享載入區保護已離線接通</h2>'
 card+='<p>播放器已移到三份原廠語音的RAM範圍之後，仍在原廠3MiB載入區內。新增讀取保護使用每次呼叫的私人descriptor，限制新檔案與其宣告RAM不能覆蓋播放器；明示改寫共享容量時，私人限制仍保留。這是開機期間持續保留的區域，尚未處理卸載。</p>'
 card+='<p>離線原廠DLL流程依序載入中文（大陸）美玲、英文Jill、中文（台灣）美玲，三次成功並保留播放器完整狀態，每次仍能接收下一包原生F1／Source／SBC／mixer音訊。過大的整合檔案在複製前被拒絕，過大RAM則在執行前被拒絕；拒絕後也能繼續播放。六包連續音樂PCM與參考相符。</p>'
 card+='<p><strong>仍是離線整合：</strong>完整語音選單的前置政策與並行流程、MAIN RAM修改／cache／保護安裝、正常導航音訊ownership／heap、菜單及真手機／喇叭尚未驗證。Source目前仍使用明示冷啟動fixture，必須改成正常模式初始化，避免重設其他導航音訊。原始TTS前綴是可變的可執行區，沒有冒稱全部DLL不可寫；radio／heap／硬體仍有fixture。</p>'
 card+='<p>整體估計37%、App35%。ROOT已核對保存區域、299766筆CPU寫入與回呼；1116bytes為音樂PCM，10752bytes總輸出另含靜音。本輪沒有車機改寫、來電或聲音，沒有製作或安裝VPM。使用者回來先確認Aud Ver2.10，再安排Wxxx；配對優先、麥克風取消、Android Auto排後、Maps暫緩。</p></div>'
 report,n=re.subn(r'<div class="card"><h2>最新進展：原廠載入器已讀入整合播放器映像</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
 report,n=re.subn(r'(<div class="progress-total">約 <strong>)36(%</strong>)',r'\g<1>37\2',report,count=1);assert n==1
 report,n=re.subn(r'(<progress id="research-progress" max="100" value=")36("[^>]*>)36(%</progress>)',r'\g<1>37\g<2>37\3',report,count=1);assert n==1
 old='<tr><td>原生 App 入口與功能整合</td><td>30%</td><td>'+html.escape(old_next)+'</td></tr>';assert report.count(old)==1
 report=report.replace(old,'<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>'+html.escape(next_text)+'</td></tr>',1)
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
  current_findings=268,current_public_details=242,estimate_percent=37,weighted_estimate_percent=36.5,App_estimate_percent=35,
  selected_native_reserved_tail_scopes=guest['cases'],native_reserved_tail_totals=files['totals'],native_private_reader_limit_and_three_voice_DLLs_offline=True,
  actual_MAIN_cache_patch_full_voice_selector_warm_heap_App_phone_or_STOP_DONE=False,new_independent_agent_review=False,device_IO_this_turn=False,
  scope_checks=dict(prior['scope_checks'],old3920_sources_preserved=True,three_original_voice_native_loads_preserve_player=True,
   protected_file_and_RAM_negative_controls=True,shared_limit_alias_control=True,mutable_TTS_RWE_not_claimed_unchanged=True,live_report_37_App35_visible=True))
 create(OUT,audit)
 oldkey='current_native_loaded_image_ROOT_checkpoint';assert latest.pop(oldkey)==OLD
 latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_loaded_image_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),current_native_reserved_tail_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},
  local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,current_physical_test_requested=False,
  user_away_for_class=True,canonical_hash_readback_uncached=True,service_not_restarted=True)
 latest['progress_display_verified'].update(estimate_percent=37,completed_items=242,report_updated_time=iso,research_updated_time=iso,
  reserved_tail_reader_protection_offline_scope_visible=True,App_estimate_percent=35,physical_patch_full_selector_limit_visible=True)
 write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=268,details=242,protected_sources=len(protected),updated_Taiwan=iso,estimate_percent=37,App_estimate_percent=35,
  totals=files['totals'],report_bytes=len(served),served_sha256=after[P.CANONICAL[3]],goal_status='active',device_IO=False)),flush=True)
if __name__=='__main__':main()
