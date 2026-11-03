#!/usr/bin/env python3
"""Publish loaded single-image progress and actual shared-buffer limitation."""
import json,hashlib,re,html,importlib.util,urllib.request
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('loaded_report_helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
G='staging/native-player-loaded-single-image/'
B='staging/native-player-loaded-image-checkpoint/'
OLD='evidence/firmware-analysis/native-remote-pause-ROOT-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-loaded-image-ROOT-checkpoint-audit.json'
def main():
 assert not(ROOT/B).exists()and not(ROOT/OUT).exists()
 prior=read(OLD);assert prior['all_passed']and prior['current_findings']==261 and prior['current_public_details']==233
 assert all(sha(p)==h for p,h in prior['canonical_after_sha256'].items())
 protected=dict(prior['protected_sources']);verified={}
 def register(entries):
  for p,h in entries.items():
   if p not in verified:verified[p]=sha(p)
   assert verified[p]==h and (p not in protected or protected[p]==h),p
   protected[p]=h
 register(protected.copy())
 build=read(G+'build-v3.json');guest=read(G+'loaded-integration-v3-proof.json');files=read(G+'ROOT-loaded-image-file-proof-v2.json');replacement=read(G+'native-reader-replacement-v3-proof.json')
 assert all(x['all_passed']for x in (build,guest,files,replacement))
 assert files['case_count']==len(guest['cases'])==1
 assert guest['stock_loader_original_forty_exports_retained']and guest['compiled_single_image_real_native_F1_Source_SBC_mixer']
 assert guest['passive_entry_does_not_activate_or_reset_audio']and guest['no_old_synthetic_module_maps']
 assert not guest['warm_ownership_heap_lifetime_App_phone_or_device_verified']
 assert replacement['reader_full_return']==11 and len(replacement['overwritten_player_spans'])==11
 assert replacement['earlier_caller_policy_or_global_lock_not_fully_audited']
 for receipt in ('build-v3','guest-v3','file-v2','replacement-v3'):
  d=read(G+receipt+'-terminal-tool-receipt.json');assert d['terminal']and d['actual_terminal_result']['exit_code']==0
 register(files['source_sha256']);register(replacement['source_sha256'])
 for p in sorted((ROOT/G).rglob('*')):
  if p.is_file():register({str(p.relative_to(ROOT)):sha(str(p.relative_to(ROOT)))})
 for p in (OLD,'scripts/publish_native_loaded_image_checkpoint_v1.py','staging/native-player-remote-pause-checkpoint/publication-v2-terminal-tool-receipt.json'):register({p:sha(p)})
 state,task,public=[read(p)for p in P.CANONICAL[:3]];app=state['native_app_music'];progress=public['research_progress']
 assert state['goal_status']=='active'and not state['goal_complete']and state['required_work_remaining']
 assert not app['native_app_running']and not app['direct_phone_music_verified']
 assert len(app['static_findings'])==261 and len(progress['completed'])==233
 latest=read('evidence/report-web-latest.json');service=P.service_now()
 with urllib.request.urlopen(latest['url'],timeout=10)as r:before=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','')
 assert hashlib.sha256(before).hexdigest()==sha(P.CANONICAL[3])
 (ROOT/B).mkdir();snapshots=[]
 for p,name in [(OLD,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]+list(zip(P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
  target=B+name;(ROOT/target).write_bytes((ROOT/p).read_bytes());h=sha(target)
  register({target:h});snapshots.append(dict(original=p,snapshot=target,sha256=h))
 findings=[
  ('native_single_loaded_player_image',G+'build-v3.json','Current Source/SBC/FIFO/pause/remote compiled into one stock-address DLL. Internal link-resolved function/PCM addresses replace07000000/08E00000 synthetic imports; passive bootstrap and original TTS retained. No VPM or install candidate.'),
  ('native_stock_loader_single_image_media_pause',G+'loaded-integration-v3-proof.json','New same-VM loader/F1/Source/SBC/mixer scope. Whole image poisoned before native reader copy, original40 exports and loader11, two media packets, Suspend/Start resume. Cold/kernel/BT/heap/cache/hardware fixtures explicit.'),
  ('native_loaded_image_ROOT_saved_file_reconstruction',G+'ROOT-loaded-image-file-proof-v2.json','All37 loader zones and33 playback RW/4 unchangedRX reconstructed from152796 CPUstores, file/fixture writes and selected callback ABI. No guest rerun, full nonstoreCFG/effectiveaddress or new independent agent claim.'),
  ('native_shared_DLL_voice_replacement_overwrite',G+'native-reader-replacement-v3-proof.json','Original3B3294 reader fully returns11 for stock GB voice and replaces11 player code/data spans. Examined body never reads player guard. Direct reader only; earlier voice-selection concurrency/policy and physical overwrite not tested. Lifetime protection required.')]
 for key,p,scope in findings:
  assert key not in app['static_findings'];app['static_findings'][key]=dict(evidence=p,evidence_sha256=sha(p),scope=scope,evidence_type='ROOT bounded offline evidence',device_io=False,physical_App_or_audio_verified=False)
 details=[
  '目前具備Source工作、SBC解碼、PCM緩衝、藍牙媒體回呼及暫停／恢復的元件，已整合成單一原廠DLL映像。函式與PCM頁面透過同一連結結果取得，移除原先兩個模擬模組的固定位址；額外RAM約158172bytes，總佔2454668bytes，在原廠3MiB容量內。映像只留本機，尚未製作或安裝VPM。',
  '新的離線環境先將整個模組區填入非零資料，再讓原廠載入器實際呼叫檔案讀取、執行原始語音bootstrap與新增入口，完整返回11並保留四十個原始語音函式。新增入口只清除私人狀態與公布API，沒有啟動播放工作或修改全域音訊區；一般導航模式的啟動仍需真正warm資源方案。',
  '同一載入映像已完成原生Configure／Start／五參數F1回呼，兩包媒體經真正Source與四次SBC完整返回、原生mixer輸出，再完成Suspend靜音保留緩衝與Start恢復。Source與remote不再映射於舊07000000／08E00000模擬位址；radio、BTmutex、冷啟動、配置器、cache與硬體輸出仍為明示fixture，不能視為真手機／喇叭或已安裝App。',
  'ROOT由保存檔案重建載入器37個完整區域，以及播放33個可寫區域與4個程式區域；核對152796筆CPU寫入、檔案／其他fixture寫入及選定回呼ABI。播放有7次原生回呼、2次Source接收、4次SBC返回與24次完整原生音訊返回；沒有重跑已完成guest，亦不宣稱完整非寫入指令流程或新的獨立agent審查。',
  '共享DLL區的生命週期限制已取得具體證據：原廠3B3294讀取器接受中文（大陸）美玲DLL並返回11，覆蓋11個播放器函式／狀態區域，包括入口、解碼器、媒體回呼與Source資訊，但較後方Source stack仍保留。該讀取器本體不查播放器忙碌狀態；此為單獨reader範圍，完整語音切換的前置政策與並行流程仍待分析。下一步先處理模組保護或獨立配置，再正常模式音訊共存與菜單。']
 now=datetime.now(timezone.utc);old_next=progress['phases'][4]['next']
 focus='Protect the stock shared DLL buffer before voice replacement or recover separate native-owned resident storage; original reader overwrites player code without consulting its guard. Then recover warm channel ownership/heap and integrate menu. Current one-image loader/F1/pause integration is offline with declared cold/BT/cache/hardware fixtures. No device writes/calls; original2.10 and read-only Wxxx still pending until user returns.'
 next_text='下一步保護共享DLL區的模組生命週期，或取得獨立原生配置；再處理正常導航音訊共存、Source暖啟動与App菜單。斷線重連／STOP_DONE仍待完成。回來先確認原語音2.10，再安排Wxxx診斷。'
 state.update(updated_utc=now.isoformat(),current_priority=focus)
 state['next_actions']=[focus,
  'Audit earlier native voice selection, lifetime and reload boundaries; a player-entry guard after file copy is too late. Native source task stack/callbacks must remain resident.',
  'Recover warm condition/Timer/channel ownership and heap without resetting all18 channels; complete reconnect/full STOP_DONE before unload.',
  'Integrate native GUI/menu using actual settings/heap lifetime. Later attended original2.10 and Wxxx; pairing first when present. Android Auto later, Maps deferred.']
 app['remaining_work']=state['next_actions'][:3]
 app['development_observations']['native_current_player_single_loaded_image']=dict(build=findings[0][1],guest=findings[1][1],ROOT_FILE=findings[2][1],replacement=findings[3][1],totals=files['totals'],
  single_original_DLL_address=True,passive_loader_entry=True,private_function_and_PCM_link_resolution=True,
  native_warm_owner_or_heap_menu_phone_or_lifetime_pin=False,modified_VPM_generated=False,device_IO=False)
 state['attended_testing'].update(user_present=False,waiting_for_user_return=True,no_pending_question=True,recorded_utc=now.isoformat())
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',
  focused_evidence=findings[2][1],focused_evidence_sha256=sha(findings[2][1]),next_focus=focus,
  reasons=['Compiled the current pause-capable remote and Source into one native-loader-address DLL without synthetic Source/PCM imports.',
   'Native loader/five-argument F1/Source/SBC/mixer and pause/resume complete in the same live VM; preserved40 original TTS exports and passive entry.',
   'Saved-file reconstruction complete. Original GB voice reader demonstrably overwrites player code/state, changing next action to lifetime protection.'],
  device_IO=False,device_calls_or_sound=False,complete_native_App_or_phone_audio=False,goal_status='active',full_goal_complete=False)
 for key in ('updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research'):task[key]=state[key]
 public.update(updated=now.isoformat(),deep_research=state)
 progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
 progress['phases'][4].update(estimate_percent=30,next=next_text)
 weighted=sum(p['weight']*p['estimate_percent']/100 for p in progress['phases']);assert weighted==36
 progress.update(estimate_percent=36,weighted_estimate_percent=weighted,research_updated_utc=now.isoformat(),next=next_text)
 assert len(app['static_findings'])==265 and len(progress['completed'])==238
 report=before.decode()
 card='<div class="card"><h2>最新進展：原廠載入器已讀入整合播放器映像</h2>'
 card+='<p>目前的藍牙媒體回呼、Source工作、SBC解碼、緩衝與暫停／恢復已整合為單一原廠DLL映像，移除兩個模擬模組之間的固定位址。新增RAM約158KB，仍在3MiB載入範圍內。原廠載入器在離線環境真正讀入這份檔案、保留四十個原始語音函式，再完成兩包媒體與原生播放／暫停／恢復。</p>'
 card+='<p>新增載入入口只準備私人狀態與API，没有啟動播放或重設導航音訊。ROOT已從保存檔案重建載入與播放區域、核對CPU寫入和回呼；真手機、硬體喇叭、正常導航資源、菜單及完整停止卸載仍未驗證。冷啟動／BT／heap／cache／輸出硬體的fixture仍明示。</p>'
 card+='<p><strong>下一個實際問題是模組生命週期：</strong>原廠DLL讀取器讀入中文（大陸）美玲時，覆蓋播放器程式與部分狀態，却保留較後方Source stack。這個reader本體不檢查播放器是否使用中，完整語音切換的前置流程仍需查明。需要在覆蓋之前保護模組，或取得獨立的原生配置，才能讓播放器與導航／語音安全共存。</p>'
 card+='<p>整體估計36%、App30%。本輪僅離線研究，沒有車機改寫、來電或聲音；整合映像尚未製作或安裝VPM。使用者回來先確認原語音Aud Ver2.10，再安排Wxxx。研究持續；配對優先、麥克風取消、Android Auto排後、Maps暫緩。</p></div>'
 report,n=re.subn(r'<div class="card"><h2>最新進展：離線原生播放器已能暫停與恢復</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
 old='<tr><td>原生 App 入口與功能整合</td><td>25%</td><td>'+html.escape(old_next)+'</td></tr>';assert report.count(old)==1
 report=report.replace(old,'<tr><td>原生 App 入口與功能整合</td><td>30%</td><td>'+html.escape(next_text)+'</td></tr>',1)
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
  current_findings=265,current_public_details=238,estimate_percent=36,weighted_estimate_percent=36,App_estimate_percent=30,
  selected_native_loaded_image_scopes=guest['cases'],native_loaded_image_totals=files['totals'],native_reader_replacement_scope=replacement['case'],
  original_forty_exports_and_current_single_image_native_F1_pause_offline=True,native_shared_DLL_pin_or_warm_heap_App_phone_verified=False,
  new_independent_agent_review=False,device_IO_this_turn=False,
  scope_checks=dict(prior['scope_checks'],old3766_sources_preserved=True,new_stock_loaded_single_current_player_image=True,
   original_reader_overwrite_scope_visible=True,original_earlier_voice_selection_policy_not_claimed=True,live_report_36_App30_visible=True))
 create(OUT,audit)
 oldkey='current_native_remote_pause_ROOT_checkpoint';assert latest.pop(oldkey)==OLD
 latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_remote_pause_ROOT_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),current_native_loaded_image_ROOT_checkpoint=OUT,checkpoint_sha256={OUT:sha(OUT)},
  local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],report_bytes=len(served),served_latest_report=True,current_physical_test_requested=False,
  user_away_for_class=True,canonical_hash_readback_uncached=True,service_not_restarted=True)
 latest['progress_display_verified'].update(estimate_percent=36,completed_items=238,report_updated_time=iso,research_updated_time=iso,
  single_stock_loaded_player_image_offline_scope_visible=True,App_estimate_percent=30,shared_DLL_lifetime_limit_visible=True)
 write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=265,details=238,protected_sources=len(protected),updated_Taiwan=iso,estimate_percent=36,App_estimate_percent=30,
  totals=files['totals'],report_bytes=len(served),served_sha256=after[P.CANONICAL[3]],goal_status='active',device_IO=False)),flush=True)
if __name__=='__main__':main()
