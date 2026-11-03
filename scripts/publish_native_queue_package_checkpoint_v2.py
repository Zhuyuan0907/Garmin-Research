#!/usr/bin/env python3
"""Publish actual native queue controls and a reversible local marker bundle."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
from datetime import datetime,timezone
from zoneinfo import ZoneInfo
import hashlib,html,json,re,subprocess,urllib.request
from publish_native_settings_scope_checkpoint_v2 import ROOT,read,sha,registry,write
B='staging/native-player-session-native-call/'
P='staging/native-player-inline-fields/marker-package-prep/'
C='staging/native-player-clock-caller/'
OUT='evidence/firmware-analysis/native-queue-package-checkpoint-audit.json'
DOCS={
 'native_music_original_queue_actual_six_cases':B+'native-queue-call-emulation-proof.json',
 'native_music_actual_reprofile_and_consumed_permit_controls':B+'queue-reprofile-boundary-proof.json',
 'native_music_actual_queue_independent_eight_case_review':B+'independent-review/native-queue-call-independent-review.json',
 'native_music_reprofile_multiple_RAM_writes_scope_erratum':B+'reprofile-scope-erratum.json',
 'native_music_bounded_queue_ARM_executable_zero_undefined':B+'build-v3.json',
 'native_next_clock_original_caller_static_guard_v2':C+'gui-static/clock-caller-observer-v2-contract.json',
 'native_preserving_entry_strict_eight_identity_path_controls':P+'strict-marker-control-proof.json',
 'native_preserving_entry_strict_bundle_thirteen_file_assertions':P+'strict-controls-and-local-bundle-verification.json',
 'native_preserving_entry_reversible_single_voice_bundle':P+'local-marker-bundle-manifest-v2.json',
 'native_preserving_entry_candidate_original_metadata_and_reader':P+'candidate-embedded-reader-metadata-control-v2.json',
 'native_preserving_entry_candidate_reader_ten_independent_assertions':P+'candidate-embedded-reader-independent-verification-v2.json',
 'native_preserving_entry_raw11_gate_original_caller_qualification':P+'raw-return-gate-native-caller-review.json',
 'native_clock_caller_complete_cold_prefix':'evidence/firmware-analysis/native-clock-caller-cold-prefix-emulation.json',
 'native_clock_caller_actual_partial_memory_histories':C+'runtime/independent-partial-journals.json',
 'native_clock_caller_actual_getter_and_stack_result':C+'clock-caller-observed-prefix.json',
 'native_next_allocator_exact_static_requirement':C+'next-allocation-static/next-native-allocation-contract.json'}
def main():
 assert not (ROOT/OUT).exists()
 previous=read(B+'previous-audit.json');assert previous['all_passed']and len(previous['protected_sources'])==1529
 protected={};print('revalidating previous1529 protected files',flush=True)
 registry(previous['protected_sources'],protected)
 for row in read(B+'previous-checkpoint.json')['snapshots']:
  assert sha(row['original'])==row['sha256']==sha(row['snapshot'])
 suites=list(previous['selected_frozen_suites']);assert len(suites)==47
 native_deps={}
 for suite in suites:
  doc=read(suite['path']);assert doc['all_passed']and all(case['passed']for case in doc['cases'])
  registry(doc['source_sha256'],native_deps)
 assert len(native_deps)==previous['native_unique_exact_dependencies']==1368
 for suite in suites:assert sha(suite['path'])==suite['sha256']
 docs={p:read(p)for p in DOCS.values()}
 for p,d in docs.items():
  assert d['all_static_and_pure_controls_passed']if p==C+'gui-static/clock-caller-observer-v2-contract.json'else d['all_passed'],p
  for key in ('source_sha256','dependency_sha256','verified_runtime_dependencies','artifacts_sha256','output_sha256'):
   if key in d:registry(d[key],protected)
  protected[p]=sha(p)
 queue=docs[B+'native-queue-call-emulation-proof.json'];boundary=docs[B+'queue-reprofile-boundary-proof.json']
 review=docs[B+'independent-review/native-queue-call-independent-review.json']
 assert queue['case_count']==6 and boundary['case_count']==2 and review['case_count']==8
 assert not review['complete_native_reader_or_player_or_App_verified']and not review['ownership_or_audio_exclusivity_certified']
 for d in (queue,boundary):
  for row in d['cases']:assert row['passed']and sha(row.get('path'))==row['sha256'];protected[row['path']]=row['sha256']
 assert docs[B+'reprofile-scope-erratum.json']['actual_profile_CPU_store_events']==46
 assert docs[B+'build-v3.json']['undefined_symbols']==[]and not docs[B+'build-v3.json']['complete_player_image']
 strict=docs[P+'strict-marker-control-proof.json'];bundle=docs[P+'local-marker-bundle-manifest-v2.json']
 reader=docs[P+'candidate-embedded-reader-metadata-control-v2.json']
 assert strict['control_count']==8 and strict['normal_original_and_wrapper_raw_return']==11
 assert not strict['device_io']and not strict['physical_UI_marker']
 assert sha(bundle['candidate_path'])==bundle['candidate_sha256']and sha(bundle['rollback_path'])==bundle['rollback_sha256']
 assert bundle['candidate_bytes']==20136960 and bundle['rollback_bytes']==20133888
 assert reader['all_passed']and reader['actual_original5_loader_callbacks_not_intercepted']
 assert not reader['BIN_file_input_fixture_used']and not reader['actual_physical_higher_FAT_or_signature_acceptance_verified']
 seal=read(P+'strict-marker-package-seal.json');ledger=read(P+'sealed-package-source-output-ledger.json')
 assert seal['all_passed']and ledger['all_passed']and seal['final_frozen']and ledger['final_frozen']
 registry(ledger['source_sha256'],protected);registry(ledger['output_sha256'],protected)
 for p in (P+'strict-marker-package-seal.json',P+'sealed-package-source-output-ledger.json'):protected[p]=sha(p)
 before=read(B+'previous-state.json');prior=read(B+'previous-public.json')
 state,task,public=[read(p)for p in ('evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json')]
 app=state['native_app_music'];assert app['static_findings']==before['native_app_music']['static_findings']and len(app['static_findings'])==169
 for key,p in DOCS.items():app['static_findings'][key]=dict(evidence=p,evidence_sha256=sha(p),physical_App_or_audio_verified=False,device_io=False)
 clock_meta=read(C+'runtime/terminal-metadata.json');clock_receipt=read(C+'terminal-receipt.json')
 assert clock_meta['session_id']==5264 and clock_meta['terminal_exit_code']==1
 assert clock_receipt['tool_result']['exit_code']==1 and clock_receipt['tool_result']['chunk_id']=='3bd84b'
 assert 'session_id'not in clock_receipt['tool_result']
 clock_proof=docs[C+'clock-caller-observed-prefix.json'];clock_prefix='evidence/firmware-analysis/native-clock-caller-cold-prefix-emulation.json'
 assert clock_proof['actual_original_clock_instructions']==3 and clock_proof['actual_native_push_CPU_stores']==15
 assert clock_proof['native_clock_actual_return_and_result_store_verified']and not clock_proof['actual_native_allocator_executed']
 assert docs[clock_prefix]['all_passed']and docs[clock_prefix]['case_count']==1
 assert all(case['passed']for case in docs[clock_prefix]['cases'])
 registry(docs[clock_prefix]['source_sha256'],native_deps)
 suites.append(dict(path=clock_prefix,sha256=sha(clock_prefix),case_count=1,scope='Complete original cold component prefix; actual clock caller verified separately; later allocator/body/foreground incomplete.'))
 registry(clock_meta['source_sha256'],protected)
 terminal=dict(session_id=5264,PID=566691,terminal_exit_code=1,actual_terminal_chunk='3bd84b',
  authoritative_terminal_receipt=C+'terminal-receipt.json',source='scripts/probe_native_dispatcher_clock_caller.py',
  independently_verified_complete_cold_prefix=True,actual_original_clock_getter_return_and_store=True,
  exact_next_unadmitted_original_entry='0x3954cc',exact_original_caller='0x395534',
  requested_bytes=48,complete_body_or_constructor_success=False,device_io=False)
 app['development_observations'].pop('clock_caller_pending_attempt',None)
 app['development_observations']['clock_caller_terminal_attempt']=terminal
 app['actual_original_audio_queue_call_verified_in_declared_fixture']=True
 app['native_reprofile_bypass_executed_in_declared_fixture']=True
 app['native_exclusive_certification_enabled']=False
 app['local_reversible_marker_voice_bundle']=dict(manifest=P+'local-marker-bundle-manifest-v2.json',
  candidate=bundle['candidate_path'],candidate_sha256=bundle['candidate_sha256'],rollback=bundle['rollback_path'],
  rollback_sha256=bundle['rollback_sha256'],physical_installed=False,raw11_gate=True,physical_visible_marker_guaranteed=False)
 now=datetime.now(timezone.utc);next_focus=('Continue actual native audio-session/selector/full-reader binding and cover original277D26 reprofile bypass before enabling ownership; '
  'provide a fresh native heap initialization scope and continue original395520 allocations without host allocator returns; '
  'controlled single-voice code-execution test is prepared but waits for user availability/USB mode. '
  'App/menu/direct-phone audio incomplete; pairing first, mic canceled, fidelity deferred, AA later, Maps deferred; active/no-achieve.')
 state.update(updated_utc=now.isoformat(),current_priority='Native menu/music integration and reversible physical changed-code acceptance test; active/no-achieve.')
 state['next_actions'][0]=next_focus;app['remaining_work']=state['next_actions'][:4]
 state['attended_testing']['native_marker_code_test']=dict(candidate_prepared=True,installation_performed=False,
  user_availability_question_pending=True,physical_mode_not_confirmed=True,voice_file='Voice/Chinese_Big5_MeiLing.vpm',
  expected_positive_observation='Fresh Audio Test / Aud Ver Big5 row M7Q9',unchanged2_10_result_ambiguous=True)
 state['attended_testing'].update(user_present=None,no_pending_question=False,next_attended_test_not_requested_yet=False,
  current_attended_test='Single reversible Big5 code-execution marker test prepared; availability question pending, USB disk absent at current read-only observation.')
 state['parallel_research'].update(live_subagent_count=1,active_agent_tasks=['gui_worker_boot: new public-heap initialization scope'],tasks=['original queue native caller and reprofile coverage','original GUI clock/allocator caller','reversible marker package and physical acceptance'],
  continued_round_completed=False,root_owns_runtime_and_publication=True,agents_currently_running=True)
 state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',validated_utc=now.isoformat(),
  focused_evidence=B+'native-queue-call-emulation-proof.json',focused_evidence_sha256=sha(B+'native-queue-call-emulation-proof.json'),
  previous_state_snapshot=B+'previous-state.json',previous_current_audit_snapshot=B+'previous-audit.json',
  previous_turn_revalidation='Previous169 findings/138details checkpoint and all1529 protected sources revalidated.',
  actual_new_original_queue_cases=6,actual_new_boundary_controls=2,actual_original_reprofile_bypass_verified=True,
  strict_marker_actual_new_controls=8,candidate_metadata_embedded_reader_bounded_control=1,
  complete_native_App_or_phone_audio=False,native_exclusivity=False,native_STOP_DONE_verified=False,
  physical_audio_or_native_App_verified=False,device_io=False,device_files_written=False,automatic_calls_or_sound=False,
  local_test_package_prepared=True,physical_test_availability_question_pending=True,
  terminal_clock_caller_attempt=terminal,next_focus=next_focus,goal_status='active',full_goal_complete=False,
  reasons=['Original270458 invokes compiled queue bridge with actual7argument provenance and original277C6A returns0/5.',
   'Original reprofile actually restores stock RAM callback and bypasses guard; uncertified witness remains-200.',
   'Reversible20MB voice package preserves originalDLLINFO/SIG and is read through actual original embedded callbacks.',
   'Physical package acceptance/currentloader and original UI rendering remain unverified.'])
 for key in ('updated_utc','current_priority','next_actions','last_goal_turn','parallel_research','attended_testing'):task[key]=state[key]
 public.update(updated=now.isoformat(),deep_research=state);progress=public['research_progress']
 details=[
  '原廠音訊註冊函式已真正呼叫新ARM元件：六組有界案例通過，七參數由原指令產生，原底層函式正常回0、配置失敗回5；不符來源、執行環境、音源或停止狀態時回8。尚無實機聲音。',
  '新增兩組原指令控制：一次授權用完後第二次請求回8；原廠重新設定音訊會恢復原callback，並成功繞過新RAM入口。這個實際缺口仍待處理，獨占認證保持拒絕。',
  '音訊註冊測試元件已完成ARM可執行映像、沒有未解析符號；它只是有界測試映像，沒有形成完整播放器或替換原廠MAIN。',
  '獨立檔案核對涵蓋八例、4231筆CPU寫入及69個可單獨重建區域；混合堆疊與heap缺共同事件序號，不宣稱全記憶體時序重建。執行緒、mutex、opaque heap及喚醒仍有明示離線條件。',
  '程式標記新增八組真ARM控制，包含唯一識別、目前檔案路徑、非阻塞原鎖、錯誤來源拒絕及重入保留原值；不把模擬的目前檔案資訊當成實機讀值。',
  '已組好可回復單一Big5語音模組測試包，約20MB；僅程式成員改動，原DLLINFO、72-byte SIG及其他成員逐byte保留，原檔rollback和完整差異已封存。尚未傳入車機。',
  '候選包已通過有界原metadata與END讀取流程，再由五個原檔案callback真正讀取新程式；checksum欄位是標籤解析，沒有證明SIG或上層FAT實機接受。',
  '候選包內新程式在模擬中真寫入五個UTF16單位，原版本getter及頁面輸入收到M7Q9；原40介面及輸入轉接保留。13加10項獨立檔案斷言通過，尚未實機顯示。',
  '現候選只在原入口回11時嘗試標記，其餘返回原樣保留且不標記；原請求版本與模組相符支持正常回11的靜態推論，實機未觀察。若仍顯示2.10，不能單獨判定程式遭拒。',
  '單檔安裝與還原程序已準備：先比對原機身分、核對檔案與新備份，再寫入及讀回驗證。目前只詢問使用者是否方便現場測試，尚無裝置寫入。',
  '新原廠時鐘caller範圍通過26項純host控制；actual session5264已取得terminal退出1，停止在尚未支援的48-byte配置入口。原廠時鐘三指令、真返回及堆疊結果寫入已由檔案獨立核對；沒有host tick或假返回。',
  '本輪完整冷啟動前綴的11個原helper、5個boot區域、22個元件區域及786432-byte字型cache已獨立重建；後段停下不抹去前綴成果，也不當作完整首頁成功。',
  '後段7個body、8個FP、22個既有區域及467532-byte初始資料bank已獨立核對；時鐘caller兩組原PUSH共15筆CPU寫入，保留實際來源、執行緒、堆疊及返回。重疊區域觀察不當成獨立實驗。',
  '下一段原配置函式的呼叫鏈、N+8請求與返回指標前的handle位置已靜態核對；兩個呼叫端沒有NULL檢查，也未清零。下一輪需補原heap初始化與Dispatcher ownership，不以host配置替代。']
 assert progress['completed']==prior['research_progress']['completed']
 progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
 next_text='補齊原廠首頁與音訊生命週期，處理重新設定音訊的入口繞過；使用者方便時測單一語音模組的原機改碼接受。'
 progress.update(research_updated_utc=now.isoformat(),next=next_text);progress['phases'][4]['next']=next_text
 assert len(app['static_findings'])==185 and len(progress['completed'])==152
 assert progress['estimate_percent']==33 and progress['phases'][4]['estimate_percent']==20
 assert sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==33
 report=(ROOT/'reports/nuvi2565RT.html').read_text()
 card='<div class="card"><h2>最新離線進展：原廠音訊註冊已接上新元件，原機程式測試包已準備</h2><p><strong>原廠音訊呼叫已實際接通：</strong>六組ARM控制確認原函式以正確七參數呼叫新元件，正常與配置失敗返回保留；另兩組控制證明一次授權限制，以及原廠重新設定音訊可繞過新入口。這個缺口未修完，尚未取得完整音訊獨占或原機播放。</p><p><strong>可回復單檔測試包已準備：</strong>約20MB的Big5 Mei-Ling語音模組，只變更程式成員，原版本資料、SIG與其他內容保留，原檔可還原。模擬中已由原metadata與五個檔案callback載入候選，新ARM程式寫入M7Q9，原版本讀取路徑收到標記。</p><p>目前尚未安裝；已詢問使用者是否方便現場測試。實機看到新標記才能確認這條改碼執行路徑。現候選要求原入口回11，其餘返回不標記；仍看到2.10有多種可能，不能直接判定遭拒。完整App選單、手機直接藍牙音樂與喇叭仍未完成。</p><p>首頁這輪模擬已保留完整冷啟動前綴；原時鐘函式真正返回並寫入堆疊，後段停在48-byte記憶體配置入口。下一輪需補原heap初始化，首頁前景仍未完成。整體里程碑估計33%、App整合20%，為研究估計；配對即時優先，麥克風取消、音質擱置，Android Auto排後、Google Maps暫緩。</p></div>'
 report,n=re.subn(r'<div class="card"><h2>最新離線進展：首頁初始化與自製程式執行標記已完成有界驗證</h2>.*?</div>',lambda _:card,report,count=1,flags=re.S);assert n==1
 old=prior['research_progress']['phases'][4]['next'];row='<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(old)+'</td></tr>'
 assert report.count(row)==1;report=report.replace(row,'<tr><td>原生 App 入口與功能整合</td><td>20%</td><td>'+html.escape(next_text)+'</td></tr>',1)
 report,n=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(x)+'</li>'for x in details)+m[3],report,count=1,flags=re.S);assert n==1
 report,n=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>',report,count=1);assert n==1
 local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
 for name in ('report-updated-time','research-updated-time'):
  report,n=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>','<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1);assert n==1
 assert not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',report)and 'REDACTED_PRIVATE_ID'not in report
 for path in ('scripts/stage_native_marker_voice.py','scripts/probe_native_dispatcher_clock_caller.py',str(Path(__file__).resolve().relative_to(ROOT))):protected[path]=sha(path)
 for directory in (ROOT/B,ROOT/C/'gui-static',ROOT/C/'runtime',ROOT/C/'next-allocation-static'):
  for p in directory.rglob('*'):
   if p.is_file()and '__pycache__'not in p.parts:protected[str(p.relative_to(ROOT))]=sha(str(p.relative_to(ROOT)))
 # This clock run is terminal and sealed. New native-allocation agent drafts use another namespace.
 for p in (C+'terminal-receipt.json',C+'clock-caller-observed-prefix.json'):
  protected[p]=sha(p)
 for path,d in (('evidence/deep-research-state.json',state),('evidence/task-state.json',task),('reports/findings.json',public)):write(path,d)
 (ROOT/'reports/nuvi2565RT.html').write_text(report)
 latest=read('evidence/report-web-latest.json')
 with urllib.request.urlopen(latest['url'],timeout=10)as response:
  served,status,cache=response.read(),response.status,response.headers.get('Cache-Control','')
 result=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],text=True,capture_output=True,check=True)
 service=dict(line.split('=',1)for line in result.stdout.splitlines()if '='in line)
 assert status==200 and served==report.encode()and 'no-store'in cache
 assert service['MainPID']=='357833'and service['ActiveState']=='active'and service['UnitFileState']=='enabled'
 assert report.count('datetime="'+iso+'"')==2 and 'value="33"'in report
 assert public['deep_research']==state and task['last_goal_turn']==state['last_goal_turn']
 assert state['goal_status']=='active'and not state['goal_complete']and state['required_work_remaining']
 assert not app['native_app_running']and not app['direct_phone_music_verified']
 checks=dict(previous1529_revalidated=True,old47_native_suites_retained_new_complete_cold_prefix48=True,actual_native_queue6_and_boundary2=True,
  independent8case_review=True,original_reprofile_bypass_no_exclusivity=True,strict_marker8=True,
  reversible_candidate_rollback_verified=True,original_metadata_reader_and_compiled_marker=True,
  original_DLLINFO_SIG_preserved_not_signature_enforcement=True,raw11_gate_and_ambiguous_negative_visible=True,
  mixed_histories_and_declared_fixtures_scoped=True,actual_clock_terminal_prefix_scoped_not_fullbody=True,
  native_App_audio_STOP_DONE_not_claimed=True,goal_active_fullscope=True,weighted33_App20=True,
  canonical_task_public_consistent=True,HTML200_no_store_exact=True,two_Taiwan_timestamps=True,
  enabled_service_PID_unchanged=True,public_HTML_no_MAC_ESN=True)
 audit=dict(previous,updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=all(checks.values()),scope_checks=checks,
  previous_checkpoint=B+'previous-audit.json',protected_sources=protected,selected_frozen_suites=suites,native_unique_exact_dependencies=len(native_deps),
  selected_original_queue_control_proofs=[dict(path=B+'native-queue-call-emulation-proof.json',sha256=sha(B+'native-queue-call-emulation-proof.json'),cases=6),
   dict(path=B+'queue-reprofile-boundary-proof.json',sha256=sha(B+'queue-reprofile-boundary-proof.json'),cases=2)],
  selected_strict_local_package_proofs=[dict(path=P+'strict-marker-control-proof.json',sha256=sha(P+'strict-marker-control-proof.json'),controls=8),
   dict(path=P+'candidate-embedded-reader-metadata-control-v2.json',sha256=sha(P+'candidate-embedded-reader-metadata-control-v2.json'),bounded_control=1)],
  terminal_clock_attempt=terminal,current_state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
  physical_App_or_hardware_or_audio=False)
 write(OUT,audit)
 latest['historical_offline_checkpoint_audits']['prior_native_inline_fields_checkpoint']=dict(audit=B+'previous-audit.json',audit_sha256=sha(B+'previous-audit.json'),all_passed=True)
 latest.pop('current_native_inline_fields_checkpoint',None)
 latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,served_latest_report=True,
  local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(served).hexdigest(),report_bytes=len(served),
  service=service,service_not_restarted=True,cache_control=cache,current_native_queue_package_checkpoint=OUT,
  checkpoint_sha256={OUT:sha(OUT)},goal_status='active',full_goal_complete=False,current_physical_test_requested=True)
 latest['complete_current_offline_run'].update(protected_source_count=len(protected),native_frozen_suites_revalidated=48,
  actual_native_queue_new_cases=6,actual_boundary_new_controls=2,strict_marker_new_controls=8,
  candidate_metadata_reader_bounded_control=1,physical_App_verified=False,device_io=False,sounds_emitted=False)
 latest['progress_display_verified'].update(estimate_percent=33,completed_items=152,report_updated_time=iso,research_updated_time=iso,
  visual_browser_render_not_performed=True)
 write('evidence/report-web-latest.json',latest)
 print(json.dumps(dict(all_passed=True,findings=185,details=152,scope_checks=len(checks),protected_sources=len(protected),
  frozen_native_suites=48,native_unique_integrity_dependencies=len(native_deps),clock_run_terminal=True,updated_Taiwan=iso,HTTP_status=status,report_bytes=len(served))))
if __name__=='__main__':main()
