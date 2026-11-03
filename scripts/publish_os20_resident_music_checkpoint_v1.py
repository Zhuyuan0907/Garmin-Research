#!/usr/bin/env python3
"""Publish persistent original-kernel music-worker evidence and limits."""
import gzip,hashlib,html,importlib.util,json,re,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
OLD='evidence/firmware-analysis/garminos-backup-compaction-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-os20-resident-music-checkpoint-audit.json'
B='staging/native-os20-resident-music-checkpoint-v1/'
C='native/os20-task-bridge/resident-contract-v1.json'
G='staging/native-os20-resident-music-v2/'
F='staging/native-os20-resident-music-file-v2/ROOT_FILE-proof-v2.json'
def served(url):
    with urllib.request.urlopen(urllib.request.Request(url,headers={'Cache-Control':'no-cache'}),timeout=10)as response:
        body=response.read();assert response.status==200 and 'no-store'in response.headers.get('Cache-Control','');return body
def main():
    assert not(ROOT/B).exists() and not(ROOT/OUT).exists()
    old,guest,files,contract=[read(path)for path in [OLD,G+'guest-proof.json',F,C]]
    assert all(data['all_passed']for data in [old,guest,files,contract])
    assert old['current_findings']==313 and old['current_public_details']==302
    assert len(old['protected_sources'])==4801
    totals=files['totals']
    assert totals['combined_CPU_stores']==28050 and totals['new_tail_store_EA_values_checked']==26224
    assert totals['combined_instructions']==266145 and totals['combined_full_returns']==64
    assert totals['combined_context_destinations']==28 and totals['native_commands']==10
    assert guest['worker_entries']==1 and guest['streams']==2 and guest['SBC_frames']==4
    assert not contract['live_A2DP_DAC_GUI_App_verified']
    directories=['staging/native-os20-resident-music-build-v1/','staging/native-os20-resident-music-build-v2/',
        'staging/native-os20-resident-music-v1/',G,'staging/native-os20-resident-prefix-v1/',
        'staging/native-os20-resident-music-file-v1/','staging/native-os20-resident-music-file-v2/']
    for base,code in zip(directories,[0,0,1,0,0,1,0]):
        terminal=read(base+'terminal-tool-receipt.json')['actual_terminal_result']
        assert terminal['exit_code']==code and 'session_id'not in terminal
    assert all(sha(path)==expected for path,expected in old['canonical_after_sha256'].items())
    protected,focused=dict(old['protected_sources']),{}
    def register(path,expected=None):
        actual=sha(path);assert expected is None or actual==expected,path
        assert path not in protected or protected[path]==actual,path
        protected[path]=actual;focused[path]=actual
    for data in [guest,files,contract]:
        for path,expected in data['source_sha256'].items():register(path,expected)
    for base in directories:
        for path in sorted((ROOT/base).iterdir()):
            if path.is_file():register(str(path.relative_to(ROOT)))
    for path in [C,OLD,'scripts/publish_os20_resident_music_checkpoint_v1.py',
        'staging/garminos-backup-compaction-checkpoint-v1/publication-terminal-tool-receipt.json',
        'staging/garminos-backup-compaction-checkpoint-v1/fresh-live-readback.json']:
        register(path)
    state,task,public=[read(path)for path in P.CANONICAL[:3]]
    app,progress=state['native_app_music'],public['research_progress']
    assert state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining']
    assert not app['native_app_running'] and not app['direct_phone_music_verified']
    assert len(app['static_findings'])==313 and len(progress['completed'])==302
    old_next=progress['phases'][4]['next']
    assert progress['estimate_percent']==37 and progress['phases'][4]['estimate_percent']==40
    latest,service=read('evidence/report-web-latest.json'),P.service_now()
    before=served(latest['url']);assert hashlib.sha256(before).hexdigest()==sha(P.CANONICAL[3])
    (ROOT/B).mkdir();snapshots=[]
    for original,name in [(OLD,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]+list(zip(
        P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
        target,payload=B+name+'.gz',(ROOT/original).read_bytes()
        with(ROOT/target).open('xb')as stream:
            with gzip.GzipFile(filename='',mode='wb',fileobj=stream,mtime=0,compresslevel=6)as zipped:zipped.write(payload)
        assert gzip.decompress((ROOT/target).read_bytes())==payload;register(target)
        snapshots.append(dict(original=original,snapshot=target,encoding='gzip',decoded_sha256=hashlib.sha256(payload).hexdigest()))
    findings=[
        ('native_OS20_resident_two_stream_command_worker',C,
         'Same compiled worker and original TCB/adapter handle two START/STOP generations and four SBC frames. '
         '1024 PCM bytes match upstream independent-stream references. Ten native C commands, one entry, one occupied adapter slot; no per-frame/restart task creation.'),
        ('native_OS20_resident_C_controller_POST_WAIT',F,
         'All command publications and acknowledgements after dispatch are guest C stores and original POST/WAIT calls. '
         'Native idle heartbeat tests already-blocked WAIT; acknowledgements also exercise command POST before worker WAIT. '
         '28 original context destinations total; controller and worker remain in native WAIT at final idle marker.'),
        ('native_OS20_resident_failure_prefix_and_FILE_seal',F,
         'v1 failed wrong ARM pointer for Thumb CURRENT helper; corrected to358D25. Reused only FILE-sealed '
         '3865 original instructions/1826 stores before first compiled controller instruction, excluded bad call. '
         'FILEv1 Path/string setup error checked no tail stores; FILEv2 checks new26224 store EA-values/55 ABI returns/27 contexts '
         'and18 whole final regions. No completed native creation/restore prefix or guest rerun; no new independent agent/full nonstore interpreter.'),
        ('native_OS20_resident_STOP_not_audio_STOP_DONE',C,
         'Duplicate active START=-16 preserves decoder history; stopped DECODE=-11 leaves output/result unchanged. '
         'Decoder STOP keeps root/task/adapter/descriptor/stack/module resident. One-controller, one-outstanding-command pinned '
         'fixture; no full audio STOP_DONE, heap reclamation, safe unload, GUI, native App, direct phone A2DP or speaker proof.')]
    for key,path,scope in findings:
        assert key not in app['static_findings']
        app['static_findings'][key]=dict(evidence=path,evidence_sha256=sha(path),scope=scope,
            evidence_type='ROOT native C controller/persistent OS20 worker and FILE replay',
            device_io=False,physical_App_or_audio_verified=False)
    details=[
        '常駐OS20解碼工作完成兩段串流：同一TCB與適配槽收到原機C控制程式的10個指令，四個SBC音框輸出1,024-byte PCM，與上游兩次獨立啟動的參考逐byte一致；工作只進入一次，停止／重啟沒有新增工作槽。',
        '控制流程包含START、音框、重複START拒絕、STOP、停止後音框拒絕、再START及第二段音框。啟動兩次才reset解碼器，重複START回−16保留history，停止後音框回−11且輸出／結果的canary保持；第二段證明舊synthesis history已清除。',
        '原POST／WAIT／context restore實際執行，C idle送一次heartbeat讓工作先進入等待，再測喚醒；後續指令也測到POST先於worker WAIT。全程28個原context目的地，最終controller與worker仍在原WAIT，idle恢復；10次指令與完成序號都由對應C工作寫入。',
        '首版把原CURRENT Thumb函式用ARM指標呼叫，native controller檢查失敗；新指標358D25修正，僅接續已封存的3,865條原建立／restore前綴，沒有重跑前綴或執行錯誤呼叫。FILE首版在Path／字串組合處失敗，尚未核對tail；新版核對26,224個新store地址和值、55個新完整返回及27個新context；合併28,050 stores／64 returns／18完整區域。',
        '這個STOP只停止解碼指令，不是完整音訊STOP_DONE或安全卸載；原root／stack／TCB／adapter仍常駐。初始ready仍是bootstrap輸入，完整boot／CPU／cache／MMU與實機App未驗證。下一步接既有copied-media／typed PCM FIFO與Source／mixer，再接GUI與實機載入。整體37%、App40%保持。']
    next_text='把已驗證的常駐OS20工作接到既有媒體複製佇列、typed PCM FIFO與原Source／mixer音訊流程，替換仍不完整的工作建立假設；再接GUI／菜單所有權與實機載入。decoder STOP不能當音訊STOP_DONE，模組及stack先保持常駐。現場配對立即第一優先。'
    now=datetime.now(timezone.utc)
    state.update(updated_utc=now.isoformat(),current_priority=
        'One original OS20 worker remains resident across two streams and10 guest C commands, matching1024PCM bytes. '
        'Native POST/WAIT handles blocked and queued wakes; same adapter/TCB remains waiting after decoder Stop. '
        'Next connect copied-media/typed FIFO and Source/mixer to this OS20 lifecycle, then GUI/menu ownership and physical loading. '
        'Initial ready still bootstrap fixture; no full audio STOP_DONE, reclaim, direct A2DP or App. Pairing FIRST; full goal active.')
    state['latest_user_instruction']='Continue native App/music first after completed storage reduction; full Android Auto and offline Google Maps objectives remain later work, microphone canceled.'
    state['next_actions'][0]=state['current_priority']
    app['original_OS20_resident_music_worker_offline']=dict(contract=C,FILE=F,totals=totals,
        completed_native_creation_prefix_reused_not_rerun=True,after_dispatch_commands_all_guest_C=True,
        same_worker_two_streams_Stop_Start=True,reference_PCM_equal=True,
        controller_and_worker_final_native_WAIT_pending=True,one_adapter_slot_occupied=True,
        decoder_Stop_is_not_audio_STOP_DONE=True,module_stack_adapter_resident=True,
        initial_ready_membership_fixture=True,physical_App_direct_A2DP_DAC_GUI_verified=False)
    state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',
        validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json.gz',
        previous_current_audit_snapshot=B+'previous-audit.json.gz',snapshot_encoding='gzip',
        focused_evidence=F,focused_evidence_sha256=sha(F),reasons=[scope for _,_,scope in findings],
        next_focus=next_text,device_IO=False,device_io=False,device_files_written=False,
        goal_status='active',full_goal_complete=False)
    for name in ['updated_utc','latest_user_instruction','current_priority','next_actions','last_goal_turn']:task[name]=state[name]
    progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
    progress['phases'][4]['next']=next_text
    assert sum(phase['weight']*phase['estimate_percent']/100 for phase in progress['phases'])==37.0
    progress['research_updated_utc']=now.isoformat();public.update(updated=now.isoformat(),deep_research=state)
    assert len(app['static_findings'])==317 and len(progress['completed'])==307
    card=('<div class="card"><h2>最新進展：同一常駐工作已能停止並重新播放</h2><p>'
        '原OS20入口的同一工作接收<strong>10個C控制指令</strong>，完成兩段串流、四個SBC音框；'
        '<strong>1,024-byte PCM與參考一致</strong>。停止後重啟只占一個工作槽，工作只進入一次。</p><p>'
        '重複START回−16、停止後音框回−11；輸出未被拒絕指令改寫。原POST／WAIT涵蓋工作已等待與先收到通知的情況，'
        '兩個工作最終回到原WAIT。28個原context目的地已驗證，前綴建立／restore完成紀錄被接續使用。</p><p>'
        '<strong>仍是離線模型，尚未在車機執行App或讓手機直接播放。</strong>'
        'decoder STOP不是完整音訊STOP_DONE，模組／工作／stack仍常駐；初始ready還是bootstrap輸入。'
        '下一步接既有PCM FIFO與Source／mixer，再接菜單與實機載入。整體37%、App40%保持，本輪沒有實機操作或聲音。</p></div>')
    report,count=re.subn(r'<div class="card"><h2>最新進展：原廠排程器已切入SBC解碼工作</h2>.*?</div>',lambda _:card,before.decode(),count=1,flags=re.S)
    assert count==1
    row='<tr><td>原生 App 入口與功能整合</td><td>40%</td><td>'+html.escape(old_next)+'</td></tr>'
    assert report.count(row)==1
    report=report.replace(row,'<tr><td>原生 App 入口與功能整合</td><td>40%</td><td>'+html.escape(next_text)+'</td></tr>',1)
    report=report.replace('研究继续。','研究繼續。')
    report,count=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda match:
        match[1]+match[2]+''.join('<li>'+html.escape(detail)+'</li>'for detail in details)+match[3],report,count=1,flags=re.S)
    assert count==1
    report,count=re.subn(r'<p><strong>下一步：</strong>.*?</p>',lambda _:'<p><strong>下一步：</strong>'+html.escape(next_text)+'</p>',report,count=1,flags=re.S)
    assert count==1
    local=now.astimezone(ZoneInfo('Asia/Taipei'));iso=local.isoformat(timespec='seconds')
    for name in ['report-updated-time','research-updated-time']:
        report,count=re.subn(r'<time id="'+name+r'" datetime="[^"]+">[^<]+</time>',
            '<time id="'+name+'" datetime="'+iso+'">'+local.strftime('%Y/%m/%d %H:%M:%S')+'</time>',report,count=1)
        assert count==1
    assert 'REDACTED_PRIVATE_ID'not in report and not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',report)
    for row in snapshots:assert sha(row['original'])==row['decoded_sha256']
    create(B+'publication-inputs.json',dict(all_passed=True,previous_checkpoint=OLD,snapshots=snapshots,
        focused_sources=focused,prior4801_sources_inherited_not_fresh_full_rehash=True,
        findings=findings,details=details,weighted_percent=37.0,App_estimate=40,
        completed_creation_prefix_or_guest_rerun=False,device_IO=False))
    register(B+'publication-inputs.json')
    for path,data in zip(P.CANONICAL[:3],[state,task,public]):write(path,data)
    (ROOT/P.CANONICAL[3]).write_text(report);after={path:sha(path)for path in P.CANONICAL}
    assert read(P.CANONICAL[0])==state and read(P.CANONICAL[1])==task and read(P.CANONICAL[2])==public
    body=served(latest['url']);assert body==report.encode() and P.service_now()==service
    audit=dict(old,all_passed=True,updated_utc=now.isoformat(),previous_checkpoint=OLD,previous_canonical_snapshots=snapshots,
        protected_sources=protected,canonical_after_sha256=after,current_state_sha256=after[P.CANONICAL[0]],
        report_sha256=after[P.CANONICAL[3]],local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],
        current_findings=317,current_public_details=307,current_focused_sources_sha256=focused,
        prior_full_source_rehash_repeated_this_turn=False,native_OS20_resident_music_totals=totals,
        current_TCBs_native_constructed_in_sealed_prefix=True,completed_creation_prefix_not_rerun=True,
        declared_frozen_GP_CPSR_endpoint_restore_before_new_scope=True,host_native_context_switch_substitution=False,
        native_controller_and_worker_final_WAIT_pending=True,decoder_Stop_not_audio_STOP_DONE=True,
        OS20_adapter_descriptor_or_heap_reclamation_verified=False,physical_App_direct_A2DP_DAC_GUI_verified=False,
        weighted_estimate_percent=37.0,App_estimate_percent=40,
        scope_checks=dict(old['scope_checks'],persistent_original_OS20_root_two_streams=True,
            same_TCB_adapter_occupied_once=True,guest_C_command_stores_and_original_POST_WAIT=True,
            duplicate_START_and_stopped_decode_rejected=True,completed_native_creation_and_FILE_prefix_not_rerun=True,
            decoder_Stop_not_full_audio_STOP_DONE_and_storage_resident=True,
            full_goal_and_actual_physical_limits_preserved=True))
    create(OUT,audit)
    assert latest.pop('current_garmin_backup_compaction_checkpoint')==OLD
    latest.setdefault('historical_offline_checkpoint_audits',{})['prior_garmin_backup_compaction_checkpoint']=dict(
        audit=OLD,audit_sha256=sha(OLD),all_passed=True)
    latest.update(updated_utc=now.isoformat(),current_native_os20_resident_music_checkpoint=OUT,
        checkpoint_sha256={OUT:sha(OUT)},local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],
        report_bytes=len(body),service_not_restarted=True,served_latest_report=True,canonical_hash_readback_uncached=True)
    latest['progress_display_verified'].update(completed_items=307,report_updated_time=iso,research_updated_time=iso,
        persistent_native_OS20_Stop_Start_scope_visible=True,App_estimate_percent=40)
    write('evidence/report-web-latest.json',latest)
    print(json.dumps(dict(all_passed=True,findings=317,details=307,protected_sources=len(protected),
        report_sha256=after[P.CANONICAL[3]],report_bytes=len(body),updated_Taiwan=iso,
        original_resident_OS20_music_worker=True,physical_App=False,estimate_percent=37,App_estimate_percent=40,
        goal_status='active',device_IO=False)),flush=True)
if __name__=='__main__':main()
