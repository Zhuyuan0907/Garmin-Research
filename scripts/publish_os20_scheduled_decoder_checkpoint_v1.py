#!/usr/bin/env python3
"""Publish native scheduling into real SBC code, retaining device limits."""
import gzip,hashlib,html,importlib.util,json,re,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from zoneinfo import ZoneInfo
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('helpers',ROOT/'scripts/publish_native_warm_probe_checkpoint_v1.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
read,sha,create,write=P.read,P.sha,P.create,P.write
OLD='evidence/firmware-analysis/native-os20-create-checkpoint-audit.json'
OUT='evidence/firmware-analysis/native-os20-scheduled-decoder-checkpoint-audit.json'
B='staging/native-os20-scheduled-decoder-checkpoint-v1/'
C='native/os20-task-bridge/scheduled-contract-v1.json'
G='staging/native-os20-scheduled-decoder-v1/'
F='staging/native-os20-scheduled-decoder-file-v2/ROOT_FILE-proof-v2.json'

def served(url):
    with urllib.request.urlopen(urllib.request.Request(url,headers={'Cache-Control':'no-cache'}),timeout=10)as r:
        body=r.read();assert r.status==200 and 'no-store'in r.headers.get('Cache-Control','');return body

def main():
    assert not(ROOT/B).exists() and not(ROOT/OUT).exists()
    old,guest,files,contract=[read(p)for p in [OLD,G+'guest-proof.json',F,C]]
    assert all(d['all_passed']for d in [old,guest,files,contract])
    assert old['current_findings']==308 and old['current_public_details']==295 and len(old['protected_sources'])==4749
    assert files['totals']==dict(CPU_stores=12085,store_effective_addresses=12085,whole_zones=18,
        instructions=89710,native_full_returns=23,native_TCBs=3,context_destinations=4,reference_PCM_bytes=256)
    assert guest['original_root_and_compiled_SBC_callback_executed'] and guest['original_self_exit_and_idle_restore']
    assert contract['initial_controller_idle_ready_membership_fixture'] and not contract['live_A2DP_or_DAC_speaker_or_GUI_verified']
    directories=['staging/native-os20-scheduled-decoder-build-v1/',G,
        'staging/native-os20-scheduled-decoder-file-v1/','staging/native-os20-scheduled-decoder-file-v2/']
    for base,code in zip(directories,[0,0,1,0]):
        terminal=read(base+'terminal-tool-receipt.json')['actual_terminal_result']
        assert terminal['exit_code']==code and 'session_id'not in terminal
    assert all(sha(p)==h for p,h in old['canonical_after_sha256'].items())
    protected,focused=dict(old['protected_sources']),{}
    def register(path,expected=None):
        actual=sha(path);assert expected is None or expected==actual,path
        assert path not in protected or protected[path]==actual,path
        protected[path]=actual;focused[path]=actual
    for d in [guest,files,contract]:
        for p,h in d['source_sha256'].items():register(p,h)
    for base in directories:
        for p in sorted((ROOT/base).iterdir()):
            if p.is_file():register(str(p.relative_to(ROOT)))
    for p in [C,OLD,'scripts/publish_os20_scheduled_decoder_checkpoint_v1.py',
        'staging/native-os20-create-checkpoint-v1/publication-terminal-tool-receipt.json',
        'staging/native-os20-create-checkpoint-v1/fresh-live-readback.json']:
        register(p)
    state,task,public=[read(p)for p in P.CANONICAL[:3]]
    app,progress=state['native_app_music'],public['research_progress']
    assert state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining']
    assert not app['native_app_running'] and not app['direct_phone_music_verified']
    assert len(app['static_findings'])==308 and len(progress['completed'])==295
    old_next=progress['phases'][4]['next']
    assert progress['estimate_percent']==37 and progress['phases'][4]['estimate_percent']==35
    latest,service=read('evidence/report-web-latest.json'),P.service_now()
    before=served(latest['url']);assert hashlib.sha256(before).hexdigest()==sha(P.CANONICAL[3])
    (ROOT/B).mkdir();snapshots=[]
    for original,name in [(OLD,'previous-audit.json'),('evidence/report-web-latest.json','previous-web.json')]+list(zip(
        P.CANONICAL,['previous-state.json','previous-task.json','previous-public.json','previous-report.html'])):
        path,payload=B+name+'.gz',(ROOT/original).read_bytes()
        with(ROOT/path).open('xb')as f:
            with gzip.GzipFile(filename='',mode='wb',fileobj=f,mtime=0,compresslevel=6)as z:z.write(payload)
        assert gzip.decompress((ROOT/path).read_bytes())==payload;register(path)
        snapshots.append(dict(original=original,snapshot=path,encoding='gzip',decoded_sha256=hashlib.sha256(payload).hexdigest()))
    findings=[
        ('native_OS20_original_root_compiled_SBC_job',C,
         'NEW caller callback/job/priority7/name inputs over a reused allocation endpoint. Original create publishes the compiled entry/job. Three original TCBs built, original restore reaches521E44 root and invokes real ARMv6 SBC code with exact job.72byte frame decodes to256byte PCM equal to upstream reference; no live transport/DAC/GUI.'),
        ('native_OS20_three_tasks_POST_WAIT_restore_ABI',F,
         'Original controller WAIT yields, worker POST preempts and resumes controller with0x400, second WAIT resumes worker POST. Worker/root ABI returns completed before original exit. Four compact/full native contexts verified, no host CPU restore or return hook. Initial ready membership still an explicit bootstrap fixture, not full boot.'),
        ('native_OS20_self_exit_not_complete_adapter_reclamation',C,
         'Original kernel self-exit removes worker from all-task list and restores idle. OS20 adapter+48 and descriptor registry remain; second controller WAIT pending. Native heap reclamation and full adapter lifecycle unverified. Persistent worker and formal stop/cleanup needed before repeated user launches.'),
        ('native_OS20_scheduled_decoder_ROOT_FILE',F,
         '12085 original/compiled store EA-values,18 whole zones,89710 instructions,23 scoped ABI returns and4 native context destinations. v1 completed store/prefix/context checks then failed missing stopped host-return sentinel; v2 only finished ABI/end-state checks. No guest or completed store/prefix rerun, new independent agent or full nonstore interpreter.')]
    for key,path,scope in findings:
        assert key not in app['static_findings']
        app['static_findings'][key]=dict(evidence=path,evidence_sha256=sha(path),scope=scope,
            evidence_type='ROOT native scheduler and compiled SBC integration',device_io=False,physical_App_or_audio_verified=False)
    details=[
        '原OS20入口已切入實際編譯的SBC解碼工作：三個TCB由原358BF8建立；原create寫入新回呼、job及priority7，原restore進入521E44 root，從適配record讀到同一job後呼叫編譯程式。',
        '72-byte、16kHz單聲道SBC音框在新工作中解碼成256-byte PCM，逐byte符合上游libsbc2.1參考。原controller WAIT、worker POST及完整／compact context restore實際往返；controller收到0x400，再次WAIT後worker及root完整返回。',
        '原核心退出流程移除worker並恢復idle，但OS20適配槽和descriptor登記仍在，controller第二次WAIT也仍pending。尚未驗證完整heap／adapter回收；下一步優先常駐worker等待、喚醒與取消／清理流程。',
        'FILE共核對12085個原指令／編譯指令store地址和值、18完整區域、89710條指令、23次完整ABI返回及4個context目的地。首版store／prefix已完成，僅因漏納停止sentinel而在ABI失敗；新版只補ABI／結果核對，沒有重跑guest或已完成store範圍。',
        '本輪消除僅有合成current TCB的入口限制，但初始ready membership仍是bootstrap輸入、MMU關閉、heap／ELF storage由host提供。App研究估計35%→40%，整體加權37%；實機App、導航與音樂共存、直接A2DP及Android Auto／Google Maps仍未完成。']
    next_text='把原OS20入口接到常駐播放器：驗證多次等待／喚醒及多音框，查適配槽／descriptor退出與回收，再接正常音訊與GUI所有權。初始ready只是bootstrap fixture，完整開機、實機CPU／heap／MMU與手機直接A2DP仍待驗證；現場配對第一優先。'
    now=datetime.now(timezone.utc)
    state.update(updated_utc=now.isoformat(),current_priority=
        'Original scheduler entered OS20 root and real compiled SBC callback, matched256PCM bytes, resumed controller/worker and executed native self-exit. Next persistent multi-frame worker with repeated WAIT/POST and formal OS20 adapter/descriptor lifecycle, then audio/GUI ownership and physical loading. Three TCBs native; initial ready remains fixture, no live App/audio. Pairing FIRST; full goal active.')
    state['latest_user_instruction']='Continue native App/music research first; full original Android Auto and offline Google Maps scope retained, microphone canceled.'
    state['next_actions'][0]=state['current_priority']
    app['original_OS20_compiled_SBC_callback_scheduled_offline']=dict(contract=C,FILE=F,totals=files['totals'],
        three_TCBs_native_constructed=True,root_and_compiled_decoder_entered=True,reference_PCM_equal=True,
        original_POST_WAIT_context_and_self_exit=True,worker_and_root_full_ABI_return=True,
        adapter_and_descriptor_still_present=True,controller_second_WAIT_pending=True,
        initial_ready_membership_is_fixture=True,physical_App_direct_A2DP_DAC_GUI_verified=False)
    state['last_goal_turn'].update(classification='progress',previous_goal_turn_classification='progress',
        validated_utc=now.isoformat(),previous_state_snapshot=B+'previous-state.json.gz',
        previous_current_audit_snapshot=B+'previous-audit.json.gz',snapshot_encoding='gzip',
        focused_evidence=F,focused_evidence_sha256=sha(F),reasons=[scope for _,_,scope in findings],
        device_IO=False,device_io=False,device_files_written=False,goal_status='active',full_goal_complete=False)
    for name in ['updated_utc','latest_user_instruction','current_priority','next_actions','last_goal_turn']:task[name]=state[name]
    progress['completed'].extend(details);progress['phases'][4]['completed'].extend(details)
    progress['phases'][4].update(estimate_percent=40,next=next_text)
    weighted=sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])
    assert weighted==37.0
    progress.update(estimate_percent=37,weighted_estimate_percent=weighted,research_updated_utc=now.isoformat())
    public.update(updated=now.isoformat(),deep_research=state)
    assert len(app['static_findings'])==312 and len(progress['completed'])==300
    card=('<div class="card"><h2>最新進展：原廠排程器已切入SBC解碼工作</h2><p>'
        '三個工作控制區塊由原核心建立；原OS20入口讀取同一適配record，實際呼叫編譯的ARMv6解碼程式。'
        '72-byte SBC音框產生<strong>256-byte PCM，與上游參考逐byte一致</strong>。'
        '原WAIT／POST使controller與worker往返，編譯回呼與原root完整返回，原退出移除worker並恢復idle。</p><p>'
        '<strong>這仍是離線模型，尚未在車機運行App或由手機直接播放。</strong>'
        '初始ready鏈結仍是bootstrap輸入，MMU關閉，heap與ELF storage由模型提供；未驗證真實時鐘、DAC或GUI。'
        '退出後OS20適配槽／descriptor仍在，controller第二次WAIT仍pending，不能當作完整回收。</p><p>'
        'FILE核對12085個store、18完整區域、89710條指令、23次完整返回與4個context目的地。'
        '首版store／prefix已完成，漏納停止sentinel造成ABI檢查失敗；新版僅補ABI／結果，未重跑完成範圍。'
        '下一步常駐worker、多音框、取消／清理，再接音訊與GUI所有權。App研究估計40%、整體37%；本輪沒有實機操作或聲音。</p></div>')
    report,count=re.subn(r'<div class="card"><h2>最新進展：原廠OS20建立工作已完整返回</h2>.*?</div>',lambda _:card,before.decode(),count=1,flags=re.S)
    assert count==1
    row='<tr><td>原生 App 入口與功能整合</td><td>35%</td><td>'+html.escape(old_next)+'</td></tr>'
    assert report.count(row)==1
    report=report.replace(row,'<tr><td>原生 App 入口與功能整合</td><td>40%</td><td>'+html.escape(next_text)+'</td></tr>',1)
    report=report.replace('整體研究37%、App35%，研究繼續。','整體研究37%、App40%，研究繼續。',1)
    report,count=re.subn(r'(<ul class="completed-progress">)(.*?)(</ul>)',lambda m:m[1]+m[2]+''.join('<li>'+html.escape(d)+'</li>'for d in details)+m[3],report,count=1,flags=re.S)
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
        focused_sources=focused,prior4749_sources_inherited_not_fresh_full_rehash=True,
        findings=findings,details=details,weighted_percent=37.0,App_estimate=40,guest_rerun=False,device_IO=False))
    register(B+'publication-inputs.json')
    for p,d in zip(P.CANONICAL[:3],[state,task,public]):write(p,d)
    (ROOT/P.CANONICAL[3]).write_text(report);after={p:sha(p)for p in P.CANONICAL}
    assert read(P.CANONICAL[0])==state and read(P.CANONICAL[1])==task and read(P.CANONICAL[2])==public
    body=served(latest['url']);assert body==report.encode() and P.service_now()==service
    audit=dict(old,all_passed=True,updated_utc=now.isoformat(),previous_checkpoint=OLD,previous_canonical_snapshots=snapshots,
        protected_sources=protected,canonical_after_sha256=after,current_state_sha256=after[P.CANONICAL[0]],
        report_sha256=after[P.CANONICAL[3]],local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],
        current_findings=312,current_public_details=300,current_focused_sources_sha256=focused,
        prior_full_source_rehash_repeated_this_turn=False,native_OS20_scheduled_decoder_totals=files['totals'],
        original_root_or_user_callback_executed=True,current_TCBs_native_constructed_in_new_scope=True,
        initial_ready_membership_bootstrap_fixture=True,physical_App_direct_A2DP_DAC_GUI_verified=False,
        OS20_adapter_descriptor_or_heap_reclamation_verified=False,weighted_estimate_percent=37.0,App_estimate_percent=40,
        scope_checks=dict(old['scope_checks'],original_root_compiled_SBC_callback_and_exact_PCM=True,
            native_three_TCBs_not_full_boot_or_physical_heap=True,original_POST_WAIT_and_context_frame_ABIs=True,
            native_exit_not_adapter_reclaim_or_all_waiters_resumed=True,completed_FILE_store_prefix_checks_preserved=True,
            full_goal_and_actual_physical_limits_preserved=True))
    create(OUT,audit)
    assert latest.pop('current_native_os20_create_checkpoint')==OLD
    latest.setdefault('historical_offline_checkpoint_audits',{})['prior_native_os20_create_checkpoint']=dict(audit=OLD,audit_sha256=sha(OLD),all_passed=True)
    latest.update(updated_utc=now.isoformat(),current_native_os20_scheduled_decoder_checkpoint=OUT,
        checkpoint_sha256={OUT:sha(OUT)},local_report_sha256=after[P.CANONICAL[3]],served_report_sha256=after[P.CANONICAL[3]],
        report_bytes=len(body),service_not_restarted=True,served_latest_report=True,canonical_hash_readback_uncached=True)
    latest['progress_display_verified'].update(completed_items=300,report_updated_time=iso,research_updated_time=iso,
        original_root_compiled_decoder_scheduler_scope_visible=True,App_estimate_percent=40)
    write('evidence/report-web-latest.json',latest)
    print(json.dumps(dict(all_passed=True,findings=312,details=300,protected_sources=len(protected),
        report_sha256=after[P.CANONICAL[3]],report_bytes=len(body),updated_Taiwan=iso,
        original_scheduled_SBC_callback=True,physical_App=False,estimate_percent=37,App_estimate_percent=40,
        goal_status='active',device_IO=False)),flush=True)

if __name__=='__main__':main()
