#!/usr/bin/env python3
"""FILE-only review of already-captured C/H and generated metadata; never imports target code."""
import gzip, hashlib, json, re, stat
from pathlib import Path
ROOT=Path('/root/garmin')
SCOPE=ROOT/'staging/native-music-cancel-stop-provider-references-readonly-20261007-v1'
def sha(b): return hashlib.sha256(b).hexdigest()
def write(name,obj):
    q=SCOPE/name
    with q.open('x',encoding='utf-8') as f: json.dump(obj,f,ensure_ascii=False,indent=2);f.write('\n')
def pin_stat(p):
    s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,stat.S_IMODE(s.st_mode)]
pins=json.loads((SCOPE/'input-pins.json').read_text());text={};checks=[]
def check(name,value,evidence):
    if not value: raise ValueError('fixed_review_check_failed:'+name)
    checks.append({'name':name,'passed':True,'evidence':evidence})
for r in pins['files']:
    packed=(SCOPE/r['capture']).read_bytes(); raw=gzip.decompress(packed)
    check('capture_pin:'+r['path'],sha(packed)==r['capture_sha256'] and len(raw)==r['bytes'] and sha(raw)==r['sha256'],r['capture'])
    check('immutable_source_stat:'+r['path'],r['stat_before']==r['stat_after']==pin_stat(ROOT/r['path']),r['path'])
    text[r['path']]=raw.decode('utf-8')
check('content_budget',len(pins['files'])==10 and sum(r['bytes'] for r in pins['files'])==105421 and pins['source_content_bytes']==105421 and max(r['bytes'] for r in pins['files'])<=65536,'10 files;105421/122880 B')
manifest=json.loads(text['staging/native-music-continuous/manifest.json'])
for r in pins['files']:
    if r['path'] in manifest['source_sha256']:
        check('generated_metadata_source_identity:'+r['path'],manifest['source_sha256'][r['path']]==r['sha256'],'older continuous manifest source_sha256; metadata only, not binary verification')
def stripped(t):
    # Preserve newline/character positions while omitting comments and strings.
    return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda m:''.join('\n' if c=='\n' else ' ' for c in m.group()),t,flags=re.S)
def function(path,name):
    original=text[path];clean=stripped(original)
    m=re.search(r'\b'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{',clean)
    if not m: raise ValueError('fixed_missing_function:'+name)
    begin=clean.index('{',m.start());depth=1;end=begin+1
    while depth:
        if clean[end]=='{': depth+=1
        elif clean[end]=='}': depth-=1
        end+=1
    return original[m.start():end],original[:m.start()].count('\n')+1,original[:end].count('\n')+1
rt='native/music-continuous/runtime.c';st='native/music-continuous/stream.c';sw='native/sbc-prototype/source_worker.c';co='native/music-continuous/media_coordinator.c';ah='native/ui-music-native-adapter/native_adapter.h';gh='staging/native-player-mixer-handoff/music_session_guard_v4.h'
b,_,_=function(rt,'music_runtime_cancel')
check('runtime_direct_cancel',b.index('media_queue_stop()')<b.index('source_worker_cancel()'),'runtime.c98-102')
b,_,_=function(st,'music_stream_callback')
check('stream_cancel_after_AV_unlock',b.index('result=done(result);')<b.index('if(cancel)(void)music_runtime_cancel();'),'stream.c186-188; source-level ordering only')
b,_,_=function(sw,'source_worker_cancel')
check('cancel_is_flag_and_post_request',all(v in b for v in ['finished_on_stack','return -22','cancel_requested=1','requests++','post(0x40000u);return 0']) and 'media_coordinator_cancel' not in b,'source_worker.c106-111')
b,_,_=function(sw,'source_worker_entry')
check('actor_after_full_cancel_return',b.index('media_coordinator_cancel()')<b.index('source_worker_state.pump_calls++')<b.index('source_worker_state.last_result=result'),'source_worker.c57-60')
check('actor_clear_after_pending_zero','if (!result && !coordinator_state.cancel_pending)' in b and 'source_worker_state.cancel_requested=0' in b,'source_worker.c71-72')
check('actor_finished_not_unload', 'Flag is not' in b and 'permission to unload' in b,'source_worker.c77-79')
b,_,_=function(co,'enter')
check('coordinator_actor_identity','current()!=coordinator_state.owner_tcb' in b and 'coordinator_state.busy' in b,'media_coordinator.c44-49')
b,_,_=function(co,'remove_stopped')
check('borrow_hold_through_original_return',b.index('native_calls++')<b.index('0x277675')<b.index('native_calls--')<b.index('remove_calls++'),'media_coordinator.c72-86')
check('remove_only_idle_unique_node_matching_ticket',all(v in b for v in ['native_idle()','nodes()!=1u','active_ticket!=ticket','in_flight','!result && !nodes()']),'media_coordinator.c75-85')
b,_,_=function(co,'cancel_step')
check('cancel_waits_native_idle_and_borrows',all(v in b for v in ['owned_media_control.busy','reader_in_flight','!native_idle()','state==3u || state==4u','0x36af75','return 1;']),'media_coordinator.c88-101')
check('cancel_release_before_completion',b.index('remove_stopped(ticket)')<b.index('memory_output_release(ticket)')<b.index('continuous_media_cancel_ready()')<b.index('cancel_pending=0'),'media_coordinator.c102-109')
b,_,_=function(co,'media_coordinator_cancel')
check('coordinator_cancel_actor_gate_and_pending','enter()' in b and b.index('media_queue_stop()')<b.index('cancel_pending=1')<b.index('finish(cancel_step())'),'media_coordinator.c111-120')
b,_,_=function(sw,'source_worker_completed')
check('completion_record_identity_not_epoch',all(v in b for v in ['finished_on_stack','0x034e6f08u+memory_output_control.channel*520u','completions++','post(0x20000u)']) and not any(v in stripped(b) for v in ['generation','ownership_epoch','original_result']),'source_worker.c100-105')
occurrences=[]
for path,t in text.items():
    if path.endswith('.c'):
        for m in re.finditer(r'\bsource_worker_completed\s*\(',stripped(t)):
            occurrences.append({'path':path,'line':t[:m.start()].count('\n')+1})
check('bounded_C_completion_definition_only',occurrences==[{'path':sw,'line':100}], 'selected 6 C files only; excluded assembly and other files, not whole-project absence')
check('completion_symbols_are_metadata_not_caller',all(n in manifest['symbols'] for n in ['source_worker_completed','source_completion_hook','source_completion_after_original','source_completion_original']),'manifest symbol table; .S body/installed patch not reviewed')
check('adapter_opaque_provider_signatures',all(v in text[ah] for v in ['int (*runtime_cancel)(void *);','void (*original_source_completed)(void *,const volatile void *record);','uint32_t generation,uint32_t source_token','uint32_t generation,uint32_t ownership_epoch','native_writers_excluded,future_borrowing_callbacks_excluded']),'native_adapter.h63-80')
check('adapter_has_explicit_generation_and_full_return_observation',all(v in text[ah] for v in ['cancel_generation,cancel_count_baseline,pump_baseline','original_cleanup_returned,owner_cancel_iteration_returned','source_remove_baseline,source_release_baseline','entry_address,original_returned','with the real native iteration result','after original3B9DFC continuation']),'native_adapter.h109-150; contracts only, inherited body observation separately labeled')
check('adapter_relink_no_default_ownership',all(v in text[ah] for v in ['ownership_snapshot/prepare_session remain NULL','New relinks must supply recalculated addresses']),'native_adapter.h154-156')
check('new_shared_family_distinct_session_contract',all(v in text[gh] for v in ['scoped epoch plus controller generation','ticket identifies only one copied buffer','no hardware, installed hook or STOP_DONE','generation,epoch,session,instance','full_returns','memory_output_release_session']),'music_session_guard_v4.h1-8,21-42,65-74; only typed header read')
by_path={r['path']:r for r in pins['files']}
def ref(path,lines,function_name=None):
    r={'path':path,'sha256':by_path[path]['sha256'],'lines':lines,'read_scope':'fresh_saved_capture'}
    if function_name:r['function']=function_name
    return r
records=[
 {'id':'request_chain','implementation':'direct C caller exists','references':[ref(st,[153,190],'music_stream_callback'),ref(rt,[98,102],'music_runtime_cancel'),ref(sw,[106,111],'source_worker_cancel')],'behavior':'F2 or successful event19 stops queue; after AV unlock calls runtime cancel, which stops queue and delegates to Source flag+POST. return0 is accepted request, not finished stop.','identity':'Request API has no generation/ownership epoch arguments; Source TCB existence/finished flag are guards.','unproven':['live AV lock/session ownership','request processing by actual native scheduler','native STOP_DONE']},
 {'id':'actor_cancel','implementation':'direct C actor path exists','references':[ref(sw,[44,81],'source_worker_entry'),ref(co,[44,66],'enter / media_coordinator_init'),ref(co,[88,120],'cancel_step / media_coordinator_cancel')],'behavior':'Owner Source actor processes cancel and records counters after return; clears request only when result0 and coordinator pending0. Coordinator requires current TCB==owner and serializes busy state.','identity':'Actor identity is current task bound at coordinator init, not durable channel ownership; no UMC generation/epoch carried by these APIs.','unproven':['controller observe_stop callback bound to this actor','runtime native scheduling','source/app lifecycle completion']},
 {'id':'native_remove_release','implementation':'C full-call-return ordering exists','references':[ref(co,[32,42],'native_idle'),ref(co,[72,110],'remove_stopped / cancel_step')],'behavior':'Waits for native idle and no reader borrow; optional native stop request returns before retry. Holds native_calls through original list-removal return; checks unique node/ticket/in-flight then node disappearance; release return0 and private-ready cancellation precede pending0.','identity':'Native idle predicates and private ticket/counters, not a new hardware exclusivity certificate.','unproven':['actual original functions reach same production state','actual stop acknowledgement','full hardware/renderer/audio return']},
 {'id':'completion_receiver','implementation':'C receiver exists; no caller found in selected C set','references':[ref(sw,[100,105],'source_worker_completed'),ref(sw,[118,123],'source_worker_api'),ref('staging/native-music-continuous/manifest.json',None)],'selected_C_occurrences':occurrences,'metadata_symbols':{n:manifest['symbols'][n] for n in ['source_worker_completed','source_completion_hook','source_completion_after_original','source_completion_original']},'behavior':'Matching actual source-record address/channel posts completion notification; does not accept generation, epoch or original full-return witness. Assembly glue is named in extern/API and manifest symbols but body/installation are not examined.','unproven':['original cleanup continuation really calls this receiver after complete return on device','assembly frame semantics','installed production call site','native callback quiescence']},
 {'id':'old_adapter_contract','implementation':'typed C/H contract fresh; body inherited conditional observer','references':[ref(ah,[63,80],'umcn_bindings'),ref(ah,[109,150],'umcn_trace / cleanup frame / hook declarations')],'behavior':'Explicit opaque runtime_cancel and original_source_completed providers; separate witness generation/source token/ownership epoch and cancel/remove/release/pump baselines. Header demands Source-after-iteration and original3B9DFC full-return wrapper hooks; declarations are not installation.','inherited_body':{'path':'native/ui-music-native-adapter/native_adapter.c','sha256':'f49969bfe55f746e97f2183c9ec6a3a85c6e55ff355cd8333859039dc67d2f21','references':[{'function':'adapter_cancel','line':86},{'function':'adapter_observe','line':103},{'function':'umcn_after_native_iteration','line':230},{'function':'umcn_cleanup_begin','line':246},{'function':'umcn_cleanup_after_original','line':262}],'read_by_this_scope':False,'scope':'root message plus closed UI integration matrix; conditional observations/baselines; actual hook sites not installed'},'unproven':['native ownership_snapshot/prepare_session providers','full-return caller installation','same newer generated-image provider']},
 {'id':'exact_old_image_binding','implementation':'fresh generated metadata source identity only','references':[ref('staging/native-music-continuous/manifest.json',None),ref(ah,[154,157],'umcn_fill_exact_continuous_bindings contract')],'source_pin_match_count':sum(r['path'] in manifest['source_sha256'] for r in pins['files']),'behavior':'Seven captured old C/H source hashes match older continuous manifest. Symbol locations and API arrays establish named old-image metadata, not execution/installation or compatibility of newer loaded-pause/shared-core state.','inherited_wrapper_reference':{'path':'native/ui-music-native-adapter/original_imports.c','line':21,'source_whole_sha256':'not re-read in this scope; exact whole pin is inherited through closed UI matrix','matrix_sha256':'1d50527ca431d3995cf671a1320dc224ad32d4d2970f368e9c2e3bd2cf49117e'},'unproven':['binary content','installed original imports','relocation/state mapping to newer loaded-v2/v3 image']},
 {'id':'shared_core_distinction','implementation':'newer typed header read; real driver bodies inherited','references':[ref(gh,[1,8]),ref(gh,[21,42]),ref(gh,[65,82])],'behavior':'New family uses scoped session epoch/controller generation, true mixer actor/stack/descriptor admission and full-pull borrow frames. FIFO ticket alone is insufficient. Existing newer driver contains real UMC init/ready/start/service ops; cancel/observe_stop specifically remain uncertified (-200), not whole core absence. Old runtime/adapter pointer map and observation baselines are not automatically this provider.','unproven':['same generated-image cancel/observer implementation','production installed full-pull hooks','native exclusive-owner/STOP_DONE']},
 {'id':'source_wake_cross_reference','implementation':'separate closed peer FILE review, inherited only','references':[],'peer':{'path':'staging/native-music-source-wake-service-references-readonly-20261007-v1/call-reference-ledger.json','sha256':'25117cbeca084630a4fc0c782ebe12038baaf0b6c90b77cfc7392d366b472e59','proof_sha256':'41096c3aa7c79db1e9a60de36030d1e6282b33ffe6feca82e6800ef4954ac34d','seal_sha256':'098c23307efdd6ac96c4bfaa0e9378acfa37f616ea4dc1d99a7d1aafe19b9d9f','read_by_this_scope':False},'behavior':'Peer four selected Source/sync C files give descriptor entry, original initialize delegation, pre-sync grant and post-init flag/pull gate. No core-token/cancel-observer C caller found there; task stop delegates aas_stop to mixer16/17/18. This is family-limited, not project-wide absence.','unproven':['assembly glue and other callers','current live source ownership','actual cleanup notification to shared core']}
]
ledger={'schema':'garmin-native-cancel-stop-provider-file-review/v1','all_assigned_checks_passed':True,'STOP':True,'review_kind':'normal saved FILE content analysis only','source_content_bytes':105421,'fresh_files':10,'source_content_limit':122880,'max_single_file_bytes':55116,'records':records,'inherited_controller_lifecycle':{'ledger_sha256':'545e37dd0bd1a0ff2ddd77179648dc175cd9a2983ac33727b81d7fca238cace5','read_by_this_scope':False},'limits':{'selected_family_only':True,'original_instruction_or_ASM_body_read':False,'target_import_compile_execution':False,'guest_or_emulator':False,'MAIN_binary_RAM':False,'device_DBUS_BT_audio':False,'shared_source_or_canonical_edit':False,'hardware_or_phone_music_success':False,'system_risk_guest_retry':False},'next_missing_binding':'A newer same-image provider and installed caller must bind actual actor/session generation+epoch and original-complete-return observation to core cancellation; old C request0 or method counters alone do not establish STOP_DONE.'}
write('provider-return-ledger.json',ledger);write('file-checks.json',{'schema':'garmin-file-structural-checks/v1','checks':checks,'count':len(checks),'target_execution':False,'not_C_compilation_or_whole_project_analysis':True})
proof={'schema':'garmin-native-cancel-stop-file-review-proof/v1','all_assigned_checks_passed':True,'STOP':True,'source_content':{'fresh_files':10,'bytes':105421,'budget_bytes':122880,'largest_bytes':55116,'additional_fresh_source_reads_after_capture':0},'checks_passed':len(checks),'ledger':{'path':str((SCOPE/'provider-return-ledger.json').relative_to(ROOT)),'bytes':(SCOPE/'provider-return-ledger.json').stat().st_size,'sha256':sha((SCOPE/'provider-return-ledger.json').read_bytes())},'reviewer':{'path':str((SCOPE/'review_saved_captures.py').relative_to(ROOT)),'bytes':(SCOPE/'review_saved_captures.py').stat().st_size,'sha256':sha((SCOPE/'review_saved_captures.py').read_bytes())},'actual_scope':'Saved C/H/JSON captures and current source stat identity only; no source content rescanning, binary hash or target execution. Name-index I/O is separate and not byte-instrumented.','findings':['Cancellation C request and Source actor/coordinator full-return ordering exist. Request return0 is not completed stop.','Completion C receiver and old manifest assembly symbols exist; production callback installation and full-return glue are unreviewed.','Old adapter conditional generation/epoch/counter observations do not provide newer shared-core cancel/observe_stop implementation.'], 'unproven':['live hardware or phone playback','original scheduler and stop acknowledgement','native ownership/session/epoch provider','installed original cleanup/full-return hooks','compatible newer generated-image cancel/observer binding'], 'target_execution':0,'ASM_instruction_reads':0,'MAIN_binary_RAM_reads':0,'device_DBUS_BT_audio_operations':0,'system_risk_guest_retries':0}
write('proof.json',proof)
print(json.dumps({'checks':len(checks),'records':len(records),'ledger_sha256':proof['ledger']['sha256'],'proof_sha256':sha((SCOPE/'proof.json').read_bytes()),'STOP':True}))
