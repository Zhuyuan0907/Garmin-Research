#!/usr/bin/env python3
"""Normal FILE-content/numeric contract analysis; no target imports or C execution."""
import gzip,hashlib,json,re,stat
from pathlib import Path
ROOT=Path('/root/garmin');P=ROOT/'staging/native-music-SBC-capability-contract-readonly-20261007-v1'
def sha(b):return hashlib.sha256(b).hexdigest()
def write(name,v):
 with (P/name).open('x',encoding='utf-8') as f:json.dump(v,f,ensure_ascii=False,indent=2);f.write('\n')
def ss(q):
 s=q.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,stat.S_IMODE(s.st_mode)]
pins=json.loads((P/'input-pins.json').read_text());text={};checks=[]
def check(name,ok,evidence):
 if not ok:raise ValueError('fixed_FILE_check_failed:'+name)
 checks.append({'name':name,'passed':True,'evidence':evidence})
for r in pins['files']:
 packed=(P/r['capture']).read_bytes();b=gzip.decompress(packed)
 check('capture_pin:'+r['path'],sha(packed)==r['capture_sha256'] and len(b)==r['bytes'] and sha(b)==r['sha256'],r['capture'])
 check('source_stat_stable:'+r['path'],r['stat_before']==r['stat_after']==ss(ROOT/r['path']),r['path'])
 text[r['path']]=b.decode()
check('capture_budget',len(pins['files'])==8 and pins['source_content_bytes']==43671 and sum(r['bytes'] for r in pins['files'])==43671 and max(r['bytes'] for r in pins['files'])<=65536,'8 files /43671 B of122880 B; subsequent content reads only own captures')
paths={r['path']:r for r in pins['files']}
endpoint='native/music-endpoint/endpoint.c';policy='native/avdtp-policy/policy.c';ph='native/avdtp-policy/policy.h';remote='staging/native-player-loaded-single-image/build-v2/remote_pause_binding_v1.c';owned='staging/native-player-loaded-single-image/build-v2/owned_media_loaded_v1.c';fifo='staging/native-player-loaded-single-image/build-v2/sbc_fifo_loaded_v1.c';convert='native/sbc-prototype/pcm_converter.c'
def ref(path,first,last,func=None):
 d={'path':path,'lines':[first,last],'whole_sha256':paths[path]['sha256'],'fresh_saved_capture':True}
 if func:d['function']=func
 return d
def strip(t):return re.sub(r'/\*.*?\*/|//[^\n]*',lambda m:''.join('\n' if c=='\n' else ' ' for c in m.group()),t,flags=re.S)
def body(path,name):
 t=text[path];c=strip(t);m=re.search(r'\b'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{',c)
 if not m:raise ValueError('fixed_missing_function:'+name)
 i=c.index('{',m.start());j=i+1;dep=1
 while dep:
  dep+=(c[j]=='{')-(c[j]=='}');j+=1
 return t[m.start():j]
caps=re.search(r'music_endpoint_sbc_caps\[4\]\s*=\s*\{([^}]+)\}',text[endpoint]);cap=[int(x.strip(),0) for x in caps.group(1).split(',')]
check('capability_bytes',cap==[0x3f,0xff,2,53],'endpoint.c13')
codec=body(policy,'codec')
check('validator_frequency_subset',all(x in codec for x in ['single(rate)','rate&0x30u','rate==0x20u?44100u:48000u']),'policy.c25-29')
check('one_selected_format_each_field',all('single('+x+')' in codec for x in ['mode','blocks','bands','allocation']),'policy.c26-27')
check('bitpool_same_range',all(x in codec for x in ['minimum<2u','maximum>53u','minimum>maximum']),'policy.c27')
check('numeric_mode_mapping',all(x in codec for x in ['mode==8u?0u:mode==4u?1u:mode==2u?2u:3u','c->mode==0u?1u:2u']),'policy.c30-31')
check('blocks_bands_allocation_mapping',all(x in codec for x in ['bands==8u?4u:8u','blocks==0x80u?4u:blocks==0x40u?8u:blocks==0x20u?12u:16u','allocation==2u?1u:0u']),'policy.c31-33')
b=body(policy,'music_validate_configuration')
check('only_transport_and_SBC_services',all(x in b for x in ['category==1u','if(length || (seen&1u))','category==7u','length!=6u','if(p[position] || p[position+1])','MUSIC_UNSUPPORTED_SERVICE','seen!=3u']),'policy.c49-67')
check('validator_own_pointer_and_length_precondition',all(x in b for x in ['n<2u || n>128u','range(p,n,1)','range(out,sizeof(*out),4)','overlap(p,n,out,sizeof(*out))']),'policy.c42-48')
b=body(remote,'nsg_config_begin')
check('wrapper_reads_body_before_validator', 'music_validate_configuration(body,length,body[0]>>2,&staged)' in b and 'if(!body' not in strip(b) and 'length<' not in strip(b),'remote.c55-62; helper precondition, not proof caller permits NULL')
b=body(remote,'nsg_config_end')
check('accepted_requires_reply_and_native_identity',all(x in b for x in ['staged_valid && !result','config_witness==staged_command','s[0x12]==2u && !s[0x13]','s[0x10]==staged.remote_seid','==staged.codec_word','music_guard_bind','nsg.accepted=1']),'remote.c69-82')
b=body(remote,'framing')
check('RTP_and_nofragment_packet_contract',all(x in b for x in ['length<13u || length>4096u','p[0]>>6!=2u','12u+4u*(p[0]&15u)','p[0]&0x20u','p[0]&0x10u','frames=header&15u','header&0xf0u || !frames','music_guard_frame','off==end']),'remote.c105-124')
b=body(policy,'music_guard_frame')
check('each_frame_matches_selected_codec',all(x in b for x in ['(c.rate==44100u?2u:3u)<<6','c.mode<<2','p[0]!=0x9cu || p[1]!=expected','bitpool<minimum || bitpool>maximum','length>n']),'policy.c106-122')
b=body(policy,'music_guard_packet')
check('packet_matches_codec_and_local_MTU',all(x in b for x in ['v->codec_word!=g->codec_word','v->state!=8u','v->local_receive_mtu>4096u','bytes>v->local_receive_mtu']),'policy.c93-104')
b=body(convert,'pcm_converter_reset')
check('converter_broader_rate_and_channel_set',all(x in b for x in ['channels != 1 && channels != 2','rate != 16000 && rate != 32000 && rate != 44100 && rate != 48000','step = 441; phases = 160','step = 3; phases = 1']),'pcm_converter.c20-35')
b=body(convert,'pcm_converter_process')
check('converter_frame_capacity_and_stereo_average',all(x in b for x in ['sample_frames > 128','output_cap_bytes < sample_frames*2','input_channels == 2','(sample + *input++) / 2','*written_bytes = count*2']),'pcm_converter.c55-87')
b=body(owned,'owned_media_submit_frame')
check('loaded_decode_convert_and_output_format',all(x in b for x in ['garmin_sbc_decode_frame','pcm_converter_reset(result->sample_rate,result->channels)','DECODER_FORMAT_CHANGE','pcm_converter_process','result->sample_rate=16000; result->channels=1']),'owned.c52-72')
check('loaded_buffers',all(x in text[owned] for x in ['source_pcm[256], converted_pcm[128]','gather[4096]']),'owned.c22-23')
b=body(owned,'owned_media_consume')
check('owned_packet_failure_not_commit_and_resets',b.index('owned_packet_parse')<b.index('if (!result && owned_media_control.gather_bytes)')<b.index('memory_output_submit') and 'if (result) { owned_media_control.failed++; (void)reset_codec(); }' in b,'owned.c74-122; parser/decoder callees unreviewed')
b=body(fifo,'aas_media_ingress')
check('copied_ingress_is_queued_not_inline_decode',all(x in b for x in ['mcs_event_begin','media_queue_callback','mcs_event_end','SBI_POST']) and 'garmin_sbc_decode_frame' not in b,'fifo.c24-51; media_queue_callback callee unreviewed')
b=body(endpoint,'music_endpoint_capabilities')
check('signal_ids_not_confused',all(x in b for x in ['signal!=2u && signal!=4u','if(signal==4u)return stock','transaction,signal,0x11']),'endpoint.c73,91,96: 2 GetCapabilities; 4 GetConfiguration per parent correction; no claim on actual signal12 dispatch')
field_rows=[
 {'field':'sampling_frequency','advertised_mask':cap[0]&0xf0,'selected_values':[{'bit':0x20,'rate_hz':44100},{'bit':0x10,'rate_hz':48000}],'validator':'exactly one selected bit within0x30','references':[ref(endpoint,13,13),ref(policy,24,29,'codec'),ref(convert,20,35,'pcm_converter_reset')],'status':'declared and accepted subset agree;16/32k converter-only'},
 {'field':'channel_mode','advertised_mask':cap[0]&15,'selected_values':[{'bit':8,'numeric_mode':0,'channels':1},{'bit':4,'numeric_mode':1,'channels':2},{'bit':2,'numeric_mode':2,'channels':2},{'bit':1,'numeric_mode':3,'channels':2}],'standard_mode_names':['mono','dual_channel','stereo','joint_stereo'],'name_provenance':'SBC numeric mode convention; numeric selector/channel mapping is fresh C evidence','validator':'exactly one bit','references':[ref(endpoint,13,13),ref(policy,25,31,'codec'),ref(convert,20,26,'pcm_converter_reset')],'status':'four modes map to1/2channel converter inputs'},
 {'field':'block_length','advertised_mask':cap[1]&0xf0,'selected_values':[{'bit':128,'blocks':4},{'bit':64,'blocks':8},{'bit':32,'blocks':12},{'bit':16,'blocks':16}],'validator':'exactly one bit','references':[ref(endpoint,13,13),ref(policy,25,32,'codec')],'status':'all four declared and accepted'},
 {'field':'subbands','advertised_mask':cap[1]&12,'selected_values':[{'bit':8,'subbands':4},{'bit':4,'subbands':8}],'validator':'exactly one bit','references':[ref(endpoint,13,13),ref(policy,25,31,'codec')],'status':'both declared and accepted'},
 {'field':'allocation_method','advertised_mask':cap[1]&3,'selected_values':[{'bit':2,'numeric_allocation':1},{'bit':1,'numeric_allocation':0}],'standard_names':{'1':'SNR','0':'loudness'},'validator':'exactly one bit','references':[ref(endpoint,13,13),ref(policy,25,33,'codec')],'status':'both declared and accepted'},
 {'field':'bitpool','advertised_min':cap[2],'advertised_max':cap[3],'validator':'2<=minimum<=maximum<=53; per-frame bitpool within configured range','references':[ref(endpoint,13,13),ref(policy,24,28,'codec'),ref(policy,113,122,'music_guard_frame')],'status':'same2..53 range; variable frame bitpool within configured min/max accepted'},
 {'field':'services','validator':'one empty MediaTransport(category1) plus one6-byte audio/SBC(category7), no other category','references':[ref(policy,49,67,'music_validate_configuration'),ref(endpoint,92,97,'music_endpoint_capabilities')],'status':'category6 unsupported; custom GetCapabilities flag0x11 excludes HeaderCompression per source comment; actual signal12 route unknown'},
 {'field':'packet_and_frames','validator':'RTPv2; CSRC/extension/padding bounded; no SBC fragment bits;1..15 frames; exact consumed payload and selected rate/mode/blocks/subbands/allocation; max4096andlocalreceiveMTU','references':[ref(remote,105,124,'framing'),ref(policy,93,104,'music_guard_packet'),ref(policy,106,122,'music_guard_frame')],'status':'outer selected-codec parser agrees with format declaration; CRC/inner parser delegated'},
 {'field':'decoded_PCM_and_output','validator':'decoded result rate/channels fixed within stream; converter supports16/32/44.1/48k mono/stereo and producesmono16kS16','references':[ref(owned,22,23),ref(owned,52,72,'owned_media_submit_frame'),ref(convert,20,35,'pcm_converter_reset'),ref(convert,55,87,'pcm_converter_process')],'status':'advertised44.1/48k mono/stereo subset fits converter; decoder body/table coefficients not fresh-reviewed'}
]
# Pure arithmetic using observed maxima; this is no C invocation, fixture or runtime test.
fmt_count=2*4*4*2*2;max_samples=16*8;max_packet_PCM=15*max_samples*2
check('conservative_buffer_arithmetic',max_samples==128 and max_samples*2==256 and max_samples*2*2==512 and max_packet_PCM==3840 and max_packet_PCM<=4096,'observed block/subband/frame maxima and C arrays, scalar analysis only')
checks_obj={'schema':'garmin-SBC-FILE-contract-checks/v1','count':len(checks),'checks':checks,'not_native_or_C_tests':True,'target_executed':False}
write('file-checks.json',checks_obj)
ledger={'schema':'garmin-native-SBC-capability-contract-file-review/v1','all_assigned_checks_passed':True,'STOP':True,'field_rows':field_rows,'numeric_summary':{'codec_format_shapes':fmt_count,'max_samples_per_channel_per_SBC_frame':max_samples,'source_buffer_bytes':512,'converted_buffer_bytes':256,'conservative_15_frame_output_bound_bytes':max_packet_PCM,'gather_capacity_bytes':4096,'arithmetic_only':True,'no_PCM_or_native_execution':True},'selected_artifacts':{'custom_endpoint':{'source':'native/music-endpoint/endpoint.c','whole_sha256':paths[endpoint]['sha256'],'custom_provider_not_recovered_original_API':True,'same_loaded_image_binding_fresh_verified':False},'loaded_v2_generated_sources':[{k:r[k] for k in ['path','bytes','sha256']} for r in pins['files'] if '/build-v2/' in r['path']],'inherited_root_build_metadata':{'path':'staging/native-player-loaded-single-image/build-v2.json','whole_sha256':'ee7d464e806cfc2d2f506989ffc7b2d7b30c6ce5e2d5f068b95f303cc6b76f75','bytes':75903,'fresh_read_by_this_scope':False,'root_reused_closed_comparison_status':{'remote_cb446d':'declared matched in v2/v3','fifo_d3a298':'declared matched in v2/v3','owned_58a665':'not directly declared in comparison; no absence inference','policy_converter':'not in comparison selected rows; unknown'}}},'findings':[{'kind':'consistent_subset','detail':'All SBC masks and selected format/range fields in custom capbytes match fresh policy validator; broader converter16/32k input support is intentionally not advertised.'},{'kind':'packet_limit','detail':'Only complete nonfragmented1..15frame packets pass outer parser. RTP sequence/timestamp continuity, payload-type/SSRC continuity, reorder/jitter/retransmit behavior are not implemented in this framing body.'},{'kind':'delegated_contract','detail':'CRC and owned_packet_parse/media_queue_callback bodies are outside eight selected files; full inner-parser equivalence and decoder support are inherited/provisional, not fresh proven.'},{'kind':'helper_precondition','detail':'nsg_config_begin readsbody[0] before validator; selected capture does not contain its caller. Need caller nonNULL/readable first byte before entry; not proof current original caller allows invalid input.'},{'kind':'capability_dispatch_gap','detail':'Helper allows signals2/4 only;4 is GetConfiguration, delegatedstock. Signal12 GetAllCapabilities dispatcher/body is not captured. No global capability-response inconsistency or support claim inferred.'}], 'pixel_negotiation_conditions':{'conditional_only_not_phone_test':True,'required_selected_configuration':'44.1or48k; one mode/block/subband/allocation selector;2<=min<=max<=53; only MediaTransport and audio/SBC services','required_media':'all packet frames match accepted codec_word; nonfragmentedRTP; payload<=localreceiveMTU<=4096;1..15frames','native_acceptance_more_than_validator0':'matching accepted reply command/witness and fullresult0, actual SEPstate2/context/remoteSEID/callback/codec, later Startreply/state8 admission, Source resident guard/queue ownership','unknown':['actual Pixel offered/selected codec and bitpool','real advertised GetAllCapabilities response','original SEP/profile/callback installation','same-image endpoint capability provider link','native serialized session ownership/scheduling/backpressure','phone reconnect/live performance/speaker']}, 'historical_scope':{'BT_matrix_sha256':'bdd5f0fb13096680bab4a7712f4fa22f2bcdc29564d5afdec5184cb49365c7a1','read_by_this_scope':False,'early_discover_empty_SEP_not_direct_A2DP_completion':True,'later_offline_decode_converter_results_not_rerun':True},'errata':[{'type':'incorrect_progress_message_protocol_name','original_claim':'signal4 GetAllCapabilities','correction':'signal4 GetConfiguration; GetAllCapabilities signal12(0x0C). This final analysis does not treat stocksignal4 delegation as GetAllCapabilities mismatch.','source':'parent correction before seal; own source exact4 literal retained','original_TOOL_case_failure':False}], 'limits':{'fresh_source_files':8,'fresh_source_bytes':43671,'budget':122880,'single_max':12303,'extra_build_JSON_content_reads':0,'filename_index_IO':'metadata/name only, not byte-instrumented','target_imports':0,'compile_tests_guest_emulator':0,'ASM_MAIN_ELF_liveRAM':0,'device_BT_DBUS_audio_private_phone_config':0,'shared_source_report_edits':0,'system_risk_guest_retry':0,'runtime_or_hardware_acceptance':False}}
write('capability-contract-ledger.json',ledger)
proof={'schema':'garmin-native-SBC-capability-contract-file-proof/v1','all_assigned_checks_passed':True,'STOP':True,'checks_passed':len(checks),'fresh_source_files':8,'fresh_source_bytes':43671,'single_max':12303,'source_budget':122880,'ledger':{'path':str((P/'capability-contract-ledger.json').relative_to(ROOT)),'bytes':(P/'capability-contract-ledger.json').stat().st_size,'sha256':sha((P/'capability-contract-ledger.json').read_bytes())},'reviewer':{'path':str((P/'review_saved_captures.py').relative_to(ROOT)),'bytes':(P/'review_saved_captures.py').stat().st_size,'sha256':sha((P/'review_saved_captures.py').read_bytes())},'scope':'Saved C/H text and numeric analysis only; no native/producer imports, execution or tests. Eight input pin before/after/finalstats equal. Component metadata inherited, no binary/content acceptance verified.','result':'Declared mask/validator fields agree, converter supports advertised subset; frame limits and helper/callee/dispatch binding gaps explicit.','erratum_preserved':'Earlier signal4 naming corrected before final ledger; no renderer/phone success inference.','new_source_content_reads_after_capture':0,'source_handles_closed':True,'owned_running_sessions':0,'runtime_hardware_or_phone_acceptance':False,'target_import_compile_test_guest':0,'device_BT_DBUS_audio':0,'system_risk_guest_retries':0}
write('proof.json',proof)
print(json.dumps({'checks':len(checks),'rows':len(field_rows),'source_files':8,'source_bytes':43671,'ledger_sha256':proof['ledger']['sha256'],'proof_sha256':sha((P/'proof.json').read_bytes()),'STOP':True}))
