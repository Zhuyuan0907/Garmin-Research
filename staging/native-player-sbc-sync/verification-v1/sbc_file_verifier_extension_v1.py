# NEW SBC-specific file-only extension appended to frozen verifier logic.
import gc

def prepare_sbc_checkpoints(rp,d,symbols):
    for e in d['compiled_producer_entries']:
        rp.enqueue('compiled producer '+e['symbol'],e['entry'],e['leases']);rp.checkpoints.add(e['entry']['ordinal'])
    for e in d['compiled_decoder_full_returns']:
        rp.enqueue('actual decoder full return',e['returned'],e['return_leases']);rp.checkpoints.add(e['returned']['ordinal'])
    # Capture after each actual ticket FIFO commit to compare copied payload.
    committed=symbols['owned_media_control']['value']+32
    for e in d['CPU_store_journal']:
        if int(e['address'],16)==committed:rp.checkpoints.add(e['ordinal'])

def producer_at(z,symbols):
    return dict(owned=list(struct.unpack('<13I',get(z,symbols['owned_media_control']['value'],52))),
        queue=list(struct.unpack('<9I',get(z,symbols['media_queue_control']['value'],36))),
        packet_index=word(z,symbols['mp_packet_index']['value']),
        last_decode_error=struct.unpack('<i',get(z,symbols['mp_last_decode_error']['value'],4))[0])

def verify_sbc_pipeline(d,rp,symbols,reference):
    entries=d['compiled_producer_entries'];codec=d['compressed_decoder_entries'];returns=d['compiled_decoder_full_returns']
    require(len(codec)==len(returns),'Every actual decoder entry has full native compiled return')
    declared={bytes.fromhex(p['packet_hex']):p for p in reference['packets']}
    bad=bytes.fromhex(reference['bad_later_frame_CRC_packet_hex'])
    frames=0;failed_frames=0
    for e in entries:
        st=e['entry'];z=rp.snapshots[st['ordinal']];check_actor(st,S)
        require(st['GP16'][15]==symbols[e['symbol']]['value'] and st['CPSR']&0xff==0x1f,'Exact compiled ARM normal Source function entry')
        require(e['args']==st['GP16'][:4] and producer_at(z,symbols)==e['producer'],'Actual producer control and argument readback')
        if e['symbol'] in ('owned_packet_parse','garmin_sbc_decode_frame','pcm_converter_process','memory_output_submit'):
            require(e['leases']['borrow']==0 and e['leases']['media']==e['leases']['callback']==1,'Typed Source producer whole callback/media leases')
            require(word(z,RECORD+0x160)==symbols['mcs_queue_bridge']['value'],'Actual profile callback coherent before decode/submit')
        if e['symbol']=='media_queue_callback':
            gp=st['GP16'];size=word(z,gp[13]);raw=get(z,gp[3],size)
            require(gp[:3]==[0xf1,0,0] and raw.hex()==e['packet_hex'] and size==e['packet_bytes'],'Exact callback r0..r3/stack length actual RAM bytes')
            require(raw in declared or raw==bad,'Declared compiled compressed input')
            rawelf,sec=rp.elf.at(gp[3],size);require(sec['flags']&4 and rawelf==raw,'Actual input came from compiled RX fixture bytes; no HOST PCM seed')
    for e,r in zip(codec,returns):
        require(all(r[k]==v for k,v in e.items()),'Decoder matched original entry metadata')
        check_actor(r['returned'],S);es=e['entry'];rs=r['returned'];ez=rp.snapshots[es['ordinal']];rz=rp.snapshots[rs['ordinal']]
        require(es['ordinal']<rs['ordinal'] and rs['GP16'][15]==e['return_PC']==(es['GP16'][14]&~1),'Actual decoder complete entry/return PC order')
        require(es['GP16'][13]==e['entry_SP']==rs['GP16'][13] and es['GP16'][4:12]==rs['GP16'][4:12],'Decoder full SP/callee saved GP preservation')
        require((es['CPSR']&0xff)==(rs['CPSR']&0xff)==0x1f and r['r0']==rs['GP16'][0],'Decoder return ISA/mode/IRQ and R0 snapshot')
        require(e['args'][3]==512 and e['result_pointer']==word(ez,es['GP16'][13]),'Decoder fifth ABI result pointer, source PCM capacity')
        require(get(ez,e['args'][0],e['args'][1]).hex()==e['frame_hex'],'Actual copied frame input bytes')
        result=list(struct.unpack('<9I',get(rz,e['result_pointer'],36)));require(result==r['decoder_result'],'Actual decoder result memory readback')
        for view in (e['leases'],r['return_leases']):require(view['media']==view['callback']==1 and view['borrow']==0,'Decoder lease retained through full return')
        if r['r0']==0:
            require(result[:5]==[e['args'][1],128*reference['channels']*2,reference['rate'],reference['channels'],128],'Decoder actual consumed/written/rate/channels/samples ABI')
            frames+=1
        else:require(r['r0']==0xfffffffa,'Only declared actual later-frame CRC error');failed_frames+=1
    parses=[e for e in entries if e['symbol']=='owned_packet_parse'];submits=[e for e in entries if e['symbol']=='memory_output_submit'];success=[];reset=False;crc_checks=[]
    for j,p in enumerate(parses):
        lo=p['entry']['ordinal'];hi=parses[j+1]['entry']['ordinal'] if j+1<len(parses) else max(e['ordinal'] for e in d['CPU_store_journal'])+1
        z=rp.snapshots[lo];gp=p['entry']['GP16'];raw=get(z,gp[3],word(z,gp[13]));cs=[r for r in returns if lo<r['entry']['ordinal']<hi];ss=[e for e in submits if lo<e['entry']['ordinal']<hi]
        require(raw in declared or raw==bad,'Actual queue copied whole original compressed input')
        require(0x07902000<=gp[3] and gp[3]+len(raw)<=0x07906000,'Parser consumes resident compressed queue payload')
        if raw==bad:
            require([r['r0'] for r in cs]==[0,0xfffffffa] and not ss,'Second frame CRC failure does not enter PCM submit')
            require(j+1<len(parses),'Declared CRC recovery parser snapshot exists')
            nz=rp.snapshots[hi]
            for i in range(4):require(get(z,0x07700000+i*4096,4096)==get(nz,0x07700000+i*4096,4096),'Bad packet does not change any PCM FIFO payload')
            require(get(z,symbols['memory_output_slots']['value'],96)==get(nz,symbols['memory_output_slots']['value'],96),'Bad packet does not mutate PCM slot generations/state/lease')
            a,b=producer_at(z,symbols),producer_at(nz,symbols)
            require([a['owned'][k] for k in (2,3,4,8,11,12)]==[b['owned'][k] for k in (2,3,4,8,11,12)] and a['packet_index']==b['packet_index'],'Bad packet leaves FIFO indices/count/committed/released/lastticket/input index unchanged')
            require(word(z,symbols['memory_output_control']['value']+8)==word(nz,symbols['memory_output_control']['value']+8),'Bad packet allocates no FIFO generation')
            crc_checks.append(dict(parser_entry_ordinal=lo,next_recovery_parser_ordinal=hi,decoder_returns=[0,-6],PCM_FIFO_4096x4_unchanged=True,PCM_slot96_unchanged=True,no_submit=True));reset=True
        else:
            require([r['r0'] for r in cs]==[0,0] and len(ss)==1,'Two decoded frames precede one whole-packet submit')
            expected=bytes.fromhex(declared[raw]['expected_after_reset_PCM_hex' if reset else 'expected_continuous_PCM_hex']);reset=False
            se=ss[0];sz=rp.snapshots[se['entry']['ordinal']];require(se['args'][0]==0x07900000 and se['args'][1]==len(expected),'Whole private gather exact pointer/length')
            require(get(sz,0x07900000,len(expected))==expected,'Actual CPU-written gather matches frozen HOST comparison only')
            commits=[e for e in d['CPU_store_journal'] if lo<e['ordinal']<hi and int(e['address'],16)==symbols['owned_media_control']['value']+32]
            require(len(commits)==1 and commits[0]['value']==len(success)+1 and commits[0]['current_TCB']==S,'Exactly one Source CPU FIFO commit after packet success')
            cz=rp.snapshots[commits[0]['ordinal']];owned=producer_at(cz,symbols)['owned'];ticket=word(cz,symbols['memory_output_slots']['value']+(len(success)%4)*24)
            # The sole FIFO consumer frees slot0 before each next submission in
            # this bounded runner; retain current generation independent of it.
            ready=[(i,struct.unpack('<6I',get(cz,symbols['memory_output_slots']['value']+i*24,24))) for i in range(4)]
            ready=[(i,v) for i,v in ready if v[1]==2 and v[0] and v[2]==len(expected)]
            require(len(ready)==1,'One privately READY whole-packet slot at actual commit');i,v=ready[0];ticket=v[0]
            require(ticket==4*(len(success)+1)+i and get(cz,0x07700000+i*4096,len(expected))==expected,'Actual copied PCM page complete before private FIFO publication')
            require(v[5]==0 and owned[4]==1,'No in-flight consumer at producer commit, one FIFO packet')
            success.append(dict(parser_entry_ordinal=lo,submit_entry_ordinal=se['entry']['ordinal'],commit_ordinal=commits[0]['ordinal'],ticket=ticket,PCM_bytes=len(expected),PCM_sha256=hashlib.sha256(expected).hexdigest()))
    z=rp.final;terminal=producer_at(z,symbols);require(terminal==d['producer_terminal'],'Actual final producer fields')
    require(terminal['owned'][8]==len(success) and terminal['owned'][9]==len(crc_checks) and terminal['packet_index']==len(success),'Actual whole-packet success/error counters')
    require(terminal['owned'][1]==terminal['owned'][4]==terminal['queue'][2]==terminal['queue'][5]==terminal['queue'][6]==0,'All actual queue producer/consumer/FIFO work returned, no unfinished decoder')
    require(len(submits)==len(success) and len(codec)==2*len(parses),'Exact parser/decoder/commit call cardinalities')
    stop='Stop' in d['name'];profile='profile' in d['name']
    if stop or profile:
        denied=[e for e in entries if e['entry']['phase']=='request compressed-source command 8'];require(denied,'Actual new compressed input rejection observed')
        require(not any(e['symbol'] in ('owned_packet_parse','garmin_sbc_decode_frame','pcm_converter_process','memory_output_submit') for e in denied),'Rejected input never enters decode/FIR/PCM commit')
        if stop:require([e['symbol'] for e in denied]==['media_queue_callback'] and terminal['last_decode_error']==-22 and terminal['queue'][4]==0,'Stop denies even queue step after callback admission')
        else:require(terminal['last_decode_error']==-201 and word(z,RECORD+0x160)==0x277c6b and any(e['symbol']=='owned_media_consume' for e in denied),'Original profile callback mismatch rejects before decode')
    # Compiled producer metadata and payload are CPU-only after baseline:
    # Replay denied all host fixtures touching any allocated writable ELF section.
    require(not d['phone_AVDTP_or_live_packet_receiver_verified'] and d['expected_PCM_was_never_written_to_guest'],'Declared offline-only input limits')
    return dict(actual_decoder_full_returns=len(returns),actual_successful_decoder_returns=frames,actual_failed_decoder_returns=failed_frames,
        whole_packet_successful_commits=len(success),whole_packet_commit_rows=success,second_frame_CRC_independent_checks=crc_checks,
        Source_typed_producer_lease_full_decoder_returns_verified=True,actual_compressed_copy_gather_FIFO_and_native_PCM_bytes_verified=True,
        actual_Stop_before_decode_rejection=stop,actual_original_profile_callback_before_decode_rejection=profile,
        compressed_input_is_compiled_fixture_not_phone=True,HOST_expected_PCM_only_compared=True)

def main():
    output=Path(__file__).resolve().parent/'sbc-sync-v1-independent-file-verification.json'
    require(not output.exists(),'NEW output already exists');proofp=BASE/'sbc-sync-v1-proof.json';proof=load(proofp)
    require(sha(proofp)=='a4e7d6400f5ad67277b537ff9407b8ac8c1e3524aa33bbb6e0edd026002f8ad0' and proof['all_passed'],'Exact actual ROOT SBC proof')
    sources=dict(proof['source_sha256'])
    for path,digest in sources.items():require(sha(ROOT/path)==digest,'Frozen ROOT input '+path)
    require(load(BASE/'guest-v1/inputs-at-run.json')==sources,'Exact actual run registry')
    receiptp=BASE/'guest-v1-terminal-tool-receipt.json';receipt=load(receiptp)
    require(receipt['terminal'] and receipt['started_session_id']==35422 and receipt['actual_terminal_result']['exit_code']==0 and receipt['actual_terminal_result']['chunk_id']=='27fd35','Actual authoritative ROOT terminal')
    require(sha(BASE/'emulate_sbc_sync_v1.py')=='ac6be80e5c5a43b0abaa047bfabc4945646d1a3350d0bfdfc578aecc8b0c43cb' and sha(BASE/'guest-v1/runner-at-run.py')==sha(BASE/'emulate_sbc_sync_v1.py'),'Frozen actual runner snapshot')
    build,elf,symbols=verify_build(BASE/'build-v3.json',sources)
    require(build['ELF_sha256']=='c170e77c216abb44e6a6570034768ce00deb3226b20d1bd0349b70d1e564a4eb','Exact SBC ELF')
    n=NativeImage();require(hashlib.sha256(n.data).hexdigest()==EXPECTED,'Exact MAIN1352/8.00')
    rows=[]
    for item in proof['cases']:
        p=ROOT/item['path'];h=sha(p);require(h==item['sha256'],'Actual sealed ROOT case digest')
        d=load(p);require(d['name']==item['name'] and d['passed'],'Actual case identity')
        row=verify_case(d,n,elf,symbols);row['case_sha256']=h;row['actual_original_and_ELF_instruction_visits']=d['instructions'];rows.append(row);sources[rel(p)]=h
        print(json.dumps(dict(case=row['name'],CPU_stores=row['CPU_stores'],joint_events=row['joint_events'],decoder_full_returns=row['actual_decoder_full_returns'],native_full_returns=row['full_original_returns'],FILE_only=True)),flush=True)
        del d;gc.collect()
    expected=dict(CPU_stores=412189,joint_events=412491,tracked_whole_zones=156,actual_RW_zones_from_frozen_parent_permission_recipe=150,unchanged_RX_return_sentinel_tracked_as_RW=6,actual_final_RX_dump_zones=18,actual_decoder_full_returns=34,actual_successful_decoder_returns=33,actual_failed_decoder_returns=1,full_original_returns=128,full_original_sync_returns=7,actual_original_condition_waits=7,actual_original_ACK8=7,music_bytes=4206,underrun_silence_bytes=24466,total_output_bytes=28672,actual_original_and_ELF_instruction_visits=4671894)
    require(len(rows)==proof['case_count']==6,'Six bounded complete cases')
    for key,value in expected.items():require(sum(r[key] for r in rows)==value,'Exact independently replayed aggregate '+key)
    staticp=BASE/'static-review/sbc-pipeline-build-v3-peer-review.json';staticseal=BASE/'static-review/sbc-pipeline-build-v3-static-seal.json';seal=load(staticseal)
    require(sha(staticp)=='7705c4dfef585c508452cbce09a9a7c9099489823366881d5a61754e479e1700' and sha(staticseal)=='b12eef499499449ed3018205364f25326d9fe06505323868d3f333bc16dcfc5a','Frozen static contract')
    for path,h in {**seal['source_sha256'],**seal['output_sha256']}.items():require(sha(ROOT/path)==h,'Frozen static dependency');sources[path]=h
    # Hash only completed namespace files, excluding this new live verifier dir.
    for p in sorted(BASE.rglob('*')):
        if p.is_file() and 'verification-v1' not in p.parts and '__pycache__' not in p.parts:sources[rel(p)]=sha(p)
    for p in (Path(__file__).resolve(),ROOT/'staging/native-player-mixer-sync/verification-v3/verify_mixer_sync_v3_files_v6.py',Path(__file__).resolve().parent/'sbc_file_verifier_extension_v1.py',Path(__file__).resolve().parent/'prepare_sbc_file_verifier_v1.py',Path(__file__).resolve().parent/'source-copy-provenance-v1.json',ROOT/'scripts/analyze_native_sections.py'):sources[rel(p)]=sha(p)
    require(not any(k=='unicorn' or k.startswith('unicorn.') for k in sys.modules),'VM imported')
    for path,h in sources.items():require(sha(ROOT/path)==h,'Final exact source readback '+path)
    result=dict(all_passed=True,independent_FILE_ONLY=True,source_sha256=sources,case_count=6,cases=rows,actual_ROOT_terminal_session=35422,actual_ROOT_terminal_chunk='27fd35',actual_ROOT_guest_exit_code=0,totals=expected,
        exact_original_MAIN_and_ELF_store_opcode_ISA_GP16_CPSR_address_value_preimage_verified=True,complete_multiword_store_groups_verified=True,joint_CPU_fixture_history_and_actual_whole_after_verified=True,
        actual_compressed_SBC_and_FIR_private_gather_whole_packet_FIFO_to_original_mixer_verified=True,actual_second_frame_CRC_no_PCM_prefix_verified=True,actual_first0_second_minus6_full_decoder_returns_and_reset_recovery_verified=True,
        Source_typed_media_callback_leases_and_actual_native_fullreturn_leases_verified=True,original_raw_mutex_condition_ACK8_preemption_contention_priority_donation_unlocktransfer_fullreturn_verified=True,
        actual_after_declared_patches_RX_baseline_and_final_RX_dumps_verified=True,final_controller_idle_GP16_CPSR_SP_and_full_native_outer_sync_registers_serialized=True,complete_all_instruction_controlflow_or_kernel_lifetime_proof=False,
        actual_phone_AVDTP_receiver_or_installed_App_or_hardware_speaker_verified=False,native_heap_exclusive_STOP_DONE_or_safe_unload_verified=False,
        device_io=False,canonical_write=False,VM_import_or_instantiation=False,guest_rerun=False,
        limits=['412189 captured CPU stores independently decode exact original MAIN/compiled ELF and GP16/CPSR effective address/value; whole150 trueRW case-zones plus6 unchanged RX return sentinels and18 actual finalRX dumps replay. This is not an independent trace of all4671894 nonstore/controlflow instructions.',
        'Compressed input is18 compiled offline packets; first fixture packet is decoded synchronously in Source bootstrap to create registration ticket before original native mixer initialization. Real phone bootstrap must first initialize typed guard/profile/queue, wait for external copied first packet, decode it on Source, then create native anchor/mixer/sync. POST alone does not make actual receiver integration.',
        'Current mh_source_entry ignores WAIT bits and serves mh_command. Future copy-only original AVDTP ingress must acquire typed callback/media input lifetime, POST actual Source event after queue publication, drain queued packets on Source, and wire freed FIFO capacity to Source retry. UMC_SOURCE_EVENT=0x80000 differs from current command bit1. Current separate media_worker_state.tcb is not constructed.',
        'Second CRC packet changes private gather and speculative parser counters; all four PCM page payloads/96-byte slot state and publication counters remain unchanged, and actual decoder fullreturns are0/-6. Recovery is compared with frozen after-reset SBC/FIR HOST reference, not continued stream history.',
        'Stop closes future queue/decode/commit but does not claim native15/19 cleanup/list removal, hardware flush, nativeSTOP_DONE, anchor retirement, exclusive channel ownership or safe storage unload. Profile transition is actual original277D26 rewrite and denied before decoder; input copy may already have occurred.',
        'Original kernel/context/mutex/condition/FIFO/selector/reader/fullpull bodies execute under four explicit guest BL redirects. Direct Timer/rawmutex/condition constructors are declared boot callers, controller/idle ready input is supplied, and no full physical cold boot is claimed.',
        'Opaque handles/allocation/query/release, mixer stack/FIFO backing, bounded16KiB codec arena/free no-op, task bookkeeping/audio policy, output activation/raw output mode, explicit output consumer read-index advance, reset transport and compiled synthetic message17 completion remain fixtures. HOST expected PCM is only compared and never seeds guest PCM.',
        'No actual SEP registration, live Pixel packet reception, physical speaker/DMA/MMU backing/native general allocator, App/UI or VPM/SIG install acceptance is verified.'])
    create(output,result);print(json.dumps(dict(all_passed=True,proof=rel(output),proof_sha256=sha(output),CPU_stores=expected['CPU_stores'],joint_events=expected['joint_events'],decoder_full_returns=34,full_original_returns=128,guest_execution=False)),flush=True)
if __name__=='__main__':main()
