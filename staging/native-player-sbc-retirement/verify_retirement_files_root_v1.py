#!/usr/bin/env python3
"""ROOT FILE reconstruction of frozen Stop scopes. No VM or guest rerun.
The exact store/whole-memory algorithm derives from sealed prior FILE work;
this is not a new independent agent review or hardware quiescence proof.
"""
import ast,gc,hashlib,importlib.util,json,struct,sys
from pathlib import Path
from datetime import datetime,timezone
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
BASE=Path(__file__).resolve().parent
OLD=ROOT/'staging/native-player-sbc-ingress/root-file-review-v2/generated-file-engine-v2.py'
OUT=BASE/'root-file-review-v1'
HEAD=0x034e68d8+8*4
def sha(p):
    h=hashlib.sha256()
    with p.open('rb')as f:
        for block in iter(lambda:f.read(8<<20),b''):h.update(block)
    return h.hexdigest()
def create(p,d):
    with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def require(v,m):
    if not v:raise AssertionError(m)
def source_engine():
    text=OLD.read_text()
    text=text.replace("BASE = ROOT / 'staging/native-player-sbc-ingress'","BASE = ROOT / 'staging/native-player-sbc-retirement'")
    text=text.replace('Independent FILE ONLY review of frozen root mixer synchronization V3.',
        'ROOT FILE-only derivative for frozen resident Stop scopes; new independent agent review not claimed.')
    before="""            view=rp.leases(z);require(e['current_TCB']==M and word(z,slots+i*24+20)==0 and view['borrow'] and view['media']==view['callback']==1,'Mixer frees FIFO only after copy in_flight returns0 under full native lease');rp.copy_counts['FIFO_free_after_inflight_zero']+=1"""
    after="""            view=rp.leases(z)
            if e['current_TCB']==M:
                require(word(z,slots+i*24+20)==0 and view['borrow'] and view['media']==view['callback']==1,'Mixer frees FIFO after full copied frame');rp.copy_counts['FIFO_free_after_inflight_zero']+=1
            else:
                f=sy['continuous_media_cancel_ready'];o=sy['memory_output_control']['value']
                require(e['current_TCB']==S and f['value']<=pc<f['value']+f['size'],'Only actual compiled Source cancellation frees retired private FIFO')
                require(word(z,slots+i*24+20)==0 and not view['borrow'] and view['media']==view['callback']==0,'Canceled private slot has no live copy/frame')
                require(word(z,sy['ns_stage']['value'])==3 and word(z,sy['ns_barrier_returns']['value'])==word(z,sy['ns_remove_returns']['value'])==word(z,sy['ns_anchor_returns']['value'])==1,'Private FIFO cancel only after full original barrier/list removal and anchor return')
                require(word(z,o+12)==word(z,o+16)==word(z,o+20)==word(z,o+24)==0 and word(z,rp.guard+48)==1,'Released anchor and Source mutation hold during discard')
                require(word(z,0x034e68f8)==0 and struct.unpack('<H',get(z,RECORD+0x1c0,2))[0]==0 and get(z,RECORD+2,1)==bytes(1) and get(z,RECORD+0xf4,68)==bytes(68),'Native node/provider methods removed before private discard')
                rp.copy_counts['Source_FIFO_discard_after_full_retirement']+=1"""
    require(text.count(before)==1,'Exact inherited FIFO-free guard source');text=text.replace(before,after)
    ast.parse(text);p=OUT/'generated-retirement-file-engine-v1.py'
    with p.open('x')as f:f.write(text)
    spec=importlib.util.spec_from_file_location('retirement_file_engine',p);e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
    return e
def native(e,rp,z,sy):
    g=sy['aas_guard']['value'];o=sy['memory_output_control']['value'];idx=e.word(z,sy['ns_instance']['value'])
    return dict(head=e.word(z,HEAD),node_count=struct.unpack('<H',e.get(z,e.RECORD+0x1c0,2))[0],
        prepared=e.get(z,e.RECORD+2,1)[0],methods_hex=e.get(z,e.RECORD+0xf4,68).hex(),selected_index=e.word(z,e.RECORD+0xf0),
        mixer_active=e.get(z,e.MIXER+0x84,1)[0],provider=list(e.get(z,e.POOL+idx*576,32))if idx<5 else None,
        ns_stage=e.word(z,sy['ns_stage']['value']),ns_hold=e.word(z,sy['ns_hold']['value']),native_mutation=e.word(z,g+48),guard_held=e.word(z,g+16),
        native_calls=e.word(z,o+20),active_ticket=e.word(z,o+12),installed=e.word(z,o+16),leases=rp.leases(z))
def add(rp,label,st,view=None):
    rp.enqueue(label,st,view);rp.checkpoints.add(st['ordinal'])
def verify_case(e,d,n,elf,sy,reference):
    rp=e.Replay(d,n,elf,sy);rp.cold()
    for key,field in [('original_scheduled_actor_entries','state'),('original_kernel_events','state'),('actual_condition_entries','state'),
        ('original_mixer_ACK8_entries','state'),('original_message_sends','state'),('original_message_receives','state')]:
        for row in d[key]:add(rp,key,row[field])
    for row in d['terminal_register_snapshots']:add(rp,'actual controller/idle endpoint',row)
    for row in d['declared_service_calls']:add(rp,'opaque before',row['before']);add(rp,'opaque after',row['after'])
    for key in ('full_native_returns','original_mixer_call_site_returns'):
        for row in d[key]:add(rp,key+' entry',row['entry'],row.get('entry_leases'));add(rp,key+' returned',row['returned'],row['return_leases'])
    for key in ('original_sync_entries','compiled_ingress_entries','compiled_decoder_entries','producer_entries','native_stop_entries','compiled_retirement_entries'):
        for row in d[key]:add(rp,key,row['entry'],row.get('leases'))
    for key in ('full_original_sync_returns','compiled_ingress_full_returns','compiled_decoder_full_returns','full_native_stop_returns','full_compiled_retirement_returns'):
        for row in d[key]:add(rp,key,row['returned'],row.get('leases'))
    for row in d['notice23_before_count_commit']+d['opaque_list_release_calls']:add(rp,'pre-retirement notice/opaque release',row['state'])
    for row in d['actual_retirement_stores']:add(rp,'native retirement writer before',row['state'])
    for row in d['source_event_posts']:add(rp,'Source POST',row['state'],row['leases'])
    for row in d['CPU_store_journal']:
        if int(row['address'],16)==sy['owned_media_control']['value']+32:rp.checkpoints.add(row['ordinal'])
    counts=rp.run();z=rp.final
    # Byte provenance covers every original/ELF store and copied publication;
    # actual frame and metadata checks below are separate from opcode decoding.
    for key in ('native_stop_entries','compiled_retirement_entries'):
        for row in d[key]:require(native(e,rp,rp.snapshots[row['entry']['ordinal']],sy)==row['native'],'Actual retirement entry memory')
    for key in ('full_native_stop_returns','full_compiled_retirement_returns'):
        for row in d[key]:
            rz=rp.snapshots[row['returned']['ordinal']];require(native(e,rp,rz,sy)==row['native'],'Actual complete retirement return memory')
            gp=row['entry']['GP16'];rg=row['returned']['GP16']
            require(gp[13]==rg[13] and gp[4:12]==rg[4:12] and rg[15]==row['return_PC'] and rg[0]==row['r0'],'Complete retirement SP/callee-saved/PC/R0')
            require(row['actor']==row['returned']['current_TCB']==row['entry']['current_TCB'],'Retirement actor fullreturn')
    original=d['full_native_stop_returns']
    for row in original:
        entry=row['entry_PC'];expected=e.S if entry==0x277674 else e.M
        e.check_actor(row['entry'],expected);e.check_actor(row['returned'],expected)
        require(row['native']['ns_stage']==3 and row['native']['ns_hold']==row['native']['native_mutation']==row['native']['native_calls']==1,
            'Cleanup hold retained through every whole original helper')
        if entry in (0x48ee12,0x48ee58):require(row['args'][0]==d['retirement_status'][4],'Actual selected instance0 is a valid provider')
        if entry==0x5e75b2:require(row['args'][0]==e.POOL+d['retirement_status'][4]*576+16,'Actual backend close object')
        if entry!=0x48ee58:require(row['r0']==0,'Original typed Stop helper success')
        # 48EE58 is void; its unchanged R0 is NOT a zero-success status.
    for row in d['actual_retirement_stores']:
        ez=rp.snapshots[row['state']['ordinal']]
        require(native(e,rp,ez,sy)==row['native_before'],'Exact pre-store held metadata')
        record=next(x for x in d['CPU_store_journal']if x['ordinal']==row['journal_ordinal'])
        require(int(record['PC'],16)==row['PC']and int(record['address'],16)==row['address']and record['value']==row['value'],'Original retirement writer exact journal identity')
    sync=d['original_sync_entries'];returns=d['full_original_sync_returns'];acks=d['original_mixer_ACK8_entries']
    require(len(sync)==len(returns)==len(acks),'Actual full sync/ACK cardinality')
    stops=[]
    for entry,ret,ack in zip(sync,returns,acks):
        e.check_actor(entry['entry'],e.S);e.check_actor(ret['returned'],e.S);e.check_actor(ack['state'],e.M)
        require(entry['entry']['ordinal']<ack['state']['ordinal']<ret['returned']['ordinal'],'ACK between original entry and whole return')
        gp=entry['entry']['GP16'];rg=ret['returned']['GP16']
        require(gp[13]==rg[13]and gp[4:12]==rg[4:12]and ret['r0']==0 and rg[15]==entry['return_PC'],'Whole original46CC7A SP/GP/PC/R0')
        if entry.get('barrier_kind')=='Stop':
            nz=native(e,rp,rp.snapshots[entry['entry']['ordinal']],sy)
            require(nz['ns_hold']==nz['native_calls']==nz['native_mutation']==1 and nz['ns_stage']==3 and
                not nz['leases']['borrow'] and nz['leases']['media']==nz['leases']['callback']==0,'Stop barrier after typed full-frame leases return')
            stops.append(ret)
    require([x['bytes_hex']for x in d['original_message_sends']]==[x['bytes_hex']for x in d['original_message_receives']],'Actual native FIFO copied order')
    if original:
        commands=[struct.unpack('<3I',bytes.fromhex(x['bytes_hex']))[0]&255 for x in d['original_message_receives']]
        require(commands[-3:]==[15,19,20] and len(stops)==1,'Ordered15/19 then direct20; no extra13 or synthetic17')
        removals=[x for x in original if x['entry_PC']==0x277674];require(len(removals)==1,'One original full node removal')
        removal=removals[0];require(stops[0]['returned']['ordinal']<removal['entry']['ordinal'],'Full native Stop barrier precedes node delete')
        notices=d['notice23_before_count_commit'];releases=d['opaque_list_release_calls'];require(len(notices)==len(releases)==1,'One actual notice23/opaque release')
        notice=notices[0];nz=rp.snapshots[notice['state']['ordinal']]
        require(native(e,rp,nz,sy)==notice['native']and notice['native']['node_count']==1 and notice['native']['head']==0 and notice['native']['native_calls']==1,'Notice23 before count decrement, not quiescence')
        commits=[x for x in d['CPU_store_journal']if int(x['PC'],16)==0x277642]
        require(len(commits)==1 and commits[0]['value']==0 and
            notice['state']['ordinal']<releases[0]['state']['ordinal']<commits[0]['ordinal']<removal['returned']['ordinal'],'Actual unlink/notice/release/decrement/fullreturn sequence')
    # Decode outputs and native output ring are independently reconstructed;
    # queued data canceled by Stop is kept separate from actually played PCM.
    inputs={bytes.fromhex(p['packet_hex']):p for p in reference['packets']}
    commits=[]
    for row in d['producer_entries']:
        if row['symbol']!='memory_output_submit':continue
        ez=rp.snapshots[row['entry']['ordinal']];gp=row['entry']['GP16']
        parsers=[x for x in d['producer_entries']if x['symbol']=='owned_packet_parse'and x['entry']['ordinal']<row['entry']['ordinal']]
        parser=parsers[-1];pz=rp.snapshots[parser['entry']['ordinal']];pg=parser['entry']['GP16']
        packet=e.get(pz,pg[3],e.word(pz,pg[13]));require(packet in inputs,'Known copied compressed input')
        expected=bytes.fromhex(inputs[packet]['expected_continuous_PCM_hex'])
        require(gp[:2]==[0x07900000,len(expected)]and e.get(ez,gp[0],gp[1])==expected,'Exact Source gather from frozen SBC/FIR reference')
        commits.append(expected)
    output=[]
    for row in d['original_mixer_call_site_returns']:
        ez=rp.snapshots[row['entry']['ordinal']];rz=rp.snapshots[row['returned']['ordinal']]
        before=e.word(ez,e.DESC+16);after=e.word(rz,e.DESC+16);count=(after-before)%2048
        require(before==row['ring_before']and count==row['bytes'],'Native ring pointer readback')
        first=min(count,e.BUFFER+2048-before);raw=e.get(rz,before,first)
        if first<count:raw+=e.get(rz,e.BUFFER,count-first)
        require(raw.hex()==row['PCM_hex'],'Whole actual native ring output bytes');output.append(raw)
    music=b''.join(commits);audio=b''.join(output);played=min(len(music),len(audio))
    require(audio[:played]==music[:played]and audio[played:]==bytes(len(audio)-played),'Actual output is ordered source PCM plus explicit underrun silence')
    for row in d['full_native_returns']:
        gp=row['entry']['GP16'];rg=row['returned']['GP16'];e.check_actor(row['entry'],e.M);e.check_actor(row['returned'],e.M)
        require(rg[13]==row['entry_SP']+64 and rg[4:12]==gp[4:12]and rg[15]==row['return_PC'],'Complete original64-byte native audio frame')
    terminal=native(e,rp,z,sy);require(terminal==d['retirement_terminal'],'Actual terminal native fields')
    status=[e.word(z,sy[name]['value'])for name in ('ns_stage','ns_head','ns_epoch','ns_generation','ns_instance','ns_attempts','ns_deferred','ns_barrier_returns','ns_remove_returns','ns_anchor_returns','ns_fifo_canceled','ns_rejections','ns_hold','ns_last_result')]
    require(status==d['retirement_status'],'Actual whole retirement status')
    status_base=sy['aas_control']['value']+rp.offsets[3]-44
    require(e.word(z,status_base)==6 and e.word(z,status_base+16)==e.word(z,status_base+24)==0 and terminal['guard_held']==1,'Control stays STOPPING/armed0/StopCompleted0, guard resident')
    if status[0]==4:
        require(terminal['head']==terminal['node_count']==terminal['prepared']==terminal['mixer_active']==terminal['active_ticket']==terminal['installed']==terminal['native_calls']==terminal['native_mutation']==0,'Whole native anchor retirement')
        require(status[7]==status[8]==status[9]==1 and rp.copy_counts['Source_FIFO_discard_after_full_retirement']==status[10],'FIFO cancellation after complete original retirement')
    if d['name']=='Stop_during_actual_Mixer_borrow_defers':
        deferred=[x for x in d['full_compiled_retirement_returns']if x['r0']==1]
        require(deferred and all(x['native']['leases']['borrow']and x['native']['ns_hold']==0 for x in deferred),'Actual borrowed native frame postpones source retirement')
    if d['name']=='foreign_controller_cannot_retire_source':
        wrong=[x for x in d['full_compiled_retirement_returns']if x['actor']==e.C]
        require(len(wrong)==1 and wrong[0]['r0']==0xfffffffb and wrong[0]['actual_emu_end_PC'],'Actual wrong owner returned at verified emulation endpoint')
    if d['name']=='replaced_native_head_is_pinned':
        require(not original and not stops and terminal['active_ticket']and terminal['installed']and terminal['head']==0xd0ffffff and terminal['node_count']==1,'Changed head rejected; original anchor remains pinned')
    counts.update(name=d['name'],actual_final_RX_zones=rp.final_RX_verified,
        full_original_stop_helpers=len(original),full_original_sync=len(returns),full_original_Stop_barriers=len(stops),
        compiled_retirement_full_returns=len(d['full_compiled_retirement_returns']),native_fullpull_returns=len(d['full_native_returns']),
        decoded_PCM_bytes=len(music),actual_output_PCM_bytes=played,explicit_silence_bytes=len(audio)-played,output_bytes=len(audio),
        retired_private_FIFO_slots=status[10],deferred_Stop_returns=sum(x['r0']==1 for x in d['full_compiled_retirement_returns']),copy_guards=dict(rp.copy_counts))
    return counts
def main():
    OUT.mkdir(exist_ok=False);e=source_engine();p=BASE/'native-retirement-selected-six-scope-v1.json';selected=json.loads(p.read_text())
    require(selected['all_passed']and selected['case_count']==6,'Frozen selected scopes')
    sources=dict(selected['source_sha256'])
    for path,h in sources.items():require(sha(ROOT/path)==h,'Frozen file '+path)
    build,elf,sy=e.verify_build(BASE/'build-v2.json',sources);n=e.NativeImage();rows=[]
    try:
        for case in selected['cases']:
            path=ROOT/case['path'];require(sha(path)==case['sha256'],'Frozen completed case')
            d=json.loads(path.read_text());reference=json.loads((ROOT/'staging/native-player-sbc-sync/compressed_input_reference_v1.json').read_text())['streams'][d['stream_index']]
            row=verify_case(e,d,n,elf,sy,reference);rows.append(row)
            print(json.dumps(dict(case=d['name'],CPU_stores=row['CPU_stores'],Stop_helpers=row['full_original_stop_helpers'],FILE_only=True)),flush=True)
            del d;gc.collect()
        totals={k:sum(r[k]for r in rows)for k in ('CPU_stores','joint_events','tracked_whole_zones','actual_final_RX_zones','full_original_stop_helpers','full_original_sync','full_original_Stop_barriers','compiled_retirement_full_returns','native_fullpull_returns','decoded_PCM_bytes','actual_output_PCM_bytes','explicit_silence_bytes','output_bytes','retired_private_FIFO_slots','deferred_Stop_returns')}
        for path in (Path(__file__).resolve(),OLD,OUT/'generated-retirement-file-engine-v1.py',p):sources[str(path.relative_to(ROOT))]=sha(path)
        require(not any(k=='unicorn'or k.startswith('unicorn.')for k in sys.modules),'No VM import')
        result=dict(all_passed=True,ROOT_FILE_reconstruction=True,new_independent_agent_review=False,source_sha256=sources,case_count=6,cases=rows,totals=totals,
            original_Stop15_19_20_ACK_provider_methods_notice23_and_full_list_removal_verified=True,
            whole_original_and_compiled_return_SP_GP_PC_R0_and_all_memory_stores_verified=True,
            FIFO_discard_only_after_full_native_removal_and_anchor_return=True,
            v1_partial_suite_EXIT1_and_completed_prefix_preserved=True,old_guest_cases_rerun=False,
            limits='Store/whole-memory/serialized-frame proof only; v1 instruction totals are prefix counts before last readonly diagnostic call. No all-nonstore controlflow or native dispatcher quiescence proof. Controller/idle/cold/opaque allocation/backing/output fixtures remain. Local anchor retirement leaves control STOPPING, module/TCBs/storage resident; native STOP_DONE, exclusive, heap, hardware drain, phone and App are unverified.',
            device_IO=False,VM_import_or_execution=False,guest_rerun=False,native_STOP_DONE_heap_exclusive_phone_App_speaker_hardware_drain_safe_unload_verified=False,
            updated_utc=datetime.now(timezone.utc).isoformat())
        create(OUT/'ROOT-retirement-six-scope-file-reconstruction.json',result)
        print(json.dumps(dict(all_passed=True,totals=totals)),flush=True)
    except BaseException as error:
        create(OUT/'terminal-failure.json',dict(all_passed=False,error=str(error),cases_completed=rows,guest_rerun=False,device_IO=False));raise
if __name__=='__main__':main()
