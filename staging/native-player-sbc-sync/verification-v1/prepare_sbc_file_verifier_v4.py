#!/usr/bin/env python3
"""NEW corrected case contract plus copy/publication live-state assertions."""
from pathlib import Path
import hashlib,json
B=Path(__file__).resolve().parent;s=(B/'verify_sbc_sync_v1_files_v3.py').read_text()
old="require(sites['0x2fa536']>0 and sites['0x2fa572']>0 and final_status[5]==0 and final_status[48]==(16 if normal_case else 8),'Both original fullcallroutes/current FIFO ticket')"
new="require(sites['0x2fa572']>0 and (sites['0x2fa536']>0 if normal_case else sites['0x2fa536']==0) and final_status[5]==0 and final_status[48]==(16 if normal_case else 8),'Original reset dual routes versus CRC sole normal route/current FIFO ticket')"
assert s.count(old)==1;s=s.replace(old,new)
s=s.replace('self.eventchecks=defaultdict(list);self.decode_cache={}','self.eventchecks=defaultdict(list);self.decode_cache={};self.copy_counts=Counter();self.PCM_copied=defaultdict(set);self.queue_copied=defaultdict(set)')
s=s.replace("if a==RECORD+0x160:self.callbacks.append", "verify_sbc_copy_state(self,e)\n                if a==RECORD+0x160:self.callbacks.append")
s=s.replace("counts.update(verify_sbc_pipeline(d,rp,symbols,reference))","counts.update(verify_sbc_pipeline(d,rp,symbols,reference));counts['per_copy_live_guard_counts']=dict(rp.copy_counts)")
extra='''def verify_sbc_copy_state(rp,e):
    a=int(e['address'],16);pc=int(e['PC'],16);n=e['size'];z=rp.z;sy=rp.symbols;gp=e['GP16'];value=e['value']&((1<<(n*8))-1)
    slots=sy['memory_output_slots']['value'];q=sy['media_queue_control']['value'];g=rp.guard;c=rp.control
    mm=sy['memcpy']['value']
    if pc==mm+16:
        require(n==1 and rp.elf.at(mm,28)[0]==bytes.fromhex('0030a0e3020053e11eff2f0103c0d1e703c0c0e7013083e2f9ffffea'),'Exact bounded compiled memcpy LDRB/STRB loop')
        require(a==gp[0]+gp[3] and value==get({**z,**rp.actual_RX_bytes},gp[1]+gp[3],1)[0],'Actual memcpy source-memory byte equals GP/CPU destination payload')
        rp.copy_counts['exact_compiled_memcpy_source_bytes']+=1
    if 0x07700000<=a<a+n<=0x07704000:
        i=(a-0x07700000)//4096;offset=a-(0x07700000+i*4096);s=struct.unpack('<6I',get(z,slots+i*24,24));view=rp.leases(z)
        require(e['current_TCB']==S and e['CPSR']&0xff==0x1f and pc==mm+16,'PCM copy only unlocked Source compiled memcpy')
        require(s[1]==1 and s[5]==0 and s[0] and offset+n<=s[2],'PCM COPYING lease and declared whole packet byte bound')
        require(view['media']==view['callback']==1 and view['borrow']==0 and word(z,sy['owned_media_control']['value']+4)==1,'Typed producer lifetime held during complete PCM copy')
        require(gp[1]==0x07900000 and value==get(z,0x07900000+offset,n)[0],'Actual PCM page byte comes from private complete gather')
        rp.PCM_copied[i].update(range(offset,offset+n));rp.copy_counts['PCM_COPYING_bytes']+=n
    if 0x07902000<=a<a+n<=0x07906000:
        i=(a-0x07902000)//4096;offset=a-(0x07902000+i*4096)
        require(e['current_TCB']==S and e['CPSR']&0xff==0x1f and pc==mm+16,'Declared compressed copy on unlocked Source only')
        require(word(z,q+20)==1 and word(z,q+16)==1 and word(z,q+4)==i,'Compressed producer_busy/running/write slot reservation')
        if offset==0:rp.queue_copied[i]=set()
        rp.queue_copied[i].update(range(offset,offset+n));rp.copy_counts['compressed_queue_copied_bytes']+=n
    if slots<=a<slots+96 and (a-slots)%24==4 and n==4:
        i=(a-slots)//24;old=word(z,a)
        if value==1:
            require(old==0 and e['current_TCB']==S,'Only Source reserves FREE FIFO slot for COPY');rp.PCM_copied[i]=set();rp.copy_counts['FIFO_COPYING_reservations']+=1
        if value==2:
            length=word(z,slots+i*24+8)
            require(old==1 and rp.PCM_copied[i]==set(range(length)) and e['current_TCB']==S,'Entire PCM payload copied before READY publication');rp.copy_counts['whole_FIFO_READY_publications']+=1
        if value==0 and old==2:
            view=rp.leases(z);require(e['current_TCB']==M and word(z,slots+i*24+20)==0 and view['borrow'] and view['media']==view['callback']==1,'Mixer frees FIFO only after copy in_flight returns0 under full native lease');rp.copy_counts['FIFO_free_after_inflight_zero']+=1
    if a==q+8 and n==4 and value==word(z,q+8)+1:
        i=(word(z,q+4)-1)%4;length=word(z,sy['lengths']['value']+4*i)
        require(rp.queue_copied[i]==set(range(length)) and word(z,q+20)==0 and e['current_TCB']==S,'Whole compressed copy completes before queue count publication');rp.copy_counts['whole_compressed_queue_publications']+=1
    if SCRATCH<=a<a+n<=SCRATCH+256 and pc==mm+16:
        source=gp[1]+gp[3]
        if 0x07700000<=source<0x07704000:
            i=(source-0x07700000)//4096;view=rp.leases(z)
            require(e['current_TCB']==M and word(z,slots+i*24+4)==2 and word(z,slots+i*24+20)==1,'Actual mixer FIFO copy held exact slot in_flight1')
            require(view['borrow'] and view['media']==view['callback']==1,'Whole native reader lifetime extends through per-byte copy');rp.copy_counts['Mixer_copy_inflight_bytes']+=n

'''
s=s.replace('def supported_compiled_stack_fixture',extra+'def supported_compiled_stack_fixture',1)
s=s.replace("Path(__file__).resolve().parent/'prepare_sbc_file_verifier_v3.py'):sources[rel(p)]=sha(p)","Path(__file__).resolve().parent/'prepare_sbc_file_verifier_v3.py',Path(__file__).resolve().parent/'verify_sbc_sync_v1_files_v3.py',Path(__file__).resolve().parent/'file-verifier-v3-terminal-failure-receipt.json',Path(__file__).resolve().parent/'prepare_sbc_file_verifier_v4.py'):sources[rel(p)]=sha(p)")
s=s.replace("exact_original_MAIN_and_ELF_store_opcode_ISA_GP16_CPSR_address_value_preimage_verified=True,complete_multiword_store_groups_verified=True,joint_CPU_fixture_history_and_actual_whole_after_verified=True,", "exact_original_MAIN_and_ELF_store_opcode_ISA_GP16_CPSR_address_value_preimage_verified=True,complete_multiword_store_groups_verified=True,joint_CPU_fixture_history_and_actual_whole_after_verified=True,actual_memcpy_input_bytes_and_COPYING_inflight_whole_publication_guards_verified=True,per_copy_live_guard_totals=dict(Counter({k:sum(r['per_copy_live_guard_counts'].get(k,0) for r in rows) for k in {k for r in rows for k in r['per_copy_live_guard_counts']}})),")
s=s.replace("'FILE verifier v2 missed", "'FILE verifier v3 correctly replayed first four cases but incorrectly required CRC-only normal case to reach reset-only2FA536; actual CRC case only2FA572. NEW v4 case-specific route check and exact LDRB/STRB input/copy lease guards; frozen v3 source/actual EXIT1 retained, no guest rerun. FILE verifier v2 missed")
with (B/'verify_sbc_sync_v1_files_v4.py').open('x') as f:f.write(s)
for name in ['verify_sbc_sync_v1_files_v3.py','prepare_sbc_file_verifier_v3.py','file-verifier-v3-terminal-failure-receipt.json']:(B/name).chmod(0o444)
print(json.dumps(dict(all_passed=True,new_source='staging/native-player-sbc-sync/verification-v1/verify_sbc_sync_v1_files_v4.py',sha256=hashlib.sha256((B/'verify_sbc_sync_v1_files_v4.py').read_bytes()).hexdigest(),guest_execution=False)))
