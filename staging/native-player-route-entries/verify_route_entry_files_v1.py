#!/usr/bin/env python3
"""Reconstruct warm attach, native boot constructors and playback from saved files, without guest runs."""
import sys
sys.dont_write_bytecode=True
import json,struct,hashlib
from pathlib import Path
from datetime import datetime,timezone
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def dump(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def require(v,msg):
 if not v:raise ValueError(msg)
def main():
 out=BASE/'file-v1';out.mkdir(exist_ok=False)
 guest=json.loads((BASE/'route-entry-v5-proof.json').read_text());build=json.loads((BASE/'build-v2.json').read_text())
 deps=dict(guest['source_sha256'])
 for p in [Path(__file__),BASE/'route-entry-v5-proof.json',BASE/'guest-v5-terminal-tool-receipt.json']:
  deps[rel(p)]=sha(p)
 require(all(sha(ROOT/p)==h for p,h in deps.items()),'changed dependencies')
 case=guest['cases'][0];p=ROOT/case['path'];require(sha(p)==case['sha256'],'guest case changed');deps[rel(p)]=sha(p)
 d=json.loads(p.read_text());require(d['passed']and d['stock_loader']['status']==11,'incomplete guest')
 md={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)};opcache={}
 rx_zones={int(a):bytes.fromhex(raw)for a,raw in d['actual_final_RX_zones'].items()}
 totals=dict(loader_CPU_stores=0,loader_fixture_writes=0,playback_CPU_stores=0,playback_fixture_writes=0,
  loader_whole_zones=0,playback_whole_RW_zones=0,playback_unchanged_RX_zones=0,store_opcodes_checked=0)
 def replay(initial,final,start,end,label):
  zones={int(a):bytearray.fromhex(raw)for a,raw in initial.items()}
  def part(a,n):
   candidates=[(z,b)for z,b in zones.items()if z<=a<z+len(b)]
   require(len(candidates)==1,'address outside unique '+label+' zone '+hex(a))
   z,b=candidates[0];return b,a-z,min(n,len(b)-(a-z))
  def read(a,n):
   result=bytearray()
   while n:
    b,o,k=part(a,n);result.extend(b[o:o+k]);a+=k;n-=k
   return bytes(result)
  events=sorted([e for e in d['CPU_store_journal']+d['declared_fixture_mutations']if start<e['ordinal']<=end],key=lambda e:e['ordinal'])
  require(len({e['ordinal']for e in events})==len(events),'duplicate ordinal')
  for e in events:
   a=int(e['address'],16);before=bytes.fromhex(e['before_hex'])
   require(read(a,len(before))==before,'preimage differs '+label+' '+str(e['ordinal']))
   if e['event_type']=='actual_CPU_store':
    pc=int(e['PC'],16);opcode=bytes.fromhex(e['opcode_hex']);thumb=e['Thumb']
    # Playback replay excludes RX zones. Use the saved post-loader RX bytes;
    # original loader replay includes every zone and sees writes in order.
    if any(z<=pc<z+len(b)for z,b in zones.items()):actual=read(pc,len(opcode))
    else:
     rx=[(z,b)for z,b in rx_zones.items()if z<=pc<z+len(b)]
     require(len(rx)==1,'store PC outside saved code')
     z,b=rx[0];actual=b[pc-z:pc-z+len(opcode)]
    require(actual==opcode,'saved store opcode differs '+hex(pc))
    key=(thumb,opcode)
    if key not in opcache:
     ins=next(md[thumb].disasm(opcode,pc,count=1),None)
     require(ins is not None and ins.mnemonic.startswith(('str','stm','push','vstr','vstm')),'nonstore opcode '+str(ins))
     opcache[key]=ins.mnemonic
    after=(e['value']&((1<<(8*e['size']))-1)).to_bytes(e['size'],'little')
    require(len(after)==len(before),'store size');totals[label+'_CPU_stores']+=1;totals['store_opcodes_checked']+=1
   else:after=bytes.fromhex(e['after_hex']);totals[label+'_fixture_writes']+=1
   require(len(before)==len(after),'fixture size changed')
   cursor=0
   while cursor<len(after):
    b,o,k=part(a+cursor,len(after)-cursor);b[o:o+k]=after[cursor:cursor+k];cursor+=k
  require(set(initial)==set(final),'zone set differs')
  for a,b in zones.items():require(bytes(b)==bytes.fromhex(final[str(a)]),'whole zone differs '+label+' '+hex(a))
  return len(zones)
 totals['loader_whole_zones']=replay(d['loader_initial_whole_zones'],d['loader_final_whole_zones'],d['loader_initial_ordinal'],d['loader_final_ordinal'],'loader')
 totals['playback_whole_RW_zones']=replay(d['initial_whole_RW_zones'],d['final_whole_RW_zones'],d['initial_ordinal'],2**63,'playback')
 for a,h in d['unchanged_after_declared_patches_RX_sha256'].items():
  require(hashlib.sha256(bytes.fromhex(d['actual_final_RX_zones'][a])).hexdigest()==h,'RX changed');totals['playback_unchanged_RX_zones']+=1
 require(not any(z['start']<=0x07000000<z['start']+z['size']or z['start']<=0x08e00000<z['start']+z['size']for z in d['zones']),'synthetic module map')
 sy=build['symbols'];api=d['stock_loader']['api'];require(api[6:]==[sy[n]['value']for n in ['mh_boot_source','aas_media_ingress','mh_request_command','nsg_native_callback','resident_pcm_address','nr_configuration_gate','nr_start_suspend_gate','nr_reply_dispatch']],'loaded API mismatch')
 require(d['source_TCB']and d['mixer_TCB']and d['native_ownership_snapshot']==-200 and not d['native_STOP_DONE'],'ownership/lifecycle scope')
 callback_pairs=[('native_five_argument_callback_entries','native_five_argument_callback_full_returns'),('compiled_ingress_entries','compiled_ingress_full_returns'),('compiled_decoder_entries','compiled_decoder_full_returns')]
 for entries,returns in callback_pairs:
  require(len(d[entries])==len(d[returns])and len(d[entries])>0,'missing full ABI return')
  for entry,ret in zip(d[entries],d[returns]):
   require(entry['entry_SP']==ret['returned']['GP16'][13]and entry['return_PC']==ret['returned']['GP16'][15],'full callback SP/PC changed')
   require(entry['entry']['GP16'][4:12]==ret['returned']['GP16'][4:12],'callee-saved registers changed')

 require(not d['reader_gate_entries'] and not d['guarded_native_voice_reloads'],'unexecuted reader reload claim')
 warm=d['warm_attach_prefix'];before=warm['before'];after=warm['after']
 require(before['other_records']==after['other_records'] and before['global_heads_hex']==after['global_heads_hex'],'other17 channels or globalheads changed at attach')
 require(before['callback']==0x277c6b and after['callback']==sy['mcs_queue_bridge']['value'],'callback exchange')
 require(not warm['durable_channel_ownership'] and not d['native_live_navigation_ownership_phone_or_App'],'ownership overclaim')
 reasons={r['name']:r['reason']for r in d['warm_negative_controls']}
 require(reasons==dict(condition_magic_missing=-303,profile_callback_foreign=-305,nonempty_target_list=-306,active_target_mixer=-307,prepared_target_provider=-308,native_target_state_not_idle=-309,IRQ_marker_set=-301,native_foreign_profile_mutex_owner=-302),'warm rejection controls')
 for r in d['warm_negative_controls']:require(r['before']==r['after'],'rejected attach changed semantic audio state')
 warm_stores=[e for e in d['CPU_store_journal']if e['phase']=='compiled warm Source attaches existing channel']
 for offset in(0x1c8,0x1e0,0x58):
  native_lock=[e for e in warm_stores if int(e['address'],16)==0x034e7f48+offset+8]
  require([(int(e['PC'],16),e['value'])for e in native_lock]==[(0x3009ca,d['source_TCB']),(0x3008f2,0)],'three native mutex acquisitions/releases were not executed')
  require(all(e['current_TCB']==d['source_TCB']for e in native_lock),'warm lock wrong actor')
 # Instructions of forbidden global/table constructors never stored anything
 # during warm attach. Guest full instruction visits separately bound the
 # no-call assertion; this FILE check proves the saved mutation interval.
 require(not any(0x277e20<=int(e['PC'],16)<0x277e4c or 0x269f1c<=int(e['PC'],16)<0x26a0d0 for e in warm_stores),'warm attach executed cold reset stores')
 constructors=[e for e in d['CPU_store_journal']if e['phase']=='original all-channel object construction before App'and int(e['PC'],16)==0x3ec56c]
 require(len(constructors)==36 and all(e['value']==0xd4475b83 for e in constructors),'original native conditions not constructed')
 wanted={0x034e6f08+ch*0x208+offset for ch in range(18)for offset in (0x88,0x3c)}
 require({int(e['address'],16)for e in constructors}==wanted,'native condition constructor address provenance')
 profiles=[e for e in d['CPU_store_journal']if e['phase']=='original all-channel cold profile loop before App'and int(e['PC'],16)==0x277dbc]
 require(len(profiles)==18 and all(e['value']==0x277c6b for e in profiles),'native pre-App profile callbacks')
 require({int(e['address'],16)for e in profiles}=={0x034e6f08+ch*0x208+0x160 for ch in range(18)},'native original callback install addresses')
 # Crosscheck five compiled entry gates and actual normal/end-PC returns.
 def gatekey(r):return(r['name'],r['entry']['ordinal'],r['entry']['current_TCB'],r['entry_SP'])
 entries={gatekey(r):r for r in d['native_route_gate_entries']}
 returns={gatekey(r):r for r in d['native_route_gate_full_returns']}
 require(len(entries)==len(returns)==34 and set(entries)==set(returns),'gate full-return pairing')
 for key,entry in entries.items():
  ret=returns[key];state=ret['returned']
  require(state['GP16'][13]==entry['entry_SP']and state['GP16'][15]==entry['return_PC'],'gate actual PC/SP')
  require(state['current_TCB']==entry['entry']['current_TCB'],'gate returned actor')
  require(state['GP16'][4:12]==entry['entry']['GP16'][4:12],'gate saved registers')
 racer=d['racer_native_POSTs'];checks=d['racer_checks']
 require(len(racer)==len(checks)==2 and len(d['racer_native_entry'])==1,'two original-kernel interference runs')
 racer_tcb=racer[0]['racer_tcb'];require(racer[1]['racer_tcb']==racer_tcb,'racer changed identity')
 require(racer[0]['Source_warm_hook']and racer[0]['state']['current_TCB']==d['source_TCB'],'real Source posted racer')
 require(racer[0]['raw_mutex_owners']==[d['source_TCB']]*3,'all native locks held at preemption')
 require(racer[0]['claim']['active']==1 and racer[0]['claim']['owner']==d['source_TCB'],'claim active before preemption')
 attacks=[r for r in entries.values()if r['entry']['current_TCB']==racer_tcb]
 require(len(attacks)==10 and {r['name']for r in attacks}=={'profile','queue','selector','prepare','allocate'},'five racer API entries twice')
 for entry in attacks:require(returns[gatekey(entry)]['r0']==(0xffff if entry['name']=='allocate'else 8),'racer original route request not rejected')
 require(all(c['results']==[8,8,8,8,0xffff]for c in checks),'racer saved result bytes')
 require(d['playing_interference']['before']==d['playing_interference']['after'],'established private route changed')
 def codebytes(a,n):
  matches=[(z,b)for z,b in rx_zones.items()if z<=a and a+n<=z+len(b)]
  require(len(matches)==1,'route code outside saved final RX');z,b=matches[0];return b[a-z:a-z+n]
 for p in build['selected_native_route_entry_barriers']:
  require(codebytes(p['address'],p['patch_bytes']).hex()==p['after_hex'],'route patch differs')
 alloc=next(p for p in build['selected_native_route_entry_barriers']if p['name']=='allocate')
 require(alloc['patch_bytes']==8 and alloc['relocated_prefix_return']==0x48ee71,'allocator patch boundary')
 ins=next(md[True].disasm(codebytes(0x48ee98,2),0x48ee98,count=1))
 require(ins.mnemonic=='blt'and '48ee72'in ins.op_str and not(alloc['address']<=0x48ee72<alloc['address']+alloc['patch_bytes']),'original allocator back-edge overwritten')
 other=d['other_route_controls'];require(other['profile9_return']==other['provider_allocation_return']==0 and other['other_provider']==1 and other['private_provider']==0 and other['private_pool_preserved'],'other callers not forwarded correctly')
 allocation_stores=[e for e in d['CPU_store_journal']if e['phase']=='unclaimed output original provider allocator forwarding'and e['PC']in('0x48ee8c','0x48ee8e')]
 require(len(allocation_stores)==2 and int(allocation_stores[0]['address'],16)==0x034e3cf4+576+12 and allocation_stores[0]['before_hex']=='00'and allocation_stores[0]['value']==1 and allocation_stores[1]['value']==1,'original allocator did not reserve another free slot')
 require(d['final_route_claim']['active']==d['final_route_claim']['epoch']==1 and d['final_route_claim']['owner']==d['source_TCB'],'boot-pinned claim changed')
 require(d['selected_entry_barriers_not_full_ownership_or_Stop_yield'],'scope overclaim')
 totals.update(selected_entry_gates=5,native_gate_full_returns=34,true_kernel_interference_runs=2,target_gate_rejections=10,original_native_mutexes_held_at_claim=3,other_original_allocator_reserved_free_slot=1)
 # Rebuild two output cycles separated only by declared consumer advances.
 consumers=[e for e in d['declared_fixture_mutations']if e['reason']=='explicit output consumer advances after full original actor returns; no DMA']
 require(len(consumers)==2,'two consumer/output cycles missing')
 reference=json.loads((ROOT/'staging/native-player-sbc-sync/compressed_input_reference_v1.json').read_text())['streams'][1]
 music_bytes=0;output_bytes=0;prior=0
 for i,c in enumerate(consumers):
  actual=b''.join(bytes.fromhex(r['PCM_hex'])for r in d['original_mixer_call_site_returns']if prior<r['returned']['ordinal']<c['ordinal'])
  expected=bytes.fromhex(reference['packets'][i]['expected_continuous_PCM_hex'])
  require(len(actual)>=len(expected) and actual[:len(expected)]==expected and actual[len(expected):]==bytes(len(actual)-len(expected)),'warm continuous music/silence output differs')
  music_bytes+=len(expected);output_bytes+=len(actual);prior=c['ordinal']
 require(d['remote_final']['epoch']==1 and d['remote_final']['accepted_media']==2,'warm accepted configuration/packets')
 totals.update(negative_warm_controls=8,original_condition_constructors=36,original_profile_callbacks=18,native_profile_lock_returns=1,native_list_lock_returns=1,native_provider_lock_returns=1,music_PCM_bytes=music_bytes,output_bytes_including_silence=output_bytes)
 totals.update(native_callbacks=len(d['native_five_argument_callback_full_returns']),Source_ingress=len(d['compiled_ingress_full_returns']),SBC_full_returns=len(d['compiled_decoder_full_returns']),native_audio_full_returns=len(d['full_native_returns']))
 proof=dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),case_count=1,totals=totals,source_sha256=deps,
  complete_loader_and_playback_zone_reconstruction=True,selected_store_opcode_and_callback_ABI=True,
  no_guest_rerun_or_context_restore=True,new_independent_agent=False,complete_nonstore_CFG_or_all_store_effective_addresses=False,
  stock_address_single_DLL_with_forty_original_exports=True,selective_warm_attach_and_eight_rejections=True,original_pre_App_conditions_and_profiles=True,
  original_selector_whole_concurrency_or_physical_install_not_proven=True,selected_five_entry_gates_and_two_actual_racer_runs_verified=True,other_original_provider_allocation_preserves_private_slot=True,boot_pinned_claim_not_full_ownership_Stop_yield_or_all_native_writers=True,durable_warm_heap_ownership_menu_pin_phone_or_device=False,device_IO=False)
 dump(BASE/'ROOT-route-entry-file-proof-v1.json',proof);print(json.dumps(dict(all_passed=True,totals=totals,device_IO=False)),flush=True)
if __name__=='__main__':main()
