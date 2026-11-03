#!/usr/bin/env python3
"""FILE-only replay of warm six-provider-entry integration. No guest execution."""
import sys
sys.dont_write_bytecode=True
import json,struct,hashlib,gzip,gc,traceback
from pathlib import Path
from datetime import datetime,timezone
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def dump(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def require(v,msg):
 if not v:raise ValueError(msg)
def verify_base(d,build,reference):
 require(d['passed']and d['stock_loader']['status']==11,'incomplete completed scope')
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
 require(d['source_TCB']and (d['mixer_TCB']or d['name']=='warm_Stop_before_first_input')and d['native_ownership_snapshot']==-200 and not d['native_STOP_DONE'],'ownership/lifecycle scope')
 callback_pairs=[('native_five_argument_callback_entries','native_five_argument_callback_full_returns'),('compiled_ingress_entries','compiled_ingress_full_returns'),('compiled_decoder_entries','compiled_decoder_full_returns')]
 for entries,returns in callback_pairs:
  require(len(d[entries])==len(d[returns]),'missing full ABI return')
  for entry,ret in zip(d[entries],d[returns]):
   require(entry['entry_SP']==ret['returned']['GP16'][13]and entry['return_PC']==ret['returned']['GP16'][15],'full callback SP/PC changed')
   require(entry['entry']['GP16'][4:12]==ret['returned']['GP16'][4:12],'callee-saved registers changed')

 require(not d['reader_gate_entries'] and not d['guarded_native_voice_reloads'],'unexecuted reader reload claim')
 warm=d['warm_attach_prefix'];before=warm['before'];after=warm['after']
 require(before['other_records']==after['other_records'] and before['global_heads_hex']==after['global_heads_hex'],'other17 channels or globalheads changed at attach')
 require(before['callback']==0x277c6b and after['callback']==sy['mcs_queue_bridge']['value'],'callback exchange')
 require(not warm['durable_channel_ownership'] and not d['native_live_navigation_ownership_phone_or_App'],'ownership overclaim')
 require(not d['warm_negative_controls'],'this suite does not rerun historical warm negatives')
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
 def pair(entries,returns,key,label):
  ent={key(e):e for e in entries};ret={key(e):e for e in returns}
  require(len(ent)==len(entries)==len(ret)==len(returns) and set(ent)==set(ret),label+' full return pairing')
  for k,e in ent.items():
   s=ret[k]['returned']
   require(s['GP16'][13]==e['entry_SP'] and s['GP16'][15]==e['return_PC'],label+' PC/SP')
   require(s['current_TCB']==e['entry']['current_TCB'],label+' actor')
   require(s['GP16'][4:12]==e['entry']['GP16'][4:12],label+' callee-saved ABI')
   require(s['ordinal']>=e['entry']['ordinal'],label+' reversed ordinal')
  return ent,ret
 key=lambda e:(e['entry']['ordinal'],e['entry']['current_TCB'],e['entry_SP'])
 gates,gate_returns=pair(d['native_route_gate_entries'],d['native_route_gate_full_returns'],lambda e:(e['name'],)+key(e),'route gate')
 ns,ns_returns=pair(d['compiled_retirement_entries'],d['full_compiled_retirement_returns'],key,'compiled retirement')
 native,native_returns=pair(d['native_stop_entries'],d['full_native_stop_returns'],lambda e:(e['entry_PC'],)+key(e),'original retirement')
 sync,sync_returns=pair(d['original_sync_entries'],d['full_original_sync_returns'],lambda e:(e['barrier_kind'],)+key(e),'original sync')
 posts=d['racer_native_POSTs'];checks=d['racer_checks'];require(len(posts)==len(checks)>=1,'racer POST/check mismatch')
 racer=posts[0]['racer_tcb'];require(all(p['racer_tcb']==racer for p in posts),'racer identity')
 require(posts[0]['Source_warm_hook'] and posts[0]['state']['current_TCB']==d['source_TCB'],'Source real racer POST')
 require(posts[0]['raw_mutex_owners']==[d['source_TCB']]*3,'claim without actual locks')
 require(posts[0]['claim']['active']==1 and posts[0]['claim']['owner']==d['source_TCB'],'claim not active before racer')
 attacks=[(k,e)for k,e in gates.items()if e['entry']['current_TCB']==racer]
 require(len(attacks)==5*len(checks),'five entry attempts per racer run')
 require({e['name']for k,e in attacks}=={'profile','queue','selector','prepare','allocate'},'racer gate coverage')
 for k,e in attacks:require(gate_returns[k]['r0']==(0xffff if e['name']=='allocate'else 8),'racer attempt accepted')
 require(all(c['results']==[8,8,8,8,0xffff]for c in checks),'saved racer results')
 for c in d['Stop_racer_checks']:
  require(c['before']==c['after'] and c['racer']['results']==[8,8,8,8,0xffff],'Stop waiting racer changed audio')
  require(c['before']['ns_stage']==3 and c['before']['ns_hold']==c['before']['native_calls']==c['before']['native_mutation']==1,'Stop racer without retained hold')
 def codebytes(a,n):
  matches=[(z,b)for z,b in rx_zones.items()if z<=a and a+n<=z+len(b)]
  require(len(matches)==1,'route code outside RX');z,b=matches[0];return b[a-z:a-z+n]
 for p in build['selected_native_route_entry_barriers']:
  require(codebytes(p['address'],p['patch_bytes']).hex()==p['after_hex'],'route patch bytes')
 alloc=next(p for p in build['selected_native_route_entry_barriers']if p['name']=='allocate')
 require(alloc['patch_bytes']==8 and alloc['relocated_prefix_return']==0x48ee71,'allocator loop boundary')
 ins=next(md[True].disasm(codebytes(0x48ee98,2),0x48ee98,count=1))
 require(ins.mnemonic=='blt' and '48ee72'in ins.op_str and not(alloc['address']<=0x48ee72<alloc['address']+alloc['patch_bytes']),'allocator back-edge overwritten')
 require(d['final_route_claim']['active']==d['final_route_claim']['epoch']==1 and d['final_route_claim']['owner']==d['source_TCB'],'resident claim released')
 # Compare terminal observations with the whole reconstructed final memory.
 final={int(a):bytes.fromhex(raw)for a,raw in d['final_whole_RW_zones'].items()}
 def mem(a,n):
  candidates=[(z,b)for z,b in final.items()if z<=a and a+n<=z+len(b)]
  require(len(candidates)==1,'terminal address outside unique RW zone');z,b=candidates[0];return b[a-z:a-z+n]
 def u32(a):return struct.unpack('<I',mem(a,4))[0]
 n=d['retirement_terminal'];status=d['retirement_status'];R=0x034e7f48;M=0x034e5378+8*0x130;HEAD=0x034e68d8+8*4
 require(n['head']==u32(HEAD) and n['node_count']==struct.unpack('<H',mem(R+448,2))[0],'head/count snapshot mismatch')
 require(n['prepared']==mem(R+2,1)[0] and n['mixer_active']==mem(M+132,1)[0] and n['methods_hex']==mem(R+244,68).hex(),'native terminal bytes mismatch')
 g=sy['aas_guard']['value'];o=sy['memory_output_control']['value']
 for k,a in [('guard_held',g+16),('native_mutation',g+48),('native_calls',o+20),('active_ticket',o+12),('installed',o+16),('ns_stage',sy['ns_stage']['value']),('ns_hold',sy['ns_hold']['value'])]:require(n[k]==u32(a),'terminal '+k)
 require(n['provider']==list(mem(0x034e3cf4+u32(sy['ns_instance']['value'])*576,32)),'provider snapshot')
 require(n['guard_held']==1 and not d['native_STOP_DONE'] and not d['native_STOP_DONE_or_exclusive_hardware_drain_safe_unload_verified'],'safe unload overclaim')
 for ch in(3,4):
  require(u32(0x034e68d8+4*ch)==0x01234000+ch*16 and struct.unpack('<H',mem(0x034e6f08+ch*0x208+0x1c0,2))[0]==ch,'Stop cleared unrelated occupied channel')
 for e in d['actual_retirement_stores']:
  journal=next(x for x in d['CPU_store_journal']if x['ordinal']==e['journal_ordinal'])
  require((int(journal['PC'],16),int(journal['address'],16),journal['size'],journal['value'])==(e['PC'],e['address'],e['size'],e['value']),'retirement store provenance')
  b=e['native_before'];require(b['ns_stage']==3 and b['ns_hold']==b['native_mutation']==b['native_calls']==1,'retirement write escaped hold')
 stage=status[0];is_positive=stage==4
 if is_positive:
  expected_pcs={0x2f9f1c,0x437a90,0x48ee12,0x5e75b2,0x48ee58,0x277674}
  require(len(native)==6 and {e['entry_PC']for e in native.values()}==expected_pcs,'six full native helpers')
  for k,e in native.items():
   require(e['actor']==(d['source_TCB']if e['entry_PC']==0x277674 else d['mixer_TCB']),'native cleanup wrong actor')
   for b in(e['native'],native_returns[k]['native']):require(b['ns_stage']==3 and b['ns_hold']==b['native_mutation']==b['native_calls']==1,'native cleanup hold')
  stops=[r for r in sync_returns.values()if r['barrier_kind']=='Stop'];require(len(stops)==1 and stops[0]['r0']==0,'full Stop ACK missing')
  removal=next(e for e in native.values()if e['entry_PC']==0x277674);removed=next(r for r in native_returns.values()if r['entry_PC']==0x277674)
  require(stops[0]['returned']['ordinal']<removal['entry']['ordinal']<removed['returned']['ordinal'],'removal before full Stop ACK')
  require(removal['native']['head'] and removal['native']['node_count']==1 and removal['args'][:2]==[R+424,0],'one-node remove args')
  require(len(d['notice23_before_count_commit'])==len(d['opaque_list_release_calls'])==1,'full remove notification/release missing')
  notice=d['notice23_before_count_commit'][0];opaque=d['opaque_list_release_calls'][0]
  require(notice['native']['head']==0 and notice['native']['node_count']==1 and notice['native']['active_ticket'] and notice['native']['installed'],'notice23 mistaken for full retirement')
  count_commits=[e for e in d['CPU_store_journal']if int(e['PC'],16)==0x277642 and int(e['address'],16)==R+448 and e['value']==0]
  require(len(count_commits)==1 and notice['state']['ordinal']<opaque['state']['ordinal']<count_commits[0]['ordinal']<removed['returned']['ordinal'],'count commit/full return order')
  # No compiled session-anchor or ready-FIFO release store may precede the full native removal return.
  boundaries=[]
  for name in('memory_output_release_session','continuous_media_cancel_ready'):
   s=sy[name];events=[e for e in d['CPU_store_journal']if s['value']<=int(e['PC'],16)<s['value']+s['size']]
   require(events and min(e['ordinal']for e in events)>removed['returned']['ordinal'],name+' before full removal')
   boundaries.append(min(e['ordinal']for e in events))
  require(boundaries[0]<boundaries[1],'FIFO reclaimed before session anchor release')
  for k in('head','node_count','prepared','mixer_active','active_ticket','installed','native_calls','native_mutation','ns_hold'):require(n[k]==0,'native remains live '+k)
  require(not any(bytes.fromhex(n['methods_hex'])) and n['provider'][12]==n['provider'][28]==0,'provider methods not idle')
  require(all(n['leases'][k]==0 for k in('borrow','selected_session','media','callback')),'typed references retained')
  expected={'warm_Stop_after_music_and_foreign_actor_rejection':0,'warm_full_PCM_pending_compressed_Stop':4,'warm_Stop_during_actual_Mixer_borrow':3,'native_Disconnect_while_paused_runs_warm_retirement':1,'six_provider_entries_actual_allocator_pin_music_Stop_and_other_callers':0,'warm_backend_aliases_and_private_audio_retirement':0}[d['name']]
  require(status[7:10]==[1,1,1] and status[10]==expected and status[12:]==[0,0],'cleanup outcome counters')
  require(d['producer_terminal']['owned'][4]==d['producer_terminal']['queue'][2]==0,'queued PCM/compressed remains')
  messages=[struct.unpack('<3I',bytes.fromhex(x['bytes_hex']))[0]&255 for x in d['original_message_receives']]
  require(messages[-3:]==[15,19,20],'original Stop message order')
 else:
  require(not native and not any(e['barrier_kind']=='Stop'for e in sync.values()) and not d['notice23_before_count_commit'] and not d['opaque_list_release_calls'],'negative invented cleanup')
  if d['name']=='warm_Stop_before_first_input':
   require(stage==6 and not d['compiled_decoder_entries'] and not n['active_ticket'] and not n['installed'],'pre-input stop created native source')
  else:
   require(d['name']=='warm_foreign_head_change_keeps_anchor_pinned' and stage==2 and n['head']==0xd0ffffff and n['node_count']==1 and n['active_ticket'] and n['installed'],'foreign source anchor freed')
   require(any(f.get('reason')=='explicit foreign native head mutation negative, not gated by all known APIs'for f in d['declared_fixture_mutations']),'foreign negative input undeclared')
 if d['name']=='warm_Stop_during_actual_Mixer_borrow':
  require(status[6]==4 and any(e['native']['leases']['borrow']for e in ns.values()),'actual Mixer borrow did not defer')
  stopped=next(e for e in sync.values()if e['barrier_kind']=='Stop')
  last_borrow=max(e['entry']['ordinal']for e in ns.values()if e['native']['leases']['borrow'])
  require(last_borrow<stopped['entry']['ordinal'],'Stop sync while actual borrow held')
 if d['name']=='native_Disconnect_while_paused_runs_warm_retirement':
  require(d['remote_final']['retired']==d['remote_final']['stop_requests']==1,'Disconnect not retired')
  require(any(e['entry']['phase']=='original Disconnect F2 requests resident native retirement'for e in ns.values()),'Disconnect route not executed')
 music=0;output=0
 if d['name']=='warm_Stop_after_music_and_foreign_actor_rejection':
  rec=next(r for r in d['retirement_records']if r.get('kind')=='actual music before Stop');pcm=bytes.fromhex(rec['PCM_hex']);expected=bytes.fromhex(reference['streams'][1]['packets'][0]['expected_continuous_PCM_hex'])
  require(pcm[:len(expected)]==expected and pcm[len(expected):]==bytes(len(pcm)-len(expected)),'actual music/silence output mismatch')
  require(bytes.fromhex(rec['expected_PCM_hex'])==expected,'reference PCM mismatch');music=len(expected);output=len(pcm)
  wrong=next(r for r in d['retirement_records']if r.get('kind')=='wrong actor rejected');require(wrong['before']==wrong['after'] and wrong['returned']==0xfffffffb,'foreign controller performed cleanup')
  require(d['playing_interference']['before']==d['playing_interference']['after'],'playing racer mutated private route')
  require(mem(0x034e3cf4+576+12,1)==b'\x01','Stop freed other provider')
 totals.update(native_gate_full_returns=len(gates),true_kernel_interference_runs=len(checks),target_gate_rejections=len(attacks),Stop_wait_interference_runs=len(d['Stop_racer_checks']),compiled_retirement_full_returns=len(ns),original_retirement_full_returns=len(native),full_Stop_ACK_returns=int(is_positive),full_one_node_removals=int(is_positive),canceled_ready_PCM=status[10],actual_Mixer_borrow_deferrals=status[6],original_condition_constructors=36,original_profile_callbacks=18,native_warm_mutexes=3,music_PCM_bytes=music,output_bytes_including_silence=output,native_callbacks=len(d['native_five_argument_callback_full_returns']),Source_ingress=len(d['compiled_ingress_full_returns']),SBC_full_returns=len(d['compiled_decoder_full_returns']),native_audio_full_returns=len(d['full_native_returns']))
 return dict(name=d['name'],passed=True,totals=totals,retirement_stage=stage,complete_resident_retirement=is_positive,guard_and_claim_remain_pinned=True,native_STOP_DONE_unload_or_all_writers_not_proven=True)

def verify_provider(d,build,reference):
 row=verify_base(d,build,reference);sy=build['symbols'];tot=row['totals'];rx={int(a):bytes.fromhex(b)for a,b in d['actual_final_RX_zones'].items()}
 def code(a,n):
  candidates=[(z,b)for z,b in rx.items()if z<=a and a+n<=z+len(b)];require(len(candidates)==1,'provider code outside saved RX');z,b=candidates[0];return b[a-z:a-z+n]
 for p in build['selected_native_provider_entry_barriers']:
  raw=code(p['address'],p['patch_bytes']);require(raw.hex()==p['after_hex'],'provider entry patch mismatch')
  # This checks the actual emitted PC-relative load, including the +4
  # literal offset required by the unaligned original Stop entry.
  immediate=struct.unpack('<H',raw[:2])[0]&255;literal=((p['address']+4)&~3)+immediate*4
  require(literal==p['address']+p['patch_bytes']-4 and struct.unpack('<I',code(literal,4))[0]==sy['pg_'+p['name']+'_gate']['value'],'provider PC literal wrong')
 reset=sy['pg_stock_reset']['value']&~1;original=(ROOT/'evidence/firmware-analysis/main_02bd.bin').read_bytes();off=0x48eed0-0x50000
 # GNU assembler emits Thumb ADDS r0,#1 (0130), where original uses
 # ADDS r0,r0,#1 (401c). Both add the same immediate to r0; following CMP
 # overwrites condition flags before STRB/BLT. Accept only these encodings.
 require(code(reset+2,12)==original[off+2:off+14] and code(reset+16,8)==original[off+16:off+24], 'relocated reset loop changed outside equivalent ADD')
 require(original[off+14:off+16].hex()=='401c' and code(reset+14,2).hex()in('401c','0130'),'relocated reset counter is not r0+1')
 literal=reset+4+(struct.unpack('<H',code(reset,2))[0]&255)*4
 require(struct.unpack('<I',code(literal,4))[0]==0x034e3cf4,'relocated reset pool literal')
 reset_events=[e for e in d['CPU_store_journal']if e['phase']=='unclaimed reset relocated whole original five-slot loop' and int(e['PC'],16)==reset+18]
 require(len(reset_events)==5 and {int(e['address'],16)for e in reset_events}=={0x034e3cf4+i*576+12 for i in range(5)} and all(e['value']==0 and e['before_hex']=='01'for e in reset_events),'whole five-slot reset not actual CPU loop')
 def key(e):return(e['name'],e['entry']['ordinal'],e['entry']['current_TCB'],e['entry_SP'])
 entries={key(e):e for e in d['provider_gate_entries']};returns={key(e):e for e in d['provider_gate_full_returns']}
 require(len(entries)==len(d['provider_gate_entries'])==len(returns)==len(d['provider_gate_full_returns']) and set(entries)==set(returns),'provider gate full return pairing')
 for k,e in entries.items():
  s=returns[k]['returned'];require(s['GP16'][13]==e['entry_SP'] and s['GP16'][15]==e['return_PC'] and s['GP16'][4:12]==e['entry']['GP16'][4:12] and s['current_TCB']==e['entry']['current_TCB'],'provider full ABI')
 posts=d['provider_racer_native_POSTs'];checks=d['provider_racer_checks'];require(len(posts)==len(checks)==3 and len(d['provider_racer_actor_entries'])==1,'three actual provider racer runs')
 racer=posts[0]['racer_TCB'];require(all(p['racer_TCB']==racer and p['state']['current_TCB']==d['controller_TCB']for p in posts),'provider POST actor/identity')
 attacks=[(k,e)for k,e in entries.items()if e['entry']['current_TCB']==racer]
 require(len(attacks)==18 and {e['name']for k,e in attacks}=={'start','stop','free','config','reset','seek'},'six provider calls each racer run')
 for k,e in attacks:
  if e['name']not in('free','reset'):require(returns[k]['r0']==8,'foreign provider request forwarded')
 for c in checks:
  require(c['before']==c['after'] and c['results']==[8,8,240,8,240,8] and c['result']['denied']==[n+1 for n in c['prior']['denied']],'private pool/provider changed by foreign racer')
  require(c['void_free_reset_results_are_markers_not_ABI_success'],'void ABI overclaim')
 notes=[e for e in d['provider_allocation_note_entries']if e['args'][0]==0x034e7f48+240 and e['args'][1]==0]
 require(len(notes)==1 and notes[0]['index']==0 and notes[0]['busy']==1 and notes[0]['state']['current_TCB']==d['mixer_TCB'] and notes[0]['state']['CPSR']&128,'private note not actual allocator/excluded Mixer')
 busy=[e for e in d['CPU_store_journal']if e['current_TCB']==d['mixer_TCB'] and e['PC']=='0x48ee8c' and int(e['address'],16)==0x034e3cf4+12 and e['value']==1]
 pins=[e for e in d['CPU_store_journal']if int(e['address'],16)==sy['pg_pinned']['value'] and e['value']==1]
 require(len(busy)==len(pins)==1 and busy[0]['ordinal']<notes[0]['state']['ordinal']<pins[0]['ordinal'] and pins[0]['current_TCB']==d['mixer_TCB'],'native allocation -> private pin provenance')
 first_config=next(e for e in entries.values()if e['name']=='config' and e['entry']['current_TCB']==d['mixer_TCB'])
 require(pins[0]['ordinal']<first_config['entry']['ordinal'],'private config before reservation')
 for e in d['native_stop_entries']:
  require(e['entry']['GP16'][15]==e.get('actual_entry_PC',e['entry_PC']),'cleanup actual PC not logical identity')
  if e['entry_PC']in(0x48ee12,0x48ee58):
   n='stop'if e['entry_PC']==0x48ee12 else'free';require(e['actual_entry_PC']==sy['pg_stock_'+n]['value']&~1,'cleanup relocated body provenance')
 format_stores=[e for e in d['CPU_store_journal']if e['phase']=='unclaimed provider original format forwarding' and e['PC']in('0x48eeb0','0x48eeb6','0x48eebc')]
 require([(int(e['address'],16),e['value'])for e in format_stores]==[(0x034e3cf4+576,3),(0x034e3cf4+576+4,22050),(0x034e3cf4+576+8,8)],'other config original stores')
 for phase in('unclaimed provider original free forwarding','ordinary post-retirement provider free'):
  free=[e for e in d['CPU_store_journal']if e['phase']==phase and e['PC']=='0x48ee64']
  require(len(free)==1 and int(free[0]['address'],16)==0x034e3cf4+576+12 and free[0]['value']==0,'other void free original byte write')
 masks=[e for e in d['CPU_store_journal']if e['phase']=='original allocator skips pinned retired private slot' and int(e['address'],16)==0x034e3cf4+12]
 require(len(masks)==2 and [e['value']for e in masks]==[1,0] and [e['before_hex']for e in masks]==['00','01'],'temporary reserved busy byte not restored')
 for e in masks:
  s=sy['pg_scan_allocator'];require(s['value']<=int(e['PC'],16)<s['value']+s['size'] and e['current_TCB']==d['controller_TCB'],'reserved allocator mask CPU provenance')
 scan=[e for e in d['CPU_store_journal']if e['phase']=='original allocator skips pinned retired private slot' and e['PC']=='0x48ee8c']
 require(len(scan)==1 and int(scan[0]['address'],16)==0x034e3cf4+576+12 and scan[0]['value']==1 and masks[0]['ordinal']<scan[0]['ordinal']<masks[1]['ordinal'],'native allocator reused private slot')
 final=d['provider_reservation_final'];require(final['pinned']==final['epoch']==final['notes']==final['masked_scans']==1 and final['index']==0 and final['runs']==3 and final['denied']==[3]*6,'private reservation terminal')
 for p in d['provider_controls']:require(p.get('private_bytes_preserved',True) and p.get('original_private_busy_restored',True),'other provider changed private bytes')
 rec=next(r for r in d['retirement_records']if r.get('kind')=='actual music before Stop');pcm=bytes.fromhex(rec['PCM_hex']);expected=bytes.fromhex(reference['streams'][1]['packets'][0]['expected_continuous_PCM_hex'])
 require(pcm[:len(expected)]==expected and pcm[len(expected):]==bytes(len(pcm)-len(expected)) and bytes.fromhex(rec['expected_PCM_hex'])==expected,'music output changed by provider protection')
 tot.update(provider_gate_full_returns=len(entries),provider_foreign_racer_runs=3,provider_foreign_rejections=18,original_relocated_reset_busy_stores=5,other_original_format_stores=3,other_original_free_stores=2,private_retired_allocator_mask_stores=2,music_PCM_bytes=len(expected),output_bytes_including_silence=len(pcm))
 row['other_original_config_return']=next(c['configuration_original_return']for c in d['provider_controls']if c['kind']=='unclaimed config and void free')
 row['reset_counter_equivalent_Thumb_ADD_encoding_explicitly_checked']=True
 return row
def verify_aliases(d,build,reference):
 row=verify_provider(d,build,reference);sy=build['symbols'];rx={int(a):bytes.fromhex(raw)for a,raw in d['actual_final_RX_zones'].items()}
 def code(a,n):
  candidates=[(z,b)for z,b in rx.items()if z<=a and a+n<=z+len(b)];require(len(candidates)==1,'alias code not uniquely in saved RX');z,b=candidates[0];return b[a-z:a-z+n]
 for p in build['selected_native_backend_alias_barriers']:
  raw=code(p['address'],p['patch_bytes']);require(raw.hex()==p['after_hex'],'alias entry patch bytes')
  if p['name']=='clear':
   require(p['address']==0x5e75b2 and len(raw)==8 and raw[:2].hex()=='004b' and raw[2:4].hex()=='1847','clear overlap instructions')
   literal=((p['address']+4)&~3);fixed=struct.unpack('<I',code(literal,4))[0]
   require(literal==p['address']+2 and fixed==sy['al_clear_fixed_entry']['value']==0x02fb4718 and fixed&0xffff==0x4718,'clear BX/literal/address overlap')
   require(code(0x5e75ba,2).hex()=='70b5','next function prologue overwritten')
   op=struct.unpack('<I',code(fixed,4))[0];offset=op&0xffffff;offset=offset-(1<<24)if offset&(1<<23)else offset
   require(op>>24==0xea and fixed+8+offset*4==sy['al_clear_gate']['value'],'fixed ARM branch target')
   require(code(sy['al_stock_clear']['value']&~1,8).hex()=='0021017308007047','complete original clear leaf bytes')
  else:
   ldr=p['address']+2;immediate=struct.unpack('<H',code(ldr,2))[0]&255;literal=((ldr+4)&~3)+immediate*4
   require(literal==p['address']+p['patch_bytes']-4 and struct.unpack('<I',code(literal,4))[0]==sy['al_'+p['name']+'_entry']['value'],'alias preserved-r3 shim literal')
 def key(e):return(e['name'],e['entry']['ordinal'],e['entry']['current_TCB'],e['entry_SP'])
 entries={key(e):e for e in d['backend_alias_entries']};returns={key(e):e for e in d['backend_alias_full_returns']}
 require(len(entries)==len(d['backend_alias_entries'])==len(returns)==len(d['backend_alias_full_returns']) and set(entries)==set(returns),'alias return pairing')
 for k,e in entries.items():
  r=returns[k]['returned'];require(r['GP16'][13]==e['entry_SP'] and r['GP16'][15]==e['return_PC'] and r['GP16'][4:12]==e['entry']['GP16'][4:12] and r['current_TCB']==e['entry']['current_TCB'],'alias full ABI')
 checks=d['backend_alias_checks'];posts=d['backend_alias_racer_POSTs'];require(len(checks)==len(posts)==3 and len(d['backend_alias_actor_entries'])==1,'three original-kernel alias runs')
 racer=posts[0]['racer_TCB'];require(all(p['racer_TCB']==racer and p['state']['current_TCB']==d['controller_TCB']for p in posts),'alias racer actor/provenance')
 attacks=[(k,e)for k,e in entries.items()if e['entry']['current_TCB']==racer];require(len(attacks)==18 and {e['name']for k,e in attacks}=={'config','stop','start','seek','clear'},'five alias and interior clear coverage')
 for k,e in attacks:require(returns[k]['r0']==8,'alias attack forwarded')
 for c in checks:
  require(c['before']==c['after'] and c['results']==[8]*6 and c['result']['denied']==[n+k for n,k in zip(c['prior']['denied'],[1,1,1,1,2])],'alias changed private bytes')
 bound=0x034e3cf4+d['provider_reservation_final']['index']*576+16
 clear_attack_objects=[e['args'][0]for k,e in attacks if e['name']=='clear'];require(clear_attack_objects.count(bound)==clear_attack_objects.count(bound+4)==3,'interior receiver escaped coverage')
 require(d['backend_alias_terminal']['denied']==[3,3,3,3,6] and d['backend_alias_terminal']['runs']==3,'alias terminal counters')
 fixed=d['backend_clear_fixed_ARM_entries'];require(len(fixed)==8,'clear fixed bridge count: six rejects, one other object, one cleanup')
 require(all(e['GP16'][15]==0x02fb4718 and e['GP16'][3]==0x02fb4718 and not(e['CPSR']&32)for e in fixed),'actual Thumb to ARM fixed bridge')
 clear=next(e for e in d['native_stop_entries']if e['entry_PC']==0x5e75b2);require(clear['actual_entry_PC']==sy['al_stock_clear']['value']&~1 and clear['entry']['GP16'][15]==clear['actual_entry_PC'] and clear['args'][0]==bound,'private original leaf actual PC/receiver')
 leaf_stores=[e for e in d['CPU_store_journal']if int(e['PC'],16)==(sy['al_stock_clear']['value']&~1)+2]
 other=d['backend_alias_controls'][0]['standalone_other_object']
 require(len(leaf_stores)==2 and {(int(e['address'],16),e['value'])for e in leaf_stores}=={(bound+12,0),(other+12,0)},'copied leaf only modifies admitted private and other object')
 controls=d['backend_alias_controls'];require(len(controls)==1 and [(x['name'],x['returned'])for x in controls[0]['null_receiver_branches']]==[('stop',0xffffffff),('start',0),('seek',0xffffffff)] and controls[0]['clear_return']==0 and controls[0]['original_prepared_byte_cleared'],'original null branches/other clear')
 control=controls[0]['config_absent_callback_control'];require(control['returned']==0xffffffff and control['original_mode_halfword_cleared'] and control['null_receiver_not_valid_original_input'],'valid config fallback control')
 fallback=[e for e in d['CPU_store_journal']if e['phase']=='unclaimed backend config original absent callback fallback' and e['PC']=='0x4cae3e'];require(len(fallback)==1 and int(fallback[0]['address'],16)==control['object']+524 and fallback[0]['size']==2 and fallback[0]['value']==0 and fallback[0]['before_hex']=='0200','original config fallback halfword store')
 start_null=next(e for e in entries.values()if e['name']=='start' and e['entry']['phase']=='unclaimed backend start original null receiver branch');require(start_null['args']==[0,0,0,0x654321],'fourth backend argument clobbered by veneer')
 gap=[f for f in d['declared_fixture_mutations']if f['reason']=='declared backing of original DLL file padding, not physical MMU proof'];require(len(gap)==1,'DLL padding backing fixture not recorded')
 require(all(0x02d4bb74<=s['value']<0x02d4bb74+build['combined_ram_bytes']for n,s in sy.items()if n in('al_clear_fixed_entry','al_clear_gate')),'clear needs external image')
 row['totals'].update(backend_alias_full_returns=len(entries),backend_alias_racer_runs=3,backend_alias_foreign_rejections=18,interior_clear_rejections=3,fixed_clear_ARM_entries=8,original_copied_clear_leaf_stores=2,original_null_backend_branches=3,original_valid_config_fallbacks=1,explicit_original_DLL_padding_regions=1)
 row.update(original_clear_leaf_eight_bytes_and_adjacent_prologue_preserved=True,fixed_bridge_uses_original_single_DLL=True,known_remaining_direct_leaf_writers=[0x5e759e,0x5e75ba],all_leaf_writers_physical_MMU_heap_App_phone_not_verified=True)
 return row
def main():
 out=BASE/'file-v3';out.mkdir(exist_ok=False);guest=json.loads((BASE/'backend-alias-v4-proof.json').read_text());build=json.loads((BASE/'build-v1.json').read_text());reference=json.loads((ROOT/'staging/native-player-sbc-sync/compressed_input_reference_v1.json').read_text());deps=dict(guest['source_sha256'])
 for p in(Path(__file__),BASE/'backend-alias-v4-proof.json',BASE/'guest-v4-terminal-tool-receipt.json',ROOT/'staging/native-player-provider-entries/verify_provider_entry_files_v2.py'):deps[rel(p)]=sha(p)
 require(all(sha(ROOT/p)==h for p,h in deps.items()),'FILE dependency changed');case=guest['cases'][0];p=ROOT/case['path'];require(sha(p)==case['sha256'],'case gzip changed');deps[rel(p)]=case['sha256'];raw=gzip.decompress(p.read_bytes());require(hashlib.sha256(raw).hexdigest()==case['decoded_sha256'],'decoded case changed');d=json.loads(raw);del raw
 try:row=verify_aliases(d,build,reference)
 except BaseException as e:dump(out/'terminal-failure.json',dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),device_IO=False));raise
 dump(out/'backend-alias-integration.json',row);proof=dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=deps,case_count=1,cases=[dict(row,artifact=case['path'],artifact_sha256=case['sha256'])],totals=row['totals'],whole_loader_and_playback_reconstruction=True,all_five_alias_literals_and_return_ABI=True,eight_byte_clear_overlap_and_complete_leaf_preserved=True,actual_fixed_Thumb_to_ARM_original_loaded_image=True,declared_ELF_padding_backing_is_not_native_allocation_or_MMU_proof=True,no_guest_rerun_or_context_restore=True,new_independent_agent_review=False,all_EA_CFG_leaf_writers_STOP_DONE_heap_App_phone_or_device=False,device_IO=False)
 dump(BASE/'ROOT-backend-alias-file-proof-v3.json',proof);print(json.dumps(dict(all_passed=True,totals=row['totals'],other_config_return=row['other_original_config_return'],device_IO=False)),flush=True)
if __name__=='__main__':main()
