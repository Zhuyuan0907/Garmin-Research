#!/usr/bin/env python3
"""FILE-only replay of six completed warm resident retirement scopes. No guest execution."""
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
def verify(d,build,reference):
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
 require(d['source_TCB']and d['mixer_TCB']and d['native_ownership_snapshot']==-200 and not d['native_STOP_DONE'],'ownership/lifecycle scope')
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
  expected={'warm_Stop_after_music_and_foreign_actor_rejection':0,'warm_full_PCM_pending_compressed_Stop':4,'warm_Stop_during_actual_Mixer_borrow':3,'native_Disconnect_while_paused_runs_warm_retirement':1}[d['name']]
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

def main():
 out=BASE/'file-v1';out.mkdir(exist_ok=False)
 selected=BASE/'ROOT-selected-warm-retirement-six-scopes-v1.json';guest=json.loads(selected.read_text());build=json.loads((BASE/'build-v1.json').read_text());reference=json.loads((ROOT/'staging/native-player-sbc-sync/compressed_input_reference_v1.json').read_text())
 deps=dict(guest['source_sha256'])
 for p in(Path(__file__),selected,ROOT/'staging/native-player-route-entries/verify_route_entry_files_v1.py'):deps[rel(p)]=sha(p)
 require(all(sha(ROOT/p)==h for p,h in deps.items()),'dependency changed')
 require(guest['case_count']==6 and guest['v1_whole_suite_not_claimed_successful'] and guest['completed_prefix_not_rerun'],'selector scope')
 rows=[]
 try:
  for case in guest['cases']:
   p=ROOT/case['path'];require(sha(p)==case['sha256'],'case artifact changed');deps[rel(p)]=case['sha256']
   receipt=json.loads((ROOT/case['guest_suite_terminal_receipt']).read_text())['actual_terminal'];require(receipt['exit_code']==case['guest_suite_terminal_exit'] and 'session_id'not in receipt,'guest still running')
   raw=gzip.decompress(p.read_bytes())if case.get('encoding')=='gzip-json'else p.read_bytes()
   if case.get('decoded_sha256'):require(hashlib.sha256(raw).hexdigest()==case['decoded_sha256'],'gzip decoded bytes changed')
   d=json.loads(raw);del raw;require(d['name']==case['name'],'wrong case name')
   row=verify(d,build,reference);row.update(artifact=case['path'],artifact_sha256=case['sha256'],guest_suite_terminal_exit=case['guest_suite_terminal_exit']);rows.append(row)
   dump(out/(case['name']+'.json'),row);print(json.dumps(row),flush=True);del d;gc.collect()
 except BaseException as e:
  dump(out/'terminal-failure.json',dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),completed=rows,current_case=case['name'],device_IO=False));raise
 totals={k:sum(r['totals'][k]for r in rows)for k in rows[0]['totals']}
 proof=dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),case_count=6,cases=rows,totals=totals,source_sha256=deps,whole_loader_and_playback_reconstruction=True,callback_and_full_native_retirement_ABI_verified=True,native_Stop_ACK_then_full_remove_then_anchor_and_FIFO_release=True,original_completed_v1_prefix_not_whole_suite_success=True,no_guest_rerun_or_context_restore=True,new_independent_agent_review=False,all_store_effective_addresses_or_complete_CFG=False,heap_radio_output_DMA_still_declared_fixtures=True,guard_claim_and_TCBs_stay_resident=True,native_STOP_DONE_yield_unload_all_writers_App_phone_or_device_verified=False,device_IO=False)
 dump(BASE/'ROOT-warm-retirement-file-proof-v1.json',proof);print(json.dumps(dict(all_passed=True,case_count=6,totals=totals,device_IO=False)),flush=True)
if __name__=='__main__':main()
