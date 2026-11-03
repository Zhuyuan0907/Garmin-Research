#!/usr/bin/env python3
"""Reconstruct both loader and playback from saved files, without guest runs."""
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
 guest=json.loads((BASE/'reserved-tail-integration-v2-proof.json').read_text());build=json.loads((BASE/'build-v2.json').read_text())
 deps=dict(guest['source_sha256'])
 for p in [Path(__file__),BASE/'reserved-tail-integration-v2-proof.json',BASE/'guest-v2-terminal-tool-receipt.json']:
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
 require(len(d['reader_gate_entries'])==len(d['reader_gate_full_returns'])==5,'missing gate full returns')
 for entry,ret,desc in zip(d['reader_gate_entries'],d['reader_gate_full_returns'],d['caller_private_reader_descriptors']):
  require(entry['entry_SP']==ret['returned']['GP16'][13] and entry['return_PC']==ret['returned']['GP16'][15],'gate ABI stack/PC')
  require(entry['entry']['GP16'][4:12]==ret['returned']['GP16'][4:12],'gate callee saved')
  require(desc['pointer']!=entry['args'][0] and desc['words'][7]==build['protected_reader_limit'],'shared instead of private descriptor')
 for i,reload in enumerate(d['guarded_native_voice_reloads']):
  require(reload['before_tail_sha256']==reload['after_tail_sha256'] and reload['producer_before']==reload['producer_after'],'protected player changed')
  require(reload['status']==[11,11,11,4,9][i],'original reader return codes')
  if i<3: require(reload['original_voice_registration'] and not reload['no_file_copy'],'stock voice skipped')
  if i==3: require(reload['no_file_copy']and reload['no_new_voice_execution']and reload['shared_capacity_perturbation'],'oversize file entered')
  if i==4: require(not reload['no_file_copy']and reload['no_new_voice_execution']and reload['shared_capacity_perturbation'],'oversize RAM executed')
  require(build['protected_tail_start']<=build['symbols']['resident_loader_read_gate']['value'],'gate outside protected code')
 require(len(d['continuous_output_records'])==6 and d['remote_final']['epoch']==1 and d['remote_final']['accepted_media']==6,'continuous single stream')
 music_bytes=0;output_bytes=0
 for r in d['continuous_output_records']:
  actual=bytes.fromhex(r['PCM_hex']);expected=bytes.fromhex(r['expected_prefix_hex'])
  require(actual[:len(expected)]==expected and actual[len(expected):]==bytes(len(actual)-len(expected)),'music/silence output changed')
  music_bytes+=len(expected);output_bytes+=len(actual)
 totals.update(guard_full_returns=5,original_voice_reloads=3,reader_rejections=2,music_PCM_bytes=music_bytes,output_bytes_including_silence=output_bytes)
 totals.update(native_callbacks=len(d['native_five_argument_callback_full_returns']),Source_ingress=len(d['compiled_ingress_full_returns']),SBC_full_returns=len(d['compiled_decoder_full_returns']),native_audio_full_returns=len(d['full_native_returns']))
 proof=dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),case_count=1,totals=totals,source_sha256=deps,
  complete_loader_and_playback_zone_reconstruction=True,selected_store_opcode_and_callback_ABI=True,
  no_guest_rerun_or_context_restore=True,new_independent_agent=False,complete_nonstore_CFG_or_all_store_effective_addresses=False,
  stock_address_single_DLL_with_forty_original_exports=True,three_stock_voice_reloads_preserve_player=True,caller_local_reader_limit_preserved=True,
  original_selector_whole_concurrency_or_physical_install_not_proven=True,warm_heap_ownership_menu_pin_phone_or_device=False,device_IO=False)
 dump(BASE/'ROOT-reserved-tail-file-proof-v1.json',proof);print(json.dumps(dict(all_passed=True,totals=totals,device_IO=False)),flush=True)
if __name__=='__main__':main()
