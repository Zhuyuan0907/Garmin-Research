#!/usr/bin/env python3
"""ROOT FILE reconstruction of frozen ingress-v4; no VM or device execution.
The store decoder/replay algorithm is a derivative of the sealed SBC verifier,
not a new independent human/agent review. All differences have provenance.
"""
import ast, gc, hashlib, importlib.util, json, struct, sys
from pathlib import Path
from datetime import datetime, timezone
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[1]
OLD=ROOT/'staging/native-player-sbc-sync/verification-v1/verify_sbc_sync_v1_files_v4.py'
OUT=BASE/'root-file-review-v2'
EXTERNAL=0x09900020
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def create(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def require(v,m):
 if not v:raise AssertionError(m)
def source_engine():
 s=OLD.read_text();tree=ast.parse(s);nodes=[]
 for n in tree.body:
  if isinstance(n,ast.FunctionDef) and n.name in ('verify_case','prepare_sync_checkpoints','verify_sync','prepare_sbc_checkpoints','producer_at','verify_sbc_pipeline','main'):continue
  if getattr(n,'lineno',10000)>=499 and not (isinstance(n,ast.FunctionDef)and n.name in ('verify_sbc_copy_state','supported_compiled_stack_fixture','verify_build')):continue
  nodes.append(ast.get_source_segment(s,n))
 s='\n\n'.join(nodes)+'\n'
 s=s.replace("BASE = ROOT / 'staging/native-player-sbc-sync'","BASE = ROOT / 'staging/native-player-sbc-ingress'")
 s=s.replace('len(self.z)==26','len(self.z)==27').replace("'26 tracked whole zones'","'27 permission-declared RW zones including unchanged return sentinel'")
 s=s.replace('len(specs)==29','len(specs)==30').replace('tracked_whole_zones=26','tracked_whole_zones=27').replace('actual_RW_zones_from_frozen_parent_permission_recipe=25','actual_RW_zones_from_frozen_parent_permission_recipe=27')
 s=s.replace("view['media']==view['callback']==1 and view['borrow']==0 and word(z,sy['owned_media_control']['value']+4)==1","view['media']==view['callback']==1+int(bool(view['borrow'])) and word(z,sy['owned_media_control']['value']+4)==1")
 s=s.replace("require(e['current_TCB']==S and e['CPSR']&0xff==0x1f and pc==mm+16,'Declared compressed copy on unlocked Source only')","require(e['current_TCB']==C and e['CPSR']&0xff==0x1f and pc==mm+16,'Copied foreign packet on actual controller')\n        view=rp.leases(z);require(view['media']==view['callback']==1 and not view['borrow'],'Foreign copied payload typed lifetime')")
 s=s.replace("word(z,q+20)==0 and e['current_TCB']==S,'Whole compressed copy completes before queue count publication'","word(z,q+20)==0 and e['current_TCB']==C,'Whole foreign compressed copy completes before queue count publication'")
 compile(s,'generated-file-engine-v2.py','exec')
 p=OUT/'generated-file-engine-v2.py'
 with p.open('x')as f:f.write(s)
 spec=importlib.util.spec_from_file_location('root_file_engine',p);e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
 return e
def producer(e,z,sy):
 return dict(owned=list(struct.unpack('<13I',e.get(z,sy['owned_media_control']['value'],52))),queue=list(struct.unpack('<9I',e.get(z,sy['media_queue_control']['value'],36))),started=e.word(z,sy['mh_started']['value']),stream_error=e.word(z,sy['mh_stream_error']['value']),ingress=[e.word(z,sy[n]['value'])for n in ('sbi_callbacks','sbi_accepted','sbi_rejected','sbi_ingress_posts','sbi_capacity_posts','sbi_source_events','sbi_processed','sbi_errors')])
def add(rp,label,st,view=None):rp.enqueue(label,st,view);rp.checkpoints.add(st['ordinal'])
def verify_case(e,d,n,elf,sy,reference):
 rp=e.Replay(d,n,elf,sy);rp.cold()
 for key,field in [('original_scheduled_actor_entries','state'),('original_kernel_events','state'),('actual_condition_entries','state'),('original_mixer_ACK8_entries','state'),('original_message_sends','state'),('original_message_receives','state')]:
  for row in d[key]:add(rp,key,row[field])
 for row in d['terminal_register_snapshots']:add(rp,'controller/idle endpoint',row)
 for row in d['declared_service_calls']:
  add(rp,'declared service before',row['before']);add(rp,'declared service after',row['after'])
 for key in ('full_native_returns','original_mixer_call_site_returns'):
  for row in d[key]:
   add(rp,key+' entry',row['entry'],row.get('entry_leases'));add(rp,key+' return',row['returned'],row['return_leases'])
 for key in ('original_sync_entries','compiled_ingress_entries','compiled_decoder_entries','producer_entries'):
  for row in d[key]:add(rp,key,row['entry'],row.get('leases'))
 for key in ('full_original_sync_returns','compiled_ingress_full_returns','compiled_decoder_full_returns'):
  for row in d[key]:add(rp,key,row['returned'],row.get('leases'))
 for row in d['source_event_posts']:add(rp,'Source POST',row['state'],row['leases'])
 prefix=d['Stage1_no_input_prefix'];add(rp,'Stage1 no input',prefix['registers'])
 for row in d['CPU_store_journal']:
  if int(row['address'],16)==sy['owned_media_control']['value']+32:rp.checkpoints.add(row['ordinal'])
 counts=rp.run();z=rp.final
 for row in d['producer_entries']+d['compiled_ingress_entries']:
  ez=rp.snapshots[row['entry']['ordinal']];require(producer(e,ez,sy)==row['producer'],'Actual producer controls at entry')
  gp=row['entry']['GP16'];require(gp[15]==sy[row.get('symbol','aas_media_ingress')]['value'],'Exact compiled producer entry PC')
  if row.get('symbol')not in ('media_queue_callback','sbi_capacity_wake') and 'symbol'in row:
   e.check_actor(row['entry'],e.S)
   if row['symbol']!='media_queue_step':
    view=row['leases'];require(view['media']==view['callback']==1+int(bool(view['borrow'])),'Source lease count covers its frame plus actual suspended Mixer')
    require(e.word(ez,e.RECORD+0x160)==sy['mcs_queue_bridge']['value'],'Provider coherence at producer entry')
   if row['leases']['borrow']:
    require(row['producer']['started']==1,'Capacity Source cannot perform first registration')
    require(e.word(ez,e.RECORD+0xf0)==row['leases']['selected_instance'] and row['leases']['selected_session'],'Capacity native index0 or other selected identity coherent')
  elif row.get('symbol')=='media_queue_callback':e.check_actor(row['entry'],e.C)
  elif row.get('symbol')=='sbi_capacity_wake':e.check_actor(row['entry'],e.M)
 pz=rp.snapshots[prefix['registers']['ordinal']]
 require(producer(e,pz,sy)==prefix['producer'] and prefix['state'][30:34]==[e.S,1,1,0],'Stage1 actual initialized Source')
 require(not prefix['producer']['owned'][8] and not prefix['producer']['started'] and e.word(pz,e.MIXER+0x78)==0 and not prefix['state'][10],'No embedded first packet, registered ticket or Mixer before foreign input')
 ingress=d['compiled_ingress_entries'];returns=d['compiled_ingress_full_returns']
 require(len(ingress)==len(returns),'Foreign compiled callback full returns')
 for row,ret in zip(ingress,returns):
  ez=rp.snapshots[row['entry']['ordinal']];rz=rp.snapshots[ret['returned']['ordinal']];gp=row['entry']['GP16'];rg=ret['returned']['GP16']
  e.check_actor(row['entry'],e.C);e.check_actor(ret['returned'],e.C)
  require(gp[:3]==[0xf1,0,0] and gp[3]==EXTERNAL and e.word(ez,gp[13])==row['bytes'],'Compiled four-arg shim supplied exact fifth callback argument')
  require(e.get(ez,EXTERNAL,row['bytes']).hex()==row['packet_hex'],'Exact foreign compressed input RAM')
  require(gp[13]==rg[13] and gp[4:12]==rg[4:12] and rg[15]==row['return_PC'] and ret['r0']==rg[0],'Foreign full SP/callee-saved/PC/R0 return')
  require(rp.leases(rz)['media']==rp.leases(rz)['callback']==0,'Foreign borrowed data leases ended by full return')
  if ret['r0']:
   require(not any(row['entry']['ordinal']<r['entry']['ordinal']<ret['returned']['ordinal'] for r in d['compiled_decoder_entries']),'Rejected foreign input does not decode')
 for row in d['source_event_posts']:
  view=row['leases'];ez=rp.snapshots[row['state']['ordinal']]
  if row['state']['current_TCB']==e.C:
   require(view['media']==view['callback']==0 and row['foreign_callback_pending'],'After-copy POST has zero foreign borrowed-data refs while resident callback remains live')
   require(producer(e,ez,sy)['queue'][2]>0,'Foreign Source wake follows owned queue publication')
  elif row['state']['current_TCB']==e.M:
   require(row['mixer_full_frame_pending'] and view['borrow'] and view['media']==view['callback']==1,'Capacity POST retains genuine native Mixer full frame')
   require(row['producer']['started']==1 and row['producer']['queue'][2]>0,'Capacity notification only for started source and queued packet')
 decoder=d['compiled_decoder_entries'];dr=d['compiled_decoder_full_returns'];require(len(decoder)==len(dr),'Every decoder full return')
 for row,ret in zip(decoder,dr):
  ez=rp.snapshots[row['entry']['ordinal']];rz=rp.snapshots[ret['returned']['ordinal']];gp=row['entry']['GP16'];rg=ret['returned']['GP16']
  e.check_actor(row['entry'],e.S);e.check_actor(ret['returned'],e.S)
  require(gp[13]==rg[13] and gp[4:12]==rg[4:12] and rg[15]==row['return_PC'] and ret['r0']==rg[0],'Decoder exact full SP/GP/PC/R0')
  require(e.word(ez,gp[13])==row['result_pointer'] and e.get(ez,gp[0],gp[1]).hex()==row['frame_hex'],'Decoder stack fifth argument and owned frame bytes')
  require(list(struct.unpack('<9I',e.get(rz,row['result_pointer'],36)))==ret['result'],'Decoder result actual memory readback')
  require(ret['r0']in (0,0xfffffffa),'Only actual success or CRC error')
 declared={bytes.fromhex(p['packet_hex']):p for p in reference['packets']};bad=bytes.fromhex(reference['bad_later_frame_CRC_packet_hex'])
 parses=[r for r in d['producer_entries']if r['symbol']=='owned_packet_parse'];submits=[r for r in d['producer_entries']if r['symbol']=='memory_output_submit'];commits=[];reset=False
 for i,row in enumerate(parses):
  lo=row['entry']['ordinal'];hi=parses[i+1]['entry']['ordinal']if i+1<len(parses)else max(x['ordinal']for x in d['CPU_store_journal'])+1
  ez=rp.snapshots[lo];gp=row['entry']['GP16'];raw=e.get(ez,gp[3],e.word(ez,gp[13]));codec=[r for r in dr if lo<r['entry']['ordinal']<hi];subs=[r for r in submits if lo<r['entry']['ordinal']<hi]
  require(0x07902000<=gp[3] and gp[3]+len(raw)<=0x07906000 and (raw in declared or raw==bad),'Actual copied compressed queue input')
  if raw==bad:
   require([r['r0']for r in codec]==[0,0xfffffffa] and not subs,'CRC-later-frame creates no private PCM publication')
   require(i+1<len(parses),'CRC recovery next parser')
   nz=rp.snapshots[hi]
   require(all(e.get(ez,0x07700000+j*4096,4096)==e.get(nz,0x07700000+j*4096,4096)for j in range(4))and e.get(ez,sy['memory_output_slots']['value'],96)==e.get(nz,sy['memory_output_slots']['value'],96),'CRC preserves entire PCM FIFO pages and slot state')
   reset=True;continue
  require([r['r0']for r in codec]==[0,0] and len(subs)==1,'Two full decoder successes precede one packet submission')
  expected=bytes.fromhex(declared[raw]['expected_after_reset_PCM_hex'if reset else'expected_continuous_PCM_hex']);reset=False
  sub=subs[0];sz=rp.snapshots[sub['entry']['ordinal']]
  require(sub['args'][:2]==[0x07900000,len(expected)] and e.get(sz,0x07900000,len(expected))==expected,'Actual private gather equals frozen HOST SBC/FIR reference, never HOST seeded PCM')
  cs=[r for r in d['CPU_store_journal']if lo<r['ordinal']<hi and int(r['address'],16)==sy['owned_media_control']['value']+32]
  require(len(cs)==1 and cs[0]['current_TCB']==e.S and cs[0]['value']==len(commits)+1,'Exactly one Source FIFO commit per whole packet')
  cz=rp.snapshots[cs[0]['ordinal']];owned=producer(e,cz,sy)['owned'];ticket=e.word(cz,sy['tickets']['value']+4*((owned[3]-1)%4));slot=ticket&3
  words=struct.unpack('<6I',e.get(cz,sy['memory_output_slots']['value']+slot*24,24))
  require(words[:3]==(ticket,2,len(expected)) and e.get(cz,0x07700000+slot*4096,len(expected))==expected,'Exact published READY slot ticket and whole PCM copy')
  commits.append(dict(ticket=ticket,PCM_bytes=len(expected),expected_PCM_hex=expected.hex(),commit_ordinal=cs[0]['ordinal']))
 music=bytes.fromhex(''.join(r['expected_PCM_hex']for r in commits));audio=b''.join(bytes.fromhex(r['PCM_hex'])for r in d['original_mixer_call_site_returns'])
 record_audio=[];record_music=[]
 for row in d['records']:
  if 'PCM_hex'in row:raw=bytes.fromhex(row['PCM_hex'])
  elif 'first_PCM_hex'in row:raw=bytes.fromhex(row['first_PCM_hex']+row['second_PCM_hex'])
  else:continue
  expected=bytes.fromhex(row['HOST_expected_PCM_hex']);require(raw.startswith(expected) and raw[len(expected):]==bytes(len(raw)-len(expected)),'Per-cycle actual music plus explicitly silent underrun')
  record_audio.append(raw);record_music.append(expected)
 require(b''.join(record_audio)==audio and b''.join(record_music)==music,'All actual native output matches whole-packet commit order with explicit silence')
 for row in d['full_native_returns']:
  e.check_actor(row['entry'],e.M);e.check_actor(row['returned'],e.M)
  require(row['returned']['GP16'][13]==row['entry_SP']+64 and row['returned']['GP16'][4:12]==row['entry']['GP16'][4:12] and row['returned']['GP16'][15]==row['return_PC'],'Original complete native frame SP/GP/LR return')
  require(row['entry_leases']['borrow'] and row['return_leases']['borrow']and row['return_leases']['media']==row['return_leases']['callback']==1,'Original full frame retains Mixer leases after capacity Source returns')
 require([r['bytes_hex']for r in d['original_message_sends']]==[r['bytes_hex']for r in d['original_message_receives']],'Actual original message FIFO ordered copied bodies')
 sync=d['full_original_sync_returns'];acks=d['original_mixer_ACK8_entries'];require(len(sync)==len(acks)==len(d['original_sync_entries']),'One actual full synchronization per native ACK')
 for row,ret,ack in zip(d['original_sync_entries'],sync,acks):
  e.check_actor(row['entry'],e.S);e.check_actor(ret['returned'],e.S);e.check_actor(ack['state'],e.M)
  require(row['entry']['ordinal']<ack['state']['ordinal']<ret['returned']['ordinal'] and row['call_args'][:3]==[e.RECORD,1,0]and row['CONFIG_mixer_TCB']==e.M,'Actual CONFIG capability, native sync ABI and ACK order')
  require(ret['returned']['GP16'][13]==row['entry_SP']and ret['returned']['GP16'][4:12]==row['entry']['GP16'][4:12]and ret['r0']==0,'Original fullsync SP/GP/R0 return')
  require(rp.leases(rp.snapshots[row['entry']['ordinal']])['media']==rp.leases(rp.snapshots[row['entry']['ordinal']])['callback']==0,'First native sync requires foreign/Source borrowed-data refs quiescent')
 terminal=producer(e,z,sy);require(terminal==d['producer_terminal']and terminal['owned'][8]==len(commits),'Actual terminal producer readback and commit count')
 require(terminal['owned'][1]==terminal['owned'][4]==terminal['queue'][2]==terminal['queue'][5]==terminal['queue'][6]==terminal['stream_error']==0,'No unfinished packet/FIFO/decoder or stream error')
 require(not d['native_STOP_DONE']and not d['device_io']and d['native_ownership_snapshot']==-200,'No synthetic native completion or device claim')
 counts.update(name=d['name'],actual_final_RX_zones=rp.final_RX_verified,decoder_full_returns=len(dr),decoder_successes=sum(r['r0']==0 for r in dr),CRC_failures=sum(r['r0']==0xfffffffa for r in dr),foreign_callback_full_returns=len(returns),native_full_returns=len(d['full_native_returns']),full_sync_returns=len(sync),capacity_posts=terminal['ingress'][4],music_bytes=len(music),silence_bytes=len(audio)-len(music),output_bytes=len(audio),copy_guards=dict(rp.copy_counts))
 return counts
def main():
 OUT.mkdir(exist_ok=False);e=source_engine();proofp=BASE/'sbc-ingress-v4-proof.json';proof=json.loads(proofp.read_text());sources=dict(proof['source_sha256'])
 require(proof['all_passed']and proof['case_count']==6 and sha(proofp)=='dc3b33b1a3f3e01e41dc66dafb6f5bc1cc70115613cb5542b4cc2985d46289a5','Exact selected ROOT guest-v4')
 for p,h in sources.items():require(sha(ROOT/p)==h,'Frozen input '+p)
 require(json.loads((BASE/'guest-v4/inputs-at-run.json').read_text())==sources,'Frozen actual input registry')
 build,elf,sy=e.verify_build(BASE/'build-v3.json',sources);n=e.NativeImage();rows=[]
 try:
  for case in proof['cases']:
   p=ROOT/case['path'];require(sha(p)==case['sha256'],'Frozen actual case');d=json.loads(p.read_text());reference=json.loads((ROOT/'staging/native-player-sbc-sync/compressed_input_reference_v1.json').read_text())['streams'][d['stream_index']]
   row=verify_case(e,d,n,elf,sy,reference);rows.append(row);sources[case['path']]=case['sha256'];print(json.dumps(dict(case=row['name'],stores=row['CPU_stores'],music_bytes=row['music_bytes'],FILE_only=True)),flush=True);del d;gc.collect()
  totals={k:sum(r[k]for r in rows)for k in ('CPU_stores','joint_events','tracked_whole_zones','actual_final_RX_zones','decoder_full_returns','decoder_successes','CRC_failures','foreign_callback_full_returns','native_full_returns','full_sync_returns','capacity_posts','music_bytes','silence_bytes','output_bytes')}
  require(totals['CPU_stores']==256485 and totals['joint_events']==256705 and totals['decoder_full_returns']==24 and totals['native_full_returns']==58 and totals['music_bytes']==3988 and totals['silence_bytes']==8556,'Exact six-case aggregates')
  for p in (proofp,Path(__file__).resolve(),OLD,OUT/'generated-file-engine-v2.py',BASE/'guest-v4-terminal-tool-receipt.json'):sources[str(p.relative_to(ROOT))]=sha(p)
  require(not any(k=='unicorn'or k.startswith('unicorn.')for k in sys.modules),'No VM import')
  result=dict(all_passed=True,ROOT_FILE_reconstruction=True,new_independent_agent_review=False,source_sha256=sources,case_count=6,cases=rows,totals=totals,scope='Saved store semantics, joint whole RW and final RX replay, actual foreign/Source/Mixer frames, copied publications and HOST reference comparison. Not a trace of every non-store instruction or a device/phone/SEP registration test.',callback_refs_zero_is_not_native_full_callback_quiescence=True,device_IO=False,guest_rerun=False,native_heap_exclusive_STOP_DONE_phone_App_speaker_verified=False)
  create(OUT/'ROOT-ingress-v4-file-reconstruction.json',result);print(json.dumps(dict(all_passed=True,totals=totals)),flush=True)
 except BaseException as ex:
  create(OUT/'terminal-failure.json',dict(all_passed=False,error=str(ex),completed_cases=rows,guest_rerun=False,device_IO=False));raise
if __name__=='__main__':main()
