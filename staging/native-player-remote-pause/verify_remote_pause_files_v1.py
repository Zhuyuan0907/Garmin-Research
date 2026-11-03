#!/usr/bin/env python3
"""ROOT saved-file reconstruction. Never imports/runs a VM or touches device.
Opcode/preimage/whole-zone and callback ABI checks, not full nonstore CFG.
"""
import sys,json,hashlib,struct,gc,importlib.util
from pathlib import Path
from collections import Counter
from datetime import datetime,timezone
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def create(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def get(z,a,n):
 hits=[(s,b)for s,b in z.items()if s<=a and a+n<=s+len(b)]
 assert len(hits)==1,(hex(a),n)
 s,b=hits[0];return bytes(b[a-s:a-s+n])
def word(z,a):return struct.unpack('<I',get(z,a,4))[0]
def remote(z,address):
 names=('epoch','accepted','admitting','retired','context','channel','lcid','local_mtu','callback','configuration_command','start_command',
   'config_witness','start_witness','inflight','callbacks','media','accepted_media','rejected_media','retirements',
   'start_notifications','early_start_admissions','stop_requests','last_ingress','last_stop')
 d=dict(zip(names,struct.unpack('<24I',get(z,address,96))))
 d.update(zip(('paused','pause_requests','resume_requests','last_playback'),struct.unpack('<4I',get(z,address+160,16))))
 return d
def main():
 proofpath=BASE/'remote-pause-v1-proof.json';proof=json.loads(proofpath.read_text())
 receipt=json.loads((BASE/'guest-v3-terminal-tool-receipt.json').read_text())
 oldreceipt=json.loads((BASE/'guest-v1-terminal-tool-receipt.json').read_text());assert oldreceipt['actual_terminal_result']['exit_code']==1
 assert proof['all_passed']and len(proof['cases'])==6 and receipt['terminal']and receipt['actual_terminal_result']['exit_code']==0
 assert 'session_id'not in receipt['actual_terminal_result']
 sources=dict(proof['source_sha256']);assert all(sha(ROOT/p)==h for p,h in sources.items())
 remote_build=json.loads((BASE/'remote-build-v1.json').read_text());source=json.loads((BASE/'source-build-v2.json').read_text())
 path=ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py'
 spec=importlib.util.spec_from_file_location('file_only_elf',path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 elf=mod.ELF32(ROOT/source['ELF']);stock=NativeImage()
 native=stock.read(0x50000,0xc00000-0x50000);code=(ROOT/remote_build['flat']).read_bytes()
 reference=json.loads((ROOT/'staging/native-player-sbc-sync/compressed_input_reference_v1.json').read_text())['streams'][1]
 decoders={True:Cs(CS_ARCH_ARM,CS_MODE_THUMB),False:Cs(CS_ARCH_ARM,CS_MODE_ARM)}
 totals=Counter();rows=[]
 for selected in proof['cases']:
  p=ROOT/selected['path'];assert sha(p)==selected['sha256'];sources[selected['path']]=selected['sha256']
  d=json.loads(p.read_text());assert d['passed']and not d['device_io']and not d['native_STOP_DONE']
  rx={int(a):bytearray(len(bytes.fromhex(raw)))for a,raw in d['actual_final_RX_zones'].items()}
  rx[0x50000][:]=native;rx[0x09400000][:4]=bytes.fromhex('feffffea')
  for s in elf.sections:
   if s['flags']&6==6 and s['size']:
    a=s['address']&~4095;off=s['address']-a;rx[a][off:off+s['size']]=elf.data(s)
  rx[remote_build['base']][:len(code)]=code
  for patch in d['patches']:
   a=patch['address'];before=bytes.fromhex(patch['before_hex']);after=bytes.fromhex(patch['after_hex'])
   assert get(rx,a,len(before))==before
   base=next(s for s,b in rx.items()if s<=a<a+len(after)<=s+len(b));rx[base][a-base:a-base+len(after)]=after
  for a,b in rx.items():
   assert bytes(b).hex()==d['actual_final_RX_zones'][str(a)]
   assert hashlib.sha256(b).hexdigest()==d['unchanged_after_declared_patches_RX_sha256'][str(a)]
  z={int(a):bytearray.fromhex(raw)for a,raw in d['initial_whole_RW_zones'].items()}
  checks={};snapshots={}
  def collect(state):checks.setdefault(state['ordinal'],[]).append(state)
  for row in d['native_five_argument_callback_entries']:collect(row['entry'])
  for row in d['native_five_argument_callback_full_returns']:collect(row['returned'])
  for row in d['compiled_ingress_entries']:collect(row['entry'])
  for row in d['compiled_ingress_full_returns']:collect(row['returned'])
  for row in d['actual_Source_imports']:collect(row['state'])
  for row in d['source_event_posts']:collect(row['state'])
  for row in d['native_steps']:
   if 'endpoint'in row:collect(row['endpoint'])
  for call in d.get('call_slices',[]):
   for sl in call['slices']:collect(sl['before']);collect(sl['after'])
  for row in d['pause_records']:
   for key in ('before','after'):
    if key in row:collect(row[key]['state'])
   if 'state'in row:collect(row['state'])
  events=sorted((e for e in d['CPU_store_journal']+d['declared_fixture_mutations']if e['ordinal']>d['initial_ordinal']),key=lambda e:e['ordinal'])
  assert len({e['ordinal']for e in events})==len(events)
  saved_ordinal=set(checks)
  if d['initial_ordinal']in saved_ordinal:
   snapshots[d['initial_ordinal']]={a:bytes(b)for a,b in z.items()};saved_ordinal.remove(d['initial_ordinal'])
  for e in events:
   a=int(e['address'],16);before=bytes.fromhex(e['before_hex']);assert get(z,a,len(before))==before
   if e['event_type']=='actual_CPU_store':
    pc=int(e['PC'],16);raw=bytes.fromhex(e['opcode_hex']);assert get(rx,pc,len(raw))==raw
    ins=next(decoders[e['Thumb']].disasm(raw,pc,count=1),None)
    assert ins and ins.size==len(raw)and ins.mnemonic.startswith(('str','stm','push','vstr','vstm','swp')),(hex(pc),raw.hex())
    assert e['GP16'][15]==pc and bool(e['CPSR']&32)==e['Thumb']
    after=(e['value']&((1<<(8*e['size']))-1)).to_bytes(e['size'],'little');totals['CPU_stores']+=1
   else:
    assert e['event_type']=='declared_host_fixture';after=bytes.fromhex(e['after_hex']);totals['explicit_fixture_writes']+=1
   base=next(s for s,b in z.items()if s<=a and a+len(before)<=s+len(b));off=a-base;z[base][off:off+len(before)]=after
   if e['ordinal']in saved_ordinal:
    snapshots[e['ordinal']]={s:bytes(b)for s,b in z.items()};saved_ordinal.remove(e['ordinal'])
  assert not saved_ordinal
  assert all(bytes(b).hex()==d['final_whole_RW_zones'][str(a)]for a,b in z.items())
  addr=remote_build['symbols']['nsg'];assert remote(z,addr)==d['remote_final']
  entries=d['native_five_argument_callback_entries'];returns=d['native_five_argument_callback_full_returns'];assert len(entries)==len(returns)
  for entry,ret in zip(entries,returns):
   gp=entry['entry']['GP16'];rg=ret['returned']['GP16'];ez=snapshots[entry['entry']['ordinal']];rz=snapshots[ret['returned']['ordinal']]
   assert gp[15]==remote_build['symbols']['nsg_native_callback']and gp[:4]==entry['args'][:4]
   assert word(ez,gp[13])==entry['args'][4]and get(ez,gp[2]+4,8).hex()==entry['handle_defined_4_to_11_hex']
   assert remote(ez,addr)==entry['remote']and remote(rz,addr)==ret['remote']
   assert gp[13]==rg[13]and gp[4:12]==rg[4:12]and rg[15]==entry['return_PC']and rg[0]==ret['r0']
   assert not ret['remote']['inflight']and entry['entry']['current_TCB']==ret['returned']['current_TCB']==d['controller_TCB']
   if entry['args'][0]==17:assert entry['native_pending']==4 and not entry['remote']['admitting']
  for row in d['actual_Source_imports']:
   ez=snapshots[row['state']['ordinal']];assert remote(ez,addr)==row['remote']and row['remote']['inflight']==1 and row['remote']['admitting']==1
   assert row['state']['GP16'][15]==source['symbols']['aas_media_ingress']['value']
  for row in d['source_event_posts']:
   if row['state']['current_TCB']==d['controller_TCB']:
    assert row['leases']['media']==row['leases']['callback']==0
    assert remote(snapshots[row['state']['ordinal']],addr)['inflight']==1
  for row in d['native_steps']:
   if 'endpoint'in row:assert remote(snapshots[row['endpoint']['ordinal']],addr)==row['remote_after']
   if 'output_packet'in row:
    expected=bytes.fromhex(reference['packets'][row['output_packet']]['expected_continuous_PCM_hex']);actual=bytes.fromhex(row['actual_PCM_hex'])
    assert expected.hex()==row['expected_prefix_hex']and actual.startswith(expected)and actual[len(expected):]==bytes(len(actual)-len(expected))
    totals['music_PCM_bytes']+=len(expected);totals['original_output_bytes']+=len(actual)
  assert [r['bytes_hex']for r in d['original_message_sends']]==[r['bytes_hex']for r in d['original_message_receives']]
  final=d['remote_final']
  source_fields=('mh_remote_paused','mh_remote_pause_epoch','mh_remote_paused_reads','mh_remote_paused_bytes','mh_remote_pause_requests','mh_remote_resume_requests')
  sy=source['symbols']
  def source_pause(z):return {n:word(z,sy[n]['value'])for n in source_fields}
  def keepalive(z,row):
   assert list(struct.unpack('<13I',get(z,sy['owned_media_control']['value'],52)))==row['owned']
   assert list(struct.unpack('<9I',get(z,sy['media_queue_control']['value'],36)))==row['queue']
   assert get(z,sy['memory_output_slots']['value'],96).hex()==row['slots_hex']
   assert [hashlib.sha256(get(z,0x07700000+i*4096,4096)).hexdigest()for i in range(4)]==row['PCM_pages_sha256']
   assert word(z,sy['continuous_media_control']['value'])==row['offset']
   assert word(z,sy['continuous_anchor_instance']['value'])==row['anchor']
   assert source_pause(z)==row['source_pause']and remote(z,addr)==row['remote']
   assert row['source_TCB']==d['source_TCB']and row['mixer_TCB']in (0,d['mixer_TCB'])
  for row in d['pause_records']:
   for key in ('before','after'):
    if key in row:keepalive(snapshots[row[key]['state']['ordinal']],row[key])
   if row['kind']=='paused_native_reader':
    raw=bytes.fromhex(row['actual_PCM_hex']);assert raw and raw==bytes(len(raw))and row['no_new_decode']
    before,after=row['before'],row['after'];assert before['owned'][:5]==after['owned'][:5]
    assert all(before[k]==after[k]for k in ('queue','slots_hex','PCM_pages_sha256','offset','anchor','source_TCB','mixer_TCB'))
    assert before['source_pause']['mh_remote_paused']==after['source_pause']['mh_remote_paused']==1
    totals['paused_silent_output_bytes']+=len(raw)
   if row['kind']=='paused_queued_actor_output':
    raw=bytes.fromhex(row['actual_PCM_hex']);assert raw and raw==bytes(len(raw))
    assert source_pause(snapshots[row['state']['ordinal']])==row['source_pause']and row['source_pause']['mh_remote_paused']==1
    totals['paused_silent_output_bytes']+=len(raw)
   if row['kind']=='resumed_native_output':
    expected=b''.join(bytes.fromhex(reference['packets'][i]['expected_continuous_PCM_hex'])for i in row['packet_indices'])
    actual=bytes.fromhex(row['actual_PCM_hex']);assert expected.hex()==row['expected_PCM_hex']and actual.startswith(expected)and actual[len(expected):]==bytes(len(actual)-len(expected))
    assert source_pause(snapshots[row['state']['ordinal']])==row['source_pause']and row['source_pause']['mh_remote_paused']==0
    totals['resumed_music_PCM_bytes']+=len(expected);totals['resumed_original_output_bytes']+=len(actual)
   if row['kind']=='Suspend_Source_pause':
    assert row['after']['remote']['admitting']==0 and row['after']['remote']['paused']==1 and row['after']['source_pause']['mh_remote_paused']==1
    assert row['before']['anchor']==row['after']['anchor']and not row['after']['remote']['stop_requests']
  for call in d.get('call_slices',[]):
   assert call['full_native_endpoint']and 1<=len(call['slices'])<=6
   for prev,nxt in zip(call['slices'],call['slices'][1:]):
    assert prev['after']==nxt['before']and nxt['start_PC']==(prev['after']['GP16'][15]|int(bool(prev['after']['CPSR']&32)))
    assert prev['instructions']>0
    totals['same_live_VM_slice_continuations']+=1
  assert source_pause(z)==d['source_pause_final']
  if 'Disconnect'in selected['name']:assert final['retired']==1 and final['stop_requests']==1 and not final['admitting']
  else:assert final['epoch']==1 and not final['retired']and not final['stop_requests']
  if 'profile_rewrite'in selected['name']:assert final['paused']==1 and final['last_playback']and d['source_pause_final']['mh_remote_paused']==1
  else:assert final['paused']==0 and d['source_pause_final']['mh_remote_paused']==0
  counts=dict(name=selected['name'],whole_RW_zones=len(z),unchanged_RX_zones=len(rx),native_callbacks=len(entries),Source_ingress=len(d['compiled_ingress_entries']),SBC_full_returns=len(d['compiled_decoder_full_returns']),native_full_returns=len(d['full_native_returns']))
  for k,v in counts.items():
   if isinstance(v,int):totals[k]+=v
  rows.append(counts);print(json.dumps(counts),flush=True);del d,z,rx,snapshots;gc.collect()
 for p in (Path(__file__),proofpath,BASE/'guest-v1-terminal-tool-receipt.json',BASE/'guest-v2-terminal-tool-receipt.json',BASE/'guest-v3-terminal-tool-receipt.json',BASE/'guest-v1/terminal-failure.json',BASE/'guest-v2/terminal-failure.json',BASE/'source-build-v1-terminal-tool-receipt.json',BASE/'source-build-v2-terminal-tool-receipt.json',BASE/'remote-build-v1-terminal-tool-receipt.json'):
  sources[str(p.relative_to(ROOT))]=sha(p)
 assert all(sha(ROOT/p)==h for p,h in sources.items())
 assert not any(k=='unicorn'or k.startswith('unicorn.')for k in sys.modules)
 result=dict(all_passed=True,case_count=6,source_sha256=sources,cases=rows,totals=dict(totals),
  same_VM_native_F1_to_existing_Source_SBC_FIFO=True,accepted_Config_full_Start_native_callback_identity_verified=True,
  opcode_preimage_complete_RW_RX_and_selected_ordinal_GP_ABI_checked=True,complete_nonstore_CFG_all_store_effective_addresses_verified=False,
  new_independent_agent_review=False,VM_import_or_execution=False,device_IO=False,phone_or_speaker_or_App_or_warm_install_verified=False,
  one_stream_per_boot_resume_restart_STOP_DONE_unload_unimplemented=True,updated_utc=datetime.now(timezone.utc).isoformat())
 create(BASE/'ROOT-remote-pause-file-proof-v1.json',result);print(json.dumps(dict(all_passed=True,totals=dict(totals),device_IO=False)),flush=True)
if __name__=='__main__':main()
