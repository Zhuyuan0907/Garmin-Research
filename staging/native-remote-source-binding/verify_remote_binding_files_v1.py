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
 return dict(zip(names,struct.unpack('<24I',get(z,address,96))))
def main():
 proofpath=BASE/'remote-binding-v1-proof.json';proof=json.loads(proofpath.read_text())
 receipt=json.loads((BASE/'guest-v3-terminal-tool-receipt.json').read_text())
 assert proof['all_passed']and len(proof['cases'])==4 and receipt['terminal']and receipt['actual_terminal_result']['exit_code']==0
 assert 'session_id'not in receipt['actual_terminal_result']
 sources=dict(proof['source_sha256']);assert all(sha(ROOT/p)==h for p,h in sources.items())
 remote_build=json.loads((BASE/'build-v1.json').read_text());source=json.loads((ROOT/'staging/native-player-sbc-ingress/build-v3.json').read_text())
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
  events=sorted((e for e in d['CPU_store_journal']+d['declared_fixture_mutations']if e['ordinal']>d['initial_ordinal']),key=lambda e:e['ordinal'])
  assert len({e['ordinal']for e in events})==len(events)
  saved_ordinal=set(checks)
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
  if selected['name']=='Configure_TX_failure_never_admits':assert final['epoch']==0 and not final['accepted']and not d['compiled_decoder_entries']and not d['actual_Source_imports']
  elif 'Suspend'in selected['name']or 'Disconnect'in selected['name']:assert final['epoch']==1 and final['retired']==1 and not final['admitting']and final['stop_requests']==1 and final['last_stop']==0
  else:assert final['accepted_media']==1 and final['rejected_media']>=2
  counts=dict(name=selected['name'],whole_RW_zones=len(z),unchanged_RX_zones=len(rx),native_callbacks=len(entries),Source_ingress=len(d['compiled_ingress_entries']),SBC_full_returns=len(d['compiled_decoder_full_returns']),native_full_returns=len(d['full_native_returns']))
  for k,v in counts.items():
   if isinstance(v,int):totals[k]+=v
  rows.append(counts);print(json.dumps(counts),flush=True);del d,z,rx,snapshots;gc.collect()
 for p in (Path(__file__),proofpath,BASE/'guest-v3-terminal-tool-receipt.json',BASE/'guest-v1-terminal-tool-receipt.json',BASE/'guest-v2-terminal-tool-receipt.json',BASE/'v1-queue-field-erratum.json',BASE/'build-v1-terminal-tool-receipt.json',BASE/'guest-v1/terminal-failure.json',BASE/'guest-v2/terminal-failure.json'):
  sources[str(p.relative_to(ROOT))]=sha(p)
 assert all(sha(ROOT/p)==h for p,h in sources.items())
 assert not any(k=='unicorn'or k.startswith('unicorn.')for k in sys.modules)
 result=dict(all_passed=True,case_count=4,source_sha256=sources,cases=rows,totals=dict(totals),
  same_VM_native_F1_to_existing_Source_SBC_FIFO=True,accepted_Config_full_Start_native_callback_identity_verified=True,
  opcode_preimage_complete_RW_RX_and_selected_ordinal_GP_ABI_checked=True,complete_nonstore_CFG_all_store_effective_addresses_verified=False,
  new_independent_agent_review=False,VM_import_or_execution=False,device_IO=False,phone_or_speaker_or_App_or_warm_install_verified=False,
  one_stream_per_boot_resume_restart_STOP_DONE_unload_unimplemented=True,updated_utc=datetime.now(timezone.utc).isoformat())
 create(BASE/'ROOT-remote-binding-file-proof-v1.json',result);print(json.dumps(dict(all_passed=True,totals=dict(totals),device_IO=False)),flush=True)
if __name__=='__main__':main()
