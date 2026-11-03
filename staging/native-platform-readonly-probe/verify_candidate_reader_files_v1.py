#!/usr/bin/env python3
"""Replay two completed reader artifacts; no guest import or device action."""
import sys,json,gzip,hashlib,struct
from pathlib import Path
from datetime import datetime,timezone
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent; ROOT=BASE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
IMAGE=0x02d4bb74
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())
def main():
 out=BASE/'ROOT-platform-reader-file-proof-v1.json';assert not out.exists()
 proof=read(BASE/'platform-candidate-reader-v1-proof.json');m=read(BASE/'strict_marker/manifest.json');bundle=read(BASE/'local-platform-probe-bundle-v1.json')
 receipt=read(BASE/'reader-v1-terminal-tool-receipt.json')['actual_terminal_result'];assert receipt['exit_code']==0 and 'session_id'not in receipt
 assert proof['all_passed']and proof['case_count']==2
 sources=dict(proof['source_sha256']);sources.update({str(p.relative_to(ROOT)):sha(p)for p in [Path(__file__),BASE/'platform-candidate-reader-v1-proof.json',BASE/'reader-v1-terminal-tool-receipt.json']})
 for p,h in sources.items():assert sha(ROOT/p)==h,p
 binary=(ROOT/m['combined_file']).read_bytes();assert sha(ROOT/m['combined_file'])==m['binary_sha256']
 n=NativeImage();arm=Cs(CS_ARCH_ARM,CS_MODE_ARM);thumb=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
 rows=[];stores=returns=reads=zone_count=0
 for row in proof['cases']:
  p=ROOT/row['path'];assert sha(p)==row['sha256'];sources[row['path']]=sha(p)
  decoded=gzip.decompress(p.read_bytes());d=json.loads(decoded);assert d['all_passed']and not d['device_IO']and not d['BIN_callback_input_fixture']
  assert d['candidate_sha256']==bundle['candidate_sha256']and len(d['original40_targets'])==40
  assert len(d['native_metadata_rows'])==1 and d['native_metadata_rows'][0]['raw_return']==1 and d['native_metadata_rows'][0]['parsed_checksum']==0x0ca73f5a
  assert set(d['actual_original_loader_callbacks'])=={'0x1fb2f8','0x1fb304','0x1fb3a2','0x1fb3ce','0x1fb3e4'}and all(v>0 for v in d['actual_original_loader_callbacks'].values())
  zones=d['whole_zone_CPU_replay'];replay={k:bytearray.fromhex(z['before_hex'])for k,z in zones.items()}
  for w in d['CPU_write_journal']:
   z=zones[w['zone']];off=w['address']-z['address'];size=w['size'];assert 0<=off and off+size<=z['bytes']
   assert replay[w['zone']][off:off+size].hex()==w['before_hex']
   op=bytes.fromhex(w['opcode_hex']);pc=w['pc']
   actual=binary[pc-IMAGE:pc-IMAGE+len(op)]if m['symbols']['cache_marker_entry']<=pc<IMAGE+len(binary)else n.read(pc,len(op))
   assert actual==op,(hex(pc),actual.hex(),op.hex())
   ins=list((thumb if w['cpsr']&32 else arm).disasm(op,pc));assert len(ins)==1 and ins[0].mnemonic.startswith(('str','stm'))
   replay[w['zone']][off:off+size]=w['value'].to_bytes(size,'little')
  for k,z in zones.items():assert replay[k].hex()==z['after_hex'],k
  assert zones['native_audio_bank']['before_hex']==zones['native_audio_bank']['after_hex']and not d['new_audio_reads']and not d['new_audio_writes']
  first=bytes.fromhex(d['first_private_state_hex']);assert len(first)==124
  expected=(d['tag']+'\0').encode('utf-16le');assert d['getter_and_page_input_utf16_hex']==expected.hex()
  assert bytes(replay['record'])[0x6b8:0x6c2]==expected
  if row['name']=='positive_cached_repeat':
   assert len(d['platform_entries'])==len(d['platform_full_returns'])==1
   assert len(d['actual_platform_MRC_observations'])==2 and len(d['CPU_version_stores'])==5
   cpsr,midr,control,accepted,tag=struct.unpack_from('<5I',first,104);mode=cpsr&31;assert mode in(19,31)and accepted==1
   flags=int(mode==31)|((control&1)<<1)|(control&4)|((control>>9)&8);assert tag==(flags<<12)|((midr>>4)&4095)and d['tag']==f'{tag:04X}'
   for i,cp in enumerate(d['actual_platform_MRC_observations']):
    op=bytes.fromhex(cp['opcode_hex']);pc=cp['PC'];assert binary[pc-IMAGE:pc-IMAGE+4]==op
    word=struct.unpack('<I',op)[0];dest=(word>>12)&15;crn=(word>>16)&15
    assert ((word>>8)&15)==15 and ((word>>21)&7)==0 and (word&15)==0 and ((word>>5)&7)==0 and crn==i and dest==cp['dest']
    assert cp['before']['CPSR']&31 in(19,31)and not cp['before']['CPSR']&32
    assert cp['reference']==[midr,control][i]==cp['after']['GP16'][dest]and cp['after']['GP16'][15]==pc+4
    assert cp['before']['CPSR']==cp['after']['CPSR']
    assert all(a==b for j,(a,b)in enumerate(zip(cp['before']['GP16'],cp['after']['GP16']))if j not in(dest,15))
   entry=d['platform_entries'][0];ret=d['platform_full_returns'][0];assert entry['before']==ret['before']and entry['SP']==ret['after']['GP16'][13]and entry['return_PC']==ret['after']['GP16'][15]
   assert ret['before']['GP16'][4:12]==ret['after']['GP16'][4:12]and (ret['before']['CPSR']^ret['after']['CPSR'])&0xff==0
   repeat=bytes.fromhex(d['repeat_private_state_hex']);assert repeat[40:]==first[40:]and struct.unpack_from('<I',repeat,24)[0]==17 and struct.unpack_from('<I',repeat,16)[0]==2
   assert bytes(replay['private_state'])==repeat
   assert [s['value']for s in d['CPU_version_stores']]==list(struct.unpack('<5H',expected))
   assert len([r for r in d['new_probe_register_instruction_trace']if r['instruction'].startswith('mrs ')])==1
  else:
   assert struct.unpack_from('<I',first,24)[0]==16 and d['tag']=='2.10'
   assert not d['platform_entries']and not d['platform_full_returns']and not d['actual_platform_MRC_observations']and not d['CPU_version_stores']and not d['new_probe_register_instruction_trace']
   assert bytes(replay['private_state'])==first
  for r in d['new_probe_register_instruction_trace']:
   op=bytes.fromhex(r['opcode_hex']);assert binary[r['PC']-IMAGE:r['PC']-IMAGE+len(op)]==op
   assert next(arm.disasm(op,r['PC'])).mnemonic in('mrs','mrc')
  baseline=read(ROOT/'staging/native-player-inline-fields/code-marker/original_baseline-control.json')
  assert d['original_postheader_runtime_sha256']==baseline['original_module_postheader_runtime_sha256']and d['original40_stubs_sha256']==baseline['original40_stubs_sha256']
  stores+=len(d['CPU_write_journal']);returns+=len(d['platform_full_returns']);reads+=len(d['actual_platform_MRC_observations']);zone_count+=len(zones)
  rows.append(dict(name=row['name'],artifact=row['path'],encoded_sha256=sha(p),decoded_sha256=hashlib.sha256(decoded).hexdigest(),CPU_stores=len(d['CPU_write_journal']),whole_zones=len(zones),MRC=len(d['actual_platform_MRC_observations']),sample_full_returns=len(d['platform_full_returns']),tag=d['tag']))
 assert not any(k=='unicorn'or k.startswith('unicorn.')for k in sys.modules)
 data=dict(all_passed=True,case_count=2,cases=rows,totals=dict(CPU_stores=stores,whole_zones=zone_count,MRC_reads=reads,sample_full_returns=returns),source_sha256=sources,ROOT_FILE_only=True,VM_import_or_execution=False,device_IO=False,new_independent_agent_review=False,complete_GP_effective_address_or_full_non_store_CFG_replay=False,physical_CPU_Main_writability_navigation_App_phone_verified=False,limits='Saved exact opcode/store/preimage/whole-zone replay and MRC destination/ABI checks. Hardware register values are emulator model inputs, not physical measurements. Lower FAT/heap/TCB/outer identity fixtures remain; diagnostic is cached initialization snapshot. No CPU model can identify physical unit.',updated_utc=datetime.now(timezone.utc).isoformat())
 with out.open('x')as f:json.dump(data,f,indent=2);f.write('\n')
 print(json.dumps(dict(all_passed=True,case_count=2,totals=data['totals'],VM_import_or_execution=False,device_IO=False)))
if __name__=='__main__':main()
