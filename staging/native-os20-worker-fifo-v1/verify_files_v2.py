#!/usr/bin/env python3
"""No VM imports: replay NEW FIFO metadata/payload and job store journal only.

Checks the compact evidence it can independently reconstruct. It does not
invent a full instruction trace, scheduler model or access-boundary proof.
"""
import sys
sys.dont_write_bytecode=True
import gzip,hashlib,json,struct
from pathlib import Path
from datetime import datetime,timezone
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
G=BASE/'guest-v3';OUT=BASE/'file-v2'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def digest(b):return hashlib.sha256(b).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def segments(path):
 b=path.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
 for i in range(h[10]):
  k,o,a,_,fs,ms,fl,_=struct.unpack_from('<8I',b,h[5]+i*h[9])
  if k==1 and ms:yield a,fs,ms,fl,b[o:o+fs]
def main():
 assert not OUT.exists();OUT.mkdir()
 p=json.load(gzip.open(G/'tail-proof.json.gz','rt'));small=json.loads((G/'guest-proof.json').read_text())
 receipt=json.loads((G/'terminal-tool-receipt.json').read_text())
 assert receipt['actual_terminal_result']['exit_code']==0 and 'session_id'not in receipt['actual_terminal_result']
 assert p['all_passed']and small['all_passed']and sha(G/'tail-proof.json.gz')==small['proof_SHA256']
 for name,h in p['source_sha256'].items():assert sha(ROOT/name)==h,name
 prefix_path=ROOT/p['inherited_prefix'];assert sha(prefix_path)==p['inherited_prefix_SHA256']
 prefix=json.load(gzip.open(prefix_path,'rt'));build=json.loads((BASE/'build-v3/manifest.json').read_text())
 assert p['one_declared_frozen_GP_CPSR_endpoint_restore']==prefix['boundary']['state']
 replay={};rx=[]
 for a,fs,ms,flags,data in segments(ROOT/build['ELF']):
  start=a&~4095;end=(a+ms+4095)&~4095
  if flags&1:
   b=bytearray(end-start);b[a-start:a-start+fs]=data;rx.append((start,bytes(b)))
  else:
   b=bytearray(b'\xa5'*(end-start));b[a-start:a-start+ms]=bytes(ms);b[a-start:a-start+fs]=data
   z=next(z for z in p['zones']if z['start']==start and z['origin']=='NEW_ELF')
   assert digest(b)==z['before_SHA256'];replay[start]=b
 for a,fs,ms,flags,data in segments(ROOT/build['decoder_ELF']):
  if flags&1:
   start=a&~4095;end=(a+ms+4095)&~4095
   block=bytearray(end-start);block[a-start:a-start+fs]=data;rx.append((start,bytes(block)))
 job=next(z for z in p['zones']if z['name']=='declared_job')
 replay[job['start']]=bytearray.fromhex(prefix['whole_zones_after']['declared_job'])
 native=NativeImage();md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
 count=0
 for row in p['protocol_CPU_stores']:
  raw=bytes.fromhex(row['opcode_hex']);pc=row['PC']
  if 0x50000<=pc<0x50000+next(r['size']for r in native.copies if r['runtime_start']==0x50000):
   assert native.read(pc,len(raw))==raw
  else:
   code=next((r for r in rx if r[0]<=pc and pc+len(raw)<=r[0]+len(r[1])),None)
   assert code and code[1][pc-code[0]:pc-code[0]+len(raw)]==raw
  assert row['actor']in prefix['original_TCBs']and row['ordinal']<p['instructions']
  # This compact journal omits register dumps: do not assert independently
  # decoded effective-address coverage or all memory operations.
  z=next((z for z in p['zones']if z['start']in replay and z['start']<=row['address']and row['address']+row['size']<=z['start']+z['size']),None)
  if z:
   b=replay[z['start']];off=row['address']-z['start'];n=row['size']
   assert b[off:off+n].hex()==row['before_hex'],(hex(row['address']),row['ordinal'])
   b[off:off+n]=row['value'].to_bytes(n,'little');count+=1
 for a,b in replay.items():
  z=next(z for z in p['zones']if z['start']==a);assert digest(b)==z['after_SHA256'],hex(a)
 output=next(z for z in p['zones']if z['name']=='declared_PCM_output')
 ref=(ROOT/'staging/native-os20-resident-music-v2/reference-two-streams.pcm').read_bytes()
 assert output['after_SHA256']==digest(ref[:896]+b'\xa5'*(4096-896))
 for z in p['zones']:
  if z['name']in('declared_frame_input','declared_decode_result','input_descriptors'):
   assert z['before_SHA256']==z['after_SHA256']
 sy=build['symbols'];b=replay[0x09110000]
 def words(name,n):
  off=sy[name]['address']-0x09110000;return list(struct.unpack_from('<'+'I'*n,b,off))
 assert words('memory_output_slots',24)==[16,2,256,0xffffffff,1,0]+[0]*18
 assert words('memory_output_control',12)==[1,8,4]+[0]*9
 assert words('owned_media_control',13)==[1,0,3,0,1,256,16000,1,4,0,0,3,16]
 assert words('continuous_media_control',8)==[128,5,896,0,3,0,0,0]
 assert words('media_queue_control',9)[0:7]==[0,0,0,4,0,0,0]
 assert bytes(b[0:85])==b'\xa5'*85
 assert p['actual_submit_tickets']==[4,8,12,16]and p['guard_results']==[-28,0,0,-22,-25]
 for call in p['full_helper_returns']:
  before,after=call['before'],call['after']
  assert call['full_ABI_return']and call['entry_ordinal']<call['return_ordinal']<p['instructions']
  assert before['GP16'][4:12]==after['GP16'][4:12]and before['GP16'][13]==after['GP16'][13]
  mask=0x5f if call['entry']in(0x21b6cc,0x21b6dc)else 0xdf
  assert not((before['CPSR']^after['CPSR'])&mask)
  assert after['GP16'][15]==call['return_PC']
 for window in p['reader_unlocked_copy_lease_full_returns']:
  assert window['actor']==0x0901ff90
  assert window['protocol_before']['slot0'][1]==window['protocol_after']['slot0'][1]==2
  assert window['protocol_before']['slot0'][5]==window['protocol_after']['slot0'][5]==1
 assert len(p['original_context_restores'])==len(p['original_context_destinations'])==31
 for request,result in zip(p['original_context_restores'],p['original_context_destinations']):
  assert request['target']==result['target']and result['state']['GP16'][15]==request['destination_PC']
  assert request['target']in prefix['original_TCBs']and not request['host_context_restore']
 assert p['original_MAIN_patches']==0 and not p['original_Source_factory_reader_registered']
 assert p['exclusive_native_witness']==-200 and not p['native_STOP_DONE']and not p['live_radio_phone_speaker_App_menu_install_acceptance']
 result=dict(all_passed=True,guest_proof=rel(G/'tail-proof.json.gz'),guest_proof_SHA256=sha(G/'tail-proof.json.gz'),
  actual_receipt_SHA256=sha(G/'terminal-tool-receipt.json'),source_sha256={rel(Path(__file__)):sha(Path(__file__))},
  inherited_closed_prefix_not_reverified_or_rerun=True,NEW_FIFO_and_job_CPU_store_preimages_replayed=count,
  replayed_NEW_ELF_regions=len(replay)-1,replayed_job_regions=1,output_RAM_SHA256_matches_896_reference_plus_untouched_canary=True,
  full_helper_returns_rechecked=len(p['full_helper_returns']),reader_copy_leases_through_actual_return=5,
  scheduler_restore_destination_pairs_rechecked=31,
  independent_full_instruction_or_effective_address_replay=False,complete_memory_access_boundary_claim=False,
  original_Source_factory_mixer_hardware_or_STOP_DONE_proof=False,VM_import_or_creation=False,device_IO=False,
  updated_utc=datetime.now(timezone.utc).isoformat())
 (OUT/'FILE-proof.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result),flush=True)
if __name__=='__main__':main()
