#!/usr/bin/env python3
"""Pure FILE audit of the truthful bounded mixer-creation failure.
Replays captured store preimages/values and final hashes; no VM and no claim
of full non-store semantics or independently recomputed effective addresses.
"""
import sys
sys.dont_write_bytecode=True
import gzip,json,hashlib,struct
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];OUT=BASE/'file-v1'
FAIL=BASE/'guest-v2/terminal-failure.json.gz';PREFIX=BASE/'prefix/ready-endpoint.json.gz'
BUILD=BASE/'build/manifest.json';WARM=ROOT/'staging/native-os20-audio-source-build-v1/manifest.json'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def segments(path):
 b=path.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
 for i in range(h[10]):
  k,o,a,_,fs,ms,fl,_=struct.unpack_from('<8I',b,h[5]+i*h[9])
  if k==1 and ms:yield a,fs,ms,fl,b[o:o+fs]
def main():
 assert not OUT.exists();OUT.mkdir()
 p=json.load(gzip.open(FAIL,'rt'));parent=json.load(gzip.open(PREFIX,'rt'));build=json.loads(BUILD.read_text());warm=json.loads(WARM.read_text())
 assert not p['all_passed']and 'Invalid memory write' in p['error']
 assert p['invalid_access']['address']==0x014a77d8 and p['state']['GP16'][15]==0x358bd8
 assert p['state']['current_TCB']==parent['worker_TCB']==0x183140a0
 regions=p['regions'];replay={int(a):bytearray.fromhex(b)for a,b in parent['whole_ready'].items()}
 for a,fs,ms,fl,data in segments(ROOT/build['ELF']):
  start=a&~4095;end=(a+ms+4095)&~4095;b=bytearray(b'\xa5'*(end-start));b[a-start:a-start+ms]=bytes(ms);b[a-start:a-start+fs]=data;replay[start]=b
 for z in regions:assert len(replay[z['start']])==z['size']and hashlib.sha256(replay[z['start']]).hexdigest()==z['before_SHA256']
 def raw(a,n):
  z=next(z for z in regions if z['start']<=a and a+n<=z['start']+z['size']);return bytes(replay[z['start']][a-z['start']:a-z['start']+n])
 def word(a):return int.from_bytes(raw(a,4),'little')
 initial_public_extent=dict(head=word(0x03a7f174),cached_page=word(0x03a7f178),node_words=[word(0x18308000),word(0x18308004)])
 assert initial_public_extent==dict(head=0x18308000,cached_page=0,node_words=[0,4096])
 journal=p['CPU_store_journal'];assert len(journal)==7111
 for row in journal:
  a,n=row['address'],row['size'];z=next(z for z in regions if z['start']<=a and a+n<=z['start']+z['size'])
  assert z['permissions']&2 and n in(1,2,4)
  assert raw(a,n).hex()==row['before_hex'];assert raw(row['PC'],len(bytes.fromhex(row['opcode_hex']))).hex()==row['opcode_hex']
  off=a-z['start'];replay[z['start']][off:off+n]=row['value'].to_bytes(n,'little')
 for z in regions:assert hashlib.sha256(replay[z['start']]).hexdigest()==z['after_SHA256']
 for z in regions:
  if not z['permissions']&2:assert z['before_SHA256']==z['after_SHA256']
 tts=next(z for z in regions if z['start']==0x02d4b000);assert tts['before_SHA256']==tts['after_SHA256']
 r=p['result'];s=p['Source'];pub=p['publications'];assert len(pub)==1
 refpath=ROOT/'staging/native-os20-resident-music-v2/reference-two-streams.pcm';reference=refpath.read_bytes()[:256]
 assert bytes.fromhex(pub[0]['PCM_hex'])==reference and pub[0]['slot_words']==[4,2,256,0xffffffff,0,0]
 assert r['producer_actor']==r['producer_tcb']==0x0b023f90 and r['producer_entries']==r['packet_copied']==r['packet_poisoned']==r['producer_parked']==1
 assert r['ingress_result']==0 and r['driver_fixture_installed']==r['message_sent']==r['finished']==r['fail_reason']==0
 packet=build['symbols']['packet']['address'];assert raw(packet,85)==b'\xa5'*85
 assert pub[0]['state']['current_TCB']==0x183140a0 and pub[0]['copied_packet_poisoned']==1
 slot=warm['symbols']['memory_output_slots']['value'];assert raw(slot,24)==struct.pack('<6I',4,2,256,0xffffffff,0,0)
 assert s['mh_initialized']==s['mh_os20_ready_posts']==s['mh_os20_ready_post_returns']==1
 assert s['mh_started']==s['mh_stream_error']==s['ms_original_sync_completed']==s['mh_selector_bridge_calls']==0
 assert s['mh_ticket']==4 and s['sbi_processed']==s['mh_pcm_cycle']==1 and s['sbi_errors']==0
 assert word(0x034e5cf8+0x78)==0 and not p['native_descriptor_stores']
 calls=p['native_returns']
 required=('original_context_builder','original_descriptor_registry','sbi_receive_packet','media_queue_step',
  'memory_output_submit','original_source_registration','memory_output_register','ns_capture_registration','original_queue_start')
 for name in required:assert len([c for c in calls if c['name']==name])==1,name
 for c in calls:
  before,after=c['before'],c['after'];assert c['full_ABI_return']
  assert before['GP16'][4:12]==after['GP16'][4:12]and before['GP16'][13]==after['GP16'][13]
  mask=0x5f if c['entry']in(0x21b6cc,0x21b6dc)else 0xdf;assert not((before['CPSR']^after['CPSR'])&mask)
 dest=p['original_destinations'];assert [(d['target'],d['PC'])for d in dest]==[(0x0b023f90,build['symbols']['media_case_producer_v1']['address']&~1),(0x183140a0,0x2fd0ac)]
 assert all(d['host_context_restore']is False and d['state']['current_TCB']==d['target']for d in dest)
 assert word(0x03a7f174)==word(0x03a7f178)==0
 pop=[row for row in journal if row['address']==0x03a7f174];assert len(pop)==1 and pop[0]['PC']==0x3880a8 and pop[0]['value']==0
 diagnostic=[row for row in journal if row['PC']==0x23d6e8];assert [row['value']for row in diagnostic]==[0x6e5d800f,2,0x3b9b95,8192]
 diagnostic_lr=[row for row in journal if row['PC']==0x23d6ea][-1];assert diagnostic_lr['value']==0x388089
 assert any(e['name']=='original_mixer_initializer'and e['actor']==0x183140a0 and e['state']['GP16'][:2]==[8,0]for e in p['entries'])
 assert not any(c['name']in('original_mixer_initializer','original_initializer_sync','original_selector','original_factory','original_prepare','continuous_media_read')for c in calls)
 sys.path.insert(0,str(ROOT/'scripts'));from analyze_native_sections import NativeImage
 source=NativeImage();code=source.read(0x38806c,64);assert raw(0x38806c,64)==code
 proof=dict(all_passed=True,audited_integration_guest_success=False,audited_terminal_guest_EXIT=1,
  terminal_failure=rel(FAIL),terminal_failure_SHA256=sha(FAIL),prefix_SHA256=sha(PREFIX),
  CPU_store_preimages_values_opcodes_replayed=7111,regions_replayed=len(regions),helper_full_returns_checked=len(calls),
  original_context_destinations_checked=2,original_context_creation_and_POST_WAIT_actual=True,
  caller_buffer_poisoned_before_Source_decode=True,one_copied_packet_Source_FIFO_READY_PCM_byte_exact=256,
  original_register_and_queue_start_full_returns=True,initial_public_extent=initial_public_extent,
  consumed_public_extent_store=pop[0],final_public_and_cached_page_heads_zero=True,
  failure=dict(original_mixer_initializer=0x3b9b66,actual_Source_TCB=0x183140a0,original_request_caller_LR=0x3b9b95,
   requested_bytes=8192,allocator_flags=2,original_allocator_page_pop=0x38806c,diagnostic_callsite=0x388084,
   diagnostic_entry=0x23d6e8,diagnostic_code=0x6e5d800f,severity=2,
   original_diagnostic_stack_switch=0x358bc4,actual_invalid_store_PC=0x358bd8,invalid_store_address=0x014a77d8,
   root_cause='sealed synthetic public extent provides only one 4096-byte page; original mixer allocation requests further mapping metadata pages',
   mapping_diagnostic_stack_would_not_make_allocator_succeed=True),
  original_allocator_source=dict(start=0x38806c,bytes=64,hex=code.hex(),SHA256=hashlib.sha256(code).hexdigest()),
  Source_initializer_ready_counters_preserved=True,mixer_TCB_not_published=True,selector_factory_reader_or_mixer_output_not_executed=True,
  TTS_runtime_and_RX_unchanged=True,full_effective_address_or_nonstore_semantics_recomputed=False,
  file_audit_does_not_rerun_guest=True,VM_import_or_creation=False,device_IO=False,
  exclusive_native_witness=-200,native_STOP_DONE=False,physical_install_App_phone_speaker=False,
  source_sha256={rel(p):sha(p)for p in(Path(__file__),FAIL,PREFIX,BUILD,WARM,refpath,ROOT/'scripts/analyze_native_sections.py')})
 with(OUT/'FILE-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
 print(json.dumps({k:v for k,v in proof.items()if k not in('source_sha256','original_allocator_source','consumed_public_extent_store')}),flush=True)
if __name__=='__main__':main()
