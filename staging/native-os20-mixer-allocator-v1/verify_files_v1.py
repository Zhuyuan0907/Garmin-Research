#!/usr/bin/env python3
"""FILE-only audit: true original backing append/mixer init, later grant race."""
import sys
sys.dont_write_bytecode=True
import json,gzip,hashlib,struct
from pathlib import Path
from prepare_prefix_v1 import reconstruct,segments
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];OUT=BASE/'file-v1'
FAIL=BASE/'guest-v1/terminal-failure.json.gz';BUILD=BASE/'build-v2/manifest.json'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def main():
 assert not OUT.exists();OUT.mkdir();p=json.load(gzip.open(FAIL,'rt'));prefix=reconstruct();b=json.loads(BUILD.read_text())
 assert not p['all_passed']and 'compiled_media_C_check_failed' in p['error'];assert p['result']['fail_reason']==6
 replay={int(a):bytearray.fromhex(v)for a,v in prefix['whole_ready'].items()};regions=p['regions']
 for a,fs,ms,fl,data in segments(ROOT/b['ELF']):
  start=a&~4095;end=(a+ms+4095)&~4095;s=bytearray(b'\xa5'*(end-start));s[a-start:a-start+ms]=bytes(ms);s[a-start:a-start+fs]=data;replay[start]=s
 replay[0x183ff000]=bytearray(b'\xa5'*4096+b'\xcc'*65536+b'\xa5'*4096)
 for z in regions:assert len(replay[z['start']])==z['size']and hashlib.sha256(replay[z['start']]).hexdigest()==z['before_SHA256']
 def raw(a,n):
  z=next(z for z in regions if z['start']<=a and a+n<=z['start']+z['size']);return bytes(replay[z['start']][a-z['start']:a-z['start']+n])
 def word(a):return int.from_bytes(raw(a,4),'little')
 rows=p['CPU_store_journal'];assert len(rows)==3035
 for r in rows:
  a,n=r['address'],r['size'];z=next(z for z in regions if z['start']<=a and a+n<=z['start']+z['size'])
  assert z['permissions']&2 and n in(1,2,4)and raw(a,n).hex()==r['before_hex']
  assert raw(r['PC'],len(bytes.fromhex(r['opcode_hex']))).hex()==r['opcode_hex']
  off=a-z['start'];replay[z['start']][off:off+n]=r['value'].to_bytes(n,'little')
 for z in regions:
  assert hashlib.sha256(replay[z['start']]).hexdigest()==z['after_SHA256']
  if not z['permissions']&2:assert z['after_SHA256']==z['before_SHA256']
 assert raw(0x183ff000,4096)==raw(0x18410000,4096)==b'\xa5'*4096
 calls=p['native_returns'];assert len(calls)==82
 for c in calls:
  before,after=c['before'],c['after'];assert c['full_ABI_return']
  assert before['GP16'][4:12]==after['GP16'][4:12]and before['GP16'][13]==after['GP16'][13]
  mask=0x5f if c['entry']in(0x21b6cc,0x21b6dc)else 0xdf;assert not((before['CPSR']^after['CPSR'])&mask)
 append=p['append_full_returns'];assert len(append)==1
 assert append[0]['before']['GP16'][1:4]==[1,0,0]and append[0]['actor']==0x183140a0
 assert append[0]['virtual_pool_header_after_hex']==append[0]['virtual_pool_header_before_hex']
 supply=p['allocator_supply_result'];assert supply==[0x183140a0,1,0x18308000,0,0x18301000,32768,0x18400000,0,0x18301000,98304,1,0,1,0]
 opaque=[c for c in calls if c['name']=='original_opaque_allocator'];assert [c['before']['GP16'][:3]for c in opaque]==[[8192,2,0],[240,2,0]]
 assert all(c['actor']==0x183140a0 and c['after']['GP16'][0]for c in opaque)
 maps=[c for c in calls if c['name']=='original_software_page_mapping'];assert [(c['before']['GP16'][0],c['before']['GP16'][1])for c in maps]==[(0x18316000,0x18400000),(0x18315000,0x18401000)]
 mixer=word(0x034e5cf8+0x78);assert mixer==0x183164c8
 assert word(0x034e5cf8+0x64)==0x2fa0dd and word(0x034e5cf8+0x70)==0x0117140c
 queue=word(0x034e5cf8+0x30);top=word(0x034e5cf8+0x6c);base=word(0x034e5cf8+0x2c)
 assert queue==0x18316538 and top-base==8192 and mixer==((top-108)&~7)and word(mixer+8)==queue
 for name in('original_context_builder','original_descriptor_registry','original_mixer_initializer','original_initializer_sync','original_mixer_sync_ACK','ms_validate_completed_sync','mcs_handoff_source_to_mixer'):
  rs=[c for c in calls if c['name']==name];assert len(rs)==1,name
 grant=next(c for c in calls if c['name']=='mcs_handoff_source_to_mixer');select=next(c for c in calls if c['name']=='mcs_mixer_selector_begin')
 assert grant['actor']==0x183140a0 and grant['after']['GP16'][0]==0
 assert select['actor']==mixer and select['before']['GP16'][1]==0x2fa299 and select['after']['GP16'][0]==0xffffff37
 assert select['return_ordinal']<grant['entry_ordinal']
 assert next(c for c in calls if c['name']=='ns_bind_selected')['after']['GP16'][0]==0xffffff37
 assert p['Source']['ms_original_sync_completed']==1 and p['Source']['mh_started']==0 and p['Source']['mh_stream_error']==1
 assert p['Source']['mh_selector_denied']==1 and p['Source']['mh_original_selector_returns']==0
 assert len(p['original_destinations'])==9 and all(d['host_context_restore']is False for d in p['original_destinations'])
 assert not any(c['name']in('original_selector','original_factory','original_prepare','continuous_media_read','mcs_pull_bridge')for c in calls)
 assert p['result']['driver_fixture_installed']==p['result']['message_sent']==0
 sys.path.insert(0,str(ROOT/'scripts'));from analyze_native_sections import NativeImage
 ni=NativeImage();source=[]
 for a,n in[(0x38806c,80),(0x3881bc,30),(0x38823c,34),(0x3882c8,20),(0x388b6c,144),(0x388bfa,26),(0x388c10,120),(0x3b9c0c,82)]:
  code=ni.read(a,n);assert raw(a,n)==code or a==0x3b9c0c
  source.append(dict(start=a,bytes=n,stock_source_hex=code.hex(),stock_SHA256=hashlib.sha256(code).hexdigest()))
 proof=dict(all_passed=True,audited_integration_guest_success=False,actual_guest_EXIT=1,
  failure_proof=rel(FAIL),failure_proof_SHA256=sha(FAIL),CPU_store_preimages_values_opcodes_replayed=3035,regions_replayed=len(regions),
  helper_full_returns_checked=82,original_context_destinations_checked=9,new_original_initialized_heap_extent_append_full_return=True,
  original_virtual_pool_header_preserved=True,software_backing_extent=dict(start=0x18400000,bytes=65536,physical_availability_unknown=True),
  original_mixer_allocations_bytes=[8192,240],original_mixer_TCB=mixer,original_mixer_descriptor_registry_scheduler_provenance=True,
  original_mixer_initializer_and_sync_ACK_full_returns=True,
  partial_failure='Source89 is preempted by Mixer23 on first msg13 before CONFIG grant at later sync callsite; selector admission -201; Source binding fails -201',
  selector_return_ordinal=select['return_ordinal'],Source_grant_entry_ordinal=grant['entry_ordinal'],native_factory_reader_pull_not_executed=True,
  native_allocator_first_extent_is_backing_pages_second_extent_is_managed_virtual_heap=True,
  prior_public_private_or_mapping_metadata_wording_is_not_precise_physical_heap_evidence=True,
  original_address_bytes=source,old_closed_Source_READY_packet_decode_registration_not_rerun=True,
  VM_import_or_creation=False,full_effective_address_or_nonstore_semantics_recomputed=False,
  exclusive_native_witness=-200,native_STOP_DONE=False,physical_install_App_phone_speaker=False,device_IO=False,
  source_sha256={rel(p):sha(p)for p in(Path(__file__),BASE/'prepare_prefix_v1.py',FAIL,BUILD,BASE/'prefix/FILE-prefix-proof.json')})
 (OUT/'FILE-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
 print(json.dumps({k:v for k,v in proof.items()if k not in('source_sha256','original_address_bytes')}),flush=True)
if __name__=='__main__':main()
