#!/usr/bin/env python3
"""No VM import: replay the NEW tail CPU journal and verify READY ordering.
The inherited warm prefix is hash-pinned, not reexecuted/reinterpreted.
"""
import sys
sys.dont_write_bytecode=True
import gzip,json,hashlib,struct
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1];OUT=BASE/'file-v1';G=BASE/'guest-v3'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def digest(b):return hashlib.sha256(b).hexdigest()
def segments(path):
 b=path.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
 for i in range(h[10]):
  k,o,a,_,fs,ms,fl,_=struct.unpack_from('<8I',b,h[5]+i*h[9])
  if k==1 and ms:yield a,fs,ms,fl,b[o:o+fs]
def main():
 assert not OUT.exists();OUT.mkdir()
 small=json.loads((G/'guest-proof.json').read_text());assert small['all_passed']and sha(G/'ready-proof.json.gz')==small['proof_SHA256']
 p=json.load(gzip.open(G/'ready-proof.json.gz','rt'));assert p['all_passed']
 receipt=json.loads((G/'terminal-tool-receipt.json').read_text());assert receipt['actual_terminal_result']['exit_code']==0
 for name,h in p['source_sha256'].items():assert sha(ROOT/name)==h,name
 prefix=json.load(gzip.open(ROOT/p['prefix'],'rt'));assert sha(ROOT/p['prefix'])==p['prefix_SHA256']
 warm=json.loads((ROOT/'staging/native-os20-audio-source-build-v1/manifest.json').read_text())
 build=json.loads((BASE/'build/manifest.json').read_text());sy=warm['symbols'];replay={};rx=[]
 for a,n,perms in prefix['zones']:
  data=bytes.fromhex(prefix['whole_final'][str(a)]);assert len(data)==n
  replay[a]=bytearray(data)
  if perms&4:rx.append((a,bytearray(data)))
 for a,fs,ms,fl,data in segments(ROOT/build['ELF']):
  start=a&~4095;end=(a+ms+4095)&~4095;block=bytearray(b'\xa5'*(end-start))
  block[a-start:a-start+ms]=bytes(ms);block[a-start:a-start+fs]=data;replay[start]=block
  if fl&1:rx.append((start,block))
 # Flash page has source hash evidence and was read-only throughout the guest.
 flash=p['source_backed_flash_page'];assert flash['permissions']==1 and flash['table']==0xc7f9fc
 for z in p['regions']:
  if z['origin']=='NEW_source_backed_flash':assert z['before_SHA256']==z['after_SHA256']==flash['SHA256']
  else:assert digest(replay[z['start']])==z['before_SHA256']
 for row in p['CPU_store_journal']:
  code=next((x for x in rx if x[0]<=row['PC']and row['PC']+len(bytes.fromhex(row['opcode_hex']))<=x[0]+len(x[1])),None)
  assert code and code[1][row['PC']-code[0]:row['PC']-code[0]+len(bytes.fromhex(row['opcode_hex']))].hex()==row['opcode_hex']
  z=next(z for z in p['regions']if z['start']<=row['address']and row['address']+row['size']<=z['start']+z['size'])
  assert z['permissions']&2 and z['origin']!='NEW_source_backed_flash'
  block=replay[z['start']];off=row['address']-z['start'];size=row['size']
  assert block[off:off+size].hex()==row['before_hex'],(row['ordinal'],hex(row['address']))
  block[off:off+size]=row['value'].to_bytes(size,'little')
 for z in p['regions']:
  if z['origin']!='NEW_source_backed_flash':assert digest(replay[z['start']])==z['after_SHA256'],hex(z['start'])
 def word(address):
  z=next(z for z in p['regions']if z['start']<=address and address+4<=z['start']+z['size']);return struct.unpack_from('<I',replay[z['start']],address-z['start'])[0]
 def writes(name):return [r for r in p['CPU_store_journal']if r['address']==sy[name]['value']and r['size']==4]
 complete={}
 for row in p['full_helper_returns']:
  b,a=row['before'],row['after'];assert row['full_ABI_return']and row['return_ordinal']<p['instruction_count']
  assert b['GP16'][4:12]==a['GP16'][4:12]and b['GP16'][13]==a['GP16'][13]
  mask=0x5f if row['entry']in(0x21b6cc,0x21b6dc)else 0xdf;assert not((b['CPSR']^a['CPSR'])&mask)
  assert a['GP16'][15]==row['return_PC']
  if row['name']in p['initializer_required_full_returns']:
   assert row['actor']==p['worker_TCB']and a['GP16'][0]==0;complete[row['name']]=row
 assert set(complete)==set(p['initializer_required_full_returns'])
 initialized=next(r for r in writes('mh_initialized')if r['value']==1)
 posts=next(r for r in writes('mh_os20_ready_posts')if r['value']==1)
 post_returns=next(r for r in writes('mh_os20_ready_post_returns')if r['value']==1)
 ready_call=next(r for r in p['full_helper_returns']if r['name']=='original_POST'and r['before']['GP16'][:2]==[0x9503f90,0x400])
 assert complete['mw_attach_stage1']['return_ordinal']<=initialized['ordinal']<posts['ordinal']<ready_call['entry_ordinal']
 assert ready_call['entry_ordinal']<ready_call['return_ordinal']<=post_returns['ordinal']
 assert initialized['actor']==posts['actor']==post_returns['actor']==p['worker_TCB']
 assert p['controller']['ready_post_returns_at_wake']==0 and p['Source']['mh_os20_ready_post_returns']==1
 assert p['controller']['wrong_actor_bind']==0xfffffe6f and p['controller']['observed_ready']==1
 creator=next(c for c in p['full_helper_returns']if c['entry']==0x521e5e)
 creator_counter=next(r for r in writes('mh_os20_create_returns')if r['value']==1)
 adapter_store=next(r for r in writes('mh_os20_adapter')if r['value']==p['adapter'])
 assert creator['return_ordinal']<=creator_counter['ordinal']<adapter_store['ordinal']
 assert word(p['adapter']+48)==p['worker_TCB']and word(p['adapter']+4)==16536
 assert word(sy['mh_os20_callback_argument']['value'])==sy['mh_os20_context']['value']
 assert p['workspace']<=p['source_stack_low']<p['workspace']+p['workspace_bytes']
 assert len(p['original_context_destinations'])==len(p['original_context_restores'])==4
 for request,result in zip(p['original_context_restores'],p['original_context_destinations']):
  assert request['target']==result['target']and request['PC']==result['state']['GP16'][15]and not request['host_context_restore']
 assert [r['target']for r in p['original_context_destinations']]==[p['worker_TCB'],0x9503f90,p['worker_TCB'],0x9508f90]
 assert p['TTS_prefix_and_40_original_MAIN_jump_entries_unchanged']
 assert p['new_guest_original_instruction_patches']==0 and not p['callback_initializer_or_native_return_hooked']
 assert not p['synthetic_driver_ready_claim']and p['exclusive_native_witness']==-200 and not p['native_STOP_DONE']
 result=dict(all_passed=True,source_sha256={str(Path(__file__).relative_to(ROOT)):sha(Path(__file__))},
  proof_SHA256=sha(G/'ready-proof.json.gz'),actual_terminal_receipt_SHA256=sha(G/'terminal-tool-receipt.json'),
  CPU_store_preimages_and_final_region_hashes_replayed=len(p['CPU_store_journal']),
  full_ABI_helper_returns_rechecked=len(p['full_helper_returns']),Source_to_TYPED_FIFO_initializer_full_returns=len(complete),
  actual_native_restore_destinations=4,creator_full_return_before_adapter_publication=True,
  Source_initializer_return_before_initialized_before_POST_before_POST_return_verified=True,
  controller_ready_wake_before_Source_POST_return_verified=True,
  inherited_prefix_or_37_objects_or_TTS_loader_reexecuted=False,VM_import_or_creation=False,
  independent_full_instruction_or_store_effective_address_replay=False,complete_memory_access_boundary_claim=False,
  audio_driver_or_hardware_ready_claim=False,native_STOP_DONE=False,exclusive_native_witness=-200,device_IO=False)
 (OUT/'FILE-proof.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
if __name__=='__main__':main()
