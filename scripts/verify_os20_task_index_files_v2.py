#!/usr/bin/env python3
"""Verify saved original OS20 helper evidence without importing Unicorn."""
import sys,json,gzip,hashlib,struct,collections
from pathlib import Path
from datetime import datetime,timezone
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT/'staging/native-os20-task-index-v2'
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
POOL=0x03a1b294;STACK=0x09010000;RETURN=0x09000000
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 out=BASE/'ROOT_FILE-proof-v2.json';assert not out.exists();proof=json.loads((BASE/'guest-proof.json').read_text());static=json.loads((BASE/'static-bridge-proof.json').read_text());receipt=json.loads((BASE/'terminal-tool-receipt.json').read_text())['actual_terminal_result']
 assert proof['all_passed']and proof['case_count']==9 and proof['full_returns']==8 and proof['error_callsite_stops']==1 and proof['pool_CPU_stores']==3 and receipt['exit_code']==0 and 'session_id'not in receipt
 sources=dict(proof['source_sha256']);n=NativeImage();arm=Cs(CS_ARCH_ARM,CS_MODE_ARM);thumb=Cs(CS_ARCH_ARM,CS_MODE_THUMB);totals=collections.Counter();rows=[]
 for rel,h in sources.items():assert sha(ROOT/rel)==h
 for case in proof['cases']:
  p=ROOT/case['path'];assert sha(p)==case['sha256'];sources[case['path']]=sha(p);decoded=gzip.decompress(p.read_bytes());d=json.loads(decoded)
  zones={'pool':dict(base=POOL,before=d['pool_before_hex'],after=d['pool_after_hex']),'stack':dict(base=STACK,before=d['stack_before_hex'],after=d['stack_after_hex'])};replay={k:bytearray.fromhex(v['before'])for k,v in zones.items()};pc_rows=collections.defaultdict(list)
  for t in d['trace']:
   op=bytes.fromhex(t['opcode_hex']);assert n.read(t['PC'],len(op))==op;pc_rows[t['PC']].append(t)
  for w in d['CPU_write_journal']:
   z=zones[w['zone']];offset=w['address']-z['base'];width=w['size'];assert 0<=offset and offset+width<=len(replay[w['zone']]);assert replay[w['zone']][offset:offset+width].hex()==w['before_hex']
   instructions=pc_rows[w['PC']];assert instructions and any(t['CPSR']==w['CPSR']for t in instructions)
   op=bytes.fromhex(instructions[0]['opcode_hex']);ins=next((thumb if w['CPSR']&32 else arm).disasm(op,w['PC']));assert (ins.mnemonic.startswith(('str','stm'))or ins.mnemonic=='push')
   replay[w['zone']][offset:offset+width]=w['value'].to_bytes(width,'little')
  for k,z in zones.items():assert replay[k].hex()==z['after']
  before_pool=bytes.fromhex(d['pool_before_hex']);expected=bytearray(before_pool);kind=d['reference_semantics'];index=d['reference_slot']
  if kind=='current_new':struct.pack_into('<I',expected,index*64+48,d['input_current_TCB']);struct.pack_into('<I',expected,index*64+8,0x59);expected[index*64+44]=0
  assert bytes(replay['pool'])==expected
  lookup_reads=0
  for pos,t in enumerate(d['trace']):
   if t['PC']==0x521d86:
    address=t['GP16'][3]+48;slot=(address-POOL-48)//64;assert (address-POOL-48)%64==0 and 0<=slot<15
    nxt=d['trace'][pos+1];assert nxt['PC']==0x521d88 and nxt['GP16'][3]==struct.unpack_from('<I',before_pool,slot*64+48)[0];lookup_reads+=1
  assert d['all_passed']and not d['device_IO']and not d['allocator_or_task_create_called']and not d['original_assert_body_executed']
  if d['original_full_return']:
   assert d['before']['GP16'][4:12]==d['after']['GP16'][4:12]and d['before']['GP16'][13]==d['after']['GP16'][13]and d['after']['GP16'][15]==RETURN
   assert (d['before']['CPSR']^d['after']['CPSR'])&0xdf==0
   if kind in('lookup','current','current_new'):assert d['after']['GP16'][0]==d['expected_return']
  else:
   assert d['expected_error_callsite_stop']and d['after']['GP16'][15]==0x521da8 and d['after']['GP16'][2]==0x522098
   offset=d['after']['GP16'][13]-STACK;assert struct.unpack_from('<I',replay['stack'],offset)[0]==0x522084
  if kind in('current','current_new'):
   save,restore=d['native_irq_calls'];assert save['entry']==0x21b6cc and restore['entry']==0x21b6dc and restore['state']['GP16'][0]==save['state']['CPSR']
   assert all(t['CPSR']&128 for t in d['trace']if 0x521d7c<=t['PC']<0x521db0)
  poolwrites=[w for w in d['CPU_write_journal']if w['zone']=='pool'];assert len(poolwrites)==(3 if kind=='current_new'else 0)
  totals.update(CPU_stores=len(d['CPU_write_journal']),pool_stores=len(poolwrites),whole_zones=2,instructions=len(d['trace']),lookup_field_reads=lookup_reads,full_returns=int(d['original_full_return']),error_boundaries=int(d['expected_error_callsite_stop']))
  rows.append(dict(name=d['name'],path=case['path'],encoded_sha256=sha(p),decoded_sha256=hashlib.sha256(decoded).hexdigest(),instructions=len(d['trace']),CPU_stores=len(d['CPU_write_journal']),pool_stores=len(poolwrites),lookup_field_reads=lookup_reads))
 for key,graph in static['graphs'].items():
  for t in graph['instructions']:
   op=bytes.fromhex(t['bytes']);assert n.read(t['address'],len(op))==op and next(thumb.disasm(op,t['address'])).mnemonic+' '+next(thumb.disasm(op,t['address'])).op_str==t['instruction']
 for p in(Path(__file__),BASE/'guest-proof.json',BASE/'static-bridge-proof.json',BASE/'terminal-tool-receipt.json'):sources[str(p.relative_to(ROOT))]=sha(p)
 assert not any(k=='unicorn'or k.startswith('unicorn.')for k in sys.modules)
 result=dict(all_passed=True,case_count=9,cases=rows,totals=dict(totals),source_sha256=sources,ROOT_FILE_only=True,VM_import_or_execution=False,new_independent_agent_review=False,device_IO=False,actual_task_creation_or_allocator_contract_or_live_pool_proven=False,scope='Original helper bounded execution over explicit pool/current/stack input. Full pool stops before original assertion body. FILE verifies exact opcodes, store preimages, whole zones, lookup effective addresses/results, helper ABI and IRQ save/restore inputs. Does not recreate complete non-store CPU semantics or execute create/allocator/root callback/physical scheduler.',updated_utc=datetime.now(timezone.utc).isoformat())
 with out.open('x')as f:json.dump(result,f,indent=2);f.write('\n')
 print(json.dumps(dict(all_passed=True,case_count=9,totals=dict(totals),VM_import_or_execution=False,device_IO=False)))
if __name__=='__main__':main()
