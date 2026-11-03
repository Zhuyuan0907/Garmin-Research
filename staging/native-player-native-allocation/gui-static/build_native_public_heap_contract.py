#!/usr/bin/env python3
"""Pure file analysis and host recipe controls; no VM import or guest execution."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,json,struct,importlib.util
from collections import deque
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
ROOT=Path(__file__).resolve().parents[3]
BASE=Path(__file__).resolve().parent
ANALYZER=ROOT/'staging/native-player-clock-caller/next-allocation-static/analyze_next_native_allocation.py'
spec=importlib.util.spec_from_file_location('frozen_allocation_file_analyzer',ANALYZER)
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

def write(name,doc):
    with (BASE/name).open('x') as h:json.dump(doc,h,ensure_ascii=False,indent=2);h.write('\n')

def cfg(im,name,entry,ranges,thumb):
    pending=deque([entry]);seen=set();rows=[];calls=[];edges=[];outside=[]
    conds={'b','beq','bne','bhs','blo','bhi','bls','bge','blt','bgt','ble','bpl','bmi','bvs','bvc','bcs','bcc'}
    while pending:
      pc=pending.popleft()
      if pc in seen:continue
      if not any(lo<=pc<hi for lo,hi in ranges):outside.append(hex(pc));continue
      seen.add(pc);a.require(len(seen)<=500,'Bounded CFG cap')
      i=im.instruction(pc,thumb);r=dict(PC=hex(pc),Thumb=thumb,opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)
      if i.mnemonic=='ldr' and len(i.operands)==2 and i.operands[1].type==ARM_OP_MEM and i.operands[1].mem.base==ARM_REG_PC:
        lit=((pc+(4 if thumb else 8))&~3)+i.operands[1].mem.disp;r.update(literal_address=hex(lit),literal_value=hex(im.word(lit)))
      target=i.operands[0].imm if len(i.operands)==1 and i.operands[0].type==ARM_OP_IMM else None
      nxt=[]
      if i.mnemonic in ('bl','blx'):
        calls.append(dict(PC=hex(pc),continuation=hex(pc+i.size),instruction=r['instruction'],target=hex(target)if target is not None else None));nxt=[pc+i.size]
      elif i.mnemonic in conds:
        a.require(target is not None,'Original immediate branch');nxt=[target]+([]if i.mnemonic=='b' else[pc+i.size])
      elif i.mnemonic.startswith('bx'):
        r['terminal_transfer']=True
        if i.mnemonic!='bx':nxt=[pc+i.size]
      elif i.mnemonic=='pop' and 'pc' in i.op_str:r['terminal_transfer']=True
      else:nxt=[pc+i.size]
      rows.append(r)
      for q in nxt:edges.append([hex(pc),hex(q)]);pending.append(q)
    return dict(name=name,entry=hex(entry),Thumb=thumb,original_ranges=[[hex(lo),hex(hi)]for lo,hi in ranges],
      instructions=sorted(rows,key=lambda r:int(r['PC'],16)),direct_or_indirect_calls=calls,edges=edges,
      bounded_exit_addresses=sorted(set(outside)),direct_calls_are_not_recursively_claimed_executed=True)

def main():
    im=a.Image()
    specs=[('heap cold/private/public constructor',0x388B6C,[(0x388B6C,0x388CB8),(0x388D88,0x388DF2)],True),
      ('native descriptor pop',0x388DF2,[(0x388DF2,0x388E32)],True),
      ('private page pop',0x38806C,[(0x38806C,0x3880BC)],True),
      ('free bin insertion',0x3880BC,[(0x3880BC,0x388144)],True),
      ('free bin removal',0x388144,[(0x388144,0x3881BC)],True),
      ('original ARM floorlog2',0x21210C,[(0x21210C,0x212154)],False),
      ('original ARM memzero',0x35B4F4,[(0x35B4F4,0x35B548)],False)]
    functions={hex(e):cfg(im,n,e,r,t)for n,e,r,t in specs}
    old=json.loads((ROOT/'staging/native-player-clock-caller/next-allocation-static/next-native-allocation-contract.json').read_text())
    for key in ('0x3881bc','0x38850a','0x388804','0x388e92','0x2dc9ea','0x3954cc'):
      functions[key]=old['bounded_CFG'][key]
    writer={}
    for f,row in functions.items():
      for i in row['instructions']:
        if i['instruction'].startswith(('str','stm','swp')):
          a.require(i['PC'] not in writer,'Unique bounded heap writer PC')
          writer[i['PC']]=dict(i,function_entry=f)
    # Raw native stores retain parent epilogue/ownership semantics, and are bound
    # to new exact pending rows at runtime rather than being unconditionally allowed.
    for e,z in [(0x3009A0,0x300A0C),(0x3008B0,0x30092C)]:
      # Mixed-mode words include Thumb at entry and after BX. Record exact Thumb
      # stores from known code regions; ARM portions are separately file decoded.
      for t,lo,hi in [(True,e,e+8),(False,e+8,e+0x40),(True,e+0x40,z)]:
        for i in im.md[t].disasm(im.read(lo,hi-lo),lo):
          if i.mnemonic.startswith(('str','stm','swp')):
            writer[hex(i.address)]=dict(PC=hex(i.address),Thumb=t,opcode_hex=i.bytes.hex(),
              instruction=i.mnemonic+' '+i.op_str,function_entry=hex(e),raw_pending_required=True)
    # Actual raw store modes/PCs are determined again from live CPSR and unchanged
    # MAIN in helper; no admission depends on speculative linear mode decoding.
    writer={pc:r for pc,r in writer.items() if not r.get('raw_pending_required')}
    for p in [0x20B8D4,0x20B8D8,0x8DC64C,0x8DC650,0x8DC654,0x8DC658]:
      a.require(im.word(p)=={0x20B8D4:0x8DC654,0x20B8D8:0x8DC64C,0x8DC64C:0x14E5238,
        0x8DC650:0x1800000,0x8DC654:0xC0000000,0x8DC658:0x10000000}[p],'Boot original literal/data')
    boot=[dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)
      for i in im.md[True].disasm(im.read(0x20B86E,0x20),0x20B86E)]
    public=dict(private_base=0x18301000,private_bytes=8192,public_base=0x18305000,public_bytes=16384,
      public_envelope_base=0x18304000,public_envelope_bytes=24576,
      public_descriptor_page=0x1830B000,public_descriptor=0x1830B020,
      public_descriptor_page_bytes=4096,initial_payload_byte=0xCC,guard_byte=0xA5)
    sourcepaths=[Path(__file__).resolve(),ANALYZER,a.MAIN,
      ROOT/'scripts/probe_native_heap_settings_boot.py',ROOT/'scripts/native_cold_fp_guard_copies.py',
      ROOT/'scripts/probe_native_dispatcher_clock_caller.py',ROOT/'scripts/probe_native_task_mutex.py',
      ROOT/'staging/native-player-clock-caller/gui-static/clock_caller_observer_v2.py',
      ROOT/'staging/native-player-clock-caller/runtime/terminal-probe.json',
      ROOT/'staging/native-player-clock-caller/terminal-receipt.json',
      ROOT/'staging/native-player-native-allocation/previous-checkpoint.json']
    sources={a.rel(p):a.sha(p)for p in sourcepaths}
    terminal=json.loads(sourcepaths[-3].read_text())
    a.require(terminal['registers']=={'r0':'0x30','r1':'0xf09098','r2':'0x8804058','r3':'0xea60',
      'lr':'0x395535','pc':'0x3954cc','sp':'0x8803fb0'},'Actual terminal registers, not assumed allocator result')
    partial=terminal['partial_inherited_zone_verification'];work=next(r for r in partial if r['start']=='0x3a7f150')
    raw=bytearray.fromhex(work['before_hex'])
    for e in work['stores']:
      o=int(e['address'],16)-int(work['start'],16);n=e['size']
      a.require(raw[o:o+n].hex()==e['before_hex'],'Actual WORK chronological beforeimage')
      raw[o:o+n]=e['value'].to_bytes(n,'little')
    a.require(hashlib.sha256(raw).hexdigest()==work['after_sha256'],'Actual whole WORK128 after SHA')
    a.require(struct.unpack_from('<I',raw,32+0xC)[0]==0 and struct.unpack_from('<I',raw,32+0x10)[0]==0,
      'Actual current private-only configuration has no descriptor/free-public list')
    write('native-heap-original-opcodes.json',dict(all_passed=True,static_only=True,guest_execution=False,
      source_sha256=sources,bounded_CFG=functions,writer_opcodes=writer,boot_caller=boot,
      original_boot_extents=dict(private=['0x14e5238','0x1800000'],public=['0xc0000000','0x10000000'],
        file_addresses=['0x8dc64c','0x8dc654'],physical_mapping_or_availability_verified=False),
      existing_cold_arguments=['EXTENT',1,0,0],existing_argument_source='scripts/probe_native_dispatcher_clock_caller.py:215',
      actual_terminal_registers=terminal['registers'],actual_WORK128_replay=raw.hex(),
      actual_backend24_hex=raw[60:84].hex(),public_input_candidate=public,
      public_size_and_base_alignment_gate='388C9A OR(base,bytes); LSL20 == 0 => both low12bits zero',
      whole_WORK_initialization_onlyonce_gate='word(WORK+18)==0 at388B72; nonzero+publiccount branch diagnostic388C0C',
      public_extent_does_not_increment_WORK50=True,
      WORK50_semantics='Only primary/private loop388C2C adds extent bytes; publicloop does not update this field.',
      runtime_native_public_initialization_or_allocation_verified=False))
    write('native-public-heap-input-config.json',dict(schema=1,fixture_only=True,physical_heap_available_verified=False,
      native_constructor='0x388b6d',native_call_arguments=['existing EXTENT',1,hex(public['public_descriptor']),1],
      **{k:(hex(v)if 'base' in k or k in ['public_descriptor_page','public_descriptor'] else v)for k,v in public.items()},
      initialize_before_original_first_call_and_zone_baselines=True,WORK_must_be_actual_zero96_before_firstcall=True,
      host_generated_descriptors_or_bins=False,guest_code_or_owner_patched=False,
      intended_controller_original_call_then_actual_Dispatcher_two_allocations=True))
    print(json.dumps(dict(all_passed=True,file_only=True,functions=len(functions),writers=len(writer),assertions=a.COUNT,
      original_opcodes_sha256=a.sha(BASE/'native-heap-original-opcodes.json'),config_sha256=a.sha(BASE/'native-public-heap-input-config.json'))))
if __name__=='__main__':main()
