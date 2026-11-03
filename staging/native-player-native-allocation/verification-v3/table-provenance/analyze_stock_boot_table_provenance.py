#!/usr/bin/env python3
"""Bounded FILE ONLY stock startup table provenance, no CPU/VM execution."""
import hashlib,json,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from capstone.arm import ARM_OP_REG,ARM_OP_IMM,ARM_OP_MEM,ARM_REG_PC,ARM_REG_SP
HERE=Path(__file__).resolve().parent
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8388608),b''):h.update(b)
 return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def main():
 n=NativeImage();bootp=ROOT/'evidence/firmware-analysis/boot_0008.bin';boot=bootp.read_bytes()
 assert sha(bootp)=='aa1e36b7a315c2d2f551b6e9e0988947c0bb964e27216ea05a257f121eee2b4e'
 gcdp=ROOT/'evidence/live-device/GUPDATE.GCD';h=hashlib.sha256();payloads={8:bytearray(),0x2bd:bytearray()}
 with gcdp.open('rb')as f:
  magic=f.read(8);assert magic==b'GARMINd\0';h.update(magic)
  while True:
   hdr=f.read(4);assert len(hdr)==4;h.update(hdr);kind,size=struct.unpack('<HH',hdr)
   if kind==0xffff:
    assert size==0
    for b in iter(lambda:f.read(8388608),b''):h.update(b)
    break
   body=f.read(size);assert len(body)==size;h.update(body)
   if kind in payloads:payloads[kind].extend(body)
 assert h.hexdigest()=='8513f805d3c57ec99aefa1f085f4861197eed4e2ae1d6428076f8762d71f7819'
 assert bytes(payloads[8])==boot and bytes(payloads[0x2bd])==n.data
 del payloads
 md={True:Cs(CS_ARCH_ARM,CS_MODE_THUMB),False:Cs(CS_ARCH_ARM,CS_MODE_ARM)}
 for m in md.values():m.detail=True
 def rows(start,end,thumb=True,data=None):
  data=n.data if data is None else data
  out=[]
  for i in md[thumb].disasm(data[start-0x50000:end-0x50000],start):
   row=dict(PC=hex(i.address),Thumb=thumb,opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)
   if i.mnemonic=='ldr'and len(i.operands)==2 and i.operands[1].type==ARM_OP_MEM and i.operands[1].mem.base==ARM_REG_PC:
    p=((i.address+4)&~3)+i.operands[1].mem.disp if thumb else i.address+8+i.operands[1].mem.disp
    row.update(literal_PC=hex(p),literal_word=hex(struct.unpack_from('<I',data,p-0x50000)[0]))
   out.append(row)
  return out
 def text(pc,thumb=True,data=None):return rows(pc,pc+4,thumb,data)[0]['instruction']
 for pc,target in((0x5017a,0x5751c),(0x57534,0x210ee2),(0x210ef8,0x4d8818),(0x210f00,0x2223c6),(0x2223c8,0x22239a),(0x2223c0,0x1f9ce0)):
  assert text(pc)=='bl #'+hex(target)
 assert text(0x2223b2)=='str r1, [r2, r4]' and text(0x2223bc)=='blx #0x35b4f4'
 for pc,v in((0x2223ec,0x3e04000),(0x2223f0,0x3e00000),(0x2223f8,0x55555555),(0x2223fc,0x45297b),(0x1f9f98,0xf08a10),(0x1f9fa0,0x2cf2dd4)):
  assert n.word(pc)==v
 for pc,target in((0x33e67c,0x6f050c),(0x33e680,0x6f0514),(0x33e684,0x6f049c)):
  assert text(pc,False)=='b #'+hex(target)
 assert text(0x6f050c,False)=='mcr p15, #0, r0, c3, c0, #0'
 assert text(0x6f0514,False)=='mcr p15, #0, r0, c2, c0, #0'
 assert n.word(0x4d8898)==0xf08a08 and n.word(0x4d889c)==0xa0007ffc and n.word(0x4d88a0)==0x8dcb14
 assert text(0x4d8884)=='str r0, [r2, #8]'
 assert n.word(0x8dcb14)==0x4000000 and n.word(0x8dcb18)==0x8000000
 assert n.word(n.runtime_to_load(0xf08a10,4))==0
 # Constant propagation over the straight-line argument setup ONLY. Callees
 # are not executed and all r0-r3 are killed after calls. RAM read stays symbolic.
 regs={};stack={};calls=[]
 def value(op):return op.imm if op.type==ARM_OP_IMM else regs.get(op.reg)
 for i in md[True].disasm(n.read(0x1f9cec,0x1f9ec4-0x1f9cec),0x1f9cec):
  ops=i.operands;mn=i.mnemonic
  if mn=='ldr':
   mem=ops[1].mem
   if mem.base==ARM_REG_PC:v=n.word(((i.address+4)&~3)+mem.disp)
   elif mem.base==ARM_REG_SP:v=stack[mem.disp]
   elif regs.get(mem.base)==0xf08a10:v='stock_RAM_size_from_A0007FFC_bit0'
   else:raise AssertionError(('unreviewed static load',hex(i.address)))
   regs[ops[0].reg]=v
  elif mn=='str'and ops[1].mem.base==ARM_REG_SP:stack[ops[1].mem.disp]=value(ops[0])
  elif mn=='stm'and i.address==0x1f9cf8:stack.update({k:0 for k in range(0,20,4)})
  elif mn in('mov','movs'):regs[ops[0].reg]=value(ops[1])
  elif mn in('adds','lsls','lsrs','bics','orrs','rsbs'):
   dst=ops[0].reg
   if mn in('bics','orrs'):a=regs[dst];b=value(ops[1])
   elif mn=='rsbs':a=value(ops[1]);b=value(ops[2])
   elif len(ops)==2:a=regs[dst];b=value(ops[1])
   else:a=value(ops[1]);b=value(ops[2])
   assert isinstance(a,int)and isinstance(b,int),(hex(i.address),a,b)
   v={'adds':lambda:a+b,'lsls':lambda:a<<b,'lsrs':lambda:a>>b,'bics':lambda:a&~b,'orrs':lambda:a|b,'rsbs':lambda:b-a}[mn]()
   regs[dst]=v&0xffffffff
  elif mn=='bl':
   assert ops[0].imm==0x222116
   calls.append(dict(caller_PC=hex(i.address),entry='0x222116',r0='address of native stack descriptor20',r1=regs.get(67),descriptor_words=[stack[k]for k in range(0,20,4)]))
   for k in(66,67,68,69):regs.pop(k,None)
  else:raise AssertionError(('unreviewed argument instruction',hex(i.address),mn))
 assert len(calls)==11
 # Additional prebuilt native descriptor-vector mapping and conditional final
 # mapping are kept as original instruction ranges, not abstracted guest state.
 assert text(0x1f9f02)=='bl #0x222116'
 assert all(not(isinstance(x['descriptor_words'][1],int)and x['descriptor_words'][1]<=0x18305000<x['descriptor_words'][1]+(x['descriptor_words'][2]if isinstance(x['descriptor_words'][2],int)else 0))for x in calls)
 for pc,target in((0x50120,0x6adcc),(0x6af40,0x7045e),(0x70460,0x70432),(0x70458,0x685ac)):
  assert text(pc,True,boot)=='bl #'+hex(target)
 srcs=[Path(__file__).resolve(),gcdp,bootp,ROOT/'evidence/firmware-analysis/main_02bd.bin',ROOT/'evidence/firmware-analysis/layout.json',ROOT/'scripts/analyze_gcd.py',ROOT/'scripts/analyze_native_sections.py',HERE.parent/'native-MMU-input-contract-independent-review.json']
 d=dict(all_passed=True,pure_static=True,source_sha256={rel(p):sha(p)for p in srcs},original_GCD_MAIN_BOOT_payloads_identical=True,
  no_VM_import_or_execution=True,device_io=False,actual_table_before_after_available=False,
  MAIN_caller_chain=['5017A->5751C','57534->210EE2','210EF8->4D8818 RAM identity input','210F00->2223C6','2223C8->22239A','2223C0->1F9CE0','1F9CE0->222116'],
  BOOT_caller_chain=['50120->6ADCC','6AF40->7045E','70460->70432','70458->685AC','685AC->701AE'],
  original_clear_recipe=dict(L1_base='03E00000',L1_words=4096,L1_bytes=16384,L1_store_PC='2223B2',L2_base='03E04000',L2_bytes=262144,memzero_call_PC='2223BC',original_memzero_entry='35B4F4',counter_words='F08F80+0/+2 reset0'),
  original_privileged_inputs=dict(DACR='55555555',DACR_caller='2223CE',DACR_store='6F050C',TTBR='03E00000',TTBR_caller='2223D4',TTBR_store='6F0514',SCTLR_declared_bits='45297B merged with previous bits31:30',SCTLR_caller='2223DE',SCTLR_writer='6F049C..6F050C'),
  RAM_size_producer=dict(boot_word='A0007FFC',selector='bit0 from stock4D8870..4D8882',stock_lookup='8DCB14',values=[67108864,134217728],native_writer_PC='4D8884',destination='F08A10',MAIN_initialized_value=0,hardware_word_captured=False),
  first11_descriptor_argument_setups=calls,
  remaining_recipe=dict(prebuilt_vector_mapping=dict(caller='1F9F02',physical_base=0,virtual_base='C0000000',bytes=268435456,typed_vector='02CF2DD4',vector_words=256,original_vector_fill='1F9EC4..1F9EFE'),last_mapping='Only if RAM_size==08000000: physical/virtual04400000+01000000 via1F9F34; otherwise1F9F5C clears selected identity slots to08000000'),
  fixture_virtual18305000=dict(L1_slot='03E0060C',not_covered_by_this_stock_cold_recipe=True,after_original_clear_and_recipe='type0/zero absent a separate later producer',table_bytes_cannot_be_imported_from_file=True,coarse_L2_for_this_VA_not_established=True),
  bounded_original_ranges=dict(MAIN={hex(s):rows(s,e,t)for s,e,t in((0x50018,0x50120,False),(0x50120,0x5017e,True),(0x5751c,0x5753e,True),(0x210ee2,0x210f32,True),(0x4d8818,0x4d888a,True),(0x22239a,0x2223ec,True),(0x1f9ce0,0x1f9f86,True),(0x222116,0x222200,True),(0x221ece,0x222116,True),(0x6f049c,0x6f051c,False))},BOOT={hex(s):rows(s,e,True,boot)for s,e in((0x50100,0x50124),(0x6af22,0x6af4c),(0x70432,0x70482),(0x685ac,0x687dc))}),
  limits=['This is bounded original static provenance, not execution of stock boot or recovered actual hardware L1/L2 snapshots.','Logical USB backup provides exact updater BOOT and MAIN; installed ROM/bootloader and physical A0007FFC input are not captured. The file-backed recipe is recovered without assuming those inputs.','18305000 is the new runner fixture virtual address, distinct from stock cold mapping intervals. A synthetic coarse L1/L2 control must remain labelled software input; no invented descriptor is evidence of original cold boot.','Later mapping producers outside these bounded startup ranges remain unreviewed. No native pagepop/malloc48/8 return, physical backing, native Dispatcher completion or App is proved.'])
 assert not any(k=='unicorn'or k.startswith('unicorn.')for k in sys.modules)
 p=HERE/'stock-BOOT-MAIN-table-provenance.json'
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
 print(json.dumps(dict(all_passed=True,proof=rel(p),proof_sha256=sha(p),descriptor_setups=len(calls),guest_execution=False)))
if __name__=='__main__':main()
