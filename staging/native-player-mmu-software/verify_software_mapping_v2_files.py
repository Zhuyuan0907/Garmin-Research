#!/usr/bin/env python3
"""Independent FILE ONLY verification of frozen ten original software controls.

Never imports the guest/Unicorn; never executes original ARM code. Whole-zone
replay and store semantics use recorded GP16/CPSR and exact original opcodes.
Final returned GP16 was not serialized: preserve that material limitation.
"""
import ast,hashlib,json,struct,sys
from collections import Counter
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM
L1,L2,STACK,RETURN,VA=0x03e00000,0x03f00000,0x08800000,0x08ff0000,0x18305000
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8388608),b''):h.update(b)
 return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def read(p):return json.loads(p.read_text())
def create(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def require(x,message):
 if not x:raise AssertionError(message)
def condition(mn,cpsr):
 n,z,c,v=[bool(cpsr&(1<<b))for b in(31,30,29,28)]
 return {'b':True,'beq':z,'bne':not z,'bhs':c,'bcs':c,'blo':not c,'bcc':not c,
  'bmi':n,'bpl':not n,'bvs':v,'bvc':not v,'bhi':c and not z,'bls':not c or z,
  'bge':n==v,'blt':n!=v,'bgt':not z and n==v,'ble':z or n!=v}[mn]
def main():
 proofp=BASE/'software-mapping-v2-proof.json';proof=read(proofp)
 require(sha(proofp)=='6524c9566313154ce54a8a1c0fdab34449a1bc7ae812613e4a4a0a5327dd7f8f','Frozen proof mismatch')
 sources=dict(proof['source_sha256'])
 require(sources[rel(BASE/'emulate_mapping_v2.py')]=='c0aec32bd7fad3bd063db2d1ce96244067719a0f5b4ef3833054853d13476a8f','Frozen runner mismatch')
 for p,h in sources.items():require(sha(ROOT/p)==h,p)
 require(read(BASE/'guest-v2/inputs-at-run.json')==sources,'Actual input registry mismatch')
 require(sha(BASE/'guest-v2/runner-at-run.py')==sources[rel(BASE/'emulate_mapping_v2.py')],'Actual runner snapshot mismatch')
 receiptp=BASE/'guest-v2-terminal-tool-receipt.json';receipt=read(receiptp)
 require(receipt['tool_result']['chunk_id']=='538421'and receipt['tool_result']['exit_code']==0,'No actual root terminal success')
 require(proof['all_passed']and proof['case_count']==len(proof['cases'])==10,'Ten actual controls missing')
 require(proof['no_function_hooks_or_original_code_patches']and not proof['captured_original_boot_MMU_state']and not proof['real_hardware_MMU_page_backing_cache_TLB_or_native_heap_or_App_verified'],'Scope differs')
 # Read source as AST/text, never import it. Verify actual runtime return checks
 # exist, but do not turn those source assertions into a final GP readback.
 runnerp=BASE/'emulate_mapping_v2.py';runner=runnerp.read_text();tree=ast.parse(runner)
 require('self.uc.reg_read(UC_ARM_REG_SP)==self.sp'in runner,'Missing runtime SP assertion')
 require('self.uc.reg_read(UC_ARM_REG_CPSR)==(saved_IRQ_CPSR|32)'in runner,'Missing runtime CPSR assertion')
 require('self.uc.reg_read(UC_ARM_REG_R0)==saved_IRQ_CPSR'in runner,'Missing runtime R0 assertion')
 require('if address==RETURN:self.done=True;uc.emu_stop();return'in runner,'Actual return sentinel guard absent')
 require(not any(isinstance(a,ast.Call)and isinstance(a.func,ast.Attribute)and a.func.attr in('host_return','context_restore')for a in ast.walk(tree)),'Unexpected fabricated function result')
 n=NativeImage();require(hashlib.sha256(n.data).hexdigest()==EXPECTED,'Wrong MAIN')
 md={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
 for m in md.values():m.detail=True
 def decode(pc,thumb):return next(md[thumb].disasm(n.read(pc,4),pc,count=1))
 allowed=[(0x221d34,0x221dca,True),(0x21b6cc,0x21b6e4,False),(0x3275a4,0x3275a8,False),
  (0x33e664,0x33e668,False),(0x33e678,0x33e67c,False),(0x6f012c,0x6f0170,False),
  (0x6f0250,0x6f0258,False),(0x6f040c,0x6f0430,False)]
 expected_names=['missing_L1_returns_without_mapping','section_L1_keeps_low20']+[
  kind+'_L2_class'+str(k)for kind in('coarse','fine')for k in range(4)]
 require([x['name']for x in proof['cases']]==expected_names,'Unexpected controls')
 rx_pages=[(0x221000,0x2000),(0x21b000,0x1000),(0x327000,0x1000),(0x33e000,0x1000),(0x6f0000,0x1000)]
 expectedRX={str(a):hashlib.sha256(n.read(a,z)).hexdigest()for a,z in rx_pages}
 expectedRX[str(RETURN)]=hashlib.sha256(bytes.fromhex('7047')+bytes(4094)).hexdigest()
 rows=[];cpu_total=0;table_total=0;trace_total=0
 for item in proof['cases']:
  p=ROOT/item['path'];require(sha(p)==item['sha256'],str(p));d=read(p);spec=d['declared_synthetic_input'];name=d['name']
  require(d['passed']and name==item['name']==spec['name'],'Case identity')
  typ=spec['L1_type'];phy=spec['physical_fixture'];slot=L1+4*(VA>>20)
  require(d['virtual_address']==VA and d['L1_slot']==slot,'Original L1 address')
  require(not d['model_SCTLR']&1,'MMU enabled outside declared scope')
  require(d['function_fixtures']==[]and d['original_code_modified']is False,'Original body fixtures/patches')
  for k in('captured_hardware_L1_L2','real_MMU_translation_or_physical_backing_or_cache_TLB_verified','native_heap_return_or_constructor_or_App_verified','device_io'):
   require(d[k]is False,k)
  zones=[('L1',L1,0x4000),('L2',L2,0x1000),('stack',STACK,0x10000)]
  require(d['zones']==[dict(name=label,start=start,size=size)for label,start,size in zones],'Whole three zones differ')
  initial={'L1':bytearray(0x4000),'L2':bytearray(b'\xa5'*0x1000),'stack':bytearray(b'\xa5'*0x10000)}
  l1word=0 if typ==0 else(0xabc00a02 if typ==2 else L2|typ)
  struct.pack_into('<I',initial['L1'],slot-L1,l1word)
  l2slot=None
  if typ in(1,3):
   l2slot=L2+4*((VA&0xfffff)>>(12 if typ==1 else 10))
   struct.pack_into('<I',initial['L2'],l2slot-L2,spec['L2_word'])
  require(d['L2_slot']==l2slot,'L2 class-specific slot')
  require({k:v.hex()for k,v in initial.items()}==d['initial_whole_zones'],'Declared fixture beforebytes differ')
  trace=d['original_instruction_trace'];require(len(trace)==d['instructions'],'Trace length')
  require(dict(Counter(hex(t['PC'])for t in trace))==d['original_visits'],'Actual visit histogram')
  require(trace[0]['PC']==0x221d34 and trace[-1]['PC']==0x221d92,'Native entry/last recorded POP')
  entrySP=STACK+0xff00;bottomSP=entrySP-24
  require(trace[0]['SP']==entrySP and trace[0]['LR']==RETURN+1 and trace[0]['CPSR']==0x3f,'Actual pre-PUSH frame ABI')
  require(all(t['SP']==bottomSP for t in trace[1:]),'Original 24-byte frame history')
  for j,t in enumerate(trace):
   pc=t['PC'];thumb=t['Thumb'];cpsr=t['CPSR']
   require(thumb==bool(cpsr&32)and any(a<=pc<b and thumb==mode for a,b,mode in allowed),'Unreviewed original PC/ISA')
   i=decode(pc,thumb)
   if j==len(trace)-1:
    require(i.mnemonic=='pop'and i.op_str=='{r3, r4, r5, r6, r7, pc}','Original final POP differs');continue
   nxt=trace[j+1];mn=i.mnemonic;target=pc+i.size;next_thumb=thumb
   if mn in('bl','blx'):
    require(i.operands[0].type==ARM_OP_IMM,'Indirect call outside bounded original chain')
    target=i.operands[0].imm;next_thumb=thumb if mn=='bl'else not thumb
    require(nxt['LR']==((pc+i.size)|(1 if thumb else 0)),'Native link register at direct call')
   elif mn=='bx':
    require(i.op_str=='lr','Unexpected indirect branch');target=t['LR']&~1;next_thumb=bool(t['LR']&1)
   elif mn.startswith('b')and mn not in('bics','bkpt'):
    target=i.operands[0].imm if condition(mn,cpsr)else target
   require(nxt['PC']==target and nxt['Thumb']==next_thumb,'Exact instruction/conditional controlflow '+name+' '+hex(pc))
  saved=next(t['CPSR']for t in trace if t['PC']==0x21b6cc)
  require(saved==d['saved_IRQ_CPSR']==0x1f,'Saved original ARM IRQ flags')
  require(trace[-1]['CPSR']==saved|32,'Recorded Thumb pre-POP IRQ restore')
  require(all(d['original_visits'].get(hex(pc),0)==1 for pc in(0x21b6cc,0x3275a4,0x6f012c,0x33e664,0x6f0250,0x33e678,0x6f040c,0x21b6dc)),'Native maintenance chain')
  require(d['original_visits'].get('0x6f0140',0)==0 and d['original_visits'].get('0x6f016c',0)==1,'Declared MMU-disabled branch')
  require(d['unchanged_RX_sha256']==expectedRX,'Actual RX SHA versus exact MAIN/sentinel')
  replay={k:bytearray(v)for k,v in initial.items()};stores=d['actual_CPU_stores'];expected_table=[]
  if typ==2:expected_table=[(0x221d9a,slot,(l1word&0xfffff)|phy)]
  elif typ in(1,3):
   raw=spec['L2_word'];kind=raw>>30;tagged=raw|kind
   expected_table=[(0x221dae if typ==1 else 0x221d74,l2slot,tagged)]
   if kind in(1,2)or(kind==3 and typ==3):
    keep={1:0xffff,2:0xfff,3:0x3ff}[kind]
    expected_table.append(({1:0x221dc6,2:0x221dbc,3:0x221d86}[kind],l2slot,(tagged&keep)|phy))
  table=[]
  for ordinal,s in enumerate(stores,1):
   require(s['ordinal']==ordinal and s['size']==4,'CPU store ordinal/width')
   gp=s['GP16'];pc=s['PC'];cpsr=s['CPSR'];require(len(gp)==16 and gp[15]==pc,'Complete recorded store GP16')
   require(s['Thumb']==bool(cpsr&32),'Store CPSR/ISA')
   i=decode(pc,s['Thumb']);require(i.bytes.hex()==s['opcode_hex']and i.mnemonic+' '+i.op_str==s['instruction'],'Exact original store opcode')
   label,start,size=next((label,start,size)for label,start,size in zones if start<=s['address']<start+size)
   require(label==s['zone']and s['address']+4<=start+size,'Exact zone store')
   if pc==0x221d34:
    require(ordinal<=6 and i.mnemonic=='push'and i.op_str=='{r3, r4, r5, r6, r7, lr}','Reviewed original PUSH')
    reg=[3,4,5,6,7,14][ordinal-1]
    require(gp[13]==entrySP and s['address']==entrySP-24+4*(ordinal-1)and s['value']==gp[reg],'Exact PUSH GP payload/address')
    expected=[0x13520000+i for i in range(13)]+[entrySP,RETURN+1,pc];expected[0]=VA;expected[1]=phy
    require(gp==expected and cpsr==0x3f,'Declared entry state in PUSH journal')
   elif pc==0x221d9a:
    require(i.mnemonic=='str'and i.op_str=='r0, [r7, r3]'and s['address']==gp[7]+gp[3]and s['value']==gp[0],'Section STR register semantics')
    table.append((pc,s['address'],s['value']))
   else:
    require(pc in(0x221d74,0x221d86,0x221dae,0x221dbc,0x221dc6),'Unreviewed CPU store')
    require(i.mnemonic=='str'and i.op_str=='r2, [r1, r0]'and s['address']==gp[1]+gp[0]and s['value']==gp[2],'L2 STR register semantics')
    require(gp[4]==phy and gp[5]==saved and gp[6]==VA and gp[7]==L1 and gp[13]==bottomSP,'Mapping native register provenance')
    table.append((pc,s['address'],s['value']))
   require(any(t['PC']==pc and t['Thumb']==s['Thumb']and t['SP']==gp[13]and t['LR']==gp[14]and t['CPSR']==cpsr for t in trace),'Store full snapshot agrees with actual original trace')
   off=s['address']-start;require(replay[label][off:off+4].hex()==s['before_hex'],'Independent exact store preimage')
   replay[label][off:off+4]=s['value'].to_bytes(4,'little')
  require(table==expected_table and len(table)==d['exact_table_store_count'],'Independent class-specific exact table stores')
  require(len(stores)==6+len(table),'No dropped/extra CPU writes')
  require({k:v.hex()for k,v in replay.items()}==d['final_whole_zones'],'Independent actual full three-zone replay')
  require(replay['stack'][:32]==b'\xa5'*32 and replay['stack'][entrySP-STACK:entrySP-STACK+256]==b'\xa5'*256,'Stack leading/trailing canaries')
  require(struct.unpack_from('<6I',replay['stack'],bottomSP-STACK)==tuple([0x13520000+k for k in(3,4,5,6,7)]+[RETURN+1]),'Independent final POP frame contents and destination')
  require(d['actual_IRQ_flags_and_SP_restored']and d['original_mapping_function_returned']and d['whole_zone_CPU_replay_passed'],'Frozen source-asserted runtime result')
  require(not any(k in d for k in('final_GP16','final_CPSR','final_SP')),'Return snapshot scope changed: review required')
  rows.append(dict(name=name,source_case_sha256=sha(p),CPU_stores=len(stores),table_stores=len(table),original_instructions=len(trace),exact_original_store_GP_semantics_checked=True,whole_zones=[dict(name=k,bytes=len(v),actual_after_sha256=hashlib.sha256(v).hexdigest())for k,v in replay.items()],exact_branch_store_triples=[dict(PC=hex(a),address=hex(b),value=hex(c))for a,b,c in table],original_pre_POP_IRQ_and_frame_verified=True,actual_final_return_register_readback_available=False))
  cpu_total+=len(stores);table_total+=len(table);trace_total+=len(trace)
 require(cpu_total==74 and table_total==14,'Exact aggregate original store counts')
 extra=[Path(__file__).resolve(),proofp,receiptp,BASE/'guest-v2/inputs-at-run.json',BASE/'guest-v2/runner-at-run.py',BASE/'emulate_mapping_v1.py',BASE/'guest-v1/runner-at-run.py',BASE/'guest-v1/inputs-at-run.json',BASE/'guest-v1/terminal-failure.json',BASE/'guest-v1-terminal-tool-receipt.json']
 sources.update({rel(p):sha(p)for p in extra})
 for row in proof['cases']:sources[row['path']]=row['sha256']
 require(not any(k=='unicorn'or k.startswith('unicorn.')for k in sys.modules),'VM imported')
 for p,h in sources.items():require(sha(ROOT/p)==h,'Final dependency recheck '+p)
 doc=dict(all_passed=True,independent_file_only=True,source_sha256=sources,cases=rows,case_count=len(rows),actual_original_CPU_stores=cpu_total,actual_original_table_stores=table_total,actual_original_instructions=trace_total,whole_zone_case_replays=30,
  actual_guest_terminal_chunk='538421',actual_guest_exit_code=0,actual_guest_rerun=False,VM_import_or_instantiation=False,
  exact_store_opcode_ISA_GP16_address_value_preimage_verified=True,branch_class_masks_and_exact_store_PCs_verified=True,
  original_instruction_trace_controlflow_and_IRQ_pre_POP_verified=True,original_POP_frame_and_return_target_independently_verified=True,
  final_return_GP16_CPSR_SP_serialized=False,final_return_registers_independently_readback_verified=False,frozen_runtime_source_checked_final_R0_saved_flags_SP_and_CPSR=True,
  complete_native_return_state_proof=False,synthetic_L1_L2_inputs=True,model_MMU_disabled=True,
  captured_original_hardware_or_cold_boot_MMU_tables=False,actual_hardware_translation_physical_page_backing_cache_TLB_effectiveness_verified=False,
  native_heap_allocation_return_or_Dispatcher_full_body_or_App_verified=False,device_io=False,canonical_write=False,
  limits=['The actual root terminal EXIT0 and exact frozen source checked final SP, CPSR and R0 saved IRQ flags; final GP16/SP/CPSR snapshot was not serialized. Independent history ends at original221D92 POP before execution. Frame destination and pre-POP IRQ state are independently checked, not a complete returned-register proof.',
   'All three-zone beforebytes are explicitly synthetic host declarations. Whole journals prove software descriptor writes to these declared bytes only, not stock cold tables, installed bootloader, physical backing, hardware translation/cache/TLB or native heap success.',
   'Model SCTLR.M is0: original6F012C skips the MMU-enabled maintenance/4-byte ARMSTM path. Ten cases cover type0,section and coarse/fine classes0..3; they do not cover actual MMU-enabled state.',
   'Original returnR0 is saved ARM IRQ flags. Type0 and unsupported coarseclass3 return without address replacement; a successful native function return is not evidence of mapping.',
   'V1 wrong ARM-initial versus Thumb-return CPSR comparison failure and actual terminal receipt remain immutable dependencies. V2 succeeded without modifying any original MAIN code or function result.'])
 out=BASE/'software-mapping-v2-independent-file-verification.json';create(out,doc)
 print(json.dumps(dict(all_passed=True,proof=rel(out),proof_sha256=sha(out),case_count=len(rows),CPU_stores=cpu_total,table_stores=table_total,final_return_register_readback_verified=False,guest_execution=False)))
if __name__=='__main__':main()
