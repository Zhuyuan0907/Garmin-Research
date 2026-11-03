#!/usr/bin/env python3
"""Original 221D34 bounded software writes against DECLARED SYNTHETIC tables.

Not captured boot MMU state, physical backing, hardware translation/cache/TLB,
heap allocation, complete constructor/App, or an installation candidate.
Original IRQ/maintenance veneers and bodies run; no function hooks or patches.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import struct
import traceback
from collections import Counter

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn.arm_const import *

BASE=Path(__file__).resolve().parent
L1,L2,STACK,RETURN = 0x03e00000,0x03f00000,0x08800000,0x08ff0000
VA=0x18305000
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,
      UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
      UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,
      UC_ARM_REG_R12,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC]

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(path,value):
    with path.open('x') as h:json.dump(value,h,indent=2);h.write('\n')
def require(value,message):
    if not value:raise ValueError(message)

class MappingCase:
    def __init__(self,stock,spec):
        self.stock=stock;self.spec=spec;self.uc=uc=Uc(UC_ARCH_ARM,UC_MODE_ARM)
        uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
        self.decoders={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
        self.pages=[(0x221000,0x2000),(0x21b000,0x1000),(0x327000,0x1000),
                    (0x33e000,0x1000),(0x6f0000,0x1000)]
        for a,n in self.pages:
            uc.mem_map(a,n,UC_PROT_READ|UC_PROT_EXEC);uc.mem_write(a,stock.read(a,n))
        uc.mem_map(RETURN,4096,UC_PROT_READ|UC_PROT_EXEC)
        uc.mem_write(RETURN,bytes.fromhex('7047'))
        self.zones=[('L1',L1,0x4000),('L2',L2,0x1000),('stack',STACK,0x10000)]
        for name,a,n in self.zones:
            uc.mem_map(a,n,UC_PROT_READ|UC_PROT_WRITE)
            uc.mem_write(a,(bytes(n)if name=='L1' else b'\xa5'*n))
        self.slot=L1+(VA>>20)*4
        l1_type=spec['L1_type']
        l1_word=0 if l1_type==0 else (0xabc00a02 if l1_type==2 else L2|l1_type)
        uc.mem_write(self.slot,struct.pack('<I',l1_word))
        self.l2_slot=None
        if l1_type in (1,3):
            self.l2_slot=L2+((VA&0xfffff)>>(12 if l1_type==1 else 10))*4
            uc.mem_write(self.l2_slot,struct.pack('<I',spec['L2_word']))
        self.initial={name:bytes(uc.mem_read(a,n)).hex()for name,a,n in self.zones}
        self.RX={str(a):hashlib.sha256(bytes(uc.mem_read(a,n))).hexdigest()for a,n in self.pages}
        self.RX[str(RETURN)]=hashlib.sha256(bytes(uc.mem_read(RETURN,4096))).hexdigest()
        self.visits=Counter();self.stores=[];self.trace=[];self.done=False
        self.sp=STACK+0xff00
        uc.reg_write(UC_ARM_REG_CPSR,0x1f)
        for i,reg in enumerate(REGS[:13]):uc.reg_write(reg,0x13520000+i)
        uc.reg_write(UC_ARM_REG_R0,VA);uc.reg_write(UC_ARM_REG_R1,spec['physical_fixture'])
        uc.reg_write(UC_ARM_REG_SP,self.sp);uc.reg_write(UC_ARM_REG_LR,RETURN+1)
        self.entry_CPSR=uc.reg_read(UC_ARM_REG_CPSR)
        self.SCTLR=uc.reg_read(UC_ARM_REG_CP_REG,(15,0,0,1,0,0,0))
        require(not self.SCTLR&1,'This software-only test requires model MMU disabled; no translation claim')
        uc.hook_add(UC_HOOK_CODE,self.code)
        uc.hook_add(UC_HOOK_MEM_WRITE,self.write)
    def code(self,uc,address,size,user):
        if address==RETURN:self.done=True;uc.emu_stop();return
        require(any(a<=address and address+size<=a+n for a,n in self.pages),'Unreviewed code target')
        require(bytes(uc.mem_read(address,size))==self.stock.read(address,size),'Original code changed')
        self.visits[address]+=1
        self.trace.append(dict(PC=address,Thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32),
            SP=uc.reg_read(UC_ARM_REG_SP),LR=uc.reg_read(UC_ARM_REG_LR)))
    def write(self,uc,access,address,size,value,user):
        zone=next((name for name,a,n in self.zones if a<=address and address+size<=a+n),None)
        require(zone is not None,'Write outside declared L1/L2/stack')
        pc=uc.reg_read(UC_ARM_REG_PC);cpsr=uc.reg_read(UC_ARM_REG_CPSR);thumb=bool(cpsr&32)
        decoded=list(self.decoders[thumb].disasm(self.stock.read(pc,4),pc,count=1))
        require(len(decoded)==1,'No original store opcode')
        insn=decoded[0]
        require(insn.mnemonic.startswith(('str','stm','push')),'Non-store origin')
        self.stores.append(dict(ordinal=len(self.stores)+1,PC=pc,Thumb=thumb,
            opcode_hex=insn.bytes.hex(),instruction=insn.mnemonic+' '+insn.op_str,
            address=address,size=size,value=value,zone=zone,
            before_hex=bytes(uc.mem_read(address,size)).hex(),CPSR=cpsr,
            GP16=[uc.reg_read(r)for r in REGS]))
    def run(self):
        self.uc.emu_start(0x221d35,0,timeout=2_000_000,count=2000)
        require(self.done,'Original function did not actually return')
        require(self.uc.reg_read(UC_ARM_REG_SP)==self.sp,'Original stack not restored')
        require(self.uc.reg_read(UC_ARM_REG_CPSR)==self.entry_CPSR,'Original IRQ/flags not restored')
        require(all(self.visits[a] for a in (0x21b6cc,0x3275a4,0x6f012c,
                0x33e664,0x6f0250,0x33e678,0x6f040c,0x21b6dc)),'Original maintenance chain bypassed')
        final={name:bytes(self.uc.mem_read(a,n)).hex()for name,a,n in self.zones}
        for name,a,n in self.zones:
            replay=bytearray.fromhex(self.initial[name])
            for s in self.stores:
                if s['zone']!=name:continue
                off=s['address']-a
                require(replay[off:off+s['size']].hex()==s['before_hex'],'Store preimage differs')
                replay[off:off+s['size']]=int(s['value']).to_bytes(s['size'],'little')
            require(replay.hex()==final[name],'Whole zone journal replay differs')
        table_stores=[s for s in self.stores if s['zone']!='stack']
        t=self.spec['L1_type'];phy=self.spec['physical_fixture']
        if t==0:expected=[]
        elif t==2:expected=[(0x221d9a,self.slot,(0xabc00a02&0xfffff)|phy)]
        else:
            word=self.spec['L2_word'];kind=word>>30
            expected=[(0x221dae if t==1 else 0x221d74,self.l2_slot,word|kind)]
            bits={1:16,2:12,3:10}.get(kind)
            if bits and(kind in (1,2)or t==3):
                expected.append(({1:0x221dc6,2:0x221dbc,3:0x221d86}[kind],self.l2_slot,
                                 ((word|kind)&((1<<bits)-1))|phy))
        require([(s['PC'],s['address'],s['value'])for s in table_stores]==expected,'Exact mapping branch stores differ')
        for a,n in [*self.pages,(RETURN,4096)]:
            require(hashlib.sha256(bytes(self.uc.mem_read(a,n))).hexdigest()==self.RX[str(a)],'RX changed')
        require(bytes(self.uc.mem_read(STACK,32))==b'\xa5'*32 and
                bytes(self.uc.mem_read(self.sp,256))==b'\xa5'*256,'Stack canaries changed')
        return dict(name=self.spec['name'],passed=True,declared_synthetic_input=self.spec,
            virtual_address=VA,L1_slot=self.slot,L2_slot=self.l2_slot,
            initial_whole_zones=self.initial,final_whole_zones=final,
            zones=[dict(name=name,start=a,size=n)for name,a,n in self.zones],
            actual_CPU_stores=self.stores,exact_table_store_count=len(table_stores),
            instructions=len(self.trace),original_instruction_trace=self.trace,
            original_visits={hex(k):v for k,v in self.visits.items()},unchanged_RX_sha256=self.RX,
            model_SCTLR=self.SCTLR,actual_IRQ_flags_and_SP_restored=True,
            original_mapping_function_returned=True,whole_zone_CPU_replay_passed=True,
            function_fixtures=[],original_code_modified=False,captured_hardware_L1_L2=False,
            real_MMU_translation_or_physical_backing_or_cache_TLB_verified=False,
            native_heap_return_or_constructor_or_App_verified=False,device_io=False)

def main():
    runtime=BASE/'guest-v1';runtime.mkdir(exist_ok=False)
    sources={str(Path(__file__).resolve().relative_to(ROOT)):sha(Path(__file__).resolve()),
        'scripts/analyze_native_sections.py':sha(ROOT/'scripts/analyze_native_sections.py'),
        'evidence/firmware-analysis/main_02bd.bin':sha(ROOT/'evidence/firmware-analysis/main_02bd.bin')}
    require(sources['evidence/firmware-analysis/main_02bd.bin']==EXPECTED,'Wrong device image')
    dump(runtime/'inputs-at-run.json',sources)
    (runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
    specs=[dict(name='missing_L1_returns_without_mapping',L1_type=0,physical_fixture=0x18303000),
        dict(name='section_L1_keeps_low20',L1_type=2,physical_fixture=0x18000000)]
    for t in (1,3):
        for kind in (0,1,2,3):
            specs.append(dict(name=('coarse'if t==1 else'fine')+'_L2_class'+str(kind),L1_type=t,
                L2_word=(kind<<30)|0x150,physical_fixture=0x18300000 if kind==1 else 0x18303000))
    stock=NativeImage();rows=[];m=None
    try:
        for spec in specs:
            m=MappingCase(stock,spec);row=m.run();p=runtime/(spec['name']+'.json');dump(p,row)
            rows.append(dict(name=spec['name'],path=str(p.relative_to(ROOT)),sha256=sha(p),passed=True))
            print(spec['name']+' PASS',flush=True);m.uc=None;m=None
        proof=dict(all_passed=True,source_sha256=sources,cases=rows,case_count=len(rows),
            updated_utc=datetime.now(timezone.utc).isoformat(),scope='Bounded original software branch/write checks only; L1/L2 are declared synthetic inputs.',
            no_function_hooks_or_original_code_patches=True,all_actual_table_stores_and_IRQ_full_return_checked=True,
            missing_L1_return_is_not_mapping=True,captured_original_boot_MMU_state=False,
            real_hardware_MMU_page_backing_cache_TLB_or_native_heap_or_App_verified=False,device_io=False)
        dump(BASE/'software-mapping-v1-proof.json',proof);print(json.dumps({'all_passed':True,'case_count':len(rows)}))
    except BaseException as e:
        failure=dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),cases_completed=rows,source_sha256=sources)
        if m:failure.update(trace=m.trace,stores=m.stores,PC=m.uc.reg_read(UC_ARM_REG_PC),
            SP=m.uc.reg_read(UC_ARM_REG_SP),LR=m.uc.reg_read(UC_ARM_REG_LR))
        dump(runtime/'terminal-failure.json',failure);raise

if __name__=='__main__':main()
