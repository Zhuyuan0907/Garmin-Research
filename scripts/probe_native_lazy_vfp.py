#!/usr/bin/env python3
"""Original lazy-VFP handler under explicit ARM undefined-entry inputs.

Exception entry is an architectural fixture, not a recovered hardware vector.
Only first/same task ownership without FP context exchange is admitted here.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import *
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
from analyze_native_sections import ROOT,NativeImage,EXPECTED

OWNER=0x3ab1038
HANDLER=0x20ebe0
FAULT=0x3404dc
RETURN=0x10000
TRAPSTACK=0x0ec00000
TRAPBYTES=4096
GENERAL=[UC_ARM_REG_R0+n for n in range(13)]+[UC_ARM_REG_SP,UC_ARM_REG_LR]
DOUBLE=[UC_ARM_REG_D0+n for n in range(16)]

def require(value,message):
    if not value:raise AssertionError(message)

class LazyVFPState:
    def __init__(self,uc,stock,current,live,stack_top):
        self.uc=uc;self.stock=stock;self.current=current;self.live=live;self.stack_top=stack_top
        self.rows=[];self.active=None;self.ds=Cs(CS_ARCH_ARM,CS_MODE_ARM)

    def snapshot(self):
        uc=self.uc
        return dict(PC=hex(uc.reg_read(UC_ARM_REG_PC)),CPSR=hex(uc.reg_read(UC_ARM_REG_CPSR)),
            FPEXC=hex(uc.reg_read(UC_ARM_REG_FPEXC)),FPSCR=hex(uc.reg_read(UC_ARM_REG_FPSCR)),
            CPACR=hex(uc.reg_read(UC_ARM_REG_C1_C0_2)),
            GP15=[hex(uc.reg_read(r)) for r in GENERAL],D16=[hex(uc.reg_read(r)) for r in DOUBLE],
            FPowner=hex(struct.unpack('<I',uc.mem_read(OWNER,4))[0]),current_TCB=hex(self.current()))

    def enter(self,error):
        require(error.errno==unicorn.UC_ERR_INSN_INVALID and self.active is None,'Unexpected or recursive exception')
        snap=self.snapshot();uc=self.uc;pc=int(snap['PC'],16);status=int(snap['CPSR'],16)
        raw=self.stock.read(pc,4);opcode=struct.unpack('<I',raw)[0]
        instructions=list(self.ds.disasm(raw,pc))
        require(not status&32 and status&31 in [16,31] and len(instructions)==1 and
                instructions[0].mnemonic.startswith('v') and ((opcode>>8)&15) in [10,11],
                'Undefined instruction is outside exact ARM CP10/11 native scope')
        require(bytes(uc.mem_read(pc,4))==raw,'Fault opcode differs from original MAIN')
        require(int(snap['FPEXC'],16)&0x40000000==0 and int(snap['CPACR'],16)&0xf00000==0xf00000,
                'Fault lacks disabled-FPEXC and explicit CP10/11 access witness')
        task=self.current();owner=int(snap['FPowner'],16)
        require(self.live(task,108) and owner in [0,task],
                'FP context exchange not admitted without complete original metadata/save backing')
        require(len(self.rows)<32,'Lazy VFP trap budget exhausted')
        row=dict(before=snap,opcode_hex=raw.hex(),original_instruction=instructions[0].mnemonic+' '+instructions[0].op_str,
            undefined_entry_is_explicit_architectural_fixture=True,host_wrote_FP_enable_or_context=False,
            original_handler_entered=False,original_exception_return_seen=False,original_opcode_retry_reached=False)
        self.rows.append(row);self.active=row
        # Model only ARM undefined entry: banked SP/LR, SPSR, mode and IRQ mask.
        # General registers, old task stack, FPEXC and FP owner are untouched.
        uc.reg_write(UC_ARM_REG_CPSR,(status&~0x3f)|0x1b|0x80)
        uc.reg_write(UC_ARM_REG_SP,self.stack_top)
        uc.reg_write(UC_ARM_REG_LR,pc+4)
        uc.reg_write(UC_ARM_REG_SPSR,status)
        return HANDLER

    def observe(self,uc,address,size,data):
        if self.active is None:return
        row=self.active
        if address==HANDLER:
            require(uc.reg_read(UC_ARM_REG_CPSR)&31==0x1b and
                    uc.reg_read(UC_ARM_REG_SPSR)==int(row['before']['CPSR'],16) and
                    uc.reg_read(UC_ARM_REG_SP)==self.stack_top and
                    uc.reg_read(UC_ARM_REG_LR)==int(row['before']['PC'],16)+4,
                    'Original handler entry banked frame differs')
            row['original_handler_entered']=True
        if address in [0x20ecd8,0x20ed0c,0x6e9340]:
            raise AssertionError('Original FP context exchange/fatal path is outside current first/same-owner scope')
        if address==0x20ed3c:
            require(row['original_handler_entered'] and uc.reg_read(UC_ARM_REG_SPSR)==int(row['before']['CPSR'],16),
                    'Original exception return SPSR differs')
            row['original_exception_return_seen']=True
        if address==int(row['before']['PC'],16):
            require(row['original_exception_return_seen'],'Fault opcode reached without original exception return')
            after=self.snapshot()
            require(after['CPSR']==row['before']['CPSR'] and after['GP15']==row['before']['GP15'] and
                    after['D16']==row['before']['D16'] and after['FPSCR']==row['before']['FPSCR'],
                    'Original handler did not restore full GP/banked status/FP payload before retry')
            require(int(after['FPEXC'],16)==0x40000000 and int(after['FPowner'],16)==self.current(),
                    'Original handler did not enable FP and select actual current task')
            row.update(original_opcode_retry_reached=True,after_native_handler=after,
                same_task_registers_stack_memory_resumed=True,original_function_not_reentered=True)
            self.active=None


def micro_main():
    require(unicorn.__version__=='2.1.4' and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    stage=ROOT/'staging/native-player-settings-vfp-context/micro';stage.mkdir(parents=True,exist_ok=True)
    target=stage/'original-lazy-vfp-micro-probe.json';require(not target.exists(),'Keep micro evidence immutable')
    stock=NativeImage();uc=unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_ARM)
    fragments=[(0x20ebd4,0x178),(0x358d24,32),(0x6e0820,0x10),(FAULT,16)]
    for page in sorted({a&~4095 for a,n in fragments}|{OWNER&~4095,0xf09000,0x9503000,TRAPSTACK,RETURN}):uc.mem_map(page,4096)
    for a,n in fragments:uc.mem_write(a,stock.read(a,n))
    task=0x9503f90;task2=0x9503f20;uc.mem_write(0xf09090,struct.pack('<I',task))
    uc.mem_write(TRAPSTACK,b'\xa5'*TRAPBYTES)
    uc.reg_write(UC_ARM_REG_C1_C0_2,0xf00000) # declared virtual coprocessor-access input
    lazy=LazyVFPState(uc,stock,lambda:struct.unpack('<I',uc.mem_read(0xf09090,4))[0],
        lambda p,n:p in [task,task2] and n<=108,TRAPSTACK+TRAPBYTES-32)
    uc.hook_add(unicorn.UC_HOOK_CODE,lazy.observe)
    uc.hook_add(unicorn.UC_HOOK_CODE,lambda u,a,s,d:u.emu_stop(),begin=RETURN,end=RETURN)
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256_before_run=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        device_io=False,sounds_emitted=False,TCBs_and_exception_entry_are_explicit_fixtures=True,
        all_passed=False,original_handler_rows=lazy.rows,cases=[])
    try:
        for value,case in [(1638,'first_owner_disable_handler_retry'),(42,'same_owner_disable_handler_retry')]:
            uc.reg_write(UC_ARM_REG_CPSR,0xa000001f)
            for r,index in zip(GENERAL[:13],range(13)):uc.reg_write(r,0x12345000+index)
            uc.reg_write(UC_ARM_REG_R0,value);uc.reg_write(UC_ARM_REG_SP,0x9503f00);uc.reg_write(UC_ARM_REG_LR,RETURN)
            for r,index in zip(DOUBLE,range(16)):uc.reg_write(r,0x0102030405060708+index)
            uc.reg_write(UC_ARM_REG_FPSCR,0);uc.reg_write(UC_ARM_REG_FPEXC,0x40000000)
            uc.emu_start(0x20ebd4,RETURN+4,count=100)
            require(uc.reg_read(UC_ARM_REG_FPEXC)==0,'Original disable helper did not clear FPEXC')
            try:
                uc.emu_start(FAULT,RETURN+4,count=100)
                raise AssertionError('Disabled original VFP did not produce expected undefined instruction')
            except unicorn.UcError as error:
                uc.emu_start(lazy.enter(error),RETURN+4,count=1000)
            expected=struct.unpack('<I',struct.pack('<f',float(value)))[0]
            require(lazy.active is None and uc.reg_read(UC_ARM_REG_R0)==expected and
                    uc.reg_read(UC_ARM_REG_PC)==RETURN and uc.reg_read(UC_ARM_REG_SP)==0x9503f00,
                    'Original uint32-to-float helper did not return expected actual bits')
            require(bytes(uc.mem_read(TRAPSTACK,32))==b'\xa5'*32 and
                    bytes(uc.mem_read(TRAPSTACK+TRAPBYTES-32,32))==b'\xa5'*32,'Exception stack canary changed')
            result['cases'].append(dict(case=case,passed=True,input_uint32=value,original_return_bits=hex(expected)))
        uc.reg_write(UC_ARM_REG_CPSR,0xa000001f);uc.reg_write(UC_ARM_REG_R0,9)
        uc.mem_write(0xf09090,struct.pack('<I',task2));uc.reg_write(UC_ARM_REG_FPEXC,0)
        try:
            uc.emu_start(FAULT,RETURN+4,count=100)
            raise AssertionError('Expected disabled VFP fault absent')
        except unicorn.UcError as error:
            try:lazy.enter(error)
            except AssertionError as admission:
                require('context exchange not admitted' in str(admission),'Wrong unsafe-owner rejection')
                result['cases'].append(dict(case='different_owner_without_FP_context_rejected',passed=True))
            else:raise AssertionError('Unsafe multi-owner context was admitted')
        require(len(lazy.rows)==2 and all(row['original_opcode_retry_reached'] for row in lazy.rows),'Native handler rows incomplete')
        for a,n in fragments:require(bytes(uc.mem_read(a,n))==stock.read(a,n),'Original code bytes changed')
        result.update(all_passed=True,case_count=3,full_original_code_fragments_unchanged=True)
    except Exception as error:
        result.update(error=str(error),registers=lazy.snapshot());print(json.dumps(dict(error=str(error))),flush=True)
    with target.open('x') as handle:json.dump(result,handle,ensure_ascii=False,indent=2);handle.write('\n')
    print(json.dumps({k:result.get(k) for k in ['all_passed','case_count','error']}),flush=True)
    if not result['all_passed']:sys.exit(1)

if __name__=='__main__':micro_main()
