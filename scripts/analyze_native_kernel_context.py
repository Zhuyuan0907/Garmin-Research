#!/usr/bin/env python3
"""Resolve bounded exact normal-event and mutex-contention mixed-mode CFGs."""
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm import ARM_INS_B, ARM_INS_BL, ARM_INS_BLX, ARM_INS_BX, ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC, ARM_CC_AL
from analyze_native_sections import ROOT, NativeImage, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage

def resolve(image,start,mode,segments,hops,tails,external):
    md={name:Cs(CS_ARCH_ARM,CS_MODE_THUMB if name=='Thumb'else CS_MODE_ARM)for name in ['Thumb','ARM']}
    for decoder in md.values():decoder.detail=True
    todo=deque([(start,mode)]);seen={};ends=[];outside=[]
    while todo:
        address,mode=todo.popleft()
        if (address,mode)in seen:continue
        assert len(seen)<512 and any(lo<=address<hi and m==mode for lo,hi,m in segments),(hex(address),mode)
        ins=next(md[mode].disasm(image.read(address,4),address,count=1))
        row=dict(address=hex(address),mode=mode,instruction=ins.mnemonic+' '+ins.op_str);seen[address,mode]=row
        if address in tails:
            assert row['instruction']==tails[address]
            row['resolved_terminal']='saved_native_task_context_dispatch'if ins.mnemonic=='movs'else'original_LR_return'
            ends.append(hex(address));continue
        if ins.id in [ARM_INS_BL,ARM_INS_BLX]:
            assert ins.operands[0].type==ARM_OP_IMM
            row['direct_call']=hex(ins.operands[0].imm)
        elif ins.id==ARM_INS_B:
            target=ins.operands[0].imm
            if target in external:
                row['known_external_tail']=external[target];outside.append(hex(target))
            else:todo.append((target,mode))
            if ins.cc==ARM_CC_AL:continue
        elif ins.id==ARM_INS_BX:
            assert address in hops,(hex(address),row['instruction'])
            target,targetmode,producer=hops[address]
            if ins.op_str=='pc':computed=(address+4)&~3;assert targetmode=='ARM'
            else:
                p=next(md[mode].disasm(image.read(producer,4),producer,count=1))
                if p.mnemonic=='adr':computed=((producer+4)&~3)+p.operands[-1].imm
                else:
                    assert mode=='ARM'and p.mnemonic=='add'and p.operands[1].reg==ARM_REG_PC
                    computed=producer+8+p.operands[-1].imm
                assert targetmode==('Thumb'if computed&1 else'ARM')
            assert computed&~1==target
            row.update(explicit_interworking_target=hex(target),target_mode=targetmode,verified_target_producer=hex(producer)if producer else'architectural Thumb PC')
            todo.append((target,targetmode));continue
        elif ARM_REG_PC in ins.regs_access()[1]:raise ValueError('Unresolved PC write '+hex(address))
        if ins.mnemonic=='ldr'and ins.operands[-1].type==ARM_OP_MEM and ins.operands[-1].mem.base==ARM_REG_PC:
            literal=(address+8 if mode=='ARM'else(address+4)&~3)+ins.operands[-1].mem.disp
            row.update(literal_address=hex(literal),literal_value=hex(image.word(literal)))
        todo.append((address+ins.size,mode))
    return dict(entry=hex(start),entry_mode=next(m for lo,hi,m in segments if lo<=start<hi),
        instructions=[seen[k]for k in sorted(seen)],returns_or_native_context_dispatch=ends,
        known_external_tails=outside,unresolved_exits=[],instruction_limit_reached=False,callees_not_recursively_executed=True)

def main():
    image=RuntimeImage(NativeImage())
    specs=[
        (0x2fcf44,'ARM',[(0x2fcf44,0x2fcf6c,'ARM'),(0x2fcf6c,0x2fcfb0,'Thumb'),(0x2fcfb0,0x2fcfec,'ARM'),(0x2fcfec,0x2fd01c,'Thumb'),(0x2fd01c,0x2fd028,'ARM'),(0x2fd028,0x2fd02c,'Thumb')],
         {0x2fcf68:(0x2fcf6c,'Thumb',0x2fcf64),0x2fcfac:(0x2fcfb0,'ARM',0x2fcfaa),0x2fcfe8:(0x2fcfec,'Thumb',0x2fcfe4),0x2fd01a:(0x2fd01c,'ARM',0x2fd018),0x2fd024:(0x2fd028,'Thumb',0x2fd020)},
         {0x2fd02a:'bx lr'},{0x2fce38:'original interrupt-marker post, separately scoped; current runtime fixture marker is zero'}),
        (0x2fd034,'Thumb',[(0x2fd034,0x2fd03c,'Thumb'),(0x2fd03c,0x2fd050,'ARM'),(0x2fd050,0x2fd06c,'Thumb'),(0x2fd06c,0x2fd0a8,'ARM'),(0x2fd0a8,0x2fd0c4,'Thumb'),(0x2fd0c4,0x2fd0d0,'ARM'),(0x2fd0d0,0x2fd0d4,'Thumb')],
         {0x2fd038:(0x2fd03c,'ARM',0x2fd036),0x2fd04c:(0x2fd050,'Thumb',0x2fd048),0x2fd06a:(0x2fd06c,'ARM',0x2fd068),0x2fd0a4:(0x2fd0a8,'Thumb',0x2fd0a0),0x2fd0c2:(0x2fd0c4,'ARM',0x2fd0c0),0x2fd0cc:(0x2fd0d0,'Thumb',0x2fd0c8)},
         {0x2fd0d2:'bx lr'},{}),
        (0x358ec4,'ARM',[(0x358ec4,0x358ecc,'ARM'),(0x358ecc,0x358ee0,'Thumb'),(0x358ee0,0x358f0c,'ARM')],
         {0x358ec8:(0x358ecc,'Thumb',0x358ec4),0x358edc:(0x358ee0,'ARM',None)},
         {0x358f08:'movs pc, lr'},{}),
        (0x358e70,'Thumb',[(0x358e70,0x358e7c,'Thumb'),(0x358e7c,0x358eb8,'ARM'),(0x358eb8,0x358ebe,'Thumb')],
         {0x358e7a:(0x358e7c,'ARM',0x358e78),0x358eb4:(0x358eb8,'Thumb',0x358eb0)},
         {0x358ebc:'bx lr'},{}),
        (0x300d08,'Thumb',[(0x300d08,0x300d44,'Thumb'),(0x300d44,0x300d80,'ARM'),(0x300d80,0x300dce,'Thumb')],
         {0x300d40:(0x300d44,'ARM',0x300d3e),0x300d7c:(0x300d80,'Thumb',0x300d78)},
         {0x300dcc:'bx r3'},{}),
    ]
    functions={hex(start):resolve(image,start,mode,segs,hops,tails,external)for start,mode,segs,hops,tails,external in specs}
    rows={int(r['address'],16):r for f in functions.values()for r in f['instructions']}
    assert rows[0x2fcfd0]['instruction']=='str sp, [r2, #0xc]'and rows[0x2fd08c]['instruction']=='str sp, [r2, #0xc]'
    assert rows[0x300d64]['instruction']=='str sp, [r6, #0xc]'and rows[0x358ed6]['instruction']=='ldr r4, [r0, #0xc]'
    assert rows[0x358ef4]['instruction']=='msr cpsr_c, ip'and rows[0x358ef8]['instruction']=='msr spsr_fsxc, r5'
    files=[Path(__file__).resolve(),ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_native_voice_acceptance.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in files},
        complete_bounded_normal_context_CFG_count=5,functions=functions,verified_interworking_transitions=sum(len(hops)for _,_,_,hops,_,_ in specs),
        original_normal_post='0x2fcf44',original_wait='0x2fd034',original_context_restore='0x358ec4',
        original_contention='0x300d08',native_saved_context_TCB_offset=12,
        restore_dispatches_original_saved_PC_and_CPSR_with_banked_SP_LR=True,
        initial_CPU_mode_must_be_declared_input=True,actual_IRQ_exit_or_full_dispatcher_App_runtime_verified=False,
        device_io=False,sounds_emitted=False,
        limits='Five bounded mixed ARM/Thumb normal-context function CFGs with explicit PC arithmetic and original native frame stores/restore verified. Normal post alternate marker tail2FCE38 is a known external tail, not unresolved or recursively recovered IRQ exit. Native restore terminal dispatches saved task PC/CPSR through banked registers rather than returning to its caller. Full boot/task inputs, actual timer/dispatcher events, priority propagation callees and device behavior require separate runtime evidence.')
    path=ROOT/'staging/native-player-kernel-context/kernel-context-static-preflight.json';assert not path.exists()
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(complete_normal_context_CFGs=5,interworking_transitions=result['verified_interworking_transitions'])))

if __name__=='__main__':main()
