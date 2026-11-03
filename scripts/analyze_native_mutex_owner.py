#!/usr/bin/env python3
"""Resolve exact mixed ARM/Thumb mutex CFGs and native owner/list stores."""
from collections import deque
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from capstone.arm import ARM_INS_B,ARM_INS_BL,ARM_INS_BLX,ARM_INS_BX,ARM_OP_IMM,ARM_OP_MEM,ARM_REG_PC,ARM_CC_AL
from analyze_native_sections import ROOT,NativeImage,EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_native_usb_transition import cfg

def mixed_cfg(image,start,segments,hops,return_tail):
    decoders={mode:Cs(CS_ARCH_ARM,CS_MODE_THUMB if mode=='Thumb'else CS_MODE_ARM)for mode in ['Thumb','ARM']}
    for md in decoders.values():md.detail=True
    queue=deque([(start,'Thumb')]);seen={};returns=[];exits=[]
    while queue:
        address,mode=queue.popleft()
        if (address,mode)in seen:continue
        assert any(a<=address<b and m==mode for a,b,m in segments),(hex(address),mode)
        assert len(seen)<512,'Unexpected local instruction count'
        i=next(decoders[mode].disasm(image.read(address,4),address,count=1))
        row=dict(address=hex(address),mode=mode,instruction=i.mnemonic+' '+i.op_str);seen[address,mode]=row
        if i.id in [ARM_INS_BL,ARM_INS_BLX]:
            assert i.operands[0].type==ARM_OP_IMM
            row['direct_call']=hex(i.operands[0].imm)
        elif i.id==ARM_INS_B:
            assert i.operands[0].type==ARM_OP_IMM
            queue.append((i.operands[0].imm,mode))
            if i.cc==ARM_CC_AL:continue
        elif i.id==ARM_INS_BX:
            if address==return_tail:
                assert mode=='Thumb'and i.op_str=='r3'
                row['balanced_epilogue_original_LR_return']=True;returns.append(hex(address));continue
            assert address in hops,(hex(address),i.op_str)
            target,targetmode,producer,text=hops[address]
            p=next(decoders[mode].disasm(image.read(producer,4),producer,count=1))
            assert p.mnemonic+' '+p.op_str==text
            if p.mnemonic=='adr':
                computed=((producer+4)&~3)+p.operands[-1].imm
            else:
                assert mode=='ARM'and p.mnemonic=='add'and p.operands[1].reg==ARM_REG_PC
                computed=producer+8+p.operands[-1].imm
            assert target==computed&~1 and targetmode==('Thumb'if computed&1 else'ARM')
            row.update(explicit_interworking_target=hex(target),target_mode=targetmode,verified_target_producer=hex(producer))
            queue.append((target,targetmode));continue
        elif ARM_REG_PC in i.regs_access()[1]:
            exits.append(dict(address=hex(address),instruction=row['instruction']));continue
        if i.mnemonic=='ldr'and i.operands[-1].type==ARM_OP_MEM and i.operands[-1].mem.base==ARM_REG_PC:
            literal=(address+8 if mode=='ARM'else(address+4)&~3)+i.operands[-1].mem.disp
            row.update(literal_address=hex(literal),literal_value=hex(image.word(literal)))
        queue.append((address+i.size,mode))
    return dict(entry=hex(start),instructions=[seen[k]for k in sorted(seen)],returns=returns,
        unresolved_exits=exits,instruction_limit_reached=False,callees_not_recursively_executed=True)

def main():
    image=RuntimeImage(NativeImage())
    specs=[
        (0x3009a0,[(0x3009a0,0x3009a8,'Thumb'),(0x3009a8,0x3009bc,'ARM'),(0x3009bc,0x3009f8,'Thumb'),(0x3009f8,0x300a04,'ARM'),(0x300a04,0x300a0c,'Thumb')],
         {0x3009a6:(0x3009a8,'ARM',0x3009a4,'adr r3, #0'),0x3009b8:(0x3009bc,'Thumb',0x3009b4,'add r3, pc, #1'),0x3009f6:(0x3009f8,'ARM',0x3009f4,'adr r2, #0'),0x300a00:(0x300a04,'Thumb',0x3009fc,'add r2, pc, #1')},0x300a0a),
        (0x3008b0,[(0x3008b0,0x3008b8,'Thumb'),(0x3008b8,0x3008cc,'ARM'),(0x3008cc,0x300918,'Thumb'),(0x300918,0x300924,'ARM'),(0x300924,0x30092c,'Thumb')],
         {0x3008b6:(0x3008b8,'ARM',0x3008b4,'adr r3, #0'),0x3008c8:(0x3008cc,'Thumb',0x3008c4,'add r3, pc, #1'),0x300914:(0x300918,'ARM',0x300912,'adr r2, #4'),0x300920:(0x300924,'Thumb',0x30091c,'add r2, pc, #1')},0x30092a),
        (0x300ae4,[(0x300ae4,0x300af4,'Thumb'),(0x300af4,0x300b08,'ARM'),(0x300b08,0x300b74,'Thumb'),(0x300b74,0x300b80,'ARM'),(0x300b80,0x300b88,'Thumb')],
         {0x300af0:(0x300af4,'ARM',0x300aee,'adr r2, #4'),0x300b04:(0x300b08,'Thumb',0x300b00,'add r2, pc, #1'),0x300b70:(0x300b74,'ARM',0x300b6e,'adr r2, #4'),0x300b7c:(0x300b80,'Thumb',0x300b78,'add r2, pc, #1')},0x300b86)]
    functions={hex(a):mixed_cfg(image,a,segments,hops,tail)for a,segments,hops,tail in specs}
    functions['0x3008a0']=cfg(image,0x3008a0,0x3008b0)
    functions['0x358d24']=cfg(image,0x358d24,0x358d34)
    rows={int(r['address'],16):r for f in functions.values()for r in f['instructions']}
    epilogues=[(0x3009a0,'push {lr}',[(0x3009a2,'sub sp, #4'),(0x300a06,'add sp, #4'),(0x300a08,'pop {r3}')]),
        (0x3008b0,'push {r4, lr}',[(0x3008b2,'sub sp, #8'),(0x300924,'add sp, #8'),(0x300926,'pop {r4}'),(0x300928,'pop {r3}')]),
        (0x300ae4,'push {r4, r5, lr}',[(0x300ae6,'sub sp, #4'),(0x300b80,'add sp, #4'),(0x300b82,'pop {r4, r5}'),(0x300b84,'pop {r3}')])]
    for entry,push,stack in epilogues:
        assert rows[entry]['instruction']==push and all(rows[a]['instruction']==text for a,text in stack)
        functions[hex(entry)]['balanced_saved_LR_stack_frame_verified']=True
    assert all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in functions.values())
    assert rows[0x3009ca]['instruction']=='str r2, [r0, #8]'and rows[0x3009d4]['instruction']=='str r0, [r2]'
    assert rows[0x3009e6]['instruction']=='strh r3, [r0, #0x14]'and rows[0x3008f2]['instruction']=='str r1, [r0, #8]'
    assert rows[0x3009ec]['direct_call']=='0x300d08'and rows[0x30090c]['direct_call']=='0x358e70'
    assert rows[0x300b1e]['instruction']=='cmp r1, r4'and rows[0x300b20]['instruction']=='beq #0x300b6c'
    assert rows[0x300b3a]['instruction']=='str r4, [r0, #8]'and rows[0x300b46]['instruction']=='str r0, [r1]'
    assert image.word(0x300a0c)==image.word(0x300930)==0xf09090
    files=[Path(__file__).resolve(),ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_native_voice_acceptance.py',
        ROOT/'scripts/analyze_native_usb_transition.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in files},
        complete_bounded_CFG_count=5,complete_mixed_ARM_Thumb_function_count=3,functions=functions,
        explicit_verified_instruction_set_transitions=12,
        original_owner_store='0x3009ca',original_owned_list_insert='0x3009d4',
        original_owner_clear='0x3008f2',original_recursion_increment='0x3009e6',
        original_transfer_owner_store='0x300b3a',original_task_list_global='0xf09090',
        contention_callee_not_recovered='0x300d08',reschedule_callee_not_recovered='0x358e70',
        real_task_scheduler_IRQ_boot_event_dispatch_or_App_verified=False,device_io=False,sounds_emitted=False,
        limits='Five complete bounded CFGs including three original mixed ARM/Thumb mutex bodies and12 verified ADR/ADD-PC/BX transitions with balanced LR epilogues. Original immediate owner/list and recursion stores established, no host-written owner fields. Contention, waiter wakeup, scheduler and priority-transfer callees are recorded but not recursively recovered. Runtime controls and full controller/device behavior remain separate.')
    path=ROOT/'staging/native-player-mutex-owner/mutex-owner-static-preflight.json';assert not path.exists()
    path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(complete_CFGs=5,mixed_functions=3,verified_mode_transitions=12)))

if __name__=='__main__':main()
