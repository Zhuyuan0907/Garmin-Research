#!/usr/bin/env python3
"""Observe original lazy-VFP save/clone/restore with declared virtual inputs.

This observer never writes an FP register, owner, metadata or task pointer.
Only undefined exception entry is modeled architecturally. The standalone
micro uses two explicitly supplied TCBs; it is not a recovered full boot.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, struct, sys
import unicorn
from unicorn.arm_const import *
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from analyze_native_sections import ROOT, NativeImage, EXPECTED
from probe_native_lazy_vfp import LazyVFPState, OWNER, HANDLER, FAULT, GENERAL, DOUBLE

MAGIC = 0xfce3e2ca
STAGE = ROOT/'staging/native-player-dispatcher-fp/micro-vfp'
STOP = 0x10000
UND = 0x18310000
UND_BYTES = 4096

def require(value, message):
    if not value: raise AssertionError(message)

def sha(raw): return hashlib.sha256(raw).hexdigest()
def word(uc, address): return struct.unpack('<I', uc.mem_read(address, 4))[0]
def dump(path, doc):
    with path.open('x') as handle:
        json.dump(doc, handle, ensure_ascii=False, indent=2); handle.write('\n')

class MultiOwnerVFPState(LazyVFPState):
    """Narrow two-task handler observer, with original-only mutation history."""
    def __init__(self, uc, stock, current, live, stack_top, tasks, exclusive=False):
        super().__init__(uc, stock, current, live, stack_top)
        self.tasks = tasks; self.exclusive = exclusive; self.allocations = []
        self.zones = {}; self.decoded = {}; self.pushes = []; self.code_hashes = {}
        self.disassemblers = {False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
        require(len(tasks)==2 and all(self.live(t,108) for t in tasks), 'Need exactly two admitted live TCB108s')
        ranges = [(OWNER&~4095,4096),(stack_top-UND_BYTES+32,UND_BYTES)]
        for t, spec in tasks.items():
            m, base = spec['metadata'], spec['pool']
            require(word(uc,t+28)==m and self.live(m,40) and self.live(base,320), 'Declared task metadata/pool lacks live backing')
            raw = bytes(uc.mem_read(m,40)); words = list(struct.unpack('<10I',raw))
            require(words[2]==base and words[7]==0 and base+320<spec['minimum_live_SP'], 'Cold pool collides with live stack/slot')
            require(bytes(uc.mem_read(base,320))==b'\xff'*320, 'Cold native-filled pool/guard differs')
            spec.update(original_metadata_hex=raw.hex(),initial_TCB_hex=bytes(uc.mem_read(t,108)).hex(),
                        first_context=(base+15)&~7,expected_metadata=m,context=0)
            ranges += [(t,108),(m,40),(base,320)]
        ranges.sort()
        require(all(a+n<=b for (a,n),(b,k) in zip(ranges,ranges[1:])), 'FP journals overlap')
        for low,n in ranges:
            self.zones[low] = dict(start=hex(low),bytes=n,before_hex=bytes(uc.mem_read(low,n)).hex(),stores=[])
            uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.journal,begin=low,end=low+n-1)

    def metadata(self, task):
        require(task in self.tasks and self.live(task,108), 'FP actor outside declared two-task inventory')
        spec=self.tasks[task]; m=word(self.uc,task+28)
        require(m==spec['expected_metadata'] and self.live(m,40), 'Live metadata differs from observed native publication')
        raw=bytes(self.uc.mem_read(m,40)); words=list(struct.unpack('<10I',raw))
        require(words[2]==spec['pool'] and words[7]==spec['context'], 'Live pool/slot differs from observed native history')
        if m!=spec['metadata']:
            expected=bytearray.fromhex(spec['original_metadata_hex']);expected[4]=1
            struct.pack_into('<I',expected,28,spec['context'])
            require(raw==expected and bytes(self.uc.mem_read(spec['metadata'],40)).hex()==spec['original_metadata_hex'],
                    'Native cloned metadata or immutable original changed')
        else:
            expected=bytearray.fromhex(spec['original_metadata_hex']);struct.pack_into('<I',expected,28,spec['context'])
            require(raw==expected, 'Mutable metadata changed outside original FP slot')
        return m, words, raw

    def enter(self,error):
        require(error.errno==unicorn.UC_ERR_INSN_INVALID and self.active is None, 'Unexpected or recursive exception')
        before=self.snapshot(); uc=self.uc;pc=int(before['PC'],16);status=int(before['CPSR'],16)
        raw=self.stock.read(pc,4);opcode=struct.unpack('<I',raw)[0];ins=list(self.ds.disasm(raw,pc))
        require(not status&32 and status&31 in [16,31] and len(ins)==1 and ins[0].mnemonic.startswith('v') and
                ((opcode>>8)&15) in [10,11] and bytes(uc.mem_read(pc,4))==raw, 'Fault is not unchanged original ARM CP10/11 code')
        require(int(before['FPEXC'],16)==0 and int(before['CPACR'],16)&0xf00000==0xf00000, 'Missing disabled-FPEXC/access witness')
        task=self.current();owner=word(uc,OWNER)
        self.metadata(task)
        if owner:self.metadata(owner)
        require(len(self.rows)<32, 'Native FP trap budget exhausted')
        newslot=self.tasks[task]['context'];expected_bank=[int(v,16) for v in before['D16']]
        expected_fpscr=int(before['FPSCR'],16)
        if owner!=task and newslot:
            saved=bytes(uc.mem_read(newslot,148));controls=list(struct.unpack_from('<4I',saved,132))
            require(controls[0]==0x40000000, 'Saved context has unsupported exceptional FPEXC')
            expected_bank=list(struct.unpack_from('<16Q',saved));expected_fpscr=controls[3]
        row=dict(before=before,opcode_hex=raw.hex(),original_instruction=ins[0].mnemonic+' '+ins[0].op_str,
            undefined_entry_is_explicit_architectural_fixture=True,host_wrote_FP_enable_or_context=False,
            original_handler_entered=False,original_exception_return_seen=False,original_opcode_retry_reached=False,
            old_owner=hex(owner),new_owner=hex(task),old_context=hex(self.tasks[owner]['context']) if owner else '0x0',
            new_context_before=hex(newslot),expected_retry_D16=[hex(v) for v in expected_bank],
            expected_retry_FPSCR=hex(expected_fpscr),expected_retry_bank_source='new_owner_saved_context' if owner!=task and newslot else 'actual_fault_bank',
            TCB_before={hex(t):bytes(uc.mem_read(t,108)).hex() for t in self.tasks},
            allocation_rows=[],push_rows=[],VSTM_callbacks=[],control_STM_callbacks=[],save_complete=False,restore_complete=False)
        self.rows.append(row);self.active=row
        # Architectural UND entry only, preserving all ordinary/FP state.
        uc.reg_write(UC_ARM_REG_CPSR,(status&~0x3f)|0x1b|0x80)
        uc.reg_write(UC_ARM_REG_SP,self.stack_top);uc.reg_write(UC_ARM_REG_LR,pc+4);uc.reg_write(UC_ARM_REG_SPSR,status)
        return HANDLER

    def decode(self,pc,thumb):
        key=(pc,thumb)
        if key not in self.decoded:
            load=self.stock.runtime_to_load(pc,4) if any(r['runtime_start']<=pc and pc+4<=r['runtime_end'] for r in self.stock.copies) else pc
            raw=self.stock.read(load,4);ins=list(self.disassemblers[thumb].disasm(raw,pc,count=1))
            require(len(ins)==1 and ins[0].mnemonic.startswith(('str','stm','push','vstm','swp')), 'FP zone writer is not original store code')
            self.decoded[key]=(load,raw[:ins[0].size],ins[0].mnemonic+' '+ins[0].op_str)
        load,raw,instruction=self.decoded[key]
        require(bytes(self.uc.mem_read(pc,len(raw)))==raw, 'Original FP writer opcode changed')
        return load,raw,instruction

    def journal(self,uc,access,address,size,value,data):
        pc=uc.reg_read(UC_ARM_REG_PC);thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)
        require(not self.exclusive or self.active is not None, 'Mutation outside explicit native FP exception')
        require(size in [1,2,4,8], 'Unexpected original FP store callback width')
        zone=next((r for lo,r in self.zones.items() if lo<=address and address+size<=lo+r['bytes']),None)
        require(zone is not None, 'Original FP store crosses whole-zone boundary')
        load,opcode,instruction=self.decode(pc,thumb);value &= (1<<(size*8))-1
        row=self.active
        if row:
            require(uc.reg_read(UC_ARM_REG_CPSR)&31==0x1b, 'Original handler store left UND mode')
            if self.stack_top-UND_BYTES+32<=address<self.stack_top+32:
                push=row.get('pending_push');require(push and push['PC']==hex(pc) and size==4 and address in push['expected'], 'Unadmitted UND stack write')
                require(value==push['expected'][address] and address not in push['seen'], 'UND push register value/coverage differs')
                push['seen'].append(address)
            elif pc==0x20ecd8:
                pending=row.get('pending_save');require(pending and pending['context']<=address and address+size<=pending['context']+128,
                    'VSTM address outside exact context128')
                offset=address-pending['context'];expected=bytes.fromhex(pending['bank_hex'])[offset:offset+size]
                require(value.to_bytes(size,'little')==expected and not any(i in pending['coverage'] for i in range(offset,offset+size)),
                    'VSTM payload/coverage differs from pre-instruction D16')
                pending['coverage'].extend(range(offset,offset+size));row['VSTM_callbacks'].append(dict(address=hex(address),size=size,value=value))
            elif pc==0x20ecf8:
                pending=row.get('pending_control');require(pending and size==4 and address in pending['expected'] and
                    value==pending['expected'][address] and address not in pending['seen'], 'Control STM differs from actual r1/r2/r3/ip')
                pending['seen'].append(address);row['control_STM_callbacks'].append(dict(address=hex(address),size=size,value=value))
            else:
                require(pc in [0x20ec98,0xf6f02,0xf6f10,0xf6f18,0xf6e2e,0xf6e32,0xf6e36,0xf6e3c,0xf6e40,0x6e0858],
                    'Unknown handler metadata/pool/owner store')
                if pc==0x20ec98:require(address==OWNER and size==4 and value==int(row['new_owner'],16), 'Original owner publication differs')
                if pc==0xf6e40:
                    task=int(row['old_owner'],16);alloc=row['allocation_rows'][-1]
                    require(alloc['request']==40 and address==task+28 and size==4 and value==int(alloc['result'],16), 'Clone TCB+28 publication differs')
                if pc==0x6e0858:
                    require(address==row['attach_metadata']+28 and size==4 and value==row['attach_context'], 'FP metadata slot store differs')
        zone['stores'].append(dict(PC=hex(pc),load_PC=hex(load),Thumb=thumb,address=hex(address),size=size,value=value,
            before_hex=bytes(uc.mem_read(address,size)).hex(),opcode_hex=opcode.hex(),original_instruction=instruction))

    def finish_push(self,row):
        push=row.get('pending_push')
        if push:
            require(sorted(push['seen'])==sorted(push['expected']), 'Original UND push did not write every expected word')
            require(self.uc.reg_read(UC_ARM_REG_SP)==push['after_SP'], 'Original UND push SP result differs')
            row['push_rows'].append({k:v for k,v in push.items() if k!='expected'}|{'expected_words':{hex(a):hex(v) for a,v in push['expected'].items()}})
            row['pending_push']=None

    def observe(self,uc,address,size,data):
        if self.active is None:return
        row=self.active;self.finish_push(row)
        old,new=int(row['old_owner'],16),int(row['new_owner'],16);U=self.stack_top
        if address==HANDLER:
            require(uc.reg_read(UC_ARM_REG_CPSR)&31==0x1b and uc.reg_read(UC_ARM_REG_SPSR)==int(row['before']['CPSR'],16) and
                    uc.reg_read(UC_ARM_REG_SP)==U and uc.reg_read(UC_ARM_REG_LR)==int(row['before']['PC'],16)+4, 'Original UND entry differs')
            row['original_handler_entered']=True
        if address==0x6e9340:raise AssertionError('Original handler reached fatal path')
        push_specs={0x20ebe0:([0,1,2,3,4,12],U,0xe92d101f,False),0x20ec78:([5,14],U-24,0xe92d4020,False),
                    0x6e0830:([4,14],U-32,0xe92d4010,False),0xf6e14:([4,5,6,14],U-40,0xb570,True)}
        if address==0xf6edc:
            lr=uc.reg_read(UC_ARM_REG_LR);n=uc.reg_read(UC_ARM_REG_R1);task=uc.reg_read(UC_ARM_REG_R0)
            require(task==old and old!=new and (n,lr) in [(148,0x20ecc4),(40,0xf6e2d)] and not row.get('pending_allocation'),
                    'Original FP allocation request/caller differs')
            spec=self.tasks[old];base=spec['pool'];cursor=word(uc,base+4) if word(uc,base)==MAGIC else (base+15)&~7
            end=cursor+((n+7)&~7)
            require(cursor%8==0 and base+8<=cursor and end<=base+256 and end<spec['minimum_live_SP'], 'Unchecked native FP allocation exceeds admitted pool')
            allocation=dict(task=hex(task),request=n,LR=hex(lr),result=hex(cursor),advance=(n+7)&~7,end=hex(end),
                original_allocator_capacity_check=False,external_pool_budget=256,returned=False)
            row['pending_allocation']=allocation
            push_specs[address]=([4,5,6,14],U-32 if n==148 else U-56,0xb570,True)
        if address in push_specs:
            indices,pre,opcode,thumb=push_specs[address];require(uc.reg_read(UC_ARM_REG_SP)==pre and bool(uc.reg_read(UC_ARM_REG_CPSR)&32)==thumb,
                'Original UND nested push SP/mode differs')
            raw=opcode.to_bytes(2 if thumb else 4,'little');require(self.stock.read(address,len(raw))==raw and bytes(uc.mem_read(address,len(raw)))==raw,
                'Nested push original opcode differs')
            after=pre-4*len(indices);regs=[UC_ARM_REG_R0+i for i in indices[:-1]]+[UC_ARM_REG_LR] if indices[-1]==14 else [UC_ARM_REG_R0+i for i in indices]
            row['pending_push']=dict(PC=hex(address),Thumb=thumb,before_SP=pre,after_SP=after,
                expected={after+4*i:uc.reg_read(r) for i,r in enumerate(regs)},seen=[],opcode_hex=raw.hex())
        if address in [0x20ecc4,0xf6e2c] and row.get('pending_allocation'):
            alloc=row['pending_allocation'];require(uc.reg_read(UC_ARM_REG_R0)==int(alloc['result'],16) and
                word(uc,self.tasks[old]['pool'])==MAGIC and word(uc,self.tasks[old]['pool']+4)==int(alloc['end'],16), 'Original allocator actual return/header differs')
            alloc['returned']=True;row['allocation_rows'].append(alloc);self.allocations.append(alloc);row['pending_allocation']=None
        if address==0x6e0858:
            m,ctx=uc.reg_read(UC_ARM_REG_R0),uc.reg_read(UC_ARM_REG_R4);spec=self.tasks[old]
            require(ctx==spec['first_context'] and old!=new, 'Native attach context differs')
            if bytes.fromhex(spec['original_metadata_hex'])[4]==0:
                alloc=row['allocation_rows'][-1];require(alloc['request']==40 and m==int(alloc['result'],16) and word(uc,old+28)==m,
                    'Original readonly metadata clone missing')
                expected=bytearray.fromhex(spec['original_metadata_hex']);expected[4]=1
                require(bytes(uc.mem_read(m,40))==expected, 'Original clone40 before slot publication differs')
            else:require(m==spec['metadata'] and word(uc,old+28)==m, 'Mutable metadata unexpectedly cloned')
            row['attach_metadata']=m;row['attach_context']=ctx
        if address==0x6e085c and 'attach_metadata' in row:
            spec=self.tasks[old];spec['expected_metadata']=row['attach_metadata'];spec['context']=row['attach_context'];self.metadata(old)
        if address==0x20ecd8:
            require(old and old!=new and word(uc,OWNER)==new, 'Original save owner publication missing')
            ctx=uc.reg_read(UC_ARM_REG_R0);require(ctx==self.tasks[old]['context']!=0, 'Original VSTM context differs')
            row['pending_save']=dict(context=ctx,bank_hex=struct.pack('<16Q',*[uc.reg_read(r) for r in DOUBLE]).hex(),coverage=[],
                hole_hex=bytes(uc.mem_read(ctx+128,4)).hex(),padding_hex=bytes(uc.mem_read(ctx+148,4)).hex())
        if address==0x20ecdc:
            p=row['pending_save'];require(sorted(p['coverage'])==list(range(128)) and bytes(uc.mem_read(p['context'],128)).hex()==p['bank_hex'],
                'Original VSTM128 full actual callback/readback failed')
            row['VSTM_full128_readback_passed']=True
        if address==0x20ecf8:
            ctx=row['pending_save']['context'];require(uc.reg_read(UC_ARM_REG_R0)==ctx+132, 'Original control store context+132 differs')
            regs=[UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R12];values=[uc.reg_read(r) for r in regs]
            require(values[0]==0x40000000, 'Original control FPEXC is not handler-enabled value')
            row['pending_control']=dict(expected={ctx+132+4*i:v for i,v in enumerate(values)},seen=[])
            row['actual_control_register_words']=[hex(v) for v in values]
        if address==0x20ecfc and row.get('pending_control'):
            p=row['pending_save'];control=row['pending_control']
            require(sorted(control['seen'])==sorted(control['expected']) and bytes(uc.mem_read(p['context']+132,16))==
                struct.pack('<4I',*control['expected'].values()), 'Original four control words did not store/read back')
            require(bytes(uc.mem_read(p['context']+128,4)).hex()==p['hole_hex'] and bytes(uc.mem_read(p['context']+148,4)).hex()==p['padding_hex'],
                'Native context hole or allocator padding changed')
            row['save_complete']=True
        if address==0x20ed0c:
            ctx=uc.reg_read(UC_ARM_REG_R0);require(old!=new and ctx==self.tasks[new]['context']!=0, 'Original restore slot differs')
            row['restore_bank_hex']=bytes(uc.mem_read(ctx,128)).hex();row['restore_controls']=[hex(v) for v in struct.unpack('<4I',uc.mem_read(ctx+132,16))]
        if address==0x20ed10:
            require(struct.pack('<16Q',*[uc.reg_read(r) for r in DOUBLE]).hex()==row['restore_bank_hex'], 'Actual original VLDM D16 result differs')
            row['original_VLDM128_readback_passed']=True
        if address==0x20ed30:
            require(uc.reg_read(UC_ARM_REG_SP)==U-32, 'Original exception inner pop balance differs')
            if 'restore_controls' in row:
                require(uc.reg_read(UC_ARM_REG_FPEXC)==int(row['restore_controls'][0],16) and
                    uc.reg_read(UC_ARM_REG_FPSCR)==int(row['restore_controls'][3],16), 'Original restored control registers differ')
                row['restore_complete']=True
        if address==0x20ed38:require(uc.reg_read(UC_ARM_REG_SP)==U-24, 'Original outer pop balance differs')
        if address==0x20ed3c:
            require(row['original_handler_entered'] and uc.reg_read(UC_ARM_REG_SP)==U and
                uc.reg_read(UC_ARM_REG_SPSR)==int(row['before']['CPSR'],16), 'Original exception return frame differs')
            row['original_exception_return_seen']=True
        if address==int(row['before']['PC'],16):
            after=self.snapshot()
            require(row['original_exception_return_seen'] and after['CPSR']==row['before']['CPSR'] and after['GP15']==row['before']['GP15'],
                'Original native exception did not restore fault GP15/status')
            require(after['D16']==row['expected_retry_D16'] and after['FPSCR']==row['expected_retry_FPSCR'] and
                int(after['FPEXC'],16)==0x40000000 and word(uc,OWNER)==new, 'Native retry FP bank differs from actual fault/saved-owner contract')
            require(row['save_complete']==bool(old and old!=new) and row['restore_complete']==bool(old!=new and int(row['new_context_before'],16)),
                'Original save/no-restore/restore path differs')
            for t in self.tasks:
                actual=bytearray(uc.mem_read(t,108));expected=bytearray.fromhex(row['TCB_before'][hex(t)])
                struct.pack_into('<I',expected,28,self.tasks[t]['expected_metadata'])
                require(actual==expected, 'Original FP handler changed TCB108 outside metadata publication')
                self.metadata(t)
            row.update(original_opcode_retry_reached=True,after_native_handler=after,
                same_task_registers_stack_memory_resumed=True,original_function_not_reentered=True)
            self.active=None

    def verify(self):
        require(self.active is None and self.rows and all(r['original_opcode_retry_reached'] for r in self.rows), 'Incomplete original native FP exception')
        zones=[]
        for low,row in self.zones.items():
            expected=bytearray.fromhex(row['before_hex'])
            for store in row['stores']:
                offset=int(store['address'],16)-low;n=store['size']
                require(expected[offset:offset+n].hex()==store['before_hex'], 'FP history missed an intervening mutation')
                expected[offset:offset+n]=store['value'].to_bytes(n,'little')
            actual=bytes(self.uc.mem_read(low,row['bytes']))
            require(actual==expected, 'Whole FP zone differs from original CPU history')
            zones.append(dict(row,after_sha256=sha(actual),whole_zone_replayed=True))
        for t,spec in self.tasks.items():
            self.metadata(t);base=spec['pool']
            require(bytes(self.uc.mem_read(base+256,64))==b'\xff'*64, 'Native FP pool trailing64 changed')
            if spec['context']:
                expected_end=spec['context']+152+(40 if bytes.fromhex(spec['original_metadata_hex'])[4]==0 else 0)
                require(word(self.uc,base)==MAGIC and word(self.uc,base+4)==expected_end, 'Native pool cursor differs from observed allocation history')
        low=self.stack_top-UND_BYTES+32
        require(bytes(self.uc.mem_read(low,32))==b'\xa5'*32 and bytes(self.uc.mem_read(self.stack_top,32))==b'\xa5'*32,
            'UND leading/trailing canary changed')
        return zones

def main():
    require(unicorn.__version__=='2.1.4' and unicorn.uc_version()==(2,1,33621247), 'Use isolated Unicorn2.1.4')
    STAGE.mkdir(parents=True,exist_ok=True);require(not (STAGE/'source-at-run.py').exists(), 'Keep terminal source/evidence immutable')
    source=Path(__file__).resolve();(STAGE/'source-at-run.py').write_bytes(source.read_bytes())
    stock=NativeImage();uc=unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_ARM)
    fragments=[(0x20ebd4,0x178),(0x358d24,32),(0x6e0820,0x40),(0xf6e08,0x40),(0xf6edc,0x98),(0x21b6cc,24),(FAULT,16)]
    C,D,CM,DM,CS,DS=0x9503f90,0x8804fb8,0x9400900,0x8800fe0,0x9500000,0x8801024
    task_specs={C:dict(metadata=CM,pool=CS,minimum_live_SP=C-0x90),D:dict(metadata=DM,pool=DS,minimum_live_SP=D-0x90)}
    regions=[(C,108),(D,108),(CM,40),(DM,40),(CS,320),(DS,320),(UND,UND_BYTES),(OWNER&~4095,4096),(0xf09000,4096),(STOP,4096)]
    pages={p for a,n in fragments+regions for p in range(a&~4095,((a+n+4095)&~4095),4096)}
    for page in sorted(pages):uc.mem_map(page,4096)
    for a,n in fragments:uc.mem_write(a,stock.read(a,n))
    for task,m,pool,flag,object_marker in [(C,CM,CS,1,0),(D,DM,DS,0,0x8805220)]:
        tcb=bytearray(b'\x5a'*108);struct.pack_into('<I',tcb,28,m);uc.mem_write(task,bytes(tcb))
        uc.mem_write(m,struct.pack('<10I',0x261e30 if task==D else 0x9400980,flag,pool,4096,0,0,0,0,object_marker,0))
        uc.mem_write(pool,b'\xff'*320)
    uc.mem_write(UND,b'\xa5'*UND_BYTES);uc.mem_write(0xf09090,struct.pack('<I',C))
    uc.reg_write(UC_ARM_REG_C1_C0_2,0xf00000);uc.reg_write(UC_ARM_REG_CPSR,0xa000001f)
    for r,i in zip(GENERAL[:13],range(13)):uc.reg_write(r,0x12345000+i)
    for r,i in zip(DOUBLE,range(16)):uc.reg_write(r,0x0102030405060708+i)
    uc.reg_write(UC_ARM_REG_FPSCR,0x03000000);uc.reg_write(UC_ARM_REG_FPEXC,0x40000000)
    live=lambda p,n:any(a<=p and p+n<=a+k for a,k in regions)
    lazy=MultiOwnerVFPState(uc,stock,lambda:word(uc,0xf09090),live,UND+UND_BYTES-32,task_specs,exclusive=True)
    uc.hook_add(unicorn.UC_HOOK_CODE,lazy.observe)
    uc.hook_add(unicorn.UC_HOOK_CODE,lambda u,a,s,d:u.emu_stop(),begin=STOP,end=STOP)
    deps={str(source.relative_to(ROOT)):sha(source.read_bytes()),'scripts/probe_native_lazy_vfp.py':sha((ROOT/'scripts/probe_native_lazy_vfp.py').read_bytes()),
        'scripts/analyze_native_sections.py':sha((ROOT/'scripts/analyze_native_sections.py').read_bytes()),'evidence/firmware-analysis/main_02bd.bin':EXPECTED}
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=deps,all_passed=False,
        device_io=False,sounds_emitted=False,original_MAIN_patch_bytes=0,explicit_two_TCB_metadata_pool_and_task_selection_fixtures=True,
        undefined_entry_is_explicit_architectural_fixture=True,original_full_boot_GUI_foreground_App_or_package_acceptance_verified=False,
        emulator_binding_version=unicorn.__version__,emulator_native_version=list(unicorn.uc_version()),fragments=[dict(address=hex(a),bytes=n,sha256=sha(stock.read(a,n))) for a,n in fragments],cases=[])
    dump(STAGE/'inputs-before-run.json',dict(source_sha256=deps,task_inputs=task_specs,original_fragments=result['fragments']))
    try:
        for task,value,name in [(C,1638,'first_controller_owner'),(D,42,'first_C_to_D_save_C_without_D_restore'),
                                (C,7,'D_to_C_save_D_clone40_restore_C'),(D,9,'C_to_D_reuse_C_context_restore_D'),(D,11,'same_D_owner_no_context_exchange')]:
            # Declared task-selection stimulus and ordinary helper-call inputs;
            # native20EBD4 alone disables FP. Owner/metadata/bank are untouched.
            uc.mem_write(0xf09090,struct.pack('<I',task));uc.reg_write(UC_ARM_REG_R0,value)
            uc.reg_write(UC_ARM_REG_SP,task-0x90);uc.reg_write(UC_ARM_REG_LR,STOP)
            uc.emu_start(0x20ebd4,STOP+4,count=100);require(uc.reg_read(UC_ARM_REG_FPEXC)==0, 'Original disable did not run')
            uc.reg_write(UC_ARM_REG_R0,value)
            try:
                uc.emu_start(FAULT,STOP+4,count=100)
                raise AssertionError('Expected original disabled-FP fault absent')
            except unicorn.UcError as error:uc.emu_start(lazy.enter(error),STOP+4,count=10000)
            expected=struct.unpack('<I',struct.pack('<f',float(value)))[0]
            require(lazy.active is None and uc.reg_read(UC_ARM_REG_PC)==STOP and uc.reg_read(UC_ARM_REG_R0)==expected and
                uc.reg_read(UC_ARM_REG_SP)==task-0x90, 'Original conversion did not resume/return')
            result['cases'].append(dict(name=name,passed=True,actual_result_bits=hex(expected),task=hex(task)))
            print(json.dumps(dict(case=name,passed=True)),flush=True)
        result['whole_zones']=lazy.verify()
        require([a['request'] for a in lazy.allocations]==[148,148,40], 'Native first-save/clone allocation sequence differs')
        require(lazy.rows[2]['expected_retry_bank_source']=='new_owner_saved_context' and
                lazy.rows[2]['before']['D16']!=lazy.rows[2]['after_native_handler']['D16'] and
                lazy.rows[3]['before']['D16']!=lazy.rows[3]['after_native_handler']['D16'], 'Restore controls did not distinguish saved-owner bank from old fault bank')
        for a,n in fragments:require(bytes(uc.mem_read(a,n))==stock.read(a,n), 'Original code fragments changed')
        result.update(all_passed=True,case_count=len(result['cases']),original_fragments_unchanged=True,
            full_native_FP_save_clone_restore_and_whole_zone_guards_passed=True,
            VSTM_observed_callback_widths=sorted({v['size'] for row in lazy.rows for v in row['VSTM_callbacks']}))
    except Exception as error:
        result.update(error=str(error),error_type=type(error).__name__,actual_registers=lazy.snapshot())
        if isinstance(error,unicorn.UcError):result['UcError_errno']=error.errno
        print(json.dumps(dict(error=str(error),PC=hex(uc.reg_read(UC_ARM_REG_PC)))),flush=True)
    result.update(original_handler_rows=lazy.rows,native_allocations=lazy.allocations,
        partial_zone_journals=lazy.zones,finished_utc=datetime.now(timezone.utc).isoformat())
    dump(STAGE/'terminal-probe.json',result)
    print(json.dumps({k:result.get(k) for k in ['all_passed','case_count','error','VSTM_observed_callback_widths']}),flush=True)
    if not result['all_passed']:sys.exit(1)

if __name__=='__main__':main()
