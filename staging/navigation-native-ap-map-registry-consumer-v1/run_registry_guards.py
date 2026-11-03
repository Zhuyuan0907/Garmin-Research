#!/usr/bin/env python3
"""Finite original Map-load guards. Synthetic registry/stack, startup selector bytes.

No semantic hooks or return substitutes; CODE observer only stops at original
branch boundaries. This is not a complete Map loader, opener, or renderer.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import *

ROOT=Path('/root/garmin'); HERE=Path(__file__).resolve().parent
PINNED_CAPTURES=['windows-seeds.json','windows-registry.json','windows-exacttables.json','windows-registrations.json','windows-cpuguard.json','windows-exactguards.json']
REGISTRY=0x1286bcc; EXTRA_A=0x1287a3c; EXTRA_B=0x1287bc8
STACK=0x2008000; HEAP=0x2100000

def sha(b): return hashlib.sha256(b).hexdigest()
def u32(b): return struct.unpack('<I',bytes(b))[0]
def save(name,d): (HERE/name).write_text(json.dumps(d,indent=2)+'\n')
def main():
    captures=[];windows=[]
    for pn in PINNED_CAPTURES:
        b=(HERE/pn).read_bytes();d=json.loads(b);captures.append(dict(path=str((HERE/pn).relative_to(ROOT)),sha256=sha(b)))
        windows+=d['windows']
    def exact(a,n):
        matches=[bytes.fromhex(w['raw_hex'])[a-int(w['runtime_start'],16):a-int(w['runtime_start'],16)+n]for w in windows if int(w['runtime_start'],16)<=a and a+n<=int(w['runtime_start'],16)+w['bytes']]
        assert matches and all(b==matches[0]for b in matches),(hex(a),n)
        return matches[0]
    ranges=[(0x1101fc,38),(0xfe648,54),(0xfe7d0,4),(0xf00114,99),(0x110fee,34),(0x10df5a,94),(0x10dfb8,4),(0x10e150,12)]
    # 10E150/154/158 are exact PC literals previously captured by the tool.
    literal_words={int(i['literal_address'],16):int(i['literal_value'],16)for w in windows for i in w['instructions']if 'literal_value'in i}
    def machine(stops):
        uc=Uc(UC_ARCH_ARM,UC_MODE_ARM);uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
        pages=set()
        for a,n in ranges:
            for p in range(a&~4095,(a+n+4095)&~4095,4096):
                if p not in pages: uc.mem_map(p,4096);pages.add(p)
        for a,n in ranges:
            if a==0x10e150: b=b''.join(struct.pack('<I',literal_words[x])for x in (0x10e150,0x10e154,0x10e158))
            else:b=exact(a,n)
            uc.mem_write(a,b)
        uc.mem_map(0x1286000,0x3000);uc.mem_map(0x2000000,0x10000);uc.mem_map(HEAP,0x10000)
        uc.reg_write(UC_ARM_REG_SP,STACK)
        trace=[]
        def observer(u,a,n,user):
            trace.append(a)
            if a in stops:u.emu_stop()
        uc.hook_add(UC_HOOK_CODE,observer)
        return uc,trace
    cases=[]
    for name,slot,want in [('AP_startup_slot',2,1),('gmapprom_startup_slot',1,1),('other_startup_slot',0,0),('sentinel_slot',99,0)]:
        uc,tr=machine({0x110222});uc.mem_write(STACK+0x15c,struct.pack('<I',slot))
        uc.emu_start(0x1101fd,0,count=2000)
        assert tr[-1]==0x110222
        got=u32(uc.mem_read(STACK+0x58,4));assert got==want
        assert 0xfe648 in tr and not any(a in [0x1e7e24,0x1e7e40]for a in tr)
        cases.append(dict(name=name,entry='0x1101fc',slot_fixture=slot,classification_stack58=got,stop='0x110222 beforevolumeactivecalls',instruction_count=len(tr)-1,trace=[hex(a)for a in tr],selector_bytes_source='actual startup copy; live inventory notread'))
    for name,minimum,threshold,drop in [('registry_drop_guard',5,6,True),('registry_retain_guard',7,6,False)]:
        slot=2;uc,tr=machine({0x111010,0x11102e});base=REGISTRY+slot*24
        initial=bytearray(0x3000);initial[:]=b'\xa5'*len(initial);uc.mem_write(0x1286000,bytes(initial))
        # All three actual linked-head fields are synthetic; node identity/order
        # and an unrelated slot are asserted after original pointer clearing.
        nodes=[HEAP+0x100*i for i in range(1,5)]
        for i,p in enumerate(nodes):uc.mem_write(p,struct.pack('<IIII',0x9900+i,nodes[1]if i==0 else 0,0xdead0000+i,0x11112222))
        uc.mem_write(base,struct.pack('<IIIIII',nodes[0],nodes[2],nodes[3],0x07080003,0xcafebabe,0x12345678))
        uc.mem_write(EXTRA_A+slot*4,struct.pack('<I',0x13572468));uc.mem_write(EXTRA_B+slot*4,struct.pack('<I',0xabcdef12))
        before=bytes(uc.mem_read(0x1286000,0x3000));oldnodes=[bytes(uc.mem_read(p,16))for p in nodes]
        for offset,value in [(0x60,minimum),(0x6c,threshold),(0x1a4,slot*24),(0x11c,10)]:uc.mem_write(STACK+offset,struct.pack('<I',value))
        uc.reg_write(UC_ARM_REG_R6,slot)
        uc.emu_start(0x110fef,0,count=3000)
        assert tr[-1]==(0x111010 if drop else 0x11102e)
        after=bytes(uc.mem_read(0x1286000,0x3000));expected=bytearray(before)
        def set_mem(a,b):expected[a-0x1286000:a-0x1286000+len(b)]=b
        if drop:
            for off in [0,4,8]:set_mem(base+off,b'\0'*4)
            set_mem(base+12,b'\0\0');set_mem(base+14,b'\0')
            set_mem(EXTRA_A+slot*4,b'\0'*4);set_mem(EXTRA_B+slot*4,b'\0'*4)
            for p,b in zip(nodes,oldnodes):assert bytes(uc.mem_read(p,16))==b'\0'*8+b[8:]
            assert u32(uc.mem_read(STACK+0x11c,4))==8
            assert 0x10df5a in tr
        else:
            assert all(bytes(uc.mem_read(p,16))==b for p,b in zip(nodes,oldnodes))
            assert u32(uc.mem_read(STACK+0x11c,4))==10 and 0x10df5a not in tr
        assert after==bytes(expected),'Unexpected registry mutation'
        cases.append(dict(name=name,entry='0x110fee',slot_fixture=slot,minimum_fixture=minimum,threshold_fixture=threshold,registry_head_dropped=drop,stop=hex(tr[-1]),instruction_count=len(tr)-1,trace=[hex(a)for a in tr],all_other_registry_bytes_preserved=True,all_node_tail_fields_preserved=True,field_semantics_notinferred=True))
    save('registry-guard-cpu-proof.json',dict(schema='bounded-original-map-load-registry-guards/v1',source_sha256=sha(Path(__file__).read_bytes()),captures=captures,code_ranges=[dict(start=hex(a),bytes=n)for a,n in ranges],case_count=len(cases),cases=cases,all_passed=True,synthetic_stack_and_registry=True,startup_inventory_is_exact_filebacked_data=True,live_inventory_unknown=True,semantic_hooks=[],observer_stops_only=True,IMG_reads=0,complete_map_loader_run=False,APphysicalopener_bound=False,admission_renderer_or_regression_rootcause_proved=False,old_closed_cases_notrun=True,handles_closed=True))
    print(json.dumps(dict(all_passed=True,cases=len(cases),instructions=sum(c['instruction_count']for c in cases),IMG_reads=0,proof='registry-guard-cpu-proof.json')))

if __name__=='__main__':main()
