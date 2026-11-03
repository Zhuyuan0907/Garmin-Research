#!/usr/bin/env python3
"""Stock button closure/member dispatcher to audio mixer action, offline.

The parent page and event invocation are fixtures; widget/rendering objects
are not constructed. Stock closure storage, virtual dispatch and page action
execute. Mixer allocation/constructor/publication and free are boundaries.
"""
from datetime import datetime, timezone
import hashlib
import json
import struct
from pathlib import Path

import unicorn
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_sdp_activation import trace
from emulate_avdtp_control import ControlVM, REGS, RETURN, STACK

PAGE, ARENA, CHILD = 0x02200000, 0x02210000, 0x02300000
CLOSURE, WRAPPER, CLONE, DESTINATION = ARENA+0x100, ARENA+0x200, ARENA+0x300, ARENA+0x400


class MenuVM(ControlVM):
    def __init__(self, stock):
        super().__init__(stock)
        for start,size in [(PAGE,4096),(ARENA,4096),(CHILD,0x3000)]:
            self.uc.mem_map(start,size)
            self.uc.mem_write(start,b'\xa5'*size)
        self.uc.mem_write(PAGE,struct.pack('<I',0xc0cc9c))
        self.uc.mem_write(WRAPPER,struct.pack('<I',CLOSURE))
        self.actions=[];self.operations=[];self.history=[]

    def hook(self,uc,address,size,unused):
        self.executed.add(address)
        r=[uc.reg_read(reg) for reg in REGS]
        if address==0x3954cc:
            assert r[0] in (16,0x258c)
            result=CLONE if r[0]==16 else CHILD
            self.operations.append({'operation':'allocation_fixture','bytes':r[0],'result':hex(result)})
            self.ret(result)
        elif address==0x53146c:
            assert r[0]==CHILD
            self.operations.append({'operation':'mixer_constructor_fixture','object':hex(r[0])})
            # Do not manufacture a vtable or claim the real constructor ran.
            self.ret(r[0])
        elif address==0x36c00a:
            assert r[:3]==[PAGE,CHILD,10]
            self.actions.append({'operation':'page_publication_fixture','parent':hex(r[0]),
                'child':hex(r[1]),'navigation_code':r[2]})
            self.ret()
        elif address==0x386f14:
            assert r[0]==CLOSURE
            self.operations.append({'operation':'closure_free_fixture','address':hex(r[0])})
            self.ret()
        else:
            super().hook(uc,address,size,unused)

    def run(self, name, entry, args, fifth=0):
        self.executed=set();self.actions=[];self.operations=[]
        sp=STACK+0xf000
        self.uc.mem_write(sp,struct.pack('<I',fifth))
        self.uc.reg_write(UC_ARM_REG_SP,sp);self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
        for reg,value in zip(REGS,list(args)+[0]*4):self.uc.reg_write(reg,value)
        self.uc.emu_start(entry|1,RETURN+2,timeout=2000000,count=30000)
        assert self.uc.reg_read(UC_ARM_REG_PC)==RETURN and self.uc.reg_read(UC_ARM_REG_SP)==sp
        assert bytes(self.uc.mem_read(0x50000,len(self.code)))==self.code
        # Unallocated child storage must stay untouched by the boundaries.
        assert bytes(self.uc.mem_read(CHILD,0x3000))==b'\xa5'*0x3000
        for a,n in [(PAGE+8,4096-8),(ARENA,0x100),(ARENA+0x110,0xf0),
                    (ARENA+0x204,0xfc),(ARENA+0x310,0xf0),(ARENA+0x404,4096-0x404)]:
            assert bytes(self.uc.mem_read(a,n))==b'\xa5'*n,(a,n)
        result={'step':name,'entry':hex(entry),'actions':list(self.actions),
            'boundary_operations':list(self.operations),'return_value':self.uc.reg_read(REGS[0]),
            'closure_hex':bytes(self.uc.mem_read(CLOSURE,16)).hex(),
            'stock_action_executed':0x5193c8 in self.executed,
            'stock_member_dispatcher_executed':0x615b44 in self.executed,
            'stock_closure_builder_executed':0x5e0ab2 in self.executed,
            'code_and_unallocated_child_storage_unchanged':True,'RAM_guards_and_SP_intact':True}
        self.history.append(result);return result

    def bind(self, selector=0, member_offset=0xf0, adjustment=1, object_address=PAGE):
        r=self.run('stock_closure_binding',0x5e0ab2,
            [CLOSURE,member_offset,adjustment,object_address],selector)
        assert bytes(self.uc.mem_read(CLOSURE,16))==struct.pack('<4I',member_offset,adjustment,object_address,selector)
        return r

    def invoke(self):return self.run('stock_member_dispatch_and_action',0x615b44,[WRAPPER])


def main():
    stock=NativeImage();image=RuntimeImage(stock);cases=[]
    assert image.word(0x9cd9ec)==0xf0 and image.word(0x9cd9f0)==1
    assert image.word(0xf711d4)==0x614e6d and image.word(0xf711d8)==0x615b45
    assert image.word(0xc0cc9c+0xf0)==0x5193c9
    functions={hex(a):trace(image,a,2000) for a in
        [0x2e2eaa,0x5e0ab2,0x615b44,0x614e6c,0x2e2a6c,0x376e5e]}
    assert all(not f['instruction_limit_reached'] and not f['unresolved_exits'] for f in functions.values())
    builder=functions['0x2e2eaa']['instructions']
    assert any(r.get('direct_call')=='0x5e0ab2' for r in builder)
    assert any(r.get('literal_value')=='0xf711d4' for r in builder)
    assert any(r.get('direct_call')=='0x2e2a6c' for r in builder)
    def check(name,vm,observations):
        assert all(observations.values()),(name,observations)
        cases.append({'name':name,'passed':True,'checks':observations,'steps':vm.history})
    def opens(r):
        return (r['stock_member_dispatcher_executed'] and r['stock_action_executed'] and len(r['actions'])==1 and
            [x['operation'] for x in r['boundary_operations']]==['allocation_fixture','mixer_constructor_fixture'])

    vm=MenuVM(stock);vm.bind();r=vm.invoke()
    check('stock_virtual_slot60_binding_dispatches_selector0_to_mixer_action',vm,{'stock_dispatch_to_action':opens(r)})
    vm=MenuVM(stock);vm.bind(selector=2);r=vm.invoke()
    check('unhandled_selector_returns_without_page_allocation',vm,{'stock_dispatch_to_noop':r['stock_action_executed'] and not r['actions'] and not r['boundary_operations']})
    vm=MenuVM(stock);vm.bind(member_offset=0x5193c9,adjustment=0);r=vm.invoke()
    check('direct_member_pointer_control_calls_same_stock_action',vm,{'direct_pointer_no_vtable_lookup':opens(r)})
    vm=MenuVM(stock);vm.bind(adjustment=17,object_address=PAGE-8);r=vm.invoke()
    check('positive_this_adjustment_virtual_pointer_control',vm,{'synthetic_adjustment8_restores_parent':opens(r)})
    vm=MenuVM(stock);vm.bind()
    r=vm.run('clone_closure',0x614e6c,[WRAPPER,DESTINATION,0])
    assert vm.word(DESTINATION)==CLONE and bytes(vm.uc.mem_read(CLONE,16))==bytes(vm.uc.mem_read(CLOSURE,16))
    # Use the real manager-produced destination as the invoker wrapper.
    r=vm.run('invoke_copied_closure',0x615b44,[DESTINATION])
    check('stock_closure_manager_copies16_bytes_and_copy_dispatches',vm,{'copy_dispatches_same_action':opens(r)})
    vm=MenuVM(stock);vm.bind()
    vm.run('move_closure',0x614e6c,[WRAPPER,DESTINATION,1])
    check('stock_closure_move_transfers_pointer_and_clears_source',vm,{'original_move_ownership':vm.word(WRAPPER)==0 and vm.word(DESTINATION)==CLOSURE})
    vm=MenuVM(stock);vm.bind();vm.uc.mem_write(DESTINATION,struct.pack('<I',CLOSURE))
    r=vm.run('release_closure',0x614e6c,[WRAPPER,DESTINATION,2])
    check('stock_closure_release_calls_free_boundary_and_clears_pointer',vm,{
        'release_pointer_cleared':vm.word(DESTINATION)==0,
        'free_boundary_invoked':len(r['boundary_operations'])==1 and r['boundary_operations'][0]['operation']=='closure_free_fixture'})
    deps=[Path(__file__),ROOT/'scripts/emulate_avdtp_control.py',ROOT/'scripts/analyze_native_sections.py',
        ROOT/'scripts/analyze_native_voice_acceptance.py',ROOT/'scripts/analyze_sdp_activation.py',
        ROOT/'evidence/firmware-analysis/main_02bd.bin']
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in deps},
        'cpu_model':'ARM1176','case_count':len(cases),'cases':cases,'all_passed':True,
        'bounded_static_functions':functions,
        'button_binding':{'label':'STR_AUDIO_MIXER','settings_constructor':'0x518ec2',
            'button_builder':'0x2e2eaa','closure_builder':'0x5e0ab2','closure_bytes':16,
            'descriptor_address':'0x9cd9ec','member_pointer_words':[240,1],
            'selector0_stored_with_page_pointer':True,'function_wrapper_table':'0xf711d4',
            'manager':'0x614e6c','member_invoker':'0x615b44','virtual_slot':60,
            'action':'0x5193c8','binding_registration_path':['0x2e2a6c','0x376e5e'],
            'stock_widget_constructor_executed':False,'stock_event_queue_executed':False},
        'real_closure_binding_member_dispatch_and_action_executed_offline':True,
        'real_mixer_constructor_or_page_publication_executed':False,
        'actual_UI_dispatch_or_screen_execution_verified':False,
        'generic_App_registration_or_install_API_identified':False,
        'device_io':False,'firmware_modified':False,'device_install_candidate':False,
        'limitations':'Direct invocation of stock closure dispatcher using synthetic parent page/vtable boundary. Existing button binding is statically traced; actual widget construction/event routing/rendering/lifetime not executed. Mixer allocator/constructor/publication/free are intercepted, child storage untouched. Synthetic direct/adjusted controls describe member-pointer ABI, not arbitrary App install. No native screen, phone or speaker proof.'}
    target=ROOT/'evidence/firmware-analysis/native-music-menu-action-emulation.json'
    target.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'evidence':str(target.relative_to(ROOT)),'cases_passed':len(cases),'device_io':False}))


if __name__=='__main__':main()
