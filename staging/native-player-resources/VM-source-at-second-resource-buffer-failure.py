#!/usr/bin/env python3
"""Extend only the exact original XML parser's8196-byte heap request.

Native18AFE2 ->36D2A2 ->11A254 requests8192+4. Heap storage is a fixture;
native prefix, parsing, lock/return/free instructions remain inherited.
"""
import unicorn
from unicorn.arm_const import UC_ARM_REG_LR
from probe_native_player_resources import ResourceVM
from emulate_native_vpm_filesystem import REGS,require

class ResourceCacheVM(ResourceVM):
    def __init__(self,stock,build):
        self.resource_heap_requests=[];self.resource_buffer_handles=set();self.next_resource_buffer=0x09a00020
        super().__init__(stock,build)
        self.uc.mem_map(0x09a00000,0x100000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)

    def observe(self,uc,address,size,data):
        if address==0x38853c:
            args=[uc.reg_read(r)for r in REGS];caller=uc.reg_read(UC_ARM_REG_LR)&~1
            if args[0]>4096:
                row=dict(length=args[0],kind=args[1],output=hex(args[2]),caller=hex(caller))
                self.resource_heap_requests.append(row)
                require(args[0]==8196 and args[1]==0 and args[2] and caller==0x11a266,
                    'Unexpected resource buffer heap request '+str(row))
                handle=0xd0000000+len(self.handles)+1;pointer=self.next_resource_buffer
                self.next_resource_buffer+=(args[0]+127)&~63
                require(self.next_resource_buffer<0x09b00000,'Resource parser buffer fixture exhausted')
                uc.mem_write(pointer-32,b'\xa5'*(args[0]+64))
                self.handles[handle]=dict(pointer=pointer,length=args[0],locks=0,freed=False)
                self.resource_buffer_handles.add(handle);self.put(args[2],handle)
                self.allocations.append(dict(length=args[0],kind=args[1]))
                row.update(handle=hex(handle),pointer=hex(pointer),only_exact_stock_XML_buffer_fixture=True)
                self.visits[address]+=1;self.ret(handle);return
        return super().observe(uc,address,size,data)
