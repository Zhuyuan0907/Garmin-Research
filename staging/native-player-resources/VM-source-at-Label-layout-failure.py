#!/usr/bin/env python3
"""Guarded storage for original11A254 resource stream-buffer allocations.

Native18AFE2 asks8192+4; original bitmap output also uses this allocator.
Only requests observed entering11A254 are accepted, bounded to64KiB+4.
Native prefix, decompression, pointer-query and free instructions stay original.
"""
import unicorn
from unicorn.arm_const import UC_ARM_REG_LR
from probe_native_player_resources import ResourceVM
from emulate_native_vpm_filesystem import REGS,require

class ResourceCacheVM(ResourceVM):
    def __init__(self,stock,build):
        self.resource_heap_requests=[];self.resource_buffer_handles=set();self.next_resource_buffer=0x09a00020
        self.pending_native_buffer=None
        super().__init__(stock,build)
        self.uc.mem_map(0x09a00000,0x100000,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)

    def observe(self,uc,address,size,data):
        if address==0x11a254:
            self.pending_native_buffer=dict(context=uc.reg_read(REGS[0]),
                requested=uc.reg_read(REGS[1]),caller=uc.reg_read(UC_ARM_REG_LR)&~1)
        if address==0x38853c:
            args=[uc.reg_read(r)for r in REGS];caller=uc.reg_read(UC_ARM_REG_LR)&~1
            if args[0]>4096:
                row=dict(length=args[0],kind=args[1],output=hex(args[2]),caller=hex(caller))
                self.resource_heap_requests.append(row)
                origin=self.pending_native_buffer
                require(origin is not None and 0<origin['requested']<=65536 and
                    args[0]==origin['requested']+4 and args[1]==0 and args[2] and caller==0x11a266,
                    'Unexpected resource buffer heap request '+str(row))
                self.pending_native_buffer=None
                handle=0xd0000000+len(self.handles)+1;pointer=self.next_resource_buffer
                self.next_resource_buffer+=(args[0]+127)&~63
                require(self.next_resource_buffer<0x09b00000,'Resource parser buffer fixture exhausted')
                uc.mem_write(pointer-32,b'\xa5'*(args[0]+64))
                self.handles[handle]=dict(pointer=pointer,length=args[0],locks=0,freed=False)
                self.resource_buffer_handles.add(handle);self.put(args[2],handle)
                self.allocations.append(dict(length=args[0],kind=args[1]))
                row.update(handle=hex(handle),pointer=hex(pointer),native_buffer_entry=hex(0x11a254),
                    original_requested_bytes=origin['requested'],original_buffer_context=hex(origin['context']),
                    original_buffer_caller=hex(origin['caller']),only_observed_native_buffer_storage_fixture=True)
                self.visits[address]+=1;self.ret(handle);return
        return super().observe(uc,address,size,data)
