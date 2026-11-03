#!/usr/bin/env python3
"""Original settings cold initialization on explicit synthetic NOR storage.

Only lower bank geometry/program/erase/read services are fixtures. Settings
records, sector headers, sorting, cursor, defaults and setter stay original.
No device I/O or writes to backup files. Guest geometry is fictional.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, struct, sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP
from analyze_native_sections import NativeImage, ROOT
from probe_native_heap_callback import HeapDescriptorVM
from probe_native_player_mainmenu import BUILD
from probe_native_player_resources import INPUT
from emulate_native_vpm_filesystem import REGS, require, RETURN

STAGE = ROOT/'staging/native-player-settings-writer'
FLASH = 0x18001000
SECTOR_SIZE = 16384
SECTOR_COUNT = 2
GLOBAL = 0xf06ef4

class SettingsVM(HeapDescriptorVM):
    def __init__(self, stock, build):
        self.storage_events = []; self.settings_native_entries = []
        self.native_flash_reads = []; self.settings_storage_active = True
        self.settings_temporary_handle = None
        super().__init__(stock, build)
        self.uc.mem_map(FLASH-4096, SECTOR_SIZE*SECTOR_COUNT+8192, unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
        self.uc.mem_write(FLASH-4096, b'\xa5'*4096)
        self.uc.mem_write(FLASH, b'\xff'*(SECTOR_SIZE*SECTOR_COUNT))
        self.uc.mem_write(FLASH+SECTOR_SIZE*SECTOR_COUNT, b'\xa5'*4096)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.reject_direct_flash_write,
            begin=FLASH-4096, end=FLASH+SECTOR_SIZE*SECTOR_COUNT+4095)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_READ, self.observe_flash_read,
            begin=FLASH-4096, end=FLASH+SECTOR_SIZE*SECTOR_COUNT+4095)
        self.uc.mem_map(0x18200000, 0x2000, unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)

    def reject_direct_flash_write(self, uc, access, address, size, value, data):
        raise ValueError('Unexpected direct native flash write at '+hex(address)+' PC '+hex(uc.reg_read(UC_ARM_REG_PC)))

    def observe_flash_read(self, uc, access, address, size, value, data):
        require(FLASH <= address and address+size <= FLASH+SECTOR_SIZE*SECTOR_COUNT,
            'Native settings read crossed synthetic flash guards')
        require(len(self.native_flash_reads)<20000, 'Finite storage read observation budget exhausted')
        self.native_flash_reads.append(dict(address=hex(address), size=size, original_PC=hex(uc.reg_read(UC_ARM_REG_PC))))

    def observe(self, uc, address, size, data):
        args = [uc.reg_read(r) for r in REGS] if address in [0x26a2d0,0x26a40a,0x26a3e2,0x26a43a,0x26a300] else None
        caller = uc.reg_read(UC_ARM_REG_LR)&~1
        if address==0x38853c and caller==0x2cb6d8:
            a=[uc.reg_read(r)for r in REGS]
            require(a[:3]==[4288,0,0] and self.settings_temporary_handle is None,
                'Unexpected native settings temporary heap request')
            handle=0xd0000000+len(self.handles)+1;pointer=0x18200020
            uc.mem_write(pointer-32,b'\xa5'*(4288+64))
            self.handles[handle]=dict(pointer=pointer,length=4288,locks=0,freed=False)
            self.settings_temporary_handle=handle
            self.allocations.append(dict(length=4288,kind=0))
            self.storage_events.append(dict(operation='temporary_index_buffer',entry=hex(address),caller=hex(caller),
                opaque_handle=hex(handle),guest_pointer=hex(pointer),bytes=4288,explicit_synthetic_storage=True,
                physical_device_or_backup_written=False))
            self.visits[address]+=1;self.ret(handle);return
        if args is not None and self.settings_storage_active:
            bank = args[0]; event = dict(entry=hex(address), caller=hex(caller), arguments=[hex(a)for a in args],
                explicit_synthetic_storage=True, physical_device_or_backup_written=False)
            if address==0x26a2d0:
                require(bank==13 and args[1]==0 and caller in [0x1025aa,0x1025d8,0x102618], 'Unexpected flash-bank inventory ABI')
                self.put(args[2],FLASH); self.put(args[3],SECTOR_SIZE*SECTOR_COUNT)
                event['operation']='bank_geometry'; value=0
            elif address==0x26a40a:
                require(bank==13 and caller==0x1025e8 and 0<=args[1]<30, 'Unexpected sector inventory ABI')
                index=args[1]; value=0 if index<SECTOR_COUNT else 1
                if value==0:self.put(args[2],index*SECTOR_SIZE);self.put(args[3],SECTOR_SIZE)
                event.update(operation='sector_geometry', index=index, absent=value!=0)
            elif address==0x26a3e2:
                require(bank==13 and caller==0x1025b8 and args[1] in [n*SECTOR_SIZE for n in range(SECTOR_COUNT)], 'Unexpected aligned erase ABI')
                offset=args[1]; self.uc.mem_write(FLASH+offset,b'\xff'*SECTOR_SIZE)
                event.update(operation='erase', offset=offset, bytes=SECTOR_SIZE); value=0
            elif address==0x26a43a:
                require(bank==13 and caller==0x10262a, 'Unexpected NOR program ABI')
                offset,source,length=args[1:]; require(0<length<=SECTOR_SIZE and 0<=offset and offset+length<=SECTOR_SIZE*SECTOR_COUNT,
                    'Program exceeds explicit synthetic NOR storage')
                before=bytes(uc.mem_read(FLASH+offset,length)); incoming=bytes(uc.mem_read(source,length))
                require(all((a&b)==b for a,b in zip(before,incoming)), 'NOR program attempted zero-to-one bit change')
                uc.mem_write(FLASH+offset,incoming)
                event.update(operation='program', offset=offset, bytes=length, source=hex(source),
                    before_hex=before.hex(), incoming_hex=incoming.hex(), one_to_zero_only=True); value=0
            else:
                require(bank==34 and args[1:3]==[0,40] and caller==0x3b1d72,
                    'Unexpected auxiliary metadata read ABI')
                uc.mem_write(args[3],b'\xff'*40); event['operation']='erased_auxiliary_metadata_read';value=0
            self.storage_events.append(event); self.visits[address]+=1;self.ret(value);return
        if address in [0x2cbd16,0x2ca76c,0x2ca82c,0x2cabbc,0x2cab14,0x2ca6d0,0x2ca16a,0x2cb3a2]:
            self.settings_native_entries.append(dict(entry=hex(address), caller=hex(caller), arguments=[hex(uc.reg_read(r))for r in REGS]))
        return super().observe(uc,address,size,data)

    def verify_storage_guards(self):
        require(bytes(self.uc.mem_read(FLASH-4096,4096))==b'\xa5'*4096 and
            bytes(self.uc.mem_read(FLASH+SECTOR_SIZE*SECTOR_COUNT,4096))==b'\xa5'*4096,
            'Synthetic flash guards changed')
        if self.settings_temporary_handle is not None:
            e=self.handles[self.settings_temporary_handle];p=e['pointer'];n=e['length']
            require(e['freed'] and bytes(self.uc.mem_read(p-32,32))==b'\xa5'*32 and
                bytes(self.uc.mem_read(p+n,32))==b'\xa5'*32,'Native settings temporary buffer retained or overrun')

def main():
    STAGE.mkdir(exist_ok=True); source=Path(__file__).resolve()
    vm=SettingsVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(), source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),
        device_io=False,sounds_emitted=False,full_integration_checkpoint=False)
    try:
        print(json.dumps(dict(phase='original_settings_cold_initializer')),flush=True)
        value=vm.invoke(0x2cbd17,());vm.verify_storage_guards()
        result.update(completed=True,initializer_returned=hex(value),global_words=[hex(vm.word(GLOBAL+4*n))for n in range(10)],
            sector_bytes_hex=bytes(vm.uc.mem_read(FLASH,64)).hex(), fictional_geometry=dict(sector_count=SECTOR_COUNT,sector_bytes=SECTOR_SIZE,guest_base=hex(FLASH)))
        print(json.dumps(dict(phase='original_settings_setter')),flush=True)
        vm.uc.mem_write(INPUT+0x400,struct.pack('<HH',0x1234,0xffff))
        result['setter_result']=vm.invoke(0x2ca82d,(0x121e,INPUT+0x400,2,0))
        vm.put(INPUT+0x500,0);result['read_result']=hex(vm.invoke(0x2cabbd,(0x121e,INPUT+0x500)))
        result['record_data_pointer']=hex(vm.word(INPUT+0x500));vm.verify_storage_guards()
    except Exception as error:
        result.update(completed=False,error=str(error),recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            registers={n:hex(vm.uc.reg_read(r))for n,r in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    result.update(storage_events=vm.storage_events,settings_native_entries=vm.settings_native_entries,
        native_fatal_entries=vm.native_fatal_entries,conditional_writes=vm.conditional_region_writes)
    (STAGE/'settings-development-probe.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(completed=result['completed'],error=result.get('error'),storage_operations=len(vm.storage_events))),flush=True)
    if not result['completed']:sys.exit(1)

if __name__=='__main__':main()
