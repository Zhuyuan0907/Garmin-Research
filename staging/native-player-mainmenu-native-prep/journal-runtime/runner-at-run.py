#!/usr/bin/env python3
"""Native settings/GIR raw locks plus a whole initialized-data write journal.

Frozen prior observers remain intact. Only exact independently reviewed raw
callsites execute native bodies. No synthetic successful lock result.
"""
from pathlib import Path
import hashlib, json, struct
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_CPSR
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
import probe_mainmenu_native_settings_prep as prep
from probe_native_player_resources import INPUT, GIR
from emulate_native_vpm_filesystem import REGS, require


class JournalSettingsVM(prep.MainmenuSettingsPrepVM):
    RAW_CALLS = {}

    def __init__(self, stock, build):
        self.mutable_journal_active = False
        self.mutable_cpu_stores = []
        self.settings_raw_mutex_operations = []
        self.store_disassemblers={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
        super().__init__(stock, build)
        self.extra_stock_BSS_page_inputs = []
        for pointer,length in [(0x148e69c,0x29c),(0x34f773c,24)]:
            provenance=next((r for r in stock.zeros if r['runtime_start']<=pointer and
                            pointer+length<=r['runtime_end']),None)
            require(provenance is not None,'Extra settings/resource storage outside recovered BSS zero range')
            page=pointer&~4095
            if not any(lo<=page and page+4095<=hi for lo,hi,_ in self.uc.mem_regions()):
                self.uc.mem_map(page,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
                self.extra_stock_BSS_page_inputs.append(dict(page=hex(page),bytes=4096,
                    original_zero_provenance=provenance,initial_zero_BSS_is_explicit_fixture=True,
                    native_semaphore_initializer_still_required=True))
        rows = [r for r in stock.copies if r['runtime_start'] == 0xf00000]
        require(len(rows) == 1 and rows[0]['size'] == 467532, 'Stock initialized-data bank differs')
        self.mutable_bank_start = rows[0]['runtime_start']
        self.mutable_bank_size = rows[0]['size']
        self.mutable_bank_before = None
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, self.journal_mutable_write,
                         begin=self.mutable_bank_start, end=self.mutable_bank_start+self.mutable_bank_size-1)

    def journal_mutable_write(self, uc, access, address, size, value, data):
        if not self.mutable_journal_active:
            return
        pc = uc.reg_read(UC_ARM_REG_PC)
        thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)
        opcode=self.stock.read(pc,4)
        instructions=list(self.store_disassemblers[thumb].disasm(opcode,pc,count=1))
        require(self.mutable_bank_start <= address and address+size <= self.mutable_bank_start+self.mutable_bank_size
                and size in [1,2,4] and len(instructions)==1,
                'Mutable initialized-data write crosses declared scope')
        instruction=instructions[0]
        require(bytes(uc.mem_read(pc,instruction.size))==opcode[:instruction.size] and
                instruction.mnemonic.startswith(('str','stm','swp')),
                'Mutable-data writer opcode differs from original MAIN store instruction')
        require(len(self.mutable_cpu_stores) < 10000, 'Native settings write journal budget exhausted')
        before = bytes(uc.mem_read(address,size))
        self.mutable_cpu_stores.append(dict(PC=hex(pc),address=hex(address),size=size,
            before_hex=before.hex(),value=value, running_task=hex(self.running_task),
            Thumb=thumb,original_instruction=instruction.mnemonic+' '+instruction.op_str,
            original_opcode_hex=opcode[:instruction.size].hex()))

    def begin_mutable_scope(self):
        require(not self.mutable_journal_active and self.mutable_bank_before is None, 'Mutable journal already started')
        self.mutable_bank_before = bytes(self.uc.mem_read(self.mutable_bank_start,self.mutable_bank_size))
        self.mutable_journal_active = True

    def verify_mutable_scope(self):
        require(self.mutable_journal_active and self.mutable_bank_before is not None, 'Missing mutable-data scope')
        expected = bytearray(self.mutable_bank_before)
        for row in self.mutable_cpu_stores:
            offset = int(row['address'],16)-self.mutable_bank_start; size=row['size']
            require(expected[offset:offset+size].hex() == row['before_hex'], 'CPU write history omits an intervening host write')
            expected[offset:offset+size] = int(row['value']).to_bytes(size,'little')
        actual = bytes(self.uc.mem_read(self.mutable_bank_start,self.mutable_bank_size))
        require(actual == bytes(expected), 'Whole initialized-data bank differs outside observed original CPU stores')
        return dict(start=hex(self.mutable_bank_start),bytes=self.mutable_bank_size,
            before_sha256=hashlib.sha256(self.mutable_bank_before).hexdigest(),
            after_sha256=hashlib.sha256(actual).hexdigest(),CPU_store_count=len(self.mutable_cpu_stores),
            original_store_PCs=sorted({r['PC'] for r in self.mutable_cpu_stores}),stores=self.mutable_cpu_stores,
            whole_bank_matches_original_CPU_write_history=True,host_unrecorded_mutation=False,
            native_PC_from_exact_MAIN=True,all_RAM_or_physical_flash_verified=False)

    def observe(self,uc,address,size,data):
        caller=uc.reg_read(UC_ARM_REG_LR)&~1
        if self.kernel_active and address==0x2cbd16:
            self.begin_mutable_scope()
        if self.kernel_active and address==0x3008a0 and caller==0x41b1b2:
            pointer=uc.reg_read(REGS[0])
            require(pointer==0x34f773c and self.running_task==self.controller and self.active_backend is None,
                    'Native GIR init pointer/actor differs')
            storage=self.declared_storage(pointer,24); require(storage,'GIR backend outside declared stock BSS')
            row=dict(original_entry='0x3008a0',pointer=hex(pointer),native_caller=hex(caller),bytes=24,
                storage_boundary=storage,before_hex=bytes(uc.mem_read(pointer,24)).hex(),native_zero_writes=[],
                original_body_executed=False,host_seeded_backend_bytes=False)
            self.backend_initializations.append(row);self.active_backend=row;self.visits[address]+=1
            return
        if self.kernel_active and (address,caller) in self.RAW_CALLS:
            shape=self.RAW_CALLS[address,caller];pointer,tag=shape['pointer'],shape['tag']
            require(uc.reg_read(REGS[0])==pointer and self.running_task==self.controller and
                    self.word(0xf09090)==self.controller and self.declared_storage(pointer,24),
                    'Native raw mutex pointer/actor/storage differs')
            require(self.word(pointer+16)==tag and self.uc.mem_read(pointer+22,1)[0]==0,
                    'Native raw semaphore tag/class differs')
            if pointer not in self.native_semaphores:self.register_native_semaphore(pointer)
            require(not self.native_semaphores[pointer]['retained_condition_token'], 'Raw resource lock is a condition token')
            row=dict(original_entry=hex(address),pointer=hex(pointer),native_caller=hex(caller),
                operation='lock' if address==0x3009a0 else 'unlock',scope='reviewed_raw_settings_or_GIR',
                running_task=hex(self.running_task),entry_SP=hex(uc.reg_read(UC_ARM_REG_SP)),
                entry_LR=hex(uc.reg_read(UC_ARM_REG_LR)),before_words=[hex(self.word(pointer+4*n)) for n in range(6)],
                native_body_returned=False,semaphore_fields_written_by_original_only=True,
                host_CPU_context_restore=False,reviewed_shape=shape)
            self.native_mutex_runs.append(row);self.settings_raw_mutex_operations.append(row)
            self.task_mutex_ops[self.running_task].append(row);self.visits[address]+=1
            return
        return super().observe(uc,address,size,data)

    def verify_settings_native_inventory(self,gui_condition,before_threads):
        require(self.returned and self.running_task==self.controller and
                self.uc.reg_read(UC_ARM_REG_SP)==self.controller and self.word(0xf09090)==self.controller,
                'Settings initializer did not return to actual controller')
        require(len(self.settings_init_rows)==5,'Missing five native settings semaphore constructors')
        raw_final={}
        for caller,(pointer,tag) in prep.INIT.items():
            rows=[r for r in self.settings_init_rows if r['native_caller']==hex(caller)]
            require(len(rows)==1 and rows[0]['original_body_executed'] and len(rows[0]['native_zero_writes'])==6,
                    'Native settings constructor did not execute all six zero stores')
            raw=bytes(self.uc.mem_read(pointer,24));values=struct.unpack('<6I',raw)
            require(values[2:5]==(0,0,tag) and values[5]==0,'Settings raw semaphore not fully released/tag/class differs')
            uses=[r for r in self.settings_raw_mutex_operations if r['pointer']==hex(pointer)]
            expected=struct.pack('<6I',*[int(v,16) for v in uses[-1]['after_words']]) if uses else struct.pack('<6I',0,0,0,0,tag,0)
            require(raw==expected,'Whole released settings backend differs from its actual native epilogue')
            raw_final[hex(pointer)]=dict(raw24_hex=raw.hex(),native_released_links_are_not_assumed_zero=True)
        C=prep.COND
        expected={C:(gui_condition,self.timer_task+32,self.timer_task,0,0x2cbf8c,0),
                  gui_condition:(0,C,self.timer_task,0,0x6048e8,0), C+28:(0,0,0,0,0x2cbf8c,0)}
        for p,words in expected.items():
            require(bytes(self.uc.mem_read(p,24))==struct.pack('<6I',*words),'Native Timer dual-token chain differs '+hex(p))
        require(self.word(C+24)==self.native_condition_magic and self.word(self.timer_task+32)==C and
                set(self.dispatcher_condition_tokens)=={C,gui_condition},'Two retained native tokens not inventoried')
        ctors=[r for r in self.condition_constructor_runs if r['pointer']==hex(C)]
        transfers=[r for r in self.native_condition_owner_transfers if r['condition']==hex(C)]
        ops=[r for r in self.native_mutex_runs if r['pointer']==hex(C) and r['scope']=='condition_constructor']
        require(len(ctors)==len(transfers)==len(ops)==1 and ctors[0]['native_constructor_returned'] and
                ctors[0]['original_mutex_lock_and_owner_store_executed'] and ops[0]['native_body_returned'] and
                ops[0]['native_owner']==hex(self.controller) and transfers[0]['owner_matches_timer'] and
                self.native_semaphores[C]['retained_condition_token'],'Original settings condition construction/transfer incomplete')
        require(not any(self.task_mutex_ops.values()) and not any(self.task_waits.values()) and
                not any(self.task_releases.values()) and not any(self.task_lower_waits.values()) and
                not any(self.mutexes.values()),'Native settings still has an ordinary lock or unresolved continuation')
        after=self.native_task_inventory()
        require(after['all_tasks']==before_threads['all_tasks'] and after['ready']==before_threads['ready'],
                'Native settings changed scoped ALL/ready membership')
        for old,new in zip(before_threads['tasks'],after['tasks']):
            raw=bytearray.fromhex(old['raw108_hex'])
            if old['TCB']==hex(self.timer_task):struct.pack_into('<I',raw,32,C)
            require(bytes(raw)==bytes.fromhex(new['raw108_hex']),'Settings TCB changed outside retained-token owned head')
        self.verify_storage_guards()
        require(not self.condition_bootstrap_tokens,'Inherited fake SettingsVM lock used')
        result=dict(native_inventory=after,raw_init_operations=self.settings_init_rows,raw_settings_backends=raw_final,
                    condition_constructor=ctors[0],native_token_lock=ops[0],original_transfer=transfers[0],
                    retained_tokens=[hex(gui_condition),hex(C)],condition_magic=hex(self.word(C+24)),
                    semaphores={hex(p):bytes(self.uc.mem_read(p,24)).hex() for p in expected},
                    inherited_settings_lock_ret0_used=False,host_wrote_owner_or_ready_or_TCB=False,
                    extra_stock_BSS_page_inputs=self.extra_stock_BSS_page_inputs)
        require(self.settings_raw_mutex_operations and all(r['native_body_returned'] for r in self.settings_raw_mutex_operations),
                'Native settings raw lock continuation incomplete')
        result['native_raw_mutex_operations']=self.settings_raw_mutex_operations
        result['whole_mutable_initialized_bank']=self.verify_mutable_scope()
        return result


def main():
    from analyze_native_sections import ROOT
    artifact=ROOT/'staging/native-player-mainmenu-native-prep/mutex-static/mainmenu-native-settings-mutex-preflight.json'
    review=json.loads(artifact.read_text())
    require(review['assertions_passed'] and not review['device_io'] and not review['sounds_emitted'] and
            not review['frozen_source_or_proof_modified'], 'Need reviewed static raw call table')
    for p,s in review['source_sha256'].items():
        require(hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==s,'Static raw-call source changed '+p)
    for row in review['raw_mutex_calls']:
        key=(int(row['entry'],16),int(row['continuation'],16))
        value=dict(row,pointer=int(row['pointer'],16),tag=int(row['tag'],16))
        require(key not in JournalSettingsVM.RAW_CALLS,'Ambiguous native raw-lock caller')
        JournalSettingsVM.RAW_CALLS[key]=value
    for address,caller in [(0x3009a0,0x11c510),(0x3008b0,0x41ccd2)]:
        JournalSettingsVM.RAW_CALLS[address,caller]=dict(pointer=0x34f773c,tag=0x41b544,
            containing_function='0x41cc46',scope='exact stock GIR registration raw guard')
    # Reuse the frozen driver; the class swap chooses only this explicit
    # observer extension, and does not replace any guest function or return.
    prep.MainmenuSettingsPrepVM=JournalSettingsVM
    prep.STAGE=ROOT/'staging/native-player-mainmenu-native-prep/journal-runtime'
    prep.STAGE.mkdir(exist_ok=True)
    prep.main()


if __name__=='__main__':main()
