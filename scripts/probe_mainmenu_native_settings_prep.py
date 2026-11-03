#!/usr/bin/env python3
"""Run the stock settings initializer from the actual native controller.

This adds only five exact raw semaphore-init callsites to the frozen native
observer. Condition construction/ownership/Timer transfer execute unchanged
stock instructions. Synthetic NOR and initial boot/kernel inputs remain
explicit fixtures. No physical I/O, modified package, or foreground claim.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, struct, sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR
from analyze_native_sections import ROOT, NativeImage, EXPECTED
from analyze_native_loader import IMAGE, STUBS
from emulate_native_independent_signal import IndependentSignalVM
from emulate_native_task_runtime_full import sha
from probe_native_kernel_context import POST, WAIT
from probe_native_player_mainmenu import BUILD
from emulate_native_player_menu_selection import DATABASE
from emulate_native_vpm_filesystem import REGS, RETURN, require

STAGE = ROOT / 'staging/native-player-mainmenu-native-prep'
INIT = {0x2cbd3c: (0x148e6b4, 0x2cbf4c), 0x2cbd48: (0x148e69c, 0x2cbf5c),
        0x2cbd54: (0x148e6cc, 0x2cbf6c), 0x2cbd60: (0x148e6e4, 0x2cbf7c),
        0x2cbd82: (0x148e920, 0x2cbfa0)}
COND = 0x148e8ec


class MainmenuSettingsPrepVM(IndependentSignalVM):
    def __init__(self, stock, build):
        self.settings_init_rows = []
        super().__init__(stock, build)

    def observe(self, uc, address, size, data):
        caller = uc.reg_read(UC_ARM_REG_LR) & ~1
        if self.kernel_active and address == 0x3008a0 and caller in INIT:
            pointer, tag = INIT[caller]
            require(uc.reg_read(REGS[0]) == pointer and self.running_task == self.controller and
                    self.word(0xf09090) == self.controller, 'Settings initializer actor/pointer differs')
            storage = self.declared_storage(pointer, 24)
            require(storage and self.active_backend is None and
                    not any(r['native_caller'] == hex(caller) for r in self.settings_init_rows),
                    'Settings raw semaphore initializer storage or repetition differs')
            row = dict(original_entry='0x3008a0', pointer=hex(pointer), native_caller=hex(caller),
                       bytes=24, storage_boundary=storage, expected_final_tag=hex(tag),
                       before_hex=bytes(uc.mem_read(pointer, 24)).hex(), native_zero_writes=[],
                       original_body_executed=False, host_seeded_backend_bytes=False,
                       running_task=hex(self.running_task))
            self.backend_initializations.append(row)
            self.settings_init_rows.append(row)
            self.active_backend = row
            self.visits[address] += 1
            return  # Original MOV/six STRs execute; no PC/return/owner rewrite.
        return super().observe(uc, address, size, data)

    def verify_settings_native_inventory(self, gui_condition, before_threads):
        require(self.returned and self.running_task == self.controller and
                self.uc.reg_read(UC_ARM_REG_PC) == RETURN and
                self.uc.reg_read(UC_ARM_REG_SP) == self.controller, 'Settings did not return to controller')
        require(len(self.settings_init_rows) == 5, 'Missing all five native raw semaphore constructors')
        for caller, (pointer, tag) in INIT.items():
            rows = [r for r in self.settings_init_rows if r['native_caller'] == hex(caller)]
            require(len(rows) == 1 and rows[0]['original_body_executed'] and
                    len(rows[0]['native_zero_writes']) == 6 and
                    bytes(self.uc.mem_read(pointer, 24)) == struct.pack('<6I', 0, 0, 0, 0, tag, 0),
                    'Whole stock raw semaphore init/retag differs ' + hex(pointer))
        aux = COND + 28
        expected = {COND: (gui_condition, self.timer_task + 32, self.timer_task, 0, 0x2cbf8c, 0),
                    gui_condition: (0, COND, self.timer_task, 0, 0x6048e8, 0),
                    aux: (0, 0, 0, 0, 0x2cbf8c, 0)}
        for p, words in expected.items():
            require(bytes(self.uc.mem_read(p, 24)) == struct.pack('<6I', *words),
                    'Two-condition native Timer owned chain/tag/class/depth differs ' + hex(p))
        require(self.word(COND + 24) == self.native_condition_magic and
                self.word(self.timer_task + 32) == COND and
                set(self.dispatcher_condition_tokens) == {COND, gui_condition}, 'Native retained tokens differ')
        constructors = [r for r in self.condition_constructor_runs if r['pointer'] == hex(COND)]
        transfers = [r for r in self.native_condition_owner_transfers if r['condition'] == hex(COND)]
        token_ops = [r for r in self.native_mutex_runs if r['pointer'] == hex(COND) and
                     r['scope'] == 'condition_constructor']
        require(len(constructors) == len(transfers) == len(token_ops) == 1 and
                constructors[0]['native_constructor_returned'] and
                constructors[0]['original_mutex_lock_and_owner_store_executed'] and
                token_ops[0]['native_body_returned'] and token_ops[0]['native_owner'] == hex(self.controller) and
                transfers[0]['owner_matches_timer'] and
                self.native_semaphores[COND]['retained_condition_token'], 'Original token construction/transfer incomplete')
        require(not any(self.task_mutex_ops.values()) and not any(self.task_waits.values()) and
                not any(self.task_releases.values()) and not any(self.task_lower_waits.values()) and
                not any(self.mutexes.values()), 'Settings has unresolved ordinary lock or continuation')
        after = self.native_task_inventory()
        require(after['all_tasks'] == before_threads['all_tasks'] and
                after['ready'] == before_threads['ready'], 'Settings changed the declared ALL/ready lists')
        for old, new in zip(before_threads['tasks'], after['tasks']):
            raw = bytearray.fromhex(old['raw108_hex'])
            if old['TCB'] == hex(self.timer_task):
                struct.pack_into('<I', raw, 32, COND)
            require(bytes(raw) == bytes.fromhex(new['raw108_hex']),
                    'Stock settings changed TCB outside one retained-token head ' + old['TCB'])
        self.verify_storage_guards()
        require(not self.condition_bootstrap_tokens, 'Inherited fake settings lock was used')
        return dict(native_inventory=after, raw_init_operations=self.settings_init_rows,
                    condition_constructor=constructors[0], native_token_lock=token_ops[0],
                    original_transfer=transfers[0], retained_tokens=[hex(gui_condition), hex(COND)],
                    semaphores={hex(p):bytes(self.uc.mem_read(p,24)).hex() for p in expected},
                    condition_magic=hex(self.word(COND+24)),
                    inherited_settings_lock_ret0_used=False, host_wrote_owner_or_ready_or_TCB=False)


def main():
    require(unicorn.__version__ == '2.1.4' and unicorn.uc_version() == (2, 1, 33621247), 'Use isolated Unicorn2.1.4')
    target = STAGE / 'settings-native-prep-terminal-probe.json'
    require(not target.exists(), 'Preserve terminal artifacts; choose a new probe for another run')
    source = Path(__file__).resolve()
    result = dict(updated_utc=datetime.now(timezone.utc).isoformat(), MAIN_sha256=EXPECTED,
                  source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),
                  full_scoped_final_guards_passed=False, device_io=False, sounds_emitted=False)
    build = json.loads((ROOT/BUILD).read_text())
    vm = MainmenuSettingsPrepVM(NativeImage(), build)
    try:
        result['phase'] = 'load_and_original_singleton'
        print(json.dumps(dict(phase=result['phase'])), flush=True)
        result['load'] = vm.load()
        oldram = struct.unpack_from('<I', (ROOT/build['original_binary']).read_bytes(), 4)[0]
        voice = bytes(vm.uc.mem_read(IMAGE+12, oldram-12)); exports = bytes(vm.uc.mem_read(STUBS,480)); dbsha = sha(DATABASE)
        vm.uc.reg_write(UC_ARM_REG_CPSR, (vm.uc.reg_read(UC_ARM_REG_CPSR)&~31)|31)
        result['kernel_inventory'] = vm.configure_native_kernel_inventory()
        vm.kernel_invoke(POST, (vm.timer_task, 16)); vm.kernel_invoke(0x5d2f7d, ())
        D = vm.kernel_invoke(0x5d2131, ())
        require(vm.returned and D == 0x8800520, 'Original singleton did not return')
        result['prior_singleton_inventory'] = vm.verify_singleton_inventory()
        result['prior_memory_guards'] = vm.verify_memory(voice, exports, dbsha)
        vm.kernel_invoke(WAIT); require(vm.idle_endpoint and vm.running_task == vm.idle, 'Background did not drain')
        require(vm.kernel_invoke(POST, (vm.controller,1), stack=vm.idle) == 1 and
                vm.returned and vm.running_task == vm.controller, 'Original idle POST controller return failed')
        before = vm.native_task_inventory()
        gui_condition = int(vm.native_condition_waits[0]['condition'],16)
        result['phase'] = 'stock_settings_initializer_on_native_controller'
        print(json.dumps(dict(phase=result['phase'])), flush=True)
        result['settings_return'] = hex(vm.kernel_invoke(0x2cbd17, ()))
        result['settings_native_inventory'] = vm.verify_settings_native_inventory(gui_condition,before)
        result['settings_whole_memory_guards'] = vm.verify_memory(voice,exports,dbsha)
        result.update(completed=True, full_scoped_final_guards_passed=True,
                      foreground_or_device_App_verified=False, kernel_original_MAIN_patch_bytes=0)
        print(json.dumps(dict(completed=True,native_settings_guards=True)),flush=True)
    except Exception as error:
        result.update(completed=False,error=str(error))
        print(json.dumps(dict(phase=result.get('phase'),error=str(error))),flush=True)
    try: inventory=vm.native_task_inventory() if vm.native_TCBs else None
    except Exception as error: inventory=dict(snapshot_error=str(error))
    result.update(recent=list(vm.recent),native_inventory=inventory,settings_init_rows=vm.settings_init_rows,
                  condition_constructor_runs=vm.condition_constructor_runs,native_owner_transfers=vm.native_condition_owner_transfers,
                  native_mutex_operations=vm.native_mutex_runs,native_restores=vm.kernel_restores,
                  pending_mutex_operations={hex(t):v for t,v in vm.task_mutex_ops.items() if v},
                  conditional_GUI_writes=vm.conditional_region_writes,invalid_accesses=vm.invalid_accesses,
                  native_fatal_entries=vm.native_fatal_entries,
                  registers={n:hex(vm.uc.reg_read(r)) for n,r in zip(['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))})
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    vm.db.close()
    if not result.get('completed'): sys.exit(1)


if __name__ == '__main__': main()
