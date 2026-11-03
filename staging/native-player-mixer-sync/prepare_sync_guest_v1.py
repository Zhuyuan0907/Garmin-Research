#!/usr/bin/env python3
"""Generate NEW strict guest with original mutex/condition synchronization.

Only source generation occurs here. Frozen handoff runners are unchanged.
Original Timer descriptor/task and channel8 constructors execute in the new
guest; their direct ordinary boot callers remain explicit new boot inputs.
"""
import ast
import hashlib
import json
from pathlib import Path

BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[1]
OLD=ROOT/'staging/native-player-mixer-handoff'

def replace_once(s,a,b):
    assert s.count(a)==1,a[:100]
    return s.replace(a,b,1)

def main():
    path=OLD/'emulate_mixer_handoff_v5.py'
    text=path.read_text()
    text=replace_once(text,'self.chunks = []','self.chunks = []\n        self.sync_entries, self.sync_returns, self.condition_entries, self.ack_entries = [], [], [], []\n        self.pending_sync = None\n        self.sync_boot_prefix = None')
    text=replace_once(text,"(0x2FA572, 'mcs_pull_bridge', 0x6E8020)):",
        "(0x2FA572, 'mcs_pull_bridge', 0x6E8020),\n                (0x3B9C54, 'ms_initializer_sync_bridge', 0x6E8030)):")
    text=replace_once(text,'expected_target = 0x2F9F2E if address == 0x2FA294 else 0x2F9CCA',
        'expected_target = 0x2F9F2E if address == 0x2FA294 else (0x46CC7A if address == 0x3B9C54 else 0x2F9CCA)')
    marker='        if address in (old.RETURN, IDLE):'
    observer='''        if address == self.build['symbols']['mh_source_entry']['value']:
            self.source_tcb=self.word(self.build['symbols']['mh_source_tcb']['value'])
            require(self.source_tcb and self.word(READY_TASKS)==self.source_tcb,
                    'compiled source entry lacks actual original TCB')
        if self.pending_sync and address == self.pending_sync['return_PC']:
            p=self.pending_sync
            require(uc.reg_read(UC_ARM_REG_SP)==p['entry_SP'], 'full original sync SP return')
            require(self.word(READY_TASKS)==self.source_tcb, 'sync did not return to actual source task')
            self.sync_returns.append(dict(p, returned=self.snapshot(), r0=uc.reg_read(UC_ARM_REG_R0)))
            self.pending_sync=None
        if address == 0x46CC7A:
            require(self.pending_sync is None, 'nested original synchronous initializer')
            require(self.word(READY_TASKS)==self.source_tcb and self.regs()[:3]==[RECORD,1,0],
                    'original sync outside exact compiled source call')
            require(uc.reg_read(UC_ARM_REG_LR)==0x3B9C59, 'sync wrapper altered original LR')
            require(self.word(self.build['symbols']['ms_original_sync_completed']['value'])==0,
                    'PLAY opened before original sync completion')
            p=dict(entry=self.snapshot(), entry_SP=uc.reg_read(UC_ARM_REG_SP),
                   return_PC=0x3B9C58, call_args=self.regs(),
                   CONFIG_handoffs=self.word(self.build['symbols']['aas_guard']['value']+
                       self.mh_guard_offsets[0]))
            self.sync_entries.append(p); self.pending_sync=p
        if address in (0x3EC6A2,0x3EC6AA,0x3EC5C6,0x300A14):
            self.condition_entries.append(dict(PC=address,state=self.snapshot(),args=self.regs()))
        if address == 0x30ED24 and self.regs()[1]==8:
            require(self.word(READY_TASKS)==self.mixer_tcb, 'ACK8 outside actual original mixer')
            self.ack_entries.append(dict(state=self.snapshot(),args=self.regs(),
                flag_before_hex=bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R0),12)).hex()))
'''
    text=replace_once(text,marker,observer+marker)
    # The whole original raw mutex bodies now execute; no host owner/ack writes.
    a=text.index('        if address in (0x3009A0, 0x3008B0):')
    b=text.index('        if address == 0x38853C:',a)
    text=text[:a]+text[b:]
    text=replace_once(text,'if address in (0xF5030, 0x46CC7A, 0x2F9C52, 0x3B9674):',
        'if address in (0xF5030, 0x2F9C52, 0x3B9674):')
    text=replace_once(text,"self.offsets = struct.unpack('<5I', self.uc.mem_read(build['symbols']['aas_offsets']['value'], 20))",
        "self.offsets = struct.unpack('<5I', self.uc.mem_read(build['symbols']['aas_offsets']['value'], 20))\n"
        "        self.mh_guard_offsets = struct.unpack('<5I', self.uc.mem_read(build['symbols']['mh_offsets']['value'], 20))")
    a=text.index('    def boot(self):')
    b=text.index('    def status(self):',a)
    boot='''    def sync_status(self):
        return {name:self.word(self.build['symbols'][name]['value']) for name in
            ('ms_sync_entries','ms_sync_grants','ms_sync_reuses','ms_sync_rejections',
             'ms_before_result','ms_original_sync_completed')}

    def boot(self, existing_control=False):
        self.invoke_kernel(0x3008A1, (EXIT_LIST + 4,), phase='original kernel exit-list mutex initialization')
        for i, (entry, top, priority) in enumerate(((IDLE, IDLE_STACK + 16384, 240),
                                                  (IDLE + 4, CONTROLLER_STACK + 16384, 16))):
            desc = DESCRIPTORS + 32 * i
            self.fixture(desc, struct.pack('<5I', entry, 0, top, priority << 16, 0), 'declared controller/idle task descriptor')
            tcb = self.invoke_kernel(0x358BF9, (desc,), phase='original controller/idle TCB construction')
            if i == 0: self.idle = tcb
            else: self.controller = tcb
        for address, value in ((READY_TASKS, self.controller), (self.controller, self.idle), (self.idle, 0)):
            self.fixture(address, struct.pack('<I', value), 'initial controller/idle ready-list fixture')
        self.fixture(self.controller + 22, b'\\x01', 'initial ready controller state fixture')
        self.fixture(self.idle + 22, b'\\x01', 'initial ready idle state fixture')
        require(self.word(0xF0909C)==0 and self.word(0xF090A0)==0,
                'Timer constructors must run before live timed nodes or existing Timer')
        self.invoke_kernel(0xF6E49, phase='original Timer descriptor constructor, direct declared boot caller')
        self.invoke_kernel(0x353D3D, phase='original Timer TCB constructor, direct declared boot caller')
        require(self.word(0xF090A0)==0x02D227C8, 'original Timer TCB publication differs')
        self.invoke_kernel(0x3008A1, (RECORD+0x58,), phase='original raw channel8 mutex constructor, direct declared boot caller')
        self.invoke_kernel(0x3EC541, (RECORD+0x70,), phase='original channel8 condition constructor, direct declared boot caller')
        require(self.word(RECORD+0x88)==0xD4475B83, 'native condition constructor magic missing')
        # Native source blocks in real condition wait; controller16 resumes
        # before mixer23. Capture this genuine no-ACK prefix with PLAY closed.
        self.source_tcb = self.invoke_kernel('mh_boot_source', phase='compiled source bootstrap, original sync waits')
        require(self.source_tcb and self.mixer_tcb, 'source did not construct original mixer')
        state=self.status(); sync=self.sync_status()
        require(state[30]==state[35]==self.source_tcb and state[31]==1 and state[32]==0,
                'source initialization did not remain in original wait')
        require(sync['ms_sync_grants']==1 and sync['ms_original_sync_completed']==0 and
                len(self.sync_entries)==1 and not self.sync_returns and self.pending_sync,
                'no-ACK prefix falsely completed initializer')
        self.sync_boot_prefix=dict(state=state,sync=sync,controller=self.snapshot(),
            original_sync_entered=True,original_sync_returned=False,PLAY_open=False,
            actual_ack_count=len(self.ack_entries),source_TCB=self.source_tcb)
        self.park()
        state=self.status(); sync=self.sync_status()
        require(state[31]==state[32]==1 and state[33]==state[34]==0 and state[36]==self.mixer_tcb,
                'whole original initializer did not complete')
        require(sync['ms_sync_grants']==sync['ms_original_sync_completed']==1 and
                not sync['ms_sync_rejections'] and len(self.sync_returns)==len(self.ack_entries)==1,
                'complete original synchronization or capability failed')
        if existing_control:
            require(self.invoke_kernel('mh_request_command',(7,),phase='existing native mixer initializer request')==0,
                    'existing source request rejected')
            require(self.sync_status()['ms_original_sync_completed']==0 and len(self.sync_returns)==1,
                    'existing source did not wait with PLAY closed')
            self.park(); state=self.status(); sync=self.sync_status()
            require(state[45]==7 and state[46]==0 and sync['ms_sync_reuses']==1 and
                    sync['ms_sync_grants']==1 and sync['ms_original_sync_completed']==1 and
                    len(self.sync_returns)==len(self.ack_entries)==2,
                    'existingM+78 path failed complete original wait/ACK without duplicategrant')
        require(state[42]==state[43]==state[52] and state[42]>=1 and state[44]==0,
                'original scheduled selector did not establish native binding')
        self.fixture(DESCRIPTOR - 32, b'\\xa5' * (36 + 64), 'declared output descriptor boundaries')
        self.fixture(BUFFER - 32, b'\\xa5' * (RING_BYTES + 64), 'declared hardware output ring boundaries')
        initial = BUFFER + RING_BYTES - 64
        self.fixture(DESCRIPTOR, struct.pack('<9I', 0, BUFFER, RING_BYTES, initial, initial, 0, 0, 0, 0), 'empty output ring fixture')
        for address, value in ((MIXER, DESCRIPTOR), (MIXER + 4, CAPACITY), (MIXER + 0xB4, SCRATCH)):
            self.fixture(address, struct.pack('<I', value), 'explicit hardware buffer/capacity fixture')
        self.fixture(MIXER + 0x7F, b'\\0', 'declared raw memcpy output mode')
        self.fixture(MIXER + 0x7E, b'\\0', 'declared no hardware seek pending')
        self.fixture(MIXER + 0x84, b'\\1', 'declared hardware activation; no message14 or DMA')
        self.fixture(SCRATCH - 32, b'\\xa5' * (CAPACITY + 64), 'declared scratch boundaries')

'''
    text=text[:a]+boot+text[b:]
    text=replace_once(text,'terminal_register_snapshots=self.endpoints, patches=self.patches,',
        'terminal_register_snapshots=self.endpoints, patches=self.patches,\n'
        '            sync_boot_no_ack_prefix=self.sync_boot_prefix,original_sync_entries=self.sync_entries,\n'
        '            full_original_sync_returns=self.sync_returns,actual_condition_entries=self.condition_entries,\n'
        '            original_mixer_ACK8_entries=self.ack_entries,compiled_sync_status=self.sync_status(),')
    text=replace_once(text,"runtime = BASE / 'guest-v5'","runtime = BASE / 'guest-v1'")
    text=replace_once(text,"BASE / 'build-v5.json'","BASE / 'build-v1.json'")
    text=text.replace("BASE / 'build-v5.json'","BASE / 'build-v1.json'")
    text=replace_once(text,"m = Handoff(stock, elf, build); m.boot()",
        "m = Handoff(stock, elf, build); m.boot(existing_control=name=='Stop_revokes_new_original_pulls')")
    text=text.replace("BASE / 'mixer-handoff-v5-proof.json'","BASE / 'mixer-sync-v1-proof.json'")
    text=replace_once(text,'three_guest_only_original_call_site_branches=True,',
        'four_guest_only_original_call_site_branches=True,\n'
        '                     original_generic_mutex_and_condition_wait_ACK8_executed=True,\n'
        '                     Timer_not_registered_or_posted_direct_native_ctor_boot_inputs=True,')
    text=text.replace('Opaque memory services, generic mutexes, bookkeeping, audio timing/priority,',
        'Original generic mutexes and synchronous conditionwait/ACK are no longer intercepted.\n'
        'Opaque memory services, bookkeeping, audio priority,')
    text=replace_once(text,'outer_returns=m.outer_returns, patches=m.patches)',
        'outer_returns=m.outer_returns, patches=m.patches,\n'
        '                       native_visits={hex(a):n for a,n in m.visits.items()},\n'
        '                       sync_entries=m.sync_entries,sync_returns=m.sync_returns,\n'
        '                       condition_entries=m.condition_entries,ack_entries=m.ack_entries,\n'
        '                       sync_boot_no_ack_prefix=m.sync_boot_prefix)')
    # Explicitly record actual final RX bytes and ordinary controller returns
    # in new evidence, without changing the frozen v5 files.
    text=replace_once(text,"require(self.uc.reg_read(UC_ARM_REG_PC) in (old.RETURN, IDLE), 'kernel call missed return/idle endpoint')",
        "require(self.uc.reg_read(UC_ARM_REG_PC) in (old.RETURN, IDLE), 'kernel call missed return/idle endpoint')\n"
        "        self.endpoints.append(dict(address=self.uc.reg_read(UC_ARM_REG_PC),actual_emu_endpoint=True,**self.snapshot()))")
    text=replace_once(text,'unchanged_after_declared_patches_RX_sha256=self.RX_before, replay=self.replay(),',
        'unchanged_after_declared_patches_RX_sha256=self.RX_before,\n'
        '            actual_final_RX_zones={str(a):bytes(self.uc.mem_read(a,n)).hex() for a,n,p in self.zones if p & unicorn.UC_PROT_EXEC},\n'
        '            replay=self.replay(),')
    text=replace_once(text,'three low interworking veneers are declared guest patches.',
        'four low interworking veneers are declared guest patches.') if 'three low interworking veneers are declared guest patches.' in text else text
    ast.parse(text)
    output=BASE/'emulate_mixer_sync_v1.py'
    with output.open('x') as f:f.write(text)
    result=dict(all_passed=True,file_only=True,guest_executed=False,device_io=False,
        source_sha256={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest(),
                       str(Path(__file__).relative_to(ROOT)):hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        generated_runner=str(output.relative_to(ROOT)),runner_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
        declared_original_cold_constructor_inputs=True,native_sync_wait_ACK_or_player_verified=False)
    with (BASE/'guest-source-preparation-v1.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result))

if __name__=='__main__':main()
