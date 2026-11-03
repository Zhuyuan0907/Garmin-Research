#!/usr/bin/env python3
"""Original per-channel mixer task construction, without waking audio tasks.

Handle allocation/locking, task names and construction bookkeeping are
controlled. The exact initializer, kernel builder and descriptor registration
execute. Stop before the original wake call: no mixer playback or device I/O.
"""
from datetime import datetime, timezone
import json, struct
from pathlib import Path
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace
from emulate_native_task_creation import TaskMachine, CALL_STACK, RETURN, RESULT
from emulate_native_audio_registration import CHANNELS, CHANNEL_STRIDE, MIXERS, MIXER_STRIDE, require, sha

INITIALIZER = 0x3b9b66
PRE_WAKE = 0x3b9c1e
SOURCE_CONSTRUCTOR = 0x4379d4
POOL10_ALLOCATOR = 0x48ee68
POOL10 = 0x034e3cf4


class MixerCreation(TaskMachine):
    def __init__(self, stock):
        super().__init__(stock, 8192)
        self.allocations = {}; self.created = []; self.next_handle = 1
        self.initializer_visits = set(); self.channel = None; self.pause_allocator = False
        for page in (0x3b9000, 0x388000, 0x387000, 0x48e000):
            self.uc.mem_map(page, 4096); self.uc.mem_write(page, stock.read(page, 4096))
        self.uc.mem_map(MIXERS & ~4095, 0x5000)
        self.uc.mem_map(POOL10 & ~4095, 0x2000)
        for a in (0x38853c, 0x388804, 0x38756a):
            self.uc.mem_write(a, bytes.fromhex('7047'))
        self.stock = stock

    def observe(self, uc, address, size, data):
        self.initializer_visits.add(address)
        if address == 0x48ee80 and self.pause_allocator:
            self.pause_allocator = False; uc.emu_stop(); return
        if address == PRE_WAKE:
            uc.emu_stop(); return
        if address == 0x38853c:
            count, kind, out = (uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
            require(count in (8192, 240) and kind == 2 and out == 0,
                    'Unexpected mixer allocation ABI')
            handle = 0xd1000000+self.next_handle
            pointer = 0x09600000+(self.next_handle-1)*0x4000
            self.next_handle += 1
            mapped = (count+4095)&~4095
            uc.mem_map(pointer, mapped); uc.mem_write(pointer, b'\xa5'*mapped)
            self.allocations[handle] = {'pointer':pointer, 'bytes':count, 'mapped_bytes':mapped, 'channel':self.channel}
            uc.reg_write(UC_ARM_REG_R0, handle); return
        if address == 0x388804:
            uc.reg_write(UC_ARM_REG_R0, self.allocations[uc.reg_read(UC_ARM_REG_R0)]['pointer']); return
        if address == 0x38756a:
            # Only naming is controlled, not stack/descriptor/task construction.
            pointer = uc.reg_read(UC_ARM_REG_R0)
            uc.mem_write(pointer, ('Mixer'+str(self.channel)+'\0').encode('utf-16le'))
            uc.reg_write(UC_ARM_REG_R0, 0); return
        super().observe(uc, address, size, data)

    def create_mixer(self, channel):
        self.channel = channel
        record = CHANNELS+channel*CHANNEL_STRIDE
        mixer = MIXERS+channel*MIXER_STRIDE
        self.uc.mem_write(record, bytes([channel])); self.uc.mem_write(record+0x1f8, bytes([channel]))
        self.uc.reg_write(UC_ARM_REG_SP, CALL_STACK); self.uc.reg_write(UC_ARM_REG_LR, RETURN)
        self.uc.reg_write(UC_ARM_REG_R0, channel); self.uc.reg_write(UC_ARM_REG_R1, 0)
        self.uc.emu_start(INITIALIZER|1, RETURN, timeout=1000000, count=20000)
        require(self.uc.reg_read(UC_ARM_REG_PC) == PRE_WAKE, 'Initializer missed pre-wake endpoint')
        tcb = self.word(mixer+0x78)
        descriptor = list(struct.unpack('<5I', self.uc.mem_read(mixer+0x64, 20)))
        stack_handle = self.word(mixer+0x34); queue_handle = self.word(mixer+0x38)
        stack = self.allocations[stack_handle]; queue = self.allocations[queue_handle]
        require(descriptor == [0x2fa0dd, queue['pointer'], stack['pointer']+8192, 0x0117140c, mixer+0x3c],
                'Original per-channel descriptor differs')
        require(tcb == (stack['pointer']+8192-108)&~7 and self.byte(tcb+22) == 2,
                'Original kernel did not construct a blocked mixer task on its own stack')
        require(self.word(mixer+0x2c) == stack['pointer'] and self.word(mixer+0x30) == queue['pointer'],
                'Original initializer lost allocated stack/message storage')
        require(bytes(self.uc.mem_read(stack['pointer'], 64)) == b'\xa5'*64 and
                bytes(self.uc.mem_read(queue['pointer'], queue['mapped_bytes'])) == b'\xa5'*queue['mapped_bytes'],
                'Construction crossed stack canary or unexpectedly used message storage')
        require(self.word(0xf071d0) == len(self.created)+1, 'Original descriptor registration did not execute')
        row = {'channel':channel, 'mixer':mixer, 'descriptor':descriptor, 'tcb':tcb,
               'stack_pointer':stack['pointer'], 'stack_bytes':stack['bytes'],
               'message_storage_pointer':queue['pointer'], 'message_storage_bytes':queue['bytes'],
               'state_before_original_wake':self.byte(tcb+22), 'passed':True}
        self.created.append(row); return row

    def byte(self, address): return bytes(self.uc.mem_read(address, 1))[0]

    def allocator_interleaving(self):
        # Counterexample to treating this allocator as internally atomic.
        #Caller exclusion and actual OS preemption eligibility remain unknown.
        self.uc.mem_write(POOL10-32, b'\xa5'*32)
        self.uc.mem_write(POOL10, bytes(5*0x240))
        self.uc.mem_write(POOL10+5*0x240, b'\xa5'*32)
        self.uc.mem_write(RESULT, b'\xcc'*8)
        self.pause_allocator = True
        self.uc.reg_write(UC_ARM_REG_SP, CALL_STACK-0x2000)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN); self.uc.reg_write(UC_ARM_REG_R0, RESULT)
        self.uc.emu_start(POOL10_ALLOCATOR|1, RETURN, timeout=1000000, count=1000)
        require(self.uc.reg_read(UC_ARM_REG_PC) == 0x48ee80 and self.byte(POOL10+12) == 0,
                'First allocator did not pause after observing a free slot')
        suspended = self.uc.context_save()
        self.uc.reg_write(UC_ARM_REG_SP, CALL_STACK-0x3000)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN); self.uc.reg_write(UC_ARM_REG_R0, RESULT+4)
        self.uc.emu_start(POOL10_ALLOCATOR|1, RETURN, timeout=1000000, count=1000)
        require(self.uc.reg_read(UC_ARM_REG_PC) == RETURN and self.uc.reg_read(UC_ARM_REG_R0) == 0 and
                self.word(RESULT+4) == 0 and self.byte(POOL10+12) == 1,
                'Second allocator did not claim slot0')
        self.uc.context_restore(suspended)
        self.uc.emu_start(0x48ee81, RETURN, timeout=1000000, count=1000)
        require(self.uc.reg_read(UC_ARM_REG_PC) == RETURN and self.uc.reg_read(UC_ARM_REG_R0) == 0 and
                self.word(RESULT) == 0, 'Resumed first allocator did not also return slot0')
        require(bytes(self.uc.mem_read(POOL10-32, 32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(POOL10+5*0x240, 32)) == b'\xa5'*32,
                'Allocator touched adjacent provider data')
        return {'original_allocator':POOL10_ALLOCATOR, 'pause_after_free_check':0x48ee80,
                'both_calls_succeeded_and_returned_slot':0, 'separate_stacks_python_context_restore':True,
                'allocator_internal_atomicity_proved':False, 'actual_kernel_or_hardware_preemption_used':False,
                'caller_exclusion_or_live_race_proved':False, 'passed':True}


def main():
    stock = NativeImage(); m = MixerCreation(stock)
    rows = [m.create_mixer(c) for c in (5, 8)]
    require(len({r['tcb'] for r in rows}) == 2 and len({r['stack_pointer'] for r in rows}) == 2,
            'Different channels unexpectedly share a task/stack')
    require({INITIALIZER, 0x358bf8, 0x2fbbbe}.issubset(m.initializer_visits), 'Original construction paths skipped')
    references = []
    needle = struct.pack('<I', 0x2fa0dd); p = stock.data.find(needle)
    while p >= 0:
        load = 0x50000+p
        try: runtime = stock.load_to_runtime(load, 4)
        except ValueError: runtime = None
        references.append({'load':load, 'runtime':runtime}); p = stock.data.find(needle, p+1)
    require({'load':0x3b9eb0, 'runtime':0x3b9eb0} in references, 'Expected mixer entry literal absent')
    initializer_trace = trace(stock, INITIALIZER, 220)
    constructor_trace = trace(stock, SOURCE_CONSTRUCTOR, 100)
    allocator_trace = trace(stock, POOL10_ALLOCATOR, 40)
    require(any(x.get('literal_value') == hex(POOL10) for x in allocator_trace['instructions']),
            'Original allocator did not reference the shared kind10 pool')
    interleaving = m.allocator_interleaving()
    result = {'updated_utc':datetime.now(timezone.utc).isoformat(), 'stock_sha256':EXPECTED,
              'script_sha256':sha(Path(__file__).read_bytes()),
              'dependencies_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in
                 (ROOT/'scripts/emulate_native_task_creation.py',ROOT/'scripts/analyze_native_sections.py',
                  ROOT/'scripts/analyze_sdp_activation.py',ROOT/'scripts/emulate_native_audio_registration.py')},
              'created_channels':rows, 'entry_literal_references':references,
              'original_initializer_kernel_builder_and_registration_executed':True,
              'distinct_channels_construct_distinct_tasks_stacks_and_message_storage':True,
              'common_actor_entry_implies_single_global_audio_task':False,
              'initializer_trace':initializer_trace, 'source_constructor_static_trace':constructor_trace,
              'kind10_allocator_static_trace':allocator_trace, 'allocator_interleaving_control':interleaving,
              'shared_kind10_pool':POOL10, 'cross_actor_allocation_serialization_proved':False,
              'mixer_tasks_woken_or_run':False, 'all_channels_or_all_indirect_callers_covered':False,
              'all_passed':True, 'device_io':False, 'device_install_candidate':False,
              'limitations':'Two valid channel fixtures execute the exact initializer through original per-channel descriptor creation and registration; allocation/lock/name/bookkeeping and initial RAM are controlled, and execution stops before original wake. Shared entry does not imply one global task: channel5/8 have distinct TCB,8192-byte stacks and240-byte message storage. Neither task has run its message loop, and original allocation capacity/error/cleanup, real scheduling/IRQ, cross-channel message routing or all caller domains are not proved. Original shared kind10 allocator is paused after its free-slot test; another original call claims slot0 and the resumed first call also returns slot0. This uses separate stacks and Python CPU restore, not an actual OS/hardware preemption or live race, and does not disprove caller locks, IRQ masking or scheduling exclusion. The allocator itself must not be treated as a reservation spanning all actors. No new output-hook/controller/SEP/UI/module installation or physical audio is supplied. No device I/O.'}
    path = ROOT/'evidence/firmware-analysis/native-mixer-creation-emulation.json'
    path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'output':str(path), 'channels':len(rows), 'all_passed':True, 'tasks_woken':False, 'device_io':False}))


if __name__ == '__main__': main()
