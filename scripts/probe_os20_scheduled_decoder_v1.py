#!/usr/bin/env python3
"""NEW native controller + OS20 root + compiled SBC decoder integration.

Reuse a frozen allocation endpoint, with explicit NEW callback/name/argument
inputs. All three TCBs are made by unchanged original code. Initial ready
membership is a declared bootstrap fixture, not a recovered full boot. Real
POST/WAIT/restore execute with no Python return/context hooks.
"""
import sys
sys.dont_write_bytecode = True
import gzip
import hashlib
import json
import struct
import traceback
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from probe_os20_allocator_v1 import *
from emulate_native_sbc import Reference

OUT = ROOT / 'staging/native-os20-scheduled-decoder-v1'
PARENT = 'staging/native-os20-allocator-v1/native_OS20_two_allocation_prefix.json.gz'
BUILD = 'staging/native-os20-scheduled-decoder-build-v1/manifest.json'
JOB, FRAME_INPUT, PCM_OUTPUT, RESULT = 0x09060000, 0x09061000, 0x09062000, 0x09063000
IDLE_STACK = 0x09070000
CONTROLLER, IDLE = 0x0901ff90, 0x09073f90
TRACK = TRACKED | {0x358bf8, 0x2fbbbe, 0x2fcd0a, 0x2fccce, 0x2fc9bc,
    0x521d7c, 0x358d24, 0x521e44, 0x2fcf44, 0x2fd034,
    0x09050000, 0x0800223c, 0x08002284}


class Scheduled(HeapCase):
    def __init__(self, native, parent, build, frame, reference_pcm):
        super().__init__(native, 'NEW_OS20_scheduled_SBC_callback')
        assert parent['all_passed'] and parent['boundary']['PC'] == 0x521e90
        assert self.zones == parent['zones'] and parent['model_SCTLR'] == self.sctlr
        for z in self.zones:
            self.u.mem_write(z['start'], bytes.fromhex(parent['whole_zones_after'][z['name']]))
        self.executable = [(0x50000, 0x50000 + self.rom_size, 'original_MAIN', None)]
        self.rx_regions = []
        self.initial_new_zone_bytes = {}
        self.initial_fixture_writes, self.fixture_events = [], []
        self.open_by_task = defaultdict(list)
        self.running_task = 0
        self.pending_restore = None
        self.restores, self.destinations, self.root_entries, self.worker_entries = [], [], [], []
        self.stage = ''
        self.native_tcbs = set()
        self.exit_boundary = self.idle_boundary = False
        self.reference_pcm = reference_pcm
        self.frame = frame
        self.parent, self.build = parent, build

        def zone(name, start, size, payload, startup=False, permissions=UC_PROT_READ | UC_PROT_WRITE):
            assert len(payload) == size
            if startup:
                assert any(r['runtime_start'] <= start and start + size <= r['runtime_end'] for r in native.zeros)
            self.u.mem_map(start, size, permissions)
            self.u.mem_write(start, payload)
            self.zones.append(dict(name=name, start=start, size=size, original_startup_zero=startup))
            self.initial_new_zone_bytes[name] = payload.hex()

        for name, address in [('OS20_adapter_pool_page', 0x03a1b000), ('descriptor_registry_page', 0x014b3000)]:
            zone(name, address, 4096, bytes(4096), True)
        zone('declared_idle_stack', IDLE_STACK, 16384, b'\xa5' * 16384)
        zone('declared_job', JOB, 4096, b'\xa5' * 4096)
        zone('declared_frame_input', FRAME_INPUT, 4096, b'\xa5' * 4096, permissions=UC_PROT_READ)
        zone('declared_PCM_output', PCM_OUTPUT, 4096, b'\xa5' * 4096)
        zone('declared_decode_result', RESULT, 4096, b'\xa5' * 4096)
        for path, label in [(build['ELF'], 'new_compiled_worker'), (build['decoder_ELF'], 'frozen_decoder')]:
            elf = (ROOT / path).read_bytes()
            h = struct.unpack_from('<16sHHIIIIIHHHHHH', elf)
            assert h[0][:6] == b'\x7fELF\x01\x01' and h[1:3] == (2, 40)
            for idx in range(h[10]):
                kind, offset, address, _, filesz, memsz, flags, _ = struct.unpack_from('<8I', elf, h[5] + idx * h[9])
                if kind != 1:
                    continue
                start, end = address & ~4095, (address + memsz + 4095) & ~4095
                assert end > start
                payload = bytearray(end - start)
                payload[address - start:address - start + filesz] = elf[offset:offset + filesz]
                if flags & 1:
                    assert not flags & 2
                    self.u.mem_map(start, end - start, UC_PROT_READ | UC_PROT_EXEC)
                    self.u.mem_write(start, bytes(payload))
                    self.executable.append((start, end, label, bytes(payload)))
                    self.rx_regions.append(dict(name=label, start=start, size=end-start,
                        SHA256=hashlib.sha256(payload).hexdigest(), ELF=path))
                else:
                    zone(label + '_RW', start, end - start, bytes(payload))
        self.idle_entry = build['symbols']['scheduled_idle_v1']['address']
        self.worker_entry = build['symbols']['scheduled_decode_entry_v1']['address']
        assert self.worker_entry == 0x09050000
        self.job_input = struct.pack('<11I', 0x53424331, FRAME_INPUT, len(frame), PCM_OUTPUT,
            512, RESULT, 0, 0, 0xffffffff, CONTROLLER, 0)
        patches = [(FRAME_INPUT, frame, 'synthetic_SBC_frame_from_upstream_encoder'),
            (JOB, self.job_input, 'explicit_caller_job'),
            (INPUT + 0x100, b'Garmin Music\0', 'NEW_valid_CP1252_name'),
            (INPUT + 0x200, struct.pack('<5I', self.idle_entry | 1, 0, STACK + 65536, 16 << 16, 0), 'controller_raw_descriptor'),
            (INPUT + 0x220, struct.pack('<5I', self.idle_entry | 1, 0, IDLE_STACK + 16384, 240 << 16, 0), 'idle_raw_descriptor')]
        base_sp = parent['boundary']['state']['GP16'][13]
        patches += [(base_sp + 0x14, struct.pack('<I', self.worker_entry | 1), 'NEW_saved_caller_callback'),
            (base_sp + 0x18, struct.pack('<I', JOB), 'NEW_saved_caller_callback_argument'),
            (base_sp + 0x20, struct.pack('<I', 7), 'NEW_saved_caller_priority_index7'),
            (base_sp + 0x38, struct.pack('<I', INPUT + 0x100), 'NEW_saved_caller_name')]
        for address, payload, reason in patches:
            before = bytes(self.u.mem_read(address, len(payload)))
            self.u.mem_write(address, payload)
            self.initial_fixture_writes.append(dict(address=address, before_hex=before.hex(), after_hex=payload.hex(), reason=reason))
        self.before = {z['name']: bytes(self.u.mem_read(z['start'], z['size'])).hex() for z in self.zones}
        self.assert_current_native = False

    def word(self, address):
        return struct.unpack('<I', self.u.mem_read(address, 4))[0]

    def fixture(self, address, payload, reason):
        before = bytes(self.u.mem_read(address, len(payload)))
        self.u.mem_write(address, payload)
        self.fixture_events.append(dict(after_instruction_count=len(self.trace), address=address,
            before_hex=before.hex(), after_hex=payload.hex(), reason=reason))

    def code(self, u, address, size, unused):
        if self.pending_restore and address == self.pending_restore['PC']:
            self.running_task = self.pending_restore['target']
            self.destinations.append(dict(**self.pending_restore, instruction_index=len(self.trace), state=self.snap()))
            self.pending_restore = None
        frames = self.open_by_task[self.running_task]
        while frames and frames[-1]['return_PC'] == address:
            row = frames.pop()
            row['after'] = self.snap()
            b, a = row['before'], row['after']
            assert b['GP16'][4:12] == a['GP16'][4:12], (hex(row['entry']), self.stage, 'registers')
            assert b['GP16'][13] == a['GP16'][13], (hex(row['entry']), self.stage, 'SP')
            assert (b['CPSR'] ^ a['CPSR']) & 0xdf == 0, (hex(row['entry']), self.stage, 'CPSR')
            row['full_ABI_return'] = True
            row['return_instruction_index'] = len(self.trace)
            self.native_calls.append(row)
        if address == RETURN:
            self.done = True
            u.emu_stop()
            return
        if address == 0x358fa4 and self.stage == 'resume_decoder_to_root_return':
            self.exit_boundary = True
            self.boundary = dict(kind='before_original_kernel_exit_shim', PC=address, state=self.snap())
            u.emu_stop()
            return
        if address == self.idle_entry:
            self.idle_boundary = True
            self.boundary = dict(kind='original_idle_context_destination', PC=address, state=self.snap())
            u.emu_stop()
            return
        if address == 0x23d6e8:
            self.boundary = dict(kind='before_original_fatal_diagnostic', PC=address, state=self.snap())
            u.emu_stop()
            return
        if address == 0x358ec4:
            target = self.word(0xf09090)
            assert target in self.native_tcbs, ('Non-native restore target', hex(target))
            frame = self.word(target + 12)
            self.pending_restore = dict(target=target, frame=frame, PC=self.word(frame + 4) & ~1,
                previous_running_task=self.running_task, original_body_executed=True,
                host_CPU_context_restore=False)
            self.restores.append(dict(self.pending_restore))
        if address == 0x521e44:
            self.root_entries.append(dict(running_task=self.running_task, ready_head=self.word(0xf09090), state=self.snap()))
        if address == self.worker_entry:
            self.worker_entries.append(dict(running_task=self.running_task, state=self.snap()))
        region = next((r for r in self.executable if r[0] <= address and address + size <= r[1]), None)
        assert region, ('Unadmitted code', hex(address))
        raw = self.native.read(address, size) if region[2] == 'original_MAIN' else region[3][address-region[0]:address-region[0]+size]
        assert bytes(u.mem_read(address, size)) == raw
        assert len(self.trace) < 500000
        state = self.snap()
        self.trace.append(dict(PC=address, opcode_hex=raw.hex(), size=size, phase=self.phase,
            stage=self.stage, running_task=self.running_task, code_source=region[2], **state))
        self.visits[address] += 1
        if address in TRACK:
            frames.append(dict(entry=address, before=state, return_PC=state['GP16'][14] & ~1,
                phase=self.phase, stage=self.stage, running_task=self.running_task,
                entry_instruction_index=len(self.trace)-1, full_ABI_return=False))

    def store(self, u, access, address, size, value, unused):
        z = next((z for z in self.zones if z['start'] <= address and address + size <= z['start'] + z['size']), None)
        assert z and size in (1, 2, 4), ('Unadmitted store', hex(address), size)
        assert z['name'] not in {'input_descriptors', 'declared_frame_input'}
        pc, cpsr = u.reg_read(UC_ARM_REG_PC), u.reg_read(UC_ARM_REG_CPSR)
        instruction = next(self.decoders[bool(cpsr & 32)].disasm(bytes(u.mem_read(pc, 4)), pc, count=1))
        assert instruction.mnemonic.startswith(('str', 'stm', 'push', 'swp'))
        self.stores.append(dict(zone=z['name'], address=address, size=size,
            value=value & ((1 << (size * 8)) - 1), PC=pc, opcode_hex=instruction.bytes.hex(),
            instruction=instruction.mnemonic + ' ' + instruction.op_str,
            before_hex=bytes(u.mem_read(address, size)).hex(), phase=self.phase,
            stage=self.stage, running_task=self.running_task, **self.snap()))

    def invoke(self, stage, entry, args=(), sp=CONTROLLER):
        self.stage = self.phase = stage
        self.done = False
        self.boundary = None
        self.u.reg_write(UC_ARM_REG_CPSR, 0x3f)
        for idx, reg in enumerate(REGS[:13]):
            self.u.reg_write(reg, 0x13520000 + idx)
        for reg, value in zip(REGS[:4], args):
            self.u.reg_write(reg, value)
        self.u.reg_write(UC_ARM_REG_SP, sp)
        self.u.reg_write(UC_ARM_REG_LR, RETURN | 1)
        before = self.snap()
        self.u.emu_start(entry, 0, count=500000, timeout=15_000_000)
        after = self.snap()
        assert self.done or self.boundary, ('No endpoint', stage, hex(after['GP16'][15]))
        call = dict(stage=stage, entry=entry, arguments=list(args), before=before,
                    after=after, full_return=self.done, boundary=self.boundary)
        self.host_calls.append(call)
        return call

    def capture(self, name):
        final = {z['name']: bytes(self.u.mem_read(z['start'], z['size'])).hex() for z in self.zones}
        for r in self.rx_regions:
            assert hashlib.sha256(bytes(self.u.mem_read(r['start'], r['size']))).hexdigest() == r['SHA256']
        assert hashlib.sha256(bytes(self.u.mem_read(0x50000, self.rom_size))).hexdigest() == self.rx_sha
        return dict(all_passed=True, name=name, source_scope='NEW native scheduler and compiled SBC callback',
            parent_checkpoint=PARENT, parent_checkpoint_SHA256=sha(ROOT / PARENT), parent_allocation_prefix_not_replayed=True,
            initial_new_zone_bytes=self.initial_new_zone_bytes, initial_fixture_writes=self.initial_fixture_writes,
            bootstrap_and_fixture_events=self.fixture_events, zones=self.zones,
            whole_zones_before=self.before, whole_zones_after=final,
            original_and_compiled_instruction_trace=self.trace, CPU_stores=self.stores,
            native_full_returns=self.native_calls, original_TCBs=sorted(self.native_tcbs),
            original_context_restores=self.restores, original_context_destinations=self.destinations,
            original_root_entries=self.root_entries, compiled_worker_entries=self.worker_entries,
            host_calls=self.host_calls, open_by_task=dict(self.open_by_task), boundary=self.boundary,
            current=self.word(0xf09090), running_task=self.running_task,
            worker_task=getattr(self,'worker_task',None), worker_adapter=getattr(self,'adapter',None),
            job44_hex=bytes(self.u.mem_read(JOB,44)).hex(),
            result36_hex=bytes(self.u.mem_read(RESULT,36)).hex(),
            output512_hex=bytes(self.u.mem_read(PCM_OUTPUT,512)).hex(),
            frame_input_hex=self.frame.hex(), reference_PCM_hex=self.reference_pcm.hex(),
            all_three_TCBs_constructed_by_original_code=True, initial_ready_membership_is_explicit_bootstrap_fixture=True,
            current_controller_stack_is_original_parent_stack=True, model_SCTLR=self.sctlr,
            MMU_translation_disabled=True, original_MAIN_unmodified=True,
            original_functions_not_hooked=True, host_context_restore_or_synthetic_return=False,
            full_hardware_CP15_cache_checkpoint_restored=False,
            live_Bluetooth_DAC_GUI_or_physical_App_verified=False, device_IO=False)

    def run(self):
        for label, descriptor, expected in [('native_controller_constructor',INPUT+0x200,CONTROLLER),
                                           ('native_idle_constructor',INPUT+0x220,IDLE)]:
            call = self.invoke(label, 0x358bf9, (descriptor,), sp=0x0901fd00)
            assert call['full_return'] and call['after']['GP16'][0] == expected
            self.native_tcbs.add(expected)
        for address, payload, reason in [(0xf09090,struct.pack('<I',CONTROLLER),'initial_native_controller_ready_head'),
            (CONTROLLER,struct.pack('<I',IDLE),'initial_controller_to_idle_link'),
            (IDLE,bytes(4),'initial_idle_tail'),
            (CONTROLLER+22,b'\x01','initial_controller_ready'),(IDLE+22,b'\x01','initial_idle_ready')]:
            self.fixture(address,payload,reason)
        self.running_task = CONTROLLER
        state = self.parent['original_instruction_trace'][-2]
        assert state['PC'] == 0x521e8c
        self.u.reg_write(UC_ARM_REG_CPSR,state['CPSR'])
        for reg,value in zip(REGS,state['GP16']):self.u.reg_write(reg,value)
        self.u.reg_write(UC_ARM_REG_CPSR,state['CPSR'])
        self.stage=self.phase='NEW_original_named_create_callback_job'
        self.done=False
        # Discover the original builder's return before any POST/restore can
        # select the new task. Observe-only hook, never overwrite its return.
        expected_worker=(self.parent['payloads']['workspace']+4248-108)&~7
        self.worker_task=expected_worker
        self.native_tcbs.add(expected_worker)
        self.u.emu_start(0x521e8d,0,count=500000,timeout=15_000_000)
        assert self.done and not self.boundary
        builder=[r for r in self.native_calls if r['entry']==0x358bf8][-1]
        assert builder['after']['GP16'][0]==expected_worker
        self.adapter=self.u.reg_read(UC_ARM_REG_R0)
        assert self.adapter==0x03a1b294
        assert self.word(self.adapter+12)==self.worker_entry|1 and self.word(self.adapter+16)==JOB
        assert self.word(self.adapter+48)==self.worker_task
        assert self.word(CONTROLLER)==self.worker_task and self.word(self.worker_task)==IDLE
        assert self.u.mem_read(self.worker_task+17,1)[0]==0x59
        call=self.invoke('controller_WAIT_until_decoder_notification',0x2fd035)
        assert call['full_return'] and self.running_task==CONTROLLER
        assert call['after']['GP16'][0]==0x400
        assert bytes(self.u.mem_read(PCM_OUTPUT,len(self.reference_pcm)))==self.reference_pcm
        assert bytes(self.u.mem_read(PCM_OUTPUT+len(self.reference_pcm),4096-len(self.reference_pcm)))==b'\xa5'*(4096-len(self.reference_pcm))
        job=struct.unpack('<11I',self.u.mem_read(JOB,44))
        assert job[6:9]==(JOB,1,0) and job[10]==0
        assert len(self.root_entries)==len(self.worker_entries)==1
        assert self.worker_entries[0]['state']['GP16'][0]==JOB
        assert self.running_task==CONTROLLER and self.word(0xf09090)==CONTROLLER
        first=self.capture('decoder_completed_and_controller_resumed')
        compressed(OUT/'decoder-notification.json.gz',first)
        call=self.invoke('resume_decoder_to_root_return',0x2fd035)
        assert self.exit_boundary and not call['full_return'] and self.running_task==self.worker_task
        assert self.word(JOB+40)==1
        assert any(r['entry']==self.worker_entry for r in self.native_calls)
        assert any(r['entry']==0x521e44 for r in self.native_calls)
        second=self.capture('compiled_decoder_callback_and_original_root_returned')
        compressed(OUT/'callback-root-return.json.gz',second)
        self.stage=self.phase='original_kernel_self_exit_to_native_idle'
        self.done=False;self.boundary=None
        self.u.emu_start(0x358fa5,0,count=500000,timeout=15_000_000)
        assert self.idle_boundary and self.running_task==IDLE
        assert self.word(0xf09090)==IDLE
        seen=[];ptr=self.word(0xf0908c)
        while ptr:
            assert ptr not in seen and len(seen)<4
            seen.append(ptr);ptr=self.word(ptr+40)
        assert set(seen)=={CONTROLLER,IDLE}
        third=self.capture('original_worker_self_exit_unlinked_and_idle_restored')
        compressed(OUT/'self-exit-idle.json.gz',third)
        return third


def main():
    assert not OUT.exists();OUT.mkdir()
    build=json.loads((ROOT/BUILD).read_text());assert build['all_passed']
    for p,h in build['source_sha256'].items():assert sha(ROOT/p)==h
    assert sha(ROOT/build['ELF'])==build['ELF_sha256']
    parent=json.load(gzip.open(ROOT/PARENT,'rt'))
    ref=Reference();frame=ref.encode(dict(frequency=0,blocks=3,subbands=1,mode=0,allocation=0,bitpool=32),frames=1)[0]
    pcm=ref.decode_stream([frame])[0]
    (OUT/'frame.sbc').write_bytes(frame);(OUT/'reference.pcm').write_bytes(pcm)
    sources={str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__),ROOT/PARENT,ROOT/BUILD,
        ROOT/build['ELF'],ROOT/build['decoder_ELF'],ROOT/'scripts/probe_os20_allocator_v1.py',
        ROOT/'scripts/emulate_native_sbc.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']}
    sources.update(build['source_sha256'])
    m=None
    try:
        m=Scheduled(NativeImage(),parent,build,frame,pcm)
        final=m.run()
        cases=[]
        for name in ['decoder-notification.json.gz','callback-root-return.json.gz','self-exit-idle.json.gz']:
            p=OUT/name;cases.append(dict(path=str(p.relative_to(ROOT)),sha256=sha(p),passed=True))
        result=dict(all_passed=True,cases=cases,source_sha256=sources,
            CPU_stores=len(m.stores),instructions=len(m.trace),native_full_returns=len(m.native_calls),
            original_root_and_compiled_SBC_callback_executed=True,upstream_PCM_matches=True,
            original_controller_WAIT_resume=True,original_worker_and_root_full_return=True,
            original_self_exit_and_idle_restore=True,initial_ready_bootstrap_fixture=True,
            reference_library=str(ref.library_path),reference_library_SHA256=sha(ref.library_path),
            reference_version=ref.version,reference_frame_SHA256=sha(OUT/'frame.sbc'),
            reference_PCM_SHA256=sha(OUT/'reference.pcm'),live_App_or_direct_Bluetooth_audio_verified=False,
            device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat())
        save(OUT/'guest-proof.json',result)
        print(json.dumps({k:result[k]for k in ['all_passed','CPU_stores','instructions','native_full_returns','original_root_and_compiled_SBC_callback_executed','original_self_exit_and_idle_restore']}),flush=True)
    except BaseException as error:
        data=dict(all_passed=False,error=str(error),traceback=traceback.format_exc(),source_sha256=sources,device_IO=False)
        if m:
            data.update(state=m.snap(),trace=m.trace,CPU_stores=m.stores,native_full_returns=m.native_calls,
                open_by_task=dict(m.open_by_task),restores=m.restores,destinations=m.destinations,
                fixture_events=m.fixture_events,stage=m.stage,boundary=m.boundary)
        compressed(OUT/'terminal-failure.json.gz',data)
        raise


if __name__=='__main__':main()
