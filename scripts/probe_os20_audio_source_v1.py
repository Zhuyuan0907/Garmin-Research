#!/usr/bin/env python3
"""New OS20 allocator-backed Source executes the existing native audio pipeline.

Fresh caller state: original allocator construction is added to the warm
audio VM before the new five-argument named-create call. No checkpoint RAM
is spliced into a second scheduler. Original context switches remain native.
Radio packets, startup ready membership, unrelated mixer heaps and hardware
output remain explicit fixtures. No device operations or App success claim.
"""
import sys
sys.dont_write_bytecode = True
import ast
import gzip
import hashlib
import importlib.util
import inspect
import json
import struct
import textwrap
import traceback
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import unicorn
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
OUT = ROOT / 'staging/native-os20-audio-source-v1'
BUILD = ROOT / 'staging/native-os20-audio-source-build-v1/manifest.json'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


L = load(ROOT / 'staging/native-player-leaf-writers/emulate_leaf_writers_v1.py', 'os20_audio_frozen_warm_base')
B, I = L.B, L.I
require, sha, rel = L.require, L.sha, L.rel
PRIVATE, PUBLIC, WORK = 0x18301000, 0x18310000, 0x03a7f170
INPUT, L1, L2, POOL = 0x09030000, 0x03e00000, 0x03f00000, 0x03a1b294
TRACK = {0x388b6c, 0x521e5e, 0x358bf8, 0x2fbbbe, 0x521e44, 0x358d24,
         0x2fcd0a, 0x2fccce, 0x2fc9bc, 0x2fcf44, 0x2fd034,
         0x395440, 0x39544c, 0x2dc954, 0x38850a, 0x388804}


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def zipped(path, value):
    with path.open('xb') as stream:
        with gzip.GzipFile(fileobj=stream, mode='wb', mtime=0, compresslevel=6) as output:
            output.write(json.dumps(value, separators=(',', ':')).encode())


# The inherited observer's opaque allocation/query policy must not intercept
# genuine OS20 allocations. Only five existing service predicates acquire this
# explicit scope condition; the native bodies and all other observations stay.
original_observer = B.Handoff.code
observer_source = textwrap.dedent(inspect.getsource(original_observer))
tree = ast.parse(observer_source)
changed_predicates = []
for node in tree.body[0].body:
    if not isinstance(node, ast.If):
        continue
    constants = {n.value for n in ast.walk(node.test) if isinstance(n, ast.Constant)}
    if constants & {0x38853c, 0x388804, 0x388b22, 0x3887a2, 0xf5030}:
        changed_predicates.append(ast.unparse(node.test))
        node.test = ast.BoolOp(op=ast.And(), values=[node.test, ast.UnaryOp(op=ast.Not(),
            operand=ast.Attribute(value=ast.Name(id='self', ctx=ast.Load()),
                                  attr='native_allocator_execution', ctx=ast.Load()))])
require(len(changed_predicates) == 5, 'unexpected inherited allocator hook predicates')
ast.fix_missing_locations(tree)
observer_scope = dict(original_observer.__globals__)
exec(compile(tree, '<OS20-scoped-opaque-service-observer>', 'exec'), observer_scope)
B.Handoff.code = observer_scope['code']
scoped_observer_source = ast.unparse(tree)


class AudioSource(L.LeafVM):
    def __init__(self, *args):
        self.native_allocator_execution = False
        self.original_frames = defaultdict(list)
        self.original_returns, self.native_instructions = [], []
        self.worker_stack_low = None
        self.heap_scope_records = []
        self.os20_boot_record = None
        super().__init__(*args)
        for start, length, payload, label in [
            (WORK & ~4095, 4096, bytes(4096), 'original startup-zero WORK page'),
            (POOL & ~4095, 4096, bytes(4096), 'original startup-zero OS20 adapter pool'),
            (INPUT, 4096, b'\xa5' * 4096, 'new caller extent descriptors'),
            (PRIVATE - 4096, 32768 + 8192, b'\xa5' * 4096 + b'\xcc' * 32768 + b'\xa5' * 4096, 'new private extent and guards'),
            (PUBLIC - 4096, 65536 + 8192, b'\xa5' * 4096 + b'\xcc' * 65536 + b'\xa5' * 4096, 'new public extent and guards'),
            (L1, 16384, bytes(16384), 'explicit software L1 table'),
            (L2, 4096, b'\xa5' * 4096, 'explicit software L2 table')]:
            require(all(start + length <= a or a + n <= start for a, n, _ in self.zones), 'new heap zone overlaps existing mapping ' + label)
            self.map(start, length, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
            self.fixture(start, payload, label)
        self.fixture(INPUT, struct.pack('<2I', PRIVATE, 32768), 'new caller private extent input')
        self.fixture(INPUT + 16, struct.pack('<2I', PUBLIC, 65536), 'new caller public extent input')
        self.fixture(L1 + (PUBLIC >> 20) * 4, struct.pack('<I', L2 | 1), 'declared software table link, no hardware MMU proof')
        for address in range(PUBLIC, PUBLIC + 65536, 4096):
            self.fixture(L2 + ((address & 0xfffff) >> 12) * 4, struct.pack('<I', (2 << 30) | 0x150), 'declared pre-existing software public descriptor')
        self.sctlr = self.uc.reg_read(UC_ARM_REG_CP_REG, (15, 0, 0, 1, 0, 0, 0))
        require(not self.sctlr & 1, 'software-only mapping requires MMU disabled')

    def finish_original(self, address):
        actor = self.word(B.READY_TASKS)
        frames = self.original_frames[actor]
        while frames and frames[-1]['return_PC'] == address:
            row = frames.pop()
            before, after = row['before'], self.snapshot()
            require(before['GP16'][4:12] == after['GP16'][4:12], 'native helper callee saved ' + hex(row['entry']))
            require(before['GP16'][13] == after['GP16'][13], 'native helper SP ' + hex(row['entry']))
            require((before['CPSR'] ^ after['CPSR']) & 0xdf == 0, 'native helper CPSR ' + hex(row['entry']))
            row.update(after=after, full_ABI_return=True)
            self.original_returns.append(row)

    def invoke_kernel(self, *args, **kwargs):
        value = super().invoke_kernel(*args, **kwargs)
        self.finish_original(self.uc.reg_read(UC_ARM_REG_PC))
        return value

    def code(self, uc, address, size, data):
        self.finish_original(address)
        actor = self.word(B.READY_TASKS)
        if address in TRACK:
            state = self.snapshot()
            self.original_frames[actor].append(dict(entry=address, before=state,
                return_PC=state['GP16'][14] & ~1, allocator_scope=self.native_allocator_execution,
                full_ABI_return=False))
        if self.native_allocator_execution or actor == self.source_tcb or address in TRACK:
            self.native_instructions.append(dict(PC=address, size=size,
                opcode_hex=bytes(uc.mem_read(address, size)).hex(), actor=actor,
                CPSR=uc.reg_read(UC_ARM_REG_CPSR), ordinal=self.ordinal))
        if self.source_tcb and actor == self.source_tcb:
            stack = uc.reg_read(UC_ARM_REG_SP)
            self.worker_stack_low = stack if self.worker_stack_low is None else min(self.worker_stack_low, stack)
        super().code(uc, address, size, data)

    def original_heap(self):
        require(self.controller and self.word(B.READY_TASKS) == self.controller, 'new allocator caller must be native controller')
        old_tasks = self.word(B.ALL_TASKS)
        registry = self.word(0xf071d0)
        before = self.snapshot()
        self.native_allocator_execution = True
        try:
            value = self.invoke_kernel(0x388b6d, (INPUT, 1, INPUT + 16, 1), phase='NEW original heap constructor in native warm-controller context')
        finally:
            self.native_allocator_execution = False
        require(self.word(WORK + 0x18) == PRIVATE, 'new original private allocator publication')
        require(self.word(B.ALL_TASKS) == old_tasks and self.word(0xf071d0) == registry, 'allocator replaced existing scheduler or registry')
        self.heap_scope_records.append(dict(before=before, after=self.snapshot(), result=value,
            original_exit_list_not_reinitialized=True, native_scheduler_preserved=True))

    def boot(self):
        require(self.invoke_kernel('mh_bind_ready_controller', (self.controller,), phase='bind native ready-event recipient') == 0, 'bind ready controller failed')
        before = self.snapshot()
        self.native_allocator_execution = True
        try:
            self.source_tcb = self.invoke_kernel('mh_boot_source', phase='NEW true OS20 named Source creation')
        finally:
            self.native_allocator_execution = False
        require(self.source_tcb and not self.word(self.build['symbols']['mh_initialized']['value']), 'low-priority Source ran before native controller waited')
        adapter = self.word(self.build['symbols']['mh_os20_adapter']['value'])
        require(adapter == POOL and self.word(adapter + 48) == self.source_tcb, 'creator adapter/TCB publication mismatch')
        require(self.word(adapter + 4) == 16384 + 152, 'OS20 workspace size differs')
        ready = self.invoke_kernel(B.WAIT | 1, phase='native controller WAIT for OS20 Source initialized notification')
        require(ready == 0x400 and self.word(B.READY_TASKS) == self.controller, 'native ready event did not restore controller')
        state = self.status()
        require(state[30] == state[35] == self.source_tcb and state[31] == state[32] == 1 and state[33] == 0, 'OS20 Source did not initialize existing channel')
        require(not self.codec_entries and not self.mixer_tcb, 'Source fabricated media before external packet')
        self.stage1_prefix = dict(state=state, producer=self.producer(), registers=self.snapshot(), no_input_no_anchor_no_mixer=True)
        self.warm_prefix = dict(preexisting_audio=self.preexisting_audio, state=state, true_OS20_created=True,
            no_global_reset_or_profile_replacement=True, durable_channel_ownership=False)
        self.os20_boot_record = dict(before=before, after=self.snapshot(), adapter=adapter,
            source_TCB=self.source_tcb, ready_event=ready, actual_native_WAIT_return=True)
        self.park()

    def command(self, number):
        require(self.invoke_kernel('mh_request_command', (number,), phase='controller queues Source command ' + str(number)) == 0, 'command admission failed')
        self.park()
        state = self.status()
        require(state[45] == number and state[46] == 0, 'queued Source command did not complete')
        return state

    def complete_first_sync_and_attach_output(self):
        # Low-priority Source is queued after ingress returns. Let original
        # controller WAIT run Source/mixer and their full ACK, before attaching
        # the same explicit output fixture used by the frozen warm pipeline.
        self.park()
        state, producer = self.status(), self.producer()
        require(producer['started'] == 1 and not producer['stream_error'], 'OS20 Source first packet did not start')
        require(len(self.sync_returns) == len(self.ack_entries) == 1 and self.pending_sync is None, 'native Source/mixer ACK did not fully return')
        require(state[36] == self.mixer_tcb and state[42] == state[43] == state[52] and state[42] >= 1, 'native mixer selector binding incomplete')
        self.fixture(B.DESCRIPTOR - 32, b'\xa5' * (36 + 64), 'output descriptor guards')
        self.fixture(B.BUFFER - 32, b'\xa5' * (B.RING_BYTES + 64), 'explicit hardware ring guards')
        initial = B.BUFFER + B.RING_BYTES - 64
        self.fixture(B.DESCRIPTOR, struct.pack('<9I', 0, B.BUFFER, B.RING_BYTES, initial, initial, 0, 0, 0, 0), 'empty hardware output ring fixture')
        for address, value in [(B.MIXER, B.DESCRIPTOR), (B.MIXER + 4, B.CAPACITY), (B.MIXER + 0xb4, B.SCRATCH)]:
            self.fixture(address, struct.pack('<I', value), 'hardware buffer/capacity fixture')
        for address, value in [(B.MIXER + 0x7f, 0), (B.MIXER + 0x7e, 0), (B.MIXER + 0x84, 1)]:
            self.fixture(address, bytes([value]), 'explicit raw output/hardware activation fixture, no driver')
        self.fixture(B.SCRATCH - 32, b'\xa5' * (B.CAPACITY + 64), 'output scratch guards')


def main():
    require(unicorn.__version__ == '2.1.4', 'use isolated Unicorn2.1.4 runtime')
    require(not OUT.exists(), 'preserve attempted new scope; use successor namespace for fixes')
    OUT.mkdir()
    build = json.loads(BUILD.read_text())
    reference = json.loads(I.REFERENCE.read_text())
    dependencies = dict(build['source_sha256'], **reference['source_sha256'])
    for path in [Path(__file__), BUILD, ROOT / build['ELF'], ROOT / build['combined_binary'], I.REFERENCE]:
        dependencies[rel(path)] = sha(path)
    L.collect_modules(L, dependencies, set())
    require(all(sha(ROOT / p) == h for p, h in dependencies.items()), 'changed integration inputs')
    save(OUT / 'inputs-at-run.json', dependencies)
    (OUT / 'scoped-service-observer.py').write_text(scoped_observer_source + '\n')
    save(OUT / 'observer-derivation.json', dict(original_source=rel(Path(inspect.getfile(original_observer))),
        original_observer_sha256=hashlib.sha256(observer_source.encode()).hexdigest(),
        scoped_observer_sha256=hashlib.sha256(scoped_observer_source.encode()).hexdigest(),
        guarded_existing_predicates=changed_predicates, original_instruction_patches_added=0))
    elf = load(ROOT / 'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py', 'os20_audio_elf').ELF32(ROOT / build['ELF'])
    model = None
    try:
        model = AudioSource(L.R.R.NativeImage(), elf, build, reference)
        model.load_native()
        model.install_tail_gate(); model.install_route_gates(); model.install_provider_gates(); model.install_alias_gates(); model.install_writer_gates()
        model.boot_kernel_only(); model.original_heap(); model.reset_unclaimed(); model.construct_preexisting_audio(); model.boot_both()
        model.ready(); model.signal(7, b'\x04')
        model.media(model.packet(0)); model.complete_first_sync_and_attach_output()
        first = model.cycle(True); model.compare(first, model.expected(0))
        model.media(model.packet(1)); second = model.cycle(); model.compare(second, model.expected(1))
        adapter = model.word(build['symbols']['mh_os20_adapter']['value'])
        workspace, length = model.word(adapter), model.word(adapter + 4)
        require(model.worker_stack_low is not None and workspace <= model.worker_stack_low < workspace + length, 'OS20 source stack escaped allocated workspace')
        require(model.word(adapter + 48) == model.source_tcb and model.word(build['symbols']['mh_source_entries']['value']) == 1, 'OS20 worker identity changed during media')
        require(len(model.codec_returns) == len(model.codec_entries) and len(model.codec_returns) >= 2, 'decoder full returns missing')
        require(model.pending_ingress is model.pending_codec is model.pending_sync is None, 'native pipeline frame still pending')
        for start, length in [(PRIVATE, 32768), (PUBLIC, 65536)]:
            require(bytes(model.uc.mem_read(start - 4096, 4096)) == b'\xa5' * 4096, 'heap leading guard')
            require(bytes(model.uc.mem_read(start + length, 4096)) == b'\xa5' * 4096, 'heap trailing guard')
        payload = dict(all_passed=True, name='true_OS20_Source_two_foreign_packets_native_mixer', source_sha256=dependencies,
            CPU_store_journal=model.journal, declared_fixture_mutations=model.fixtures,
            initial_ordinal=model.initial_ordinal, stock_loader=model.loader_proof,
            loader_whole_before=model.loader_initial, loader_whole_after=model.loader_final,
            loader_initial_ordinal=model.loader_initial_ordinal, loader_final_ordinal=model.loader_final_ordinal,
            whole_RW_before=model.initial, whole_RW_after={str(a): bytes(model.uc.mem_read(a, n)).hex() for a, n, p in model.zones if p & unicorn.UC_PROT_WRITE},
            regions=model.zones, RX_before=model.RX_before,
            RX_after={str(a): hashlib.sha256(bytes(model.uc.mem_read(a, n))).hexdigest() for a, n, p in model.zones if p & unicorn.UC_PROT_EXEC},
            guest_patches=model.patches, native_instruction_observations=model.native_instructions,
            original_helper_returns=model.original_returns, original_open_frames=dict(model.original_frames),
            heap_constructor=model.heap_scope_records, OS20_boot=model.os20_boot_record,
            decoder_entries=model.codec_entries, decoder_full_returns=model.codec_returns,
            ingress_entries=model.ingress_entries, ingress_full_returns=model.ingress_returns,
            native_audio_full_returns=model.full_returns, native_sync_returns=model.sync_returns,
            native_ACKs=model.ack_entries, actual_Source_event_POSTs=model.source_event_posts,
            explicit_opaque_services=model.fixture_services, original_kernel_events=model.kernel_events,
            workspace=workspace, workspace_bytes=length, source_stack_low=model.worker_stack_low,
            output_PCM_hex=[first.hex(), second.hex()], expected_music_PCM_hex=[model.expected(0).hex(), model.expected(1).hex()],
            final_source=model.status(), final_producer=model.producer(), final_registers=model.snapshot(),
            startup_ready_fixture=True, full_hardware_DAC_App_direct_phone=False, device_IO=False)
        path = OUT / 'native-pipeline-proof.json.gz'
        zipped(path, payload)
        proof = dict(all_passed=True, recorded_utc=datetime.now(timezone.utc).isoformat(), source_sha256=dependencies,
            proof=rel(path), proof_sha256=sha(path), CPU_stores=len(model.journal), native_instructions=len(model.native_instructions),
            original_full_returns=len(model.original_returns), SBC_full_returns=len(model.codec_returns),
            native_audio_full_returns=len(model.full_returns), original_OS20_adapter=adapter,
            source_TCB=model.source_tcb, workspace_bytes=length, stack_low=model.worker_stack_low,
            music_PCM_bytes=len(model.expected(0)) + len(model.expected(1)),
            original_named_create_and_Source_decoder_native_mixer_combined=True,
            native_STOP_DONE_GUI_direct_phone_hardware_proven=False, device_IO=False)
        save(OUT / 'guest-proof.json', proof)
        print(json.dumps(proof), flush=True)
    except BaseException as error:
        failure = dict(all_passed=False, error=str(error), traceback=traceback.format_exc(), source_sha256=dependencies, device_IO=False)
        if model:
            failure.update(phase=model.phase, registers=model.snapshot(), trace=model.trace,
                CPU_store_journal=model.journal, declared_fixture_mutations=model.fixtures,
                original_returns=model.original_returns, original_open_frames=dict(model.original_frames),
                native_instructions=model.native_instructions, native_allocator_execution=model.native_allocator_execution,
                heap_constructor=model.heap_scope_records, OS20_boot=model.os20_boot_record)
        zipped(OUT / 'terminal-failure.json.gz', failure)
        raise


if __name__ == '__main__':
    main()
