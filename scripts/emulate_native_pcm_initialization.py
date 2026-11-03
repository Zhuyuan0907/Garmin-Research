#!/usr/bin/env python3
"""Original cold-producer initialization and shared TTS-ring hazards, offline.

This is not a device cold boot or an ownership protocol. Original channel /
source init and PCM/voice-setting/volume arithmetic execute. Handle services,
mutexes, start/busy policy, an unnamed environmental getter and synthetic
voice-module callbacks remain explicit controls. VFP access is supplied to
the emulated CPU, not inferred from live hardware. No device I/O occurs.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import struct

from unicorn import UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_READ_UNMAPPED, UcError
from unicorn.arm_const import (UC_ARM_REG_CP_REG, UC_ARM_REG_FPEXC, UC_ARM_REG_FPSCR,
                               UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace
from emulate_native_audio_messages import MixerMessages
from emulate_native_audio_registration import require, sha
from emulate_native_sbc import PAGE_BYTES, INPUT_PAGE, OUTPUT_PAGE
from emulate_native_sbc_pcm import CONTEXT, RING, HOST_OUTPUT

COLD_INIT = 0x33f342
PRIORITY = 0x0344cf30
VOLUME_CALLBACK = 0x09900010
RESET_CALLBACK = 0x09900020
QUEUE_RESET_CALLBACK = 0x09900030
QUEUE_CONSUME_CALLBACK = 0x09900040
ENV_QUERY = 0x3d2e8c


def f32(value): return struct.unpack('<f', struct.pack('<f', value))[0]


class ColdPcm(MixerMessages):
    def __init__(self, stock, companion, selector=0):
        self.volume_requests = []
        self.reset_requests = []
        self.test_queue_resets = 0
        self.test_queue_consumes = 0
        self.backed_pages = []
        self.cold_state_observations = []
        super().__init__(stock, 5 if selector else 8, selector, companion)
        # These BSS pages are zeroed by the exact startup section, not filled
        # with MAIN bytes at the same numerical address (which are resources).
        require(any(z['runtime_start'] <= 0x344b000 and 0x344d000 <= z['runtime_end']
                    for z in stock.zeros), 'Audio control BSS lacks original zero range')
        self.uc.mem_map(0x344b000, 0x2000)
        # Execute real priority/selector/sequence getters for normal cases.
        for address in (0x25541c, 0x2554ca, 0x2554d6):
            del self.policy[address]
            self.uc.mem_write(address, stock.read(address, 4))
        self.uc.mem_write(PRIORITY+2, bytes([selector]))
        # Original volume helpers contain ARM VFP instructions. Explicitly
        # enable the virtual CP10/11 and FPEXC rather than replace the math.
        self.uc.reg_write(UC_ARM_REG_CP_REG, (15, 0, 0, 1, 0, 0, 2, 0xf << 20))
        self.uc.reg_write(UC_ARM_REG_FPEXC, 1 << 30)
        self.uc.reg_write(UC_ARM_REG_FPSCR, 0)
        self.uc.mem_map(ENV_QUERY & ~4095, PAGE_BYTES)
        self.uc.mem_write(ENV_QUERY & ~4095, stock.read(ENV_QUERY & ~4095, PAGE_BYTES))
        # Its full conditional-runtime dependency is not initialized here.
        # This explicitly controlled getter does not claim sensor semantics.
        self.policy[ENV_QUERY] = ('unnamed_environment_query', 0)
        self.uc.mem_write(ENV_QUERY, bytes.fromhex('1eff2fe1'))
        self.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_READ_UNMAPPED,
                         self.map_backed_page)
        self.symbols.update({'stock_prepare': {'address': 0x33f931},
                             'stock_discard': {'address': 0x33f315},
                             'channel_state_set': {'address': 0x3b967d},
                             'channel_state_get': {'address': 0x3b9677},
                             'handle_allocate': {'address': 0x38853d}})
        for name in ('media_queue_init', 'media_queue_begin', 'media_queue_callback',
                     'media_queue_step'):
            self.symbols[name] = companion['symbols'][name]
        for address in (VOLUME_CALLBACK, RESET_CALLBACK, QUEUE_RESET_CALLBACK,
                        QUEUE_CONSUME_CALLBACK):
            self.uc.mem_write(address, bytes.fromhex('1eff2fe1'))
        startup = stock.read(stock.runtime_to_load(CONTEXT, 32), 32)
        require(bytes(self.uc.mem_read(CONTEXT, 32)) == startup and startup[7] == 0,
                'Test supplied initialized producer state rather than exact startup data')

    def map_backed_page(self, uc, access, address, size, value, data):
        page = address & ~4095
        try:
            load = self.stock.runtime_to_load(page, PAGE_BYTES)
        except ValueError:
            return False
        # Only actual initialized code/data copies are mapped. Do not treat
        # raw MAIN resources as runtime BSS or repair a guarded buffer access.
        uc.mem_map(page, PAGE_BYTES)
        uc.mem_write(page, self.stock.read(load, PAGE_BYTES))
        self.backed_pages.append({'runtime_page': hex(page), 'load_page': hex(load)})
        return True

    def observe(self, uc, address, size, data):
        if address == COLD_INIT:
            self.cold_state_observations.append({'producer_initialized_on_entry': self.byte(CONTEXT+7),
                                                  'entry_offsets': list(self.offsets())})
        super().observe(uc, address, size, data)
        if address == VOLUME_CALLBACK:
            pointer = uc.reg_read(UC_ARM_REG_R2)
            command = self.word(pointer)
            level = struct.unpack('<h', uc.mem_read(pointer+4, 2))[0]
            require(command == 2 and uc.reg_read(UC_ARM_REG_R3) == 1,
                    'Original volume export callback command contract changed')
            self.volume_requests.append({'command': command, 'level': level,
                                         'module_argument_r0': uc.reg_read(UC_ARM_REG_R0),
                                         'module_argument_r1': uc.reg_read(UC_ARM_REG_R1)})
            uc.reg_write(UC_ARM_REG_R0, 0)
        elif address == RESET_CALLBACK:
            self.reset_requests.append({'module_argument_r0': uc.reg_read(UC_ARM_REG_R0),
                                         'module_argument_r1': uc.reg_read(UC_ARM_REG_R1)})
            uc.reg_write(UC_ARM_REG_R0, 0)
        elif address == QUEUE_RESET_CALLBACK:
            self.test_queue_resets += 1
            uc.reg_write(UC_ARM_REG_R0, 0)
        elif address == QUEUE_CONSUME_CALLBACK:
            self.test_queue_consumes += 1
            uc.reg_write(UC_ARM_REG_R0, 0)

    def byte(self, address): return self.uc.mem_read(address, 1)[0]

    def host_pcm(self, pcm, ignored_arguments=(0, 0)):
        require(0 < len(pcm) <= PAGE_BYTES-32, 'PCM test input exceeds guarded page')
        source = INPUT_PAGE+PAGE_BYTES-len(pcm)
        self.uc.mem_write(INPUT_PAGE, b'\xa5'*PAGE_BYTES)
        self.uc.mem_write(source, pcm)
        try:
            returned, status = self.invoke('host', (*ignored_arguments, source, len(pcm)))
        except UcError as error:
            raise RuntimeError(f'Cold host: {error}, PC={self.uc.reg_read(UC_ARM_REG_PC):#x}, '
                               f'pages={self.backed_pages}, controls={self.control_events[-3:]}') from error
        require(returned and status == 0, 'Original host PCM call did not return success')
        require(bytes(self.uc.mem_read(source, len(pcm))) == pcm and
                bytes(self.uc.mem_read(source-32, 32)) == b'\xa5'*32,
                'Original cold writer changed guarded input')
        self.verify_ring_guards()
        return status

    def voice_fixture(self, voice_level=60, channel_level=60):
        # A one-node synthetic voice registry, using original handle lookup,
        # string match and setting getters. No VPM was mounted/accepted.
        self.call('handle_allocate', (0x778, 2, OUTPUT_PAGE))
        handle = self.word(OUTPUT_PAGE)
        pointer = self.handles[handle]['pointer']
        self.uc.mem_write(pointer, bytes(0x778))
        label = b'A\x00'+bytes(38)
        self.uc.mem_write(0xf09638, label)
        self.uc.mem_write(pointer+0x3fc, label)
        self.put(pointer+0x758, voice_level)
        self.put(0xf09668, handle)
        self.put(self.record+0xb0, channel_level)
        # Supply module-ready/voice-interface state and two fake export
        # callbacks. Original wrappers dispatch/capture volume/reset requests.
        self.uc.mem_write(0xf0958c, b'\x01')
        self.uc.mem_write(0xf095c8, b'\x01')
        self.put(0xf09594, 0xaa01)
        self.put(0xf09598, 0xaa02)
        self.put(0xf09548, VOLUME_CALLBACK)
        self.put(0xf09554, RESET_CALLBACK)

    def queue_packet(self):
        packet = b'\x80\x60'+bytes(10)+b'\x01'
        self.uc.mem_write(INPUT_PAGE, packet)
        # Queue callback has a fifth stack argument. external() only handles
        # four; use the ordinary single-call harness stack for this call.
        require(self.call('media_queue_callback', (0xf1, 0, 0, INPUT_PAGE), (len(packet),)) == 0,
                'Controlled queue packet was rejected')

    def verify(self):
        self.verify_controls()
        require(not self.worker_entries, 'Cold-producer test inadvertently started a mixer actor')


def startup_route(stock, companion, selector):
    m = ColdPcm(stock, companion, selector)
    initial = bytes(m.uc.mem_read(CONTEXT, 32))
    pcm = struct.pack('<128h', *range(-64, 64))
    for _ in range(39): m.host_pcm(pcm)
    require(m.visits[COLD_INIT] == 1 and m.queued() == 9984 and not m.requests and
            m.byte(CONTEXT+7) == 1 and m.byte(CONTEXT+4) == 0,
            'Actual cold producer did not initialize once or started early')
    require(m.cold_state_observations == [{'producer_initialized_on_entry': 1,
                                         'entry_offsets': [0, 0]}],
            'Original host did not set initialized byte before the initializer')
    m.host_pcm(pcm)
    require(len(m.requests) == 1 and m.queued() == 10240 and m.byte(CONTEXT+4) == 1,
            'Cold producer threshold registration/start path differs')
    require(m.requests[0]['register_args'] == [m.channel, 17, 6, CONTEXT+4],
            'Cold start selected an unexpected source kind/channel')
    require(m.call('queue_start', (m.record+0x1a8,)) == 0, 'Queue primitive failed')
    m.select_source()
    actual = m.read(3840)+m.read(3840)+m.read(2560)
    require(actual == pcm*40, 'Cold initialized source PCM differs from reference')
    require({COLD_INIT, 0x36b61c, 0x36b65e, 0x273f60, 0x27453a,
             0x25541c, 0x2554ca, 0x2554d6, 0x376454, 0x346de4,
             0x3404dc, 0x37857c, 0x6fc448, 0x378590, 0x21c2da}.issubset(m.registration_visits),
            'Original cold/volume/real policy getter path was skipped')
    m.verify()
    return {'name': 'cold_start_selector_'+str(selector), 'channel': m.channel,
            'initial_context_hex': initial.hex(), 'producer_state_not_preinitialized': True,
            'original_host_sets_initialized_before_init': True,
            'cold_initializer_calls': 1, 'first_start_queued_bytes': 10240,
            'pcm_bytes': len(actual), 'pcm_sha256': sha(actual), 'reference_byte_identical': True,
            'registration_factory_reader_original': True,
            'real_priority_selector_and_sequence_getters_executed': True,
            'voice_registry_empty_and_interface_inactive': True,
            'hardware_start_still_hooked': True, 'loaded_original_pages': m.backed_pages,
            'passed': True}


def volume_case(stock, companion, channel_level):
    m = ColdPcm(stock, companion)
    voice_level = 60
    m.voice_fixture(voice_level, channel_level)
    m.host_pcm(b'\x12\x34'*128)
    # Independently reproduce the discrete attenuation with float32 rounding.
    factor = (105-channel_level)//10
    wanted = int(f32(f32(voice_level)-f32(f32(factor)*f32(f32(voice_level)/f32(10)))))
    if wanted < 0 or channel_level == 0: wanted = 0
    elif wanted > 100: wanted = voice_level
    require(len(m.volume_requests) == 1 and m.volume_requests[0]['level'] == wanted,
            'Original VFP volume arithmetic differs from independent attenuation')
    require({0x273af6, 0x273e18, 0x273e52, 0x273a84, 0x27453a,
             0x21c260, 0x254a88, VOLUME_CALLBACK}.issubset(m.registration_visits),
            'Original synthetic voice-registry lookup/export wrapper was skipped')
    m.verify()
    return {'name': 'voice_volume_channel_'+str(channel_level), 'voice_level': voice_level,
            'channel_level': channel_level, 'captured_volume': wanted,
            'voice_registry_lookup_and_vfp_helpers_original': True,
            'voice_registry_and_module_export_callback_synthetic': True,
            'passed': True}


def shared_ring_case(stock, companion):
    m = ColdPcm(stock, companion)
    a, b = struct.pack('<64h', *range(64)), struct.pack('<64h', *range(-64, 0))
    # Different r0/r1 do not identify an output stream in this host API.
    m.host_pcm(a, (0x1111, 0x2222))
    m.host_pcm(b, (0x3333, 0x4444))
    require(m.queued() == 256 and m.call('stock_prepare') == 0, 'Shared source prepare failed')
    require(m.read(256) == a+b, 'Host caller arguments unexpectedly separated PCM streams')
    m.host_pcm(a, (0x1111, 0x2222)); m.host_pcm(b, (0x3333, 0x4444))
    queued = m.queued()
    m.call('stock_discard')
    require(queued == 256 and m.queued() == 0,
            'Original discard unexpectedly retained caller-specific audio')
    m.verify()
    return {'name': 'shared_ring_two_caller_arguments_and_discard',
            'different_host_r0_r1_still_append_same_global_pcm': True,
            'combined_pcm_bytes': 256, 'reference_byte_identical': True,
            'discard_drops_all_pending_pcm_bytes': queued,
            'caller_label_is_test_argument_not_actual_navigation_task': True,
            'real_navigation_concurrency_tested': False, 'passed': True}


def lower_channel_case(stock, companion, busy):
    m = ColdPcm(stock, companion)
    m.call('channel_state_set', (2, 3))
    require(m.call('channel_state_get', (2,)) == 3, 'State fixture setter failed')
    m.policy[0x36b69a] = ('channel_busy', busy)
    m.host_pcm(b'\x12\x34'*128)
    budget = m.word(CONTEXT+0x18)
    require(m.byte(CONTEXT+9) == 1 and budget == (0 if busy else 800),
            'Original lower-channel hold logic differs')
    require({0x2fd38e, 0x2780ac}.issubset(m.registration_visits),
            'Original hold-budget calculation was bypassed')
    m.verify()
    return {'name': 'lower_channel_state3_busy_'+str(busy),
            'lower_channel_state_set_with_original_setter': True,
            'channel_busy_return_hooked': busy, 'hold_flag': 1, 'hold_budget': budget,
            'budget_units_and_real_timing_verified': False, 'passed': True}


def priority_reset_case(stock, companion):
    m = ColdPcm(stock, companion)
    m.voice_fixture()
    m.uc.mem_write(CONTEXT+4, b'\x01')
    m.put(CONTEXT+12, 256)  # Explicit preexisting mixed-PCM fixture.
    m.uc.mem_write(RING, b'\x5a'*256)
    # Only this case supplies a priority decision rather than executes the
    # queue arbitration. Stop/module-reset wrappers still run original code.
    m.policy[0x25541c] = ('controlled_priority_preemption', 1)
    m.uc.mem_write(0x25541c, b'\x70\x47')
    status = m.host_pcm(b'\x12\x34'*128)
    require(status == 0 and m.offsets() == (0, 0) and m.queued() == 0 and
            len(m.reset_requests) == 2 and m.word(CONTEXT+0x18) == 500,
            'Controlled original priority reset did not discard shared PCM')
    require({0x36af74, 0x30edd4, 0x21c3c8}.issubset(m.registration_visits),
            'Original stop/reset request wrappers were skipped')
    m.verify()
    return {'name': 'controlled_priority_reset_during_cold_host_and_commit',
            'priority_predicate_hooked_only_in_this_case': True,
            'original_stop_and_module_reset_wrappers_executed': True,
            'module_reset_callback_requests': 2,
            'host_return_despite_no_committed_audio': status,
            'preexisting_pending_pcm_fixture_bytes_discarded': 256,
            'final_offsets': [0, 0], 'hold_budget': 500,
            'real_priority_arbitration_and_hardware_preemption_verified': False,
            'passed': True}


def queue_cold_and_underrun_case(stock, companion):
    m = ColdPcm(stock, companion)
    payload_start = companion['symbols']['__queue_payload_start']['address']
    payload_end = companion['symbols']['__queue_payload_end']['address']
    m.uc.mem_map(payload_start, payload_end-payload_start)
    m.uc.mem_write(payload_start, b'\xa5'*(payload_end-payload_start))
    require(m.external('media_queue_init', (QUEUE_CONSUME_CALLBACK, QUEUE_RESET_CALLBACK)) == 0 and
            m.external('media_queue_begin') == 0, 'Controlled queue startup failed')
    m.queue_packet()
    require(m.external('media_queue_step') == 1 and not m.visits[COLD_INIT] and
            not m.test_queue_consumes, 'Queue unexpectedly initializes a cold PCM producer')
    # Explicit host bootstrap is only a test intervention, not an implemented
    # startup policy. Existing queue output-ready gate requires context+7.
    sample = b'\x12\x34'*128
    for _ in range(4):
        m.host_pcm(sample)
        require(m.call('stock_prepare') == 0 and m.read(256) == sample,
                'Original underrun fixture changed submitted PCM')
    require(m.byte(CONTEXT+7) == 0 and m.visits[0x33f520] == 1,
            'Original four empty drains did not clear producer initialization')
    require(m.external('media_queue_step') == 1 and not m.test_queue_consumes and
            m.word(companion['symbols']['media_queue_control']['address']+8) == 1,
            'Queue did not retain deferred packet after stock producer shutdown')
    m.host_pcm(sample)  # Explicit test bootstrap, again.
    require(m.visits[COLD_INIT] == 2 and m.byte(CONTEXT+7) == 1 and
            m.external('media_queue_step') == 0 and m.test_queue_consumes == 1,
            'Explicit original host bootstrap did not clear queue gate')
    require(bytes(m.uc.mem_read(payload_start+13, payload_end-payload_start-13)) ==
            b'\xa5'*(payload_end-payload_start-13), 'Queue crossed its copied packet bounds')
    m.verify()
    return {'name': 'queue_cold_gate_and_four_empty_drains',
            'initial_cold_queue_step_status': 1,
            'original_cold_initializer_not_called_by_queue': True,
            'four_stock_empty_drains_clear_initialized_byte': True,
            'pending_packet_retained_and_step_deferred_after_underrun': True,
            'test_explicit_host_bootstrap_needed_to_clear_gate': True,
            'decode_and_reset_callbacks_synthetic': True,
            'actual_decoder_worker_or_production_restart_protocol_tested': False,
            'passed': True}


def source_inventory(stock, companion):
    """Inventory original factory contracts; do not infer new playback APIs."""
    m = ColdPcm(stock, companion)
    methods = 0x09900100
    m.symbols['stock_factory'] = {'address': 0x437765}
    table = stock.read(0x437780, 23)
    rows = []
    for kind in range(23):
        m.uc.mem_write(methods-32, b'\xa5'*(32+68+32))
        status = m.call('stock_factory', (methods, kind))
        pointers = struct.unpack('<17I', m.uc.mem_read(methods, 68))
        require(bytes(m.uc.mem_read(methods-32, 32)) == b'\xa5'*32 and
                bytes(m.uc.mem_read(methods+68, 32)) == b'\xa5'*32,
                'Original provider factory crossed descriptor guards')
        rows.append({'kind': kind, 'factory_return': status,
                     'computed_switch_target': hex(0x437780+table[kind]*2),
                     'method_words': [hex(p) for p in pointers],
                     'reader': hex(pointers[5]), 'format': hex(pointers[6]),
                     'prepare': hex(pointers[4])})
    silence_kinds = [r['kind'] for r in rows if r['reader'] == '0x48f091']
    require(silence_kinds == [1, 2, 5, 18, 19], 'Placeholder-source group changed')
    require(all(rows[k]['method_words'] == rows[1]['method_words'] for k in silence_kinds),
            'Placeholder-source methods unexpectedly differ')
    m.symbols['silence_read'] = {'address': 0x48f091}
    m.uc.mem_write(OUTPUT_PAGE, b'\xa5'*PAGE_BYTES)
    destination = OUTPUT_PAGE+PAGE_BYTES-256
    count = m.call('silence_read', (0xdeadbeef, destination, 256))
    require(count == 256 and bytes(m.uc.mem_read(destination, 256)) == bytes(256) and
            bytes(m.uc.mem_read(destination-32, 32)) == b'\xa5'*32,
            'Original placeholder reader did not produce bounded zero samples')
    m.symbols['silence_format'] = {'address': 0x48f0a5}
    require(m.call('silence_format', (0, OUTPUT_PAGE)) == 0, 'Placeholder format query failed')
    channels, bits, align, rate = struct.unpack('<HHII', m.uc.mem_read(OUTPUT_PAGE, 12))
    m.verify()
    return {'kind_count': len(rows), 'factory_and_memzero_original': True, 'kinds': rows,
            'placeholder_silence_kinds': silence_kinds,
            'placeholder_reader_returned_bytes': count,
            'placeholder_reader_samples_all_zero': True,
            'placeholder_logical_format': {'channels': channels, 'bits': bits,
                                            'block_align': align, 'rate': rate},
            'other_provider_initializers_readers_and_registration_not_tested': True,
            'dedicated_app_pcm_source_found': False, 'passed': True}


def main():
    stock = NativeImage()
    manifest = ROOT/'staging/native-media-consumer/manifest.json'
    companion = json.loads(manifest.read_text())
    for p, h in companion['source_sha256'].items(): require(sha((ROOT/p).read_bytes()) == h, 'Source changed: '+p)
    for key in ('elf', 'flat_binary'):
        require(sha((ROOT/companion[key]).read_bytes()) == companion[key+'_sha256'], 'Companion changed')
    routes = [startup_route(stock, companion, selector) for selector in (0, 1)]
    controls = [volume_case(stock, companion, v) for v in (0, 60, 100)]
    controls += [shared_ring_case(stock, companion)]
    controls += [lower_channel_case(stock, companion, b) for b in (0, 1)]
    controls += [priority_reset_case(stock, companion), queue_cold_and_underrun_case(stock, companion)]
    providers = source_inventory(stock, companion)
    dependencies = ('scripts/analyze_native_sections.py', 'scripts/analyze_sdp_activation.py',
                    'scripts/emulate_native_audio_messages.py', 'scripts/emulate_native_audio_registration.py',
                    'scripts/emulate_native_pcm_flow_control.py', 'scripts/emulate_native_sbc_pcm.py',
                    'scripts/emulate_native_sbc.py', 'staging/native-media-consumer/manifest.json')
    report = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'source_sha256': sha(Path(__file__).read_bytes()),
              'dependency_sha256': {p: sha((ROOT/p).read_bytes()) for p in dependencies},
              'consumer_companion_elf_sha256': companion['elf_sha256'],
              'routes': routes, 'control_cases': controls, 'source_factory_inventory': providers,
              'all_passed': True,
              'cold_initializer': hex(COLD_INIT), 'host_pcm_callback': hex(HOST_OUTPUT),
              'normal_cold_producer_path_executed_offline': True,
              'producer_initialized_set_by_original_host_not_test': True,
              'original_voice_registry_getters_and_vfp_arithmetic_executed': True,
              'host_caller_arguments_do_not_partition_output_ring': True,
              'queue_recovery_after_cold_or_underrun_implemented': False,
              'live_cold_boot_or_producer_initialization_verified': False,
              'output_ownership_or_real_navigation_coexistence_verified': False,
              'vfp_coprocessor_access_explicitly_supplied_to_emulator': True,
              'environment_getter_control': {'address': hex(ENV_QUERY), 'return_value': 0,
                                             'semantic_identity_verified': False},
              'voice_package_mounted_or_accepted': False,
              'native_on_device_verified': False, 'device_io': False, 'device_install_candidate': False,
              'cold_initializer_trace': trace(stock, COLD_INIT, 180),
              'volume_dispatch_trace': trace(stock, 0x21c2da, 60),
              'hold_budget_trace': trace(stock, 0x2fd38e, 60),
              'limitations': 'Offline cold-producer path, not device cold boot. Original host sets context+7 then calls initialization; original channel mapping/global source queues/profiles run with pre-hardware bound. Real priority/selector/sequence getters execute normally with synthetic arbitration RAM. Existing heap/mutex/start/busy/message controls remain, unnamed environment query0x3d2e8c returns0, virtual VFP access is supplied. Empty registry baseline and synthetic one-node voice registry are separate cases; original lookup/volume math/wrappers run, but fake module volume/reset exports only capture requests and do not prove real TTS behavior or physical audio. Controlled priority-reset case alone supplies the priority predicate result; its real queue arbitration/hardware are untested. Caller markers are test arguments, not actual concurrent navigation tasks. Shared ring concatenation/global discard and queue cold/underrun gate are demonstrated, not repaired: queue consume/reset are stubs and test explicitly calls host to bootstrap/recover. All23factory kinds inventoried with original instructions; kinds1/2/5/18/19 have one zero-filling reader. Other providers have not been initialized/read/registered here, and no independent App PCM source is established. No worker scheduling/deployment, production ownership/quiescence/rehook/cold-start protocol, true SEP/UI/phone stream, modified package acceptance, speaker or Google Maps is verified.'}
    path = ROOT/'evidence/firmware-analysis/native-pcm-initialization-emulation.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'cold_routes': len(routes), 'control_cases': len(controls),
                      'pcm_bytes_each': 10240, 'factory_kinds': len(providers['kinds']),
                      'all_passed': True, 'device_io': False}), flush=True)


if __name__ == '__main__': main()
