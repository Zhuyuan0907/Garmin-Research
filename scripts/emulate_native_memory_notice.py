#!/usr/bin/env python3
"""Compiled raw-notice journal plus original notification/main dispatch, offline.

The optional main-context query alone is supplied as 0 or 1. This is not a
registered App listener or an installed report-task hook. Original memory
source actor/handle/hardware fixtures keep their independently stated scope.
"""
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import struct

from unicorn import UC_PROT_READ, UC_PROT_EXEC, UcError, UC_ERR_READ_UNMAPPED
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP,
                               UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace
from emulate_native_memory_completion import (CompletionAudio, NOTICE_DISPATCH,
                                              MAIN_DISPATCH)
from emulate_native_audio_registration import require, sha
from emulate_native_sbc import INPUT_PAGE, OUTPUT_PAGE, PAGE_BYTES, RETURN

QUERY = 0x27811e
MAIN_DEFAULT = 0x330ede
DISPATCH_STACK = 0x0990c000
FIELDS = ('channel', 'event_mask', 'epoch', 'armed', 'in_flight', 'read', 'write',
          'count', 'calls', 'captured', 'filtered', 'full', 'canceled',
          'last_original_result', 'initialized')
EARLY = (0x1017f2, 0x52982e, 0x2ddd4c, 0x1683bc, 0x1683e4)


class RawNotice(CompletionAudio):
    def __init__(self, stock, companion, observer, query=0):
        self.notice_visits = Counter()
        self.forwarded = []
        super().__init__(stock, companion)
        # Undo the inherited capture stub. Every original early subsystem and
        # the main dispatch instructions execute; the optional context query
        # is controlled because its real filesystem context is not provided.
        del self.control_hooks[MAIN_DISPATCH]
        self.uc.mem_write(MAIN_DISPATCH, stock.read(MAIN_DISPATCH, 4))
        self.uc.mem_map(QUERY & ~4095, PAGE_BYTES)
        self.uc.mem_write(QUERY & ~4095, stock.read(QUERY & ~4095, PAGE_BYTES))
        self.policy[QUERY] = ('controlled_main_context_query', query)
        self.uc.mem_write(QUERY, bytes.fromhex('7047'))
        self.query = query
        self.symbols['original_main_dispatch'] = {'address': MAIN_DISPATCH | 1}
        self.observer = observer
        self.uc.mem_map(observer['load_base'], PAGE_BYTES)
        self.uc.mem_write(observer['load_base'], (ROOT/observer['flat_binary']).read_bytes())
        self.uc.mem_protect(observer['load_base'], PAGE_BYTES, UC_PROT_READ | UC_PROT_EXEC)
        self.state_start = observer['symbols']['__notice_state_start']['address']
        self.state_end = observer['symbols']['__notice_state_end']['address']
        self.uc.mem_map(self.state_start, PAGE_BYTES)
        self.uc.mem_write(self.state_start, b'\xa5'*PAGE_BYTES)
        # Loader-cleared BSS is a stated fixture, not a self-initializing image.
        self.uc.mem_write(self.state_start, bytes(self.state_end-self.state_start))
        for name in ('memory_notice_configure', 'memory_notice_disarm',
                     'memory_notice_dispatch', 'memory_notice_pop'):
            self.symbols[name] = observer['symbols'][name]
        self.control = observer['symbols']['memory_notice_control']['address']

    def observe(self, uc, address, size, data):
        if address == getattr(self, 'stop_address', None):
            uc.emu_stop(); return
        self.notice_visits[address] += 1
        if address == NOTICE_DISPATCH:
            pointer, control = uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)
            header = bytes(uc.mem_read(pointer, 2))
            frame = bytes(uc.mem_read(pointer, 20 if 21 <= header[1] <= 33 else 2))
            self.forwarded.append({'pointer': pointer, 'control': control, 'bytes': frame})
        super().observe(uc, address, size, data)

    def state(self):
        return dict(zip(FIELDS, struct.unpack('<15I', self.uc.mem_read(self.control, 60))))

    def configure(self, mask=0x1fff):
        return self.external('memory_notice_configure', (self.channel, mask))

    def dispatch(self, frame, control=0x12345678):
        require(len(frame) == 20, 'Valid raw notice contract is exactly20 bytes')
        pointer = INPUT_PAGE+PAGE_BYTES-20
        self.uc.mem_write(INPUT_PAGE, b'\xa5'*PAGE_BYTES)
        self.uc.mem_write(pointer, frame)
        before = len(self.forwarded)
        result = self.external('memory_notice_dispatch', (pointer, control))
        require(len(self.forwarded) == before+1 and self.forwarded[-1] ==
                {'pointer': pointer, 'control': control, 'bytes': frame},
                'Compiled observer changed original dispatcher arguments')
        require(bytes(self.uc.mem_read(pointer-32, 32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(pointer, 20)) == frame, 'Observer mutated raw input')
        # Destroy the borrowed report frame immediately: journal must own a copy.
        self.uc.mem_write(pointer, bytes(20))
        return result

    def pop(self, empty=False):
        pointer = OUTPUT_PAGE+PAGE_BYTES-20
        self.uc.mem_write(OUTPUT_PAGE, b'\xa5'*PAGE_BYTES)
        result = self.external('memory_notice_pop', (pointer, 20))
        require(result == (-26 if empty else 0), 'Journal pop returned unexpected status')
        require(bytes(self.uc.mem_read(OUTPUT_PAGE, PAGE_BYTES-20)) == b'\xa5'*(PAGE_BYTES-20),
                'Journal pop crossed output boundary')
        result_bytes = bytes(self.uc.mem_read(pointer, 20))
        if empty: require(result_bytes == b'\xa5'*20, 'Empty pop modified caller output')
        return result_bytes

    def verify(self):
        super().verify()
        require(self.state()['in_flight'] == 0, 'Observer retained an in-flight call')
        require(bytes(self.uc.mem_read(self.state_end, self.state_start+PAGE_BYTES-self.state_end)) ==
                b'\xa5'*(self.state_start+PAGE_BYTES-self.state_end), 'Journal crossed BSS guard')
        require(bytes(self.uc.mem_read(self.observer['load_base'], self.observer['flat_binary_bytes'])) ==
                (ROOT/self.observer['flat_binary']).read_bytes(), 'Observer modified protected code')


def raw(event=22, owner=0xaa01, channel=8, marker=0):
    return struct.pack('<BBH4I', channel, event, 0, owner, marker, 0, 0)


def original_main_routes(stock, companion, observer):
    cases = []
    for query in (0, 1):
        m = RawNotice(stock, companion, observer, query)
        m.uc.mem_write(OUTPUT_PAGE, struct.pack('<5I', 0xaa01, 2, 8, 0, 0))
        result = m.external('original_main_dispatch', (0x246, OUTPUT_PAGE))
        require(result == 0x140 and m.notice_visits[MAIN_DEFAULT] == 1 and
                all(m.notice_visits[p] == 1 for p in EARLY) and m.notice_visits[QUERY] == 1,
                'Original main event246 did not reach the tested default path')
        require(m.notice_visits[0x168454] == query and not m.notice_visits[0x26a300],
                'Optional handler/query scope changed')
        m.verify()
        cases.append({'query_result_fixture': query, 'default_return_instruction': hex(MAIN_DEFAULT),
                      'main_return_incidental_not_app_success': result,
                      'original_early_handlers_executed': [hex(p) for p in EARLY],
                      'optional_original_handler_executed': bool(query),
                      'main_capture_stub_removed': True, 'filesystem_query_executed': False,
                      'native_app_registration_proved': False, 'passed': True})
    return cases


def original_query_fixture_limit(stock, companion, observer):
    m = RawNotice(stock, companion, observer)
    del m.policy[QUERY]
    m.uc.mem_write(QUERY, stock.read(QUERY, 4))
    m.uc.mem_write(OUTPUT_PAGE, struct.pack('<5I', 0xaa01, 2, 8, 0, 0))
    try:
        m.external('original_main_dispatch', (0x246, OUTPUT_PAGE))
    except UcError as error:
        pc = m.uc.reg_read(UC_ARM_REG_PC)
        require(error.errno == UC_ERR_READ_UNMAPPED and pc == 0x26a24c and
                m.notice_visits[0x26a300] == 1,
                'Uninitialized filesystem fixture failed at an unexpected boundary')
        return {'original_query_restored': True, 'original_filesystem_reader_entered': '0x26a300',
                'missing_fixture_first_fault_pc': hex(pc), 'fault': str(error),
                'expected_fixture_boundary_observed': True,
                'full_context_query_or_live_main_routing_verified': False,
                'device_failure_observed': False}
    raise AssertionError('Full context query unexpectedly worked without its filesystem fixture')


def source_lifecycle(stock, companion, observer):
    m = RawNotice(stock, companion, observer)
    tts = m.tts_snapshot()
    require(m.configure() == 0, 'Journal configuration failed')
    payloads = (bytes((j*29+7)&255 for j in range(384)),
                bytes((j*37+11)&255 for j in range(600)))
    items = [m.enqueue(m.pcm_page(j, p), p, 0xaa01+j) for j, p in enumerate(payloads)]
    captured = []
    for j, item in enumerate(items):
        m.select_current(); m.activate_fixture()
        # Deliver previous source reports after new selection, so wrappers
        #22/23 reload the new current-channel identifier. All IDs are markers.
        if j:
            before = len(m.main_requests)
            for packet in pending: require(m.dispatch(packet['bytes']) == 0, 'Stock dispatch failed')
            translated = m.main_requests[before:]
            copied = [m.pop() for _ in pending]
            require(copied == [p['bytes'] for p in pending] and
                    [p['packet_owner'] for p in pending] == [items[0]['owner']]*4 and
                    [p['owner'] for p in translated] == [items[0]['owner']]*2+[item['owner']]*2,
                    'Observer lost old identity or changed original wrapper semantics')
            captured.extend(copied)
        actual = bytearray()
        for _ in range((len(item['payload'])+255)//256): actual.extend(m.actor_pull())
        require(bytes(actual) == item['payload'] and m.actor_pull() == b'', 'Actor PCM/EOF differs')
        pending = m.stop_cleanup()+m.remove_first()
        require([p['event'] for p in pending] == [26, 25, 22, 23], 'Original lifecycle reports differ')
    for packet in pending: require(m.dispatch(packet['bytes']) == 0, 'Final stock dispatch failed')
    copied = [m.pop() for _ in pending]
    require(copied == [p['bytes'] for p in pending], 'Final journal copy differs')
    captured.extend(copied); m.pop(empty=True)
    require(m.state()['calls'] == 8 and m.state()['captured'] == 8 and
            m.notice_visits[MAIN_DEFAULT] == 8 and m.tts_snapshot() == tts,
            'Journal/main lifecycle changed navigation PCM or lost reports')
    require(all(m.handles[i['handle']]['freed'] for i in items) and
            m.half(m.record+0x1c0) == 0, 'Original nodes remained live')
    m.verify()
    return {'name': 'compiled_observer_with_original_memory_source_lifecycle',
            'queued_blocks': 2, 'pcm_bytes': sum(map(len, payloads)),
            'pcm_sha256': sha(b''.join(payloads)), 'reference_byte_identical': True,
            'raw_notices_copied': 8, 'raw_notices_sha256': sha(b''.join(captured)),
            'events_each_source': [26, 25, 22, 23],
            'delayed_raw_old_identifier_preserved_before_original_translation': True,
            'original22_23_current_identifier_translation_preserved': True,
            'input_destroyed_before_pop_and_owned_journal_copy_passed': True,
            'original_main_default_path_executed_each_notice': True,
            'tts_context_entire_ring_unchanged': True,
            'automatic_hook_or_pcm_recycle_implemented': False, 'passed': True}


def bounded_fifo(stock, companion, observer):
    m = RawNotice(stock, companion, observer)
    require(m.configure(6) == 0, 'Journal configuration failed')
    frames = [raw(marker=j) for j in range(8)]
    for frame in frames[:6]: require(m.dispatch(frame) == 0, 'Full journal blocked stock dispatcher')
    require(m.state()['count'] == 4 and m.state()['captured'] == 4 and
            m.state()['full'] == 2 and len(m.forwarded) == 6, 'Journal overflow policy differs')
    require([m.pop(), m.pop()] == frames[:2], 'Journal FIFO order differs')
    for frame in frames[6:]: m.dispatch(frame)
    require([m.pop() for _ in range(4)] == frames[2:4]+frames[6:], 'Wrapped FIFO differs')
    m.pop(empty=True)
    for frame in (raw(event=25), raw(channel=9)):
        require(m.dispatch(frame) == 0, 'Filtered notice was not forwarded')
    require(m.state()['filtered'] == 2 and m.state()['count'] == 0 and
            len(m.main_requests) == 10 and m.notice_visits[MAIN_DEFAULT] == 10,
            'Filtering changed stock main dispatch or inserted excluded report')
    m.verify()
    return {'name': 'four_slot_fifo_wrap_overflow_and_filter', 'journal_capacity': 4,
            'dropped_newest_reports': 2, 'all_valid_reports_forwarded_original': 10,
            'journal_filter_mask6_events22_23': True, 'other_event_channel_filtered': True,
            'empty_output_untouched': True, 'overflow_does_not_establish_pcm_safety': True,
            'passed': True}


def invalid_and_irq(stock, companion, observer):
    m = RawNotice(stock, companion, observer)
    require(m.configure(6) == 0, 'Journal configuration failed')
    state = bytes(m.uc.mem_read(m.control, 60))
    for args in ((18, 6), (8, 0x2000)):
        require(m.external('memory_notice_configure', args) == -20 and
                bytes(m.uc.mem_read(m.control, 60)) == state, 'Invalid configure changed state')
    m.dispatch(raw())
    output = OUTPUT_PAGE+PAGE_BYTES-20
    m.uc.mem_write(OUTPUT_PAGE, b'\xa5'*PAGE_BYTES)
    for args in ((0, 20), (output, 19)):
        require(m.external('memory_notice_pop', args) == -20 and m.state()['count'] == 1 and
                bytes(m.uc.mem_read(OUTPUT_PAGE, PAGE_BYTES)) == b'\xa5'*PAGE_BYTES,
                'Invalid pop wrote output or lost a report')
    require(m.pop() == raw(), 'Invalid output guards changed report')
    # Unknown event has only2 valid bytes at a page edge. Neither compiled
    #filter nor original dispatcher may assume a valid20-byte event payload.
    pointer = INPUT_PAGE+PAGE_BYTES-2
    m.uc.mem_write(pointer, bytes((8, 255)))
    require(m.external('memory_notice_dispatch', (pointer, 0x76543210)) == 65535 and
            m.state()['last_original_result'] == 65535 and m.state()['filtered'] == 1,
            'Unknown-event original return/short-frame guard failed')
    cpsr = m.uc.reg_read(UC_ARM_REG_CPSR)
    masks = []
    for mask in (0, 0x80, 0xc0):
        m.uc.reg_write(UC_ARM_REG_CPSR, (cpsr & ~0xc0) | mask)
        before = m.uc.reg_read(UC_ARM_REG_CPSR) & 0xdf
        require(m.configure(6) == 0, 'Masked configuration failed')
        m.dispatch(raw()); m.pop(); m.external('memory_notice_disarm')
        require(m.uc.reg_read(UC_ARM_REG_CPSR) & 0xdf == before,
                'Original IRQ save/restore changed mode/masks')
        masks.append(mask)
    m.verify()
    return {'name': 'invalid_configuration_output_unknown_event_and_irq_masks',
            'channel18_mask_above13bits_rejected_without_state_changes': True,
            'null_and_short_output_rejected_without_consuming': True,
            'unknown_event_two_byte_guarded_frame_original_return_preserved': 65535,
            'original_irq_save_restore_masks_tested': masks,
            'mode_and_masks_preserved': True, 'actual_hardware_irq_tested': False, 'passed': True}


def in_flight_cancel(stock, companion, observer):
    m = RawNotice(stock, companion, observer)
    require(m.configure(6) == 0, 'Journal configuration failed')
    m.dispatch(raw(marker=1))
    frame = raw(marker=2)
    pointer = INPUT_PAGE+PAGE_BYTES-20
    m.uc.mem_write(pointer, frame)
    m.stop_address = NOTICE_DISPATCH
    m.uc.reg_write(UC_ARM_REG_R0, pointer)
    m.uc.reg_write(UC_ARM_REG_R1, 0x12345678)
    m.uc.reg_write(UC_ARM_REG_SP, DISPATCH_STACK)
    m.uc.reg_write(UC_ARM_REG_LR, RETURN)
    m.uc.emu_start(m.symbols['memory_notice_dispatch']['address'], RETURN,
                   timeout=1000000, count=100000)
    require(m.uc.reg_read(UC_ARM_REG_PC) == NOTICE_DISPATCH and m.state()['in_flight'] == 1,
            'Observer did not reach paused original-dispatch boundary')
    paused = m.uc.context_save()
    require(m.configure(6) == -25 and m.state()['count'] == 1, 'In-flight reconfigure not rejected')
    require(m.external('memory_notice_disarm') == 0 and m.state()['count'] == 0 and
            m.state()['in_flight'] == 1, 'Disarm lost in-flight accounting')
    require(m.configure(6) == -25, 'Disarmed in-flight configure was accepted')
    m.pop(empty=True)
    m.stop_address = None
    m.uc.context_restore(paused)
    m.uc.emu_start(NOTICE_DISPATCH | 1, RETURN, timeout=1000000, count=100000)
    require(m.uc.reg_read(UC_ARM_REG_PC) == RETURN and m.uc.reg_read(UC_ARM_REG_R0) == 0 and
            m.state()['in_flight'] == 0 and m.state()['canceled'] == 1 and
            m.state()['count'] == 0 and len(m.forwarded) == 2,
            'Canceled snapshot republished or original dispatch did not finish')
    require(m.configure(6) == 0, 'Reconfigure after dispatch exit failed')
    m.dispatch(raw(marker=3)); require(m.pop() == raw(marker=3), 'New epoch capture failed')
    m.put(m.control+8, 0xffffffff)
    state = bytes(m.uc.mem_read(m.control, 60))
    require(m.configure(6) == -30 and bytes(m.uc.mem_read(m.control, 60)) == state,
            'Configuration epoch silently wrapped')
    m.verify()
    return {'name': 'in_flight_disarm_and_configuration_epoch',
            'pause_at_original_dispatch_after_compiled_snapshot': hex(NOTICE_DISPATCH),
            'configuration_rejected_until_observer_dispatch_exit': True,
            'queued_and_in_flight_snapshot_canceled_without_blocking_stock_dispatch': True,
            'separate_stacks_and_python_context_restore': True,
            'new_epoch_capture_and_epoch_wrap_guard_passed': True,
            'source_callback_quiescence_or_module_unload_proved': False, 'passed': True}


def check_manifest(path):
    manifest = json.loads(path.read_text())
    for p, h in manifest['source_sha256'].items():
        require(sha((ROOT/p).read_bytes()) == h, 'Manifest source changed: '+p)
    for key in ('elf', 'flat_binary'):
        require(sha((ROOT/manifest[key]).read_bytes()) == manifest[key+'_sha256'],
                'Manifest artifact changed: '+manifest[key])
    return manifest


def main():
    stock = NativeImage()
    companion_manifest = ROOT/'staging/native-media-consumer/manifest.json'
    observer_manifest = ROOT/'staging/native-memory-notice/manifest.json'
    companion, observer = map(check_manifest, (companion_manifest, observer_manifest))
    main_routes = original_main_routes(stock, companion, observer)
    query_limit = original_query_fixture_limit(stock, companion, observer)
    route = source_lifecycle(stock, companion, observer)
    controls = [bounded_fifo(stock, companion, observer), invalid_and_irq(stock, companion, observer),
                in_flight_cancel(stock, companion, observer)]
    dependencies = (ROOT/'scripts/emulate_native_memory_completion.py',
                    ROOT/'scripts/emulate_native_memory_audio.py',
                    ROOT/'scripts/emulate_native_pcm_initialization.py',
                    ROOT/'scripts/emulate_native_audio_messages.py',
                    ROOT/'scripts/emulate_native_audio_registration.py',
                    ROOT/'scripts/emulate_native_pcm_flow_control.py',
                    ROOT/'scripts/emulate_native_sbc.py', ROOT/'scripts/emulate_native_sbc_pcm.py',
                    ROOT/'scripts/analyze_native_sections.py', ROOT/'scripts/analyze_sdp_activation.py',
                    companion_manifest, observer_manifest)
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'script_sha256': sha(Path(__file__).read_bytes()),
              'dependency_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in dependencies},
              'observer_elf_sha256': observer['elf_sha256'],
              'observer_flat_binary_bytes': observer['flat_binary_bytes'],
              'consumer_companion_elf_sha256': companion['elf_sha256'],
              'main_routes': main_routes, 'source_lifecycle': route, 'controls': controls,
              'uninitialized_original_query_fixture_limit': query_limit,
              'all_passed': True, 'compiled_raw_notice_observer_executed': True,
              'main_dispatch_stub_removed': True, 'original_main_context_query_controlled': hex(QUERY),
              'main_default_not_proof_of_global_absence_of_clients': True,
              'actual_app_listener_or_hook_installation_verified': False,
              'pcm_pinning_recycling_pool_reservation_adapter_implemented': False,
              'existing_consumer_initialized_by_inherited_fixture': True,
              'existing_sbc_queue_worker_or_consumer_audio_pipeline_called': False,
              'existing_compiled_components_changed': False,
              'device_io': False, 'device_install_candidate': False,
              'original_main_dispatch_trace': trace(stock, MAIN_DISPATCH),
              'original_main_audio_event_wrapper_trace': trace(stock, 0x1fa4a6),
              'limitations': 'Offline compiled observer invoked explicitly on valid original report frames. Original notice dispatcher/wrappers and broad main dispatcher execute, with optional context/filesystem query27811e controlled as0/1; event246 reaches tested default route and incidental main return320, while original notice dispatch returns0. Restoring the full query enters filesystem26a300 then hits missing-fixture read26a24c; this is not a live device failure. This does not establish absence of all client/App registration mechanisms or a public App API. Small four-slot journal uses loader-cleared BSS and original IRQ helpers; artificial per-block identifiers remain markers. Observer configuration epoch is not a stream generation. Overflow/drop/cancel neither proves source reader exit nor authorizes PCM recycling or module unload. Original memory source actor uses inherited synthetic wait/get/message/handles/mutex/priority/start/activation/mixer/scratch and Python context restoration; real message14/hardware drain, actual OS IRQ/preemption/navigation/resampling/speaker are absent. No decoder output redirection, immutable-buffer pinning/source reservation/auto-advance adapter, VPM merge/acceptance, actual SEP/SDP/UI/phone reception or Google Maps. Existing components unchanged; consumer initialization runs in inherited fixture setup but its audio pipeline/decoder/queue/worker are not invoked. No device I/O or install candidate.'}
    path = ROOT/'evidence/firmware-analysis/native-memory-notice-emulation.json'
    path.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'compiled_observer_bytes': observer['flat_binary_bytes'],
                      'main_query_cases': len(main_routes), 'pcm_bytes': route['pcm_bytes'],
                      'controls': len(controls), 'all_passed': True, 'device_io': False}))


if __name__ == '__main__':
    main()
