#!/usr/bin/env python3
"""Stock mixer-message loop and explicit post-selection rehook, offline only.

Original channel mapping/global queue initialization/driver start and mixer
dispatch execute. Wait/message transport and heap/mutex/priority/hardware
controls remain synthetic. Tests pause the mixer at a post-selector boundary,
run compiled attachment/refresh on another stack, then restore emulator CPU
context. This is not a production call-site hook or actual OS/IRQ scheduling.
"""
from datetime import datetime, timezone
import ctypes
import json
from pathlib import Path
import struct
from unicorn import UcError

from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace
from emulate_native_audio_registration import (RegisteredPcm, CHANNELS, CHANNEL_STRIDE,
                                              SELECT, PULL, require, sha)
from emulate_native_sbc import PAGE_BYTES, STACK, RETURN
from emulate_native_sbc_pcm import RING_BYTES

MAPPING = 0xacb12c
WORKER = 0x2fa0dc
WAIT = 0x2fd034
GET_MESSAGE = 0x37bc00
POST_SELECT = 0x2fa298
DISPATCH_TABLE = 0x2fa260
DISPATCH_ADD_PC = 0x2fa25e
EXTERNAL_STACK = 0x0990f000


class MixerMessages(RegisteredPcm):
    def __init__(self, stock, channel, selector, companion):
        self.pending_messages = []
        self.delivered_messages = []
        self.worker_context = None
        self.stop_at_selection = False
        self.resuming_at_selection = False
        self.stop_address = None
        self.worker_entries = 0
        self.post_selection_boundaries = 0
        self.synthetic_waits = 0
        super().__init__(stock, channel, selector)
        for page in (0x269000, 0x26a000, MAPPING & ~4095, WAIT & ~4095,
                     0x46c000, 0x1d8000):
            self.uc.mem_map(page, PAGE_BYTES)
            self.uc.mem_write(page, stock.read(page, PAGE_BYTES))
        self.uc.mem_map(EXTERNAL_STACK & ~0xffff, 0x10000)
        self.symbols.update({'queue_globals': {'address': 0x277e21},
                             'channel_init': {'address': 0x269f6d},
                             'profiles': {'address': 0x269ec1},
                             'queue_start': {'address': 0x277537}})
        self.call('queue_globals')
        self.mapping_rows = []
        for index in range(18):
            self.call('channel_init', (index,))
            record = CHANNELS+index*CHANNEL_STRIDE
            matched = next(j for j in range(18) if stock.read(MAPPING+28*j, 1)[0] == index)
            template = stock.read(MAPPING+28*matched, 28)
            require(bytes(self.uc.mem_read(record, 1)) == template[:1] and
                    self.word(record+0xc4) == struct.unpack_from('<I', template, 4)[0] and
                    bytes(self.uc.mem_read(record+0x1c2, 1)) == template[8:9],
                    'Original mapping initializer differs from exact readonly table')
            self.mapping_rows.append({'channel': index, 'matched_table_index': matched,
                                      'source_id': template[0],
                                      'field_c4': self.word(record+0xc4),
                                      'field_1c2': template[8]})
        # Run all18 original profile installs, stopping before hardware tails.
        self.stop_address = 0x2fa5a0
        self.uc.reg_write(UC_ARM_REG_SP, STACK)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN)
        self.uc.emu_start(self.symbols['profiles']['address'], RETURN,
                          timeout=1000000, count=100000)
        require(self.uc.reg_read(UC_ARM_REG_PC) == self.stop_address,
                'Original profile loop missed its bounded pre-hardware endpoint')
        self.stop_address = None
        require(self.word(self.record+0x1ac) == 0xffff and
                bytes(self.uc.mem_read(self.record+0x1c2, 1)) == b'\x05',
                'Original queue init did not supply empty current-source and mode5')
        self.channel_baseline = bytes(self.uc.mem_read(CHANNELS, 18*CHANNEL_STRIDE))
        self.uc.mem_write(WAIT, b'\x70\x47')
        self.uc.mem_write(GET_MESSAGE, b'\x70\x47')
        self.install_companion(companion)

    def install_companion(self, companion):
        self.companion = companion
        symbols = companion['symbols']
        base = companion['load_base']
        count = (symbols['__queue_code_end']['address']-base+4095)&~4095
        self.uc.mem_map(base, count)
        self.uc.mem_write(base, (ROOT/companion['flat_binary']).read_bytes())
        self.uc.mem_map(symbols['__queue_state_start']['address'], PAGE_BYTES)
        self.uc.mem_map(0x21b000, PAGE_BYTES)
        self.uc.mem_write(0x21b000, self.stock.read(0x21b000, PAGE_BYTES))
        for name in ('media_consumer_init', 'media_consumer_attach', 'media_consumer_detach',
                     'media_consumer_refresh_after_selection'):
            self.symbols[name] = symbols[name]
        require(self.external('media_consumer_init') == 0, 'Companion initialization failed')

    def observe(self, uc, address, size, data):
        if address == self.stop_address:
            uc.emu_stop(); return
        if address in (WAIT, GET_MESSAGE):
            self.registration_visits[address] += 1
            if address == WAIT:
                self.synthetic_waits += 1
                if self.pending_messages: uc.reg_write(UC_ARM_REG_R0, 2)
                else: uc.emu_stop()
            elif self.pending_messages:
                message = self.pending_messages.pop(0)
                uc.mem_write(uc.reg_read(UC_ARM_REG_R0), message)
                self.delivered_messages.append({'type': message[0], 'channel': message[1],
                                                 'argument': struct.unpack_from('<I', message, 4)[0]})
                uc.reg_write(UC_ARM_REG_R0, 1)
            else: uc.reg_write(UC_ARM_REG_R0, 0)
            return
        super().observe(uc, address, size, data)
        if address == WORKER: self.worker_entries += 1
        if address == POST_SELECT:
            # A Unicorn stop leaves PC on this instruction. Resuming visits
            # it once more without a second original selector invocation.
            if self.resuming_at_selection:
                self.resuming_at_selection = False
                return
            self.post_selection_boundaries += 1
            if self.stop_at_selection:
                require(not any(self.mutex_depth.values()), 'Post-selection point retained a mutex')
                self.stop_at_selection = False
                uc.emu_stop()

    def external(self, name, args=()):
        self.uc.reg_write(UC_ARM_REG_SP, EXTERNAL_STACK)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN)
        for register, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            self.uc.reg_write(register, value)
        self.uc.emu_start(self.symbols[name]['address'], RETURN,
                          timeout=1000000, count=100000)
        require(self.uc.reg_read(UC_ARM_REG_PC) == RETURN, 'External compiled call did not return')
        return ctypes.c_int32(self.uc.reg_read(UC_ARM_REG_R0)).value

    def run_worker(self, messages=(), pause_after_select=False):
        self.pending_messages.extend(struct.pack('<BBHII', kind, self.channel, 0, arg, 0)
                                     for kind, arg in messages)
        self.stop_at_selection = pause_after_select
        if self.worker_context is None:
            self.uc.reg_write(UC_ARM_REG_SP, STACK)
            self.uc.reg_write(UC_ARM_REG_LR, RETURN)
            entry = WORKER | 1
        else:
            self.uc.context_restore(self.worker_context)
            entry = self.uc.reg_read(UC_ARM_REG_PC) | 1
            self.resuming_at_selection = (entry & ~1) == POST_SELECT
        try:
            self.uc.emu_start(entry, RETURN, timeout=1000000, count=100000)
        except UcError as error:
            raise RuntimeError(f'Mixer dispatch: {error}, '
                               f'PC={self.uc.reg_read(UC_ARM_REG_PC):#x}, '
                               f'messages={self.delivered_messages[-3:]}, '
                               f'controls={self.control_events[-3:]}') from error
        pc = self.uc.reg_read(UC_ARM_REG_PC)
        require(pc in (WAIT, POST_SELECT), 'Mixer dispatch missed bounded pause/wait endpoint')
        self.worker_context = self.uc.context_save()
        return pc

    def consumer_state(self):
        address = self.companion['symbols']['media_consumer_state']['address']
        return struct.unpack('<6Ii', self.uc.mem_read(address, 28))


def message_route(stock, channel, selector, companion):
    m = MixerMessages(stock, channel, selector, companion)
    require(m.external('media_consumer_refresh_after_selection') == -28,
            'Refresh before attachment was not rejected')
    expected = m.populate(0 if channel == 5 else RING_BYTES-64)
    require(m.word(m.record+0x1ac) == 0xffff, 'Registration fabricated a current-source index')
    require(m.call('queue_start', (m.record+0x1a8,)) == 0 and
            m.word(m.record+0x1ac) == 0, 'Actual queue start did not select index0')
    m.setup_mixer()
    m.uc.mem_write(m.mixer+0x84, b'\x01')  # Mixer activation remains synthetic, not message14/hardware.
    require(m.run_worker(((13, 0), (18, 0)), True) == POST_SELECT,
            'Original mixer message13 did not finish source selection')
    methods = m.record+0xf4
    original = bytes(m.uc.mem_read(methods, 68))
    require(m.word(methods+20) == 0x484c05, 'Original worker source selection missed kind17 reader')
    require(m.external('media_consumer_attach', (methods, 68)) == 0, 'Post-selection attach failed')
    require(m.external('media_consumer_refresh_after_selection') == 0, 'Already-wrapped refresh failed')
    require(m.run_worker() == WAIT and m.consumer_state()[2] == 1,
            'Original message18 failed to call compiled wrapper/stock PCM reader')
    before_read = m.consumer_state()[2]
    require(m.run_worker(((13, 0), (18, 0)), True) == POST_SELECT and
            bytes(m.uc.mem_read(methods, 68)) == original and m.consumer_state()[1] == 1,
            'Original mixer reselection did not overwrite marked-installed wrapper')
    # Explicit provider-change guard fixtures at the paused actor boundary.
    for offset, value in ((20, 0x484c01), (24, 0x48f0a5)):
        m.put(methods+offset, value)
        provider = bytes(m.uc.mem_read(methods, 68))
        require(m.external('media_consumer_refresh_after_selection') == -27 and
                bytes(m.uc.mem_read(methods, 68)) == provider,
                'Refresh clobbered an unrelated provider reader/format')
        m.uc.mem_write(methods, original)
    require(m.external('media_consumer_refresh_after_selection') == 0,
            'Compiled refresh failed after real factory reconstruction')
    wrapped = bytearray(original)
    struct.pack_into('<I', wrapped, 20, companion['symbols']['media_consumer_read']['address'])
    require(bytes(m.uc.mem_read(methods, 68)) == wrapped,
            'Refresh changed another source method')
    require(m.run_worker() == WAIT and m.consumer_state()[2] == before_read+1,
            'Reselected message18 bypassed refreshed consumer')
    # Original message16 initiates SEEK_SEND_RESET, not a generic music pause.
    # HAM reset is queued through the existing synthetic message-send hook;
    # its real reset actor/hardware and completion are not driven here.
    before = m.word(0x09800020+16)
    m.run_worker(((16, 0), (18, 0)))
    require(bytes(m.uc.mem_read(m.mixer+0x85, 1)) == b'\x01' and
            m.word(0x09800020+16) == before and m.consumer_state()[2] == before_read+1,
            'Original reset-pending mixer message18 still consumed source data')
    require(m.worker_entries == 1 and m.post_selection_boundaries == 2,
            f'Mixer actor restarted or skipped a source-selection boundary: '
            f'entries={m.worker_entries}, selections={m.post_selection_boundaries}')
    # First256-byte pull wraps after64 bytes; second extends the head to448.
    actual = bytes(m.uc.mem_read(0x09801020+2048-64, 64)) + bytes(m.uc.mem_read(0x09801020, 448))
    require(actual == expected[:512], 'Message-driven/reselected PCM differs from reference')
    require(bytes(m.uc.mem_read(0x09800020-32, 32)) == b'\xa5'*32 and
            bytes(m.uc.mem_read(0x09800020+36, 32)) == b'\xa5'*32 and
            bytes(m.uc.mem_read(0x09801020-32, 32)) == b'\xa5'*32 and
            bytes(m.uc.mem_read(0x09801020+2048, 32)) == b'\xa5'*32 and
            bytes(m.uc.mem_read(0x09803f00-32, 32)) == b'\xa5'*32,
            'Message-driven mixer crossed a descriptor/buffer/scratch guard')
    require(m.external('media_consumer_detach') == 0 and
            bytes(m.uc.mem_read(methods, 68)) == original, 'Refreshed attachment failed clean detach')
    m.verify_controls()
    require({WORKER, 0x269f6c, 0x277e20, 0x277536, SELECT, PULL, POST_SELECT,
             0x2fa268, 0x2fa53c, 0x2fa4c2, 0x46cd78, 0x1d8c60}.issubset(m.registration_visits),
            'Original mapping/start/message paths were skipped')
    return {'channel': channel, 'mapping_rows': m.mapping_rows,
            'queue_current_index_before_start': 65535, 'after_original_queue_start': 0,
            'messages': m.delivered_messages, 'worker_entries': m.worker_entries,
            'post_selection_boundary': hex(POST_SELECT), 'post_selection_count': 2,
            'compiled_consumer_reader_calls': m.consumer_state()[2],
            'compiled_refresh_after_real_reselection_passed': True,
            'no_attachment_unrelated_reader_and_format_guards_passed': True,
            'already_wrapped_refresh_passed': True,
            'original_seek_reset_request_and_read_gate_passed': True,
            'hardware_reset_actor_or_reset_completion_verified': False,
            'pcm_bytes': 512, 'pcm_sha256': sha(actual), 'reference_byte_identical': True,
            'consumer_state_after_detach': list(m.consumer_state()),
            'mapping_initializer_and_queue_start_not_hooked': True,
            'wait_and_message_get_hooked': True, 'mixer_activation_synthetic': True,
            'post_selection_rehook_explicitly_supplied_by_test': True,
            'python_context_restore_drives_mixer_test': True,
            'capacity_feedback_to_decoder_worker_tested_here': False,
            'true_irq_or_live_callback_quiescence_verified': False, 'passed': True}


def main():
    stock = NativeImage()
    manifest = ROOT/'staging/native-media-consumer/manifest.json'
    companion = json.loads(manifest.read_text())
    for p, h in companion['source_sha256'].items(): require(sha((ROOT/p).read_bytes()) == h, 'Source changed: '+p)
    for key in ('elf', 'flat_binary'):
        require(sha((ROOT/companion[key]).read_bytes()) == companion[key+'_sha256'], 'Companion changed')
    routes = [message_route(stock, 5, 1, companion), message_route(stock, 8, 0, companion)]
    table = stock.read(DISPATCH_TABLE, 8)
    dispatch = [{'message': 13+i, 'offset_byte': b, 'target': hex(DISPATCH_ADD_PC+4+b*2)}
                for i, b in enumerate(table)]
    require(dispatch[0]['target'] == '0x2fa268' and dispatch[5]['target'] == '0x2fa454',
            'Thumb computed-PC target used aligned ADR base rather than ADD PC+4')
    report = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'source_sha256': sha(Path(__file__).read_bytes()),
              'dependency_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in
                                  (ROOT/'scripts/analyze_native_sections.py',
                                   ROOT/'scripts/analyze_sdp_activation.py',
                                   ROOT/'scripts/emulate_native_audio_registration.py',
                                   ROOT/'scripts/emulate_native_pcm_flow_control.py',
                                   ROOT/'scripts/emulate_native_sbc.py',
                                   ROOT/'scripts/emulate_native_sbc_pcm.py', manifest)},
              'consumer_companion_elf_sha256': companion['elf_sha256'],
              'routes': routes, 'all_passed': True, 'readonly_mapping_table': hex(MAPPING),
              'mapping_table_rows': 18, 'mapping_record_bytes': 28,
              'original_channel_initializer': '0x269f6c', 'original_global_queue_initializer': '0x277e20',
              'original_queue_start': '0x277536', 'original_mixer_worker': hex(WORKER),
              'message_dispatch': dispatch, 'table_address': hex(DISPATCH_TABLE),
              'computed_add_pc_address': hex(DISPATCH_ADD_PC), 'computed_pc_base': '0x2fa262',
              'seek_reset_message': 16, 'reset_done_message_not_exercised': 17,
              'seek_reset_request_wrapper': '0x46cd78', 'reset_request_transport': '0x1d8c60',
              'post_selection_boundary': hex(POST_SELECT),
              'compiled_post_selection_refresh_implemented': True,
              'production_call_site_hook_installed': False, 'live_registered_mixer_worker_verified': False,
              'wait_and_message_transport_hooked': True, 'python_cpu_context_restore_drives_test': True,
              'actual_irq_entry_exit_or_callback_quiescence_verified': False,
              'cold_pcm_initialization_and_navigation_ring_ownership_verified': False,
              'native_on_device_verified': False, 'device_io': False, 'device_install_candidate': False,
              'stock_worker_trace': trace(stock, WORKER, 400),
              'post_select_trace': trace(stock, 0x2fa268, 80),
              'channel_init_trace': trace(stock, 0x269f6c, 150),
              'limitations': 'Offline original eighteen-channel readonly mapping/global source queue initialization and queue-start primitive, then original mixer-message loop. Wait returns/messages are synthetic hooks; existing handle/mutex/pull priority/message delivery and hardware policy controls remain. Global profile loop stops before hardware tails; mixer activation is supplied, not actual message14/hardware start. The actor is paused at original post-select0x2fa298, compiled attach/refresh is called on another stack and Python restores CPU context; no production call-site hook or live OS scheduling/quiescence is established. Original message13 source selection and message18 reads are serialized in this controlled actor; this does not exclude other live callbacks/IRQ/users. Message16 is SEEK_SEND_RESET, not a generic pause; original wrappers enqueue HAM_RESET through the controlled message-send hook, then the reset-pending byte gates reads. Real reset actor/hardware and message17 completion are not exercised. Compiled refresh preserves other methods and rejects unrelated reader/format, but actual deployment/lifetime/ring ownership/navigation coexistence/cold producer init/decoder-worker capacity integration, phone SEP/UI, physical audio, VPM acceptance and safe unload remain unverified.'}
    path = ROOT/'evidence/firmware-analysis/native-audio-message-emulation.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'routes': len(routes), 'channels_initialized_each': 18,
                      'pcm_bytes_each': 512, 'compiled_refresh_passed': True,
                      'all_passed': True, 'device_io': False}), flush=True)


if __name__ == '__main__': main()
