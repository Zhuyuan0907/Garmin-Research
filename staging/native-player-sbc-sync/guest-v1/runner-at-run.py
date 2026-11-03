#!/usr/bin/env python3
"""ROOT offline compressed packets -> SBC/FIR -> real kernel mixer.

The inherited original-kernel runner retains its declared hardware, allocator,
boot and consumer fixtures. Compressed packets are compiled offline inputs;
expected PCM stays in the HOST reference and is never written into guest RAM.
No phone input, installation, speaker, ownership or STOP_DONE is certified.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import importlib.util, json, struct, hashlib, traceback
from datetime import datetime, timezone
import unicorn
from unicorn.arm_const import *

BASE = Path(__file__).resolve().parent
ROOT = BASE.parents[1]
PARENT = ROOT / 'staging/native-player-mixer-sync/emulate_mixer_sync_v3.py'

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

parent = load(PARENT, 'sbc_sync_original_kernel_runner')
sha, rel, dump, require = parent.sha, parent.rel, parent.dump, parent.require
REFERENCE = BASE / 'compressed_input_reference_v1.json'

class CompressedHandoff(parent.Handoff):
    def __init__(self, stock, elf, build, reference, stream_index):
        self.reference = reference['streams'][stream_index]
        self.stream_index = stream_index
        self.codec_entries, self.codec_returns, self.producer_entries = [], [], []
        self.pending_codec = None
        self.reference_reset_pending = False
        self.input_selected = False
        self.valid_packets = {bytes.fromhex(p['packet_hex']) for p in self.reference['packets']}
        self.valid_packets.add(bytes.fromhex(self.reference['bad_later_frame_CRC_packet_hex']))
        super().__init__(stock, elf, build)

    def invoke_kernel(self, entry, args=(), phase=None):
        if entry == 'mh_boot_source':
            require(not self.input_selected, 'compiled input selected twice')
            result = super().invoke_kernel('mp_select_stream', (self.stream_index,),
                phase='compiled selection of offline compressed stream before source bootstrap')
            require(result == 0, 'compiled compressed stream selection failed')
            self.input_selected = True
        return super().invoke_kernel(entry, args, phase)

    def producer_status(self):
        symbols = self.build['symbols']
        return dict(
            owned=list(struct.unpack('<13I', self.uc.mem_read(symbols['owned_media_control']['value'], 52))),
            queue=list(struct.unpack('<9I', self.uc.mem_read(symbols['media_queue_control']['value'], 36))),
            packet_index=self.word(symbols['mp_packet_index']['value']),
            last_decode_error=struct.unpack('<i', self.uc.mem_read(symbols['mp_last_decode_error']['value'], 4))[0])

    def code(self, uc, address, size, data):
        super().code(uc, address, size, data)
        symbols = self.build['symbols']
        if self.pending_codec and address == self.pending_codec['return_PC']:
            p = self.pending_codec
            require(uc.reg_read(UC_ARM_REG_SP) == p['entry_SP'], 'compiled decoder did not fully return')
            require(self.word(parent.READY_TASKS) == self.source_tcb, 'decoder returned outside actual Source TCB')
            view = self.leases()
            require(view['borrow'] == 0 and view['media'] == view['callback'] == 1,
                'decoder lost typed producer leases before full return')
            result = struct.unpack('<9I', uc.mem_read(p['result_pointer'], 36))
            self.codec_returns.append(dict(p, returned=self.snapshot(), return_leases=view,
                r0=uc.reg_read(UC_ARM_REG_R0), decoder_result=list(result)))
            self.pending_codec = None
        observed = ('media_queue_callback', 'media_queue_step', 'owned_media_consume',
                    'owned_packet_parse', 'garmin_sbc_decode_frame',
                    'pcm_converter_process', 'memory_output_submit')
        match = next((n for n in observed if address == symbols[n]['value']), None)
        if match:
            require(self.source_tcb and self.word(parent.READY_TASKS) == self.source_tcb,
                'compressed packet work not on actual original Source TCB')
            row = dict(symbol=match, entry=self.snapshot(), args=self.regs(),
                       leases=self.leases(), producer=self.producer_status())
            if match in ('owned_packet_parse', 'garmin_sbc_decode_frame',
                         'pcm_converter_process', 'memory_output_submit'):
                view = row['leases']
                require(view['borrow'] == 0 and view['media'] == view['callback'] == 1,
                    'compressed decoder/submit lacks typed producer leases')
                require(self.word(parent.RECORD + 0x160) == symbols['mcs_queue_bridge']['value'],
                    'decoder continued after original profile replaced source callback')
                require(uc.reg_read(UC_ARM_REG_CPSR) & 0xFF == 0x1F,
                    'decoder/submit ran outside normal IRQ-restored System context')
            if match == 'media_queue_callback':
                length = self.word(uc.reg_read(UC_ARM_REG_SP))
                require(13 <= length <= 4096, 'callback compressed packet bound')
                packet = bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R3), length))
                require(packet in self.valid_packets, 'callback received undeclared compressed input')
                row.update(packet_hex=packet.hex(), packet_bytes=length)
            if match == 'garmin_sbc_decode_frame':
                require(self.pending_codec is None, 'nested decoder frame')
                length = uc.reg_read(UC_ARM_REG_R1)
                require(4 <= length <= 4096, 'decoder frame input bound')
                row.update(frame_hex=bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R0), length)).hex(),
                    entry_SP=uc.reg_read(UC_ARM_REG_SP), return_PC=uc.reg_read(UC_ARM_REG_LR) & ~1,
                    result_pointer=self.word(uc.reg_read(UC_ARM_REG_SP)))
                self.codec_entries.append(row)
                self.pending_codec = row
            self.producer_entries.append(row)

    def command(self, number):
        cursor = len(self.chunks)
        decoder_cursor = len(self.codec_entries)
        return_cursor = len(self.codec_returns)
        before = self.producer_status()
        require(self.invoke_kernel('mh_request_command', (number,),
                phase='request compressed-source command ' + str(number)) == 0,
                'compiled compressed-source command rejected')
        state = self.status()
        require(state[45] == number and state[46] == 0, 'compressed-source command failed before yielding')
        published = self.producer_status()
        expected = b''
        if number <= 4:
            packet_index = published['packet_index'] - 1
            field = 'expected_after_reset_PCM_hex' if self.reference_reset_pending else 'expected_continuous_PCM_hex'
            expected = bytes.fromhex(self.reference['packets'][packet_index][field])
            self.reference_reset_pending = False
            require(0 < len(expected) <= 512, 'HOST reference packet output bound')
            require(published['packet_index'] == before['packet_index'] + (number != 1),
                'compiled producer advanced wrong compressed input index')
            require(published['owned'][8] == before['owned'][8] + (number != 1),
                'whole-packet commit count differs from successful decode')
        if number == 8:
            require(published['last_decode_error'] < 0 and published['packet_index'] == before['packet_index'],
                'revoked compressed producer accepted/advanced input')
            require(len(self.codec_entries) == decoder_cursor,
                'revoked compressed producer entered decoder')
            require(published['owned'][8] == before['owned'][8] and published['owned'][12] == before['owned'][12],
                'revoked producer published FIFO ticket')
        if number == 9:
            require(published['last_decode_error'] == -6, 'later-frame CRC did not return codec error')
            require(published['packet_index'] == before['packet_index'] and
                    published['owned'][8] == before['owned'][8] and
                    published['owned'][12] == before['owned'][12] and published['owned'][4] == before['owned'][4],
                'failed whole packet published speculative PCM prefix')
            require([r['r0'] for r in self.codec_returns[return_cursor:]] == [0, 0xFFFFFFFA],
                'CRC case did not execute successful first frame then failed second frame')
            self.reference_reset_pending = True
        self.park()
        actual = b''.join(self.chunks[cursor:])
        if number <= 4:
            require(len(actual) == 1792 and actual[:len(expected)] == expected and
                    actual[len(expected):] == bytes(1792 - len(expected)),
                'native scheduled PCM/FIR output differs from HOST reference for command ' + str(number))
        else:
            require(actual == b'', 'failed/stopped/revoked compressed source published output')
        state = self.status()
        require(state[2] == state[6] == state[7] == state[8] == state[12] == 0,
            'compressed path retained lease or invented completion')
        self.fixture(parent.DESCRIPTOR + 12, struct.pack('<I', self.word(parent.DESCRIPTOR + 16)),
            'explicit output consumer advances after full original kernel actor returns; no DMA claim')
        return dict(command=number, state=state, PCM_hex=actual.hex(), bytes=len(actual),
            source_PCM_bytes=len(expected), HOST_expected_PCM_hex=expected.hex(),
            original_self_posted_underrun_silence_bytes=1792-len(expected) if number <= 4 else 0,
            producer_before=before, producer_after_request=published, producer_after=self.producer_status(),
            compiled_decoder_entries=len(self.codec_entries)-decoder_cursor)

    def result(self, name, commands):
        require(self.pending_codec is None and len(self.codec_entries) == len(self.codec_returns),
            'decoder frame has not fully returned')
        row = super().result(name, commands)
        row.update(stream_index=self.stream_index, source_sample_rate=self.reference['rate'],
            source_channels=self.reference['channels'], compressed_decoder_entries=self.codec_entries,
            compiled_decoder_full_returns=self.codec_returns, compiled_producer_entries=self.producer_entries,
            producer_terminal=self.producer_status(),
            actual_compressed_SBC_and_FIR_to_original_mixer=True,
            expected_PCM_was_never_written_to_guest=True, phone_AVDTP_or_live_packet_receiver_verified=False)
        return row

def main():
    require(unicorn.__version__ == '2.1.4', 'requires isolated Unicorn 2.1.4')
    runtime = BASE / 'guest-v1'
    runtime.mkdir(exist_ok=False)
    build = json.loads((BASE / 'build-v3.json').read_text())
    reference = json.loads(REFERENCE.read_text())
    source = dict(build['source_sha256'])
    source.update(build['generated_sha256'])
    source.update(reference['source_sha256'])
    for path in (Path(__file__).resolve(), PARENT, parent.PARENT,
                 ROOT / 'scripts/analyze_native_sections.py', BASE / 'build-v3.json',
                 ROOT / build['ELF'], REFERENCE,
                 ROOT / 'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py',
                 ROOT / 'evidence/firmware-analysis/main_02bd.bin'):
        source[rel(path)] = sha(path)
    require(source['evidence/firmware-analysis/main_02bd.bin'] == parent.EXPECTED, 'wrong MAIN')
    require(source[build['ELF']] == build['ELF_sha256'], 'wrong ELF')
    for path, digest in source.items():
        require(sha(ROOT / path) == digest, 'changed input ' + path)
    require(sha(Path(reference['reference_library'])) == reference['reference_library_sha256'],
            'HOST reference SBC library changed')
    dump(runtime / 'inputs-at-run.json', source)
    (runtime / 'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
    mod = load(ROOT / 'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py',
               'sbc_sync_elf')
    elf = mod.ELF32(ROOT / build['ELF'])
    stock = parent.NativeImage()
    cases, m = [], None
    try:
        for name, index, commands, existing in (
            ('mono16_native_reuse_reselect_reset', 0, (1, 2, 3, 4), False),
            ('joint44_native_reuse_reselect_reset', 1, (1, 2, 3, 4), False),
            ('stereo48_native_reuse_reselect_reset', 2, (1, 2, 3, 4), False),
            ('joint44_Stop_rejects_compressed_input', 1, (1, 5, 8), True),
            ('joint44_later_CRC_reject_and_recover', 1, (1, 9, 2), False),
            ('stereo48_profile_rewrite_rejects_decode', 2, (1, 6, 8), False)):
            m = CompressedHandoff(stock, elf, build, reference, index)
            m.boot(existing_control=existing)
            results = [m.command(c) for c in commands]
            row = m.result(name, results)
            path = runtime / (name + '.json')
            dump(path, row)
            cases.append(dict(name=name, path=rel(path), sha256=sha(path), passed=True))
            print(json.dumps(dict(case=name, full_returns=len(m.full_returns),
                decoded_frames=len(m.codec_returns), bytes=sum(r['bytes'] for r in results))), flush=True)
            m = None
        proof = dict(all_passed=True, source_sha256=source, cases=cases, case_count=len(cases),
            updated_utc=datetime.now(timezone.utc).isoformat(),
            inherited_original_kernel_sync_and_hardware_fixture_scope_preserved=True,
            compiled_compressed_packet_SBC_FIR_and_typed_FIFO_to_original_mixer=True,
            expected_PCM_was_never_written_to_guest=True,
            independent_FILE_verification_complete=False,
            physical_speaker_phone_App_installation_or_complete_player_verified=False,
            native_heap_exclusive_or_STOP_DONE_verified=False, device_io=False)
        dump(BASE / 'sbc-sync-v1-proof.json', proof)
        print(json.dumps(dict(all_passed=True, proof=rel(BASE / 'sbc-sync-v1-proof.json'))), flush=True)
    except BaseException as error:
        row = dict(all_passed=False, error=str(error), traceback=traceback.format_exc(),
                   source_sha256=source, cases_completed=cases, device_io=False)
        if m:
            row.update(phase=m.phase, trace=m.trace, registers=m.snapshot(),
                initial_ordinal=m.initial_ordinal, initial_whole_RW_zones=m.initial,
                final_whole_RW_zones={str(a):bytes(m.uc.mem_read(a,n)).hex() for a,n,p in m.zones if not p & unicorn.UC_PROT_EXEC},
                CPU_store_journal=m.journal, declared_fixture_mutations=m.fixtures,
                service_calls=m.fixture_services, original_entries=m.entries,
                full_returns=m.full_returns, outer_returns=m.outer_returns, patches=m.patches,
                sync_entries=m.sync_entries, sync_returns=m.sync_returns,
                producer_entries=m.producer_entries, codec_entries=m.codec_entries,
                codec_returns=m.codec_returns, pending_codec=m.pending_codec,
                native_visits={hex(a):n for a,n in m.visits.items()})
        dump(runtime / 'terminal-failure.json', row)
        raise

if __name__ == '__main__':
    main()
