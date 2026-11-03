#!/usr/bin/env python3
"""Check original bootstrap/export preservation with an appended SBC module.

No VPM acceptance, device installation or audio playback is performed. The
decoder is reached via its own local API table, not original TTS API slots.
"""
from datetime import datetime, timezone
import hashlib
import json
import struct

from unicorn.arm_const import UC_ARM_REG_R0
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import IMAGE, STUBS
from emulate_native_loader import simulate
from emulate_native_sbc import Machine, Reference, RESULT_PAGE, PAGE_BYTES
from emulate_native_sbc_component import LoadedMachine
from emulate_native_sbc_pcm import PcmMachine, RING_BYTES

BUILD = ROOT/'staging/native-voice-extension-emulation'


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ExtensionMachine(LoadedMachine):
    def __init__(self, emulator, manifest):
        LoadedMachine.__init__(self, emulator, manifest)
        self.symbols = {}
        table = manifest['symbols']['voice_extension_decoder_api']['address']
        values = struct.unpack('<3I', self.uc.mem_read(table, 12))
        for name, address in zip(('garmin_sbc_reset', 'garmin_sbc_decode_frame',
                                   'voice_extension_submit_frame'), values):
            if address != manifest['symbols'][name]['address']:
                raise ValueError('Appended API table differs from its linked symbols')
            self.symbols[name] = {'address': address}
        self.table_calls = []

    def code(self, uc, address, size, data):
        self.counter += 1

    def call(self, name, args=(), fifth=None):
        self.table_calls.append(name)
        return Machine.call(self, name, args, fifth)


class VoicePcmMachine(ExtensionMachine, PcmMachine):
    def __init__(self, stock, emulator, manifest):
        ExtensionMachine.__init__(self, emulator, manifest)
        self.submit_function = 'voice_extension_submit_frame'
        self.setup_pcm_route(stock)


def check_one(stock, reference, path):
    manifest = json.loads(path.read_text())
    original = (ROOT/manifest['original_binary']).read_bytes()
    combined = (ROOT/manifest['combined_binary']).read_bytes()
    if sha(original) != manifest['original_binary_sha256'] or sha(combined) != manifest['combined_sha256']:
        raise ValueError('Original/combined image hash mismatch')
    for source, expected in manifest['source_sha256'].items():
        if sha((ROOT/source).read_bytes()) != expected: raise ValueError('Source changed: '+source)
    original_uc, original_report = simulate(stock, 'original_voice', module_bytes=original,
                                            module_ram_bytes=manifest['original_ram_bytes'],
                                            poison_module_ram=True, return_session=True)
    emulator, loader = simulate(stock, 'extended_voice', module_bytes=combined,
                                module_ram_bytes=manifest['combined_ram_bytes'],
                                poison_module_ram=True, return_session=True)
    original_exports = original_report['module_export_registration'][-1]
    extension_exports = loader['module_export_registration'][-1]
    # The descriptor is a temporary bootstrap stack object, so an extra wrapper
    # stack frame moves its address. Compare its contents and permanent table.
    export_fields = ('version', 'export_table', 'count', 'targets')
    if any(original_exports[k] != extension_exports[k] for k in export_fields) or original_exports['count'] != 40:
        changed = [k for k in export_fields if original_exports[k] != extension_exports[k]]
        raise ValueError('Original export contents/table changed: '+str(changed))
    if original_report['trampolines_verified'] != loader['trampolines_verified']:
        raise ValueError('Original main TTS import pointers/trampolines changed')
    length = manifest['original_file_bytes']
    original_runtime = bytes(original_uc.mem_read(IMAGE+12, length-12))
    extension_runtime = bytes(emulator.mem_read(IMAGE+12, length-12))
    if original_runtime != extension_runtime:
        difference = next(n for n, (a,b) in enumerate(zip(original_runtime, extension_runtime)) if a != b)
        raise ValueError(f'Original relocated file-backed bytes changed at +{difference+12:#x}')
    tail_length = manifest['original_ram_bytes']-length
    original_tail = bytes(original_uc.mem_read(IMAGE+length, tail_length))
    extension_tail = bytes(emulator.mem_read(IMAGE+length, tail_length))
    tail_differences = sum(a != b for a,b in zip(original_tail, extension_tail))
    # Original BSS may include alignment padding which its bootstrap leaves
    # untouched. Describe any changed initial padding; don't call it preserved.
    changed_tail = [{'offset': length+n, 'original': a, 'extended': b}
                    for n,(a,b) in enumerate(zip(original_tail, extension_tail)) if a != b]
    machine = VoicePcmMachine(stock, emulator, manifest)
    configs = [dict(frequency=2, mode=3, subbands=1, blocks=3, allocation=0, bitpool=53),
               dict(frequency=3, mode=3, subbands=1, blocks=3, allocation=0, bitpool=53),
               dict(frequency=0, mode=0, subbands=1, blocks=3, allocation=0, bitpool=31)]
    decoded_cases = []
    for n, config in enumerate(configs):
        # First frame is deliberately decoded without reset: the appended
        # loader entry itself must have successfully initialized the decoder.
        if n: machine.reset()
        frames = reference.encode(config, frames=8)
        expected = reference.decode_stream(frames)
        actual = []
        for frame, wanted in zip(frames, expected):
            status, result, pcm, _ = machine.decode(frame)
            if status != 0 or result[0] != len(frame) or pcm != wanted:
                raise ValueError('Appended decoder PCM differs from upstream')
            actual.append(pcm)
        decoded_cases.append({'config': config, 'frames': len(frames),
                              'reference_byte_identical': True,
                              'pcm_sha256': sha(b''.join(actual))})
    # Prove local decoder execution did not change original relocated code,
    # export arrays/import stubs or initialized state inside its file extent.
    after = bytes(emulator.mem_read(IMAGE+12, length-12))
    if after != extension_runtime: raise ValueError('Decoder changed the original TTS memory')
    for record in loader['trampolines_verified']:
        slot, storage, pointer = record['slot'], int(record['storage'],16), int(record['trampoline'],16)
        if struct.unpack('<I',emulator.mem_read(storage,4))[0] != pointer:
            raise ValueError('Decoder replaced an original TTS pointer')
        target = struct.unpack('<I',emulator.mem_read(STUBS+slot*12+8,4))[0]
        if target != int(record['target_word'],16): raise ValueError('Decoder replaced a TTS target')
    # Slot 39's short original function has been decoded: query (0,out,1)
    # returns 1 and stores zero; query with selector 1 returns 0. Run the
    # stock-created trampoline in both sessions, without speech/hardware I/O.
    query_calls = []
    query = loader['trampolines_verified'][39]
    original_machine = LoadedMachine(original_uc, manifest)
    for selector, wanted, output_value in [(0,1,0),(1,0,0xa5a5a5a5)]:
        destination = RESULT_PAGE+PAGE_BYTES-4
        machine.uc.mem_write(destination, struct.pack('<I',0xa5a5a5a5))
        machine.symbols['_original_query']={'address':int(query['trampoline'],16)}
        status = Machine.call(machine, '_original_query', (selector,destination,1))
        actual = struct.unpack('<I',machine.uc.mem_read(destination,4))[0]
        original_uc.mem_write(destination,struct.pack('<I',0xa5a5a5a5))
        original_machine.symbols['_original_query']={'address':int(query['trampoline'],16)}
        baseline_status = Machine.call(original_machine,'_original_query',(selector,destination,1))
        baseline_output = struct.unpack('<I',original_uc.mem_read(destination,4))[0]
        if (baseline_status,baseline_output)!=(status,actual):
            raise ValueError('Extended query differs from original runtime behavior')
        if status != wanted or actual != output_value: raise ValueError('Original slot 39 behavior changed')
        query_calls.append({'original_export_slot':39,'selector':selector,
                            'returned':status,'output_word':hex(actual),
                            'original_runtime_behavior_identical':True,'passed':True})
    # Add the previously verified stock buffer route without replacing any
    # original TTS exports. One starting offset exercises both writer/reader
    # wrapping, using the same explicitly hooked OS policies as the PCM test.
    pcm_frames = reference.encode(configs[-1], frames=30)
    wanted_pcm = reference.decode_stream(pcm_frames)
    machine.configure(RING_BYTES-64)
    machine.reset()
    actual_pcm = []
    for frame in pcm_frames:
        status, result = machine.submit(frame)
        if status != 0 or result[2:4] != (16000,1): raise ValueError('Voice PCM submit failed')
        if machine.queued() >= 4096: actual_pcm.append(machine.read(3840))
    while machine.queued(): actual_pcm.append(machine.read(3840))
    if b''.join(actual_pcm) != b''.join(wanted_pcm):
        raise ValueError('Voice extension -> stock PCM reader changed samples')
    if bytes(emulator.mem_read(IMAGE+12,length-12)) != original_runtime:
        raise ValueError('PCM route changed original TTS runtime memory')
    # Check main's TTS slots again after the original host callback executes.
    for entry in loader['trampolines_verified']:
        address = int(entry['storage'],16)
        if struct.unpack('<I',emulator.mem_read(address,4))[0] != int(entry['trampoline'],16):
            raise ValueError('PCM route changed an original TTS pointer')
        target = struct.unpack('<I',emulator.mem_read(STUBS+entry['slot']*12+8,4))[0]
        if target != int(entry['target_word'],16): raise ValueError('PCM route changed a TTS target')
    return {'voice': manifest['voice_package'], 'manifest': str(path.relative_to(ROOT)),
            'combined_sha256': manifest['combined_sha256'],
            'combined_ram_bytes': manifest['combined_ram_bytes'],
            'original_loader': original_report, 'extended_loader': loader,
            'original_export_contents_and_40_targets_identical': True,
            'temporary_descriptor_stack_addresses': [original_exports['module_descriptor'],
                                                       extension_exports['module_descriptor']],
            'original_main_import_pointers_and_trampolines_identical': True,
            'original_file_backed_runtime_bytes_after_header_identical': True,
            'original_runtime_sha256_excluding_header': sha(original_runtime),
            'original_tail_bytes': tail_length, 'tail_difference_count': tail_differences,
            'tail_differences': changed_tail,
            'decoder_initialized_by_extension_entry': True,
            'decoder_cases': decoded_cases, 'decoded_frames': sum(r['frames'] for r in decoded_cases),
            'decoder_calls_via_appended_local_table': True,
            'decoder_did_not_change_original_module_or_tts_slots': True,
            'original_slot_39_query_calls': query_calls,
            'stock_pcm_route': {'frames':len(pcm_frames),'pcm_bytes':len(b''.join(actual_pcm)),
                               'pcm_sha256':sha(b''.join(actual_pcm)),
                               'reference_byte_identical':True,
                               'writer_and_reader_wrap_exercised':True,
                               'original_tts_memory_and_slots_unchanged':True,
                               'operating_system_policy_hooked':True,
                               'ring_state_synthetic':True},
            'all_40_original_functions_invoked': False,
            'speech_synthesis_verified': False, 'device_io': False,
            'signature_acceptance_verified': False, 'device_install_candidate': False,
            'passed': True}


def main():
    manifests = sorted(BUILD.glob('*/manifest.json'))
    if len(manifests) != 3: raise ValueError('Build all three original voice experiments first')
    stock, reference = NativeImage(), Reference()
    cases = [check_one(stock, reference, path) for path in manifests]
    report = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256':EXPECTED,
              'cases':cases, 'original_voice_count':len(cases),
              'original_tts_exports_preserved_each':40,
              'decoded_frames':sum(c['decoded_frames'] for c in cases),
              'decoded_and_routed_frames':sum(c['stock_pcm_route']['frames'] for c in cases),
              'decoder_reference_byte_identical':True,'all_passed':True,
              'audible_output':False,'device_io':False,
              'modified_vpm_generated':False,'signature_validation_emulated':False,
              'native_on_device_verified':False,'device_install_candidate':False,
              'speech_synthesis_verified':False,
              'limitations':'Original bootstrap and all 40 export addresses/import stubs remain identical, and original relocated file-backed memory is unchanged. The added decoder executes through a separate local table; one benign original export is invoked. Other original functions and actual speech are not exercised. Header words 0/4/8 are changed, file padded to append code beyond original RAM, and any uninitialized tail difference is listed. This does not establish modified VPM/SIG acceptance, real loading, UI/A2DP/music integration or safe device installation.'}
    path=ROOT/'evidence/firmware-analysis/native-voice-extension-emulation.json'
    path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'output':str(path),'original_voices':len(cases),
                      'original_exports_preserved_each':40,'decoded_frames':report['decoded_frames'],
                      'decoded_and_routed_frames':report['decoded_and_routed_frames'],
                      'tail_difference_counts':[c['tail_difference_count'] for c in cases],
                      'all_passed':True,'device_io':False}))


if __name__ == '__main__':
    main()
