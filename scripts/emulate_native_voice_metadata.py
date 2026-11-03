#!/usr/bin/env python3
"""Execute the stock VPM metadata/END checks on immutable backup bytes.

Fresh offline VMs run the real embedded filesystem, code-page conversion,
UTF-16 tag/numeric parsing, label normalization and required-field branches.
Modified controls exist only in RAM and never execute module instructions.
This does not settle outer voice enumeration/selection or signature policy.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_LR, UC_ARM_REG_PC
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_sdp_activation import trace
from analyze_tts_vpm import parse_image
from analyze_native_loader import INIT, IMAGE, DESCRIPTOR
from emulate_native_vpm_filesystem import VpmFilesystem, REGION, sha, require, mutate_member

METADATA = 0x275590
RECORD = 0x08028000
RECORD_BYTES = 0x778
OUTER_PATH = 0x0802a000
HANDLE_DESCRIPTORS = 0x08030000
STOCK_START = 0x274acc
STOCK_END = 0x275c70
FUNCTIONS = (METADATA, 0x274acc, 0x274a8a, 0x2734e6,
             0x2fcd0a, 0x2fccce, 0x2fc9bc, 0x388804, 0x388b22)


class VoiceMetadata(VpmFilesystem):
    def __init__(self, stock, data, changed=False):
        self.changed = changed
        self.open_attempts = []
        self.pointer_queries = 0
        super().__init__(stock, data)
        # The actual pointer wrapper shifts descriptor+4 right/left by3.
        # 388B22 is simply BX LR, not a pin-count decrement. Execute both
        # original bodies; only their heap descriptor lookup remains a fixture.
        self.hooks.pop(0x388804)
        self.hooks.pop(0x388b22)
        self.uc.mem_write(0xf09658+8, bytes([REGION]))

    def observe(self, uc, address, size, unused):
        if self.changed:
            require(address != INIT and not IMAGE <= address < DESCRIPTOR,
                    'A changed-control module was executed')
        if address == 0x1fb304:
            pointer = uc.reg_read(UC_ARM_REG_R0)
            name = bytes(uc.mem_read(pointer, 128)).split(b'\0', 1)[0]
            self.open_attempts.append(name.decode('ascii'))
        if address == 0x388e92:
            self.visits[address] += 1
            require(uc.reg_read(UC_ARM_REG_LR) == 0x38881b,
                    'Heap fixture used outside original pointer-query wrapper')
            handle = uc.reg_read(UC_ARM_REG_R0)
            entry = self.handles[handle]
            require(not entry['freed'], 'Query of released fixture handle')
            descriptor = HANDLE_DESCRIPTORS+(handle-0xd0000000)*32
            require(descriptor+32 < 0x08034000, 'Heap descriptor inventory exhausted')
            self.put(descriptor+4, entry['pointer'])
            self.pointer_queries += 1
            uc.reg_write(UC_ARM_REG_R0, descriptor)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        return super().observe(uc, address, size, unused)

    def verify_heap_released(self):
        for entry in self.handles.values():
            pointer, length = entry['pointer'], entry['length']
            require(entry['freed'] and entry['locks'] == 0,
                    'Temporary fixture allocation retained')
            require(bytes(self.uc.mem_read(pointer-32, 32)) == b'\xa5'*32 and
                    bytes(self.uc.mem_read(pointer+length, 32)) == b'\xa5'*32,
                    'Original routine crossed temporary buffer boundary')


def tags_from(files):
    info = files['DLLINFO.TXT']['content'].decode('ascii')
    return {m[1]: m[2] for m in re.finditer(r'<([a-z_]+)>([^<]*)</\1>', info)}


def run(stock, row, data=None, kind='original', expected=1, load=False):
    changed = data is not None
    data = (ROOT/row['file']).read_bytes() if data is None else data
    if not changed:
        require(sha(data) == row['sha256'], 'Original package changed')
    files, geometry = parse_image(data)
    tags = tags_from(files)
    fs = VoiceMetadata(stock, data, changed)
    require(fs.mount(), 'Test volume did not become active')
    fs.uc.mem_write(RECORD-32, b'\xa5'*(RECORD_BYTES+64))
    path = ('0:/Garmin/Voice/'+Path(row['file']).name+'\0').encode('utf-16le')
    fs.uc.mem_write(OUTER_PATH, path)
    baseline = stock.read(STOCK_START, STOCK_END-STOCK_START)
    require(bytes(fs.uc.mem_read(STOCK_START, len(baseline))) == baseline,
            'Stock metadata instructions changed before execution')
    status = fs.call(METADATA, (OUTER_PATH, RECORD, 0))
    require(status == expected, f'{kind}: metadata status {status}, expected {expected}')
    require(bytes(fs.uc.mem_read(RECORD-32, 32)) == b'\xa5'*32 and
            bytes(fs.uc.mem_read(RECORD+RECORD_BYTES, 32)) == b'\xa5'*32,
            'Metadata record boundary exceeded')
    require(bytes(fs.uc.mem_read(STOCK_START, len(baseline))) == baseline,
            'Stock metadata instructions changed during execution')
    parser_called = fs.visits[0x274acc] > 0
    checksum = fs.word(RECORD+0x764)
    #2755CA writes -1 at record+0x764 before the optional tag is parsed.
    expected_sum = int(tags.get('dll_chksum', '0xffffffff'), 0)
    if parser_called:
        require(checksum == expected_sum,
                f'{kind}: native checksum {checksum:#x}, expected {expected_sum:#x}')
        require(fs.visits[0x2fcd0a] and fs.visits[0x366abc],
                'Original conversion or metadata normalization was bypassed')
    if status == 1:
        require(parser_called, 'Accepted package bypassed DLLINFO parser')
    metadata_opens = list(fs.open_attempts)
    require(all(name.lower() in ('dllinfo.txt', 'imgend.tst') for name in metadata_opens),
            'Unexpected metadata-stage file read')
    require(fs.visits[INIT] == 0, 'Metadata stage unexpectedly executed DLL initializer')
    functions_before_load = {hex(a): fs.visits[a] for a in FUNCTIONS}
    fs.verify_closed_files()
    fs.verify_heap_released()
    require(fs.visits[0x388804] == fs.pointer_queries,
            'Native pointer-query wrapper count differs from fixture lookups')
    loader = None
    if load:
        require(not changed and status == 1, 'Changed content must not be loaded')
        loader = fs.load_original(files['DLLIMG.BIN']['content'],
                                  row['module']['image_header_ram_bytes'])
        fs.verify_closed_files()
        fs.verify_heap_released()
    module = files['DLLIMG.BIN']['content']
    return {
        'voice': Path(row['file']).name, 'kind': kind,
        'memory_only_changed_control': changed,
        'package_sha256': sha(data), 'metadata_status': status,
        'metadata_parser_executed': parser_called,
        'parsed_checksum': checksum, 'metadata_checksum': expected_sum,
        'actual_dll_byte_sum': sum(module) & 0xffffffff,
        'metadata_matches_dll_byte_sum': expected_sum == (sum(module) & 0xffffffff),
        'dll_sha256': sha(module),
        'signature_sha256': sha(files['DLLIMG.SIG']['content']),
        'metadata_open_attempts': metadata_opens,
        'original_functions_executed_before_module_load': functions_before_load,
        'metadata_record_sha256': sha(bytes(fs.uc.mem_read(RECORD, RECORD_BYTES))),
        'metadata_record_and_temporary_buffer_guards_intact': True,
        'native_files_closed_and_temporary_heap_released': True,
        'original_pointer_query_wrapper_executed': fs.visits[0x388804],
        'original_noop_wrapper_executed': fs.visits[0x388b22],
        'stock_metadata_code_sha256_before_after': sha(baseline),
        'original_loader_after_metadata': loader,
        'modified_module_instructions_executed': False if changed else None,
        'native_calls': fs.calls, 'all_passed': True,
    }


def replace_metadata(data, files, geometry, before, after):
    require(len(before) == len(after) and before in files['DLLINFO.TXT']['content'],
            'Metadata control must preserve allocation/length')
    def change(payload):
        payload[:] = payload.replace(before, after)
    return mutate_member(data, files['DLLINFO.TXT'], geometry, change)


def controls(stock, row):
    original = (ROOT/row['file']).read_bytes()
    files, geometry = parse_image(original)
    checksum_text = tags_from(files)['dll_chksum'].encode()
    changed_dll = mutate_member(original, files['DLLIMG.BIN'], geometry,
        lambda payload: payload.__setitem__(0x100, payload[0x100]^1))
    zero_signature = mutate_member(original, files['DLLIMG.SIG'], geometry,
        lambda payload: payload.__setitem__(slice(None), bytes(len(payload))))
    zero_checksum = replace_metadata(original, files, geometry,
                                    checksum_text, b'0x00000000')
    absent_checksum = replace_metadata(original, files, geometry,
                                       b'dll_chksum', b'dll_chknul')
    absent_language = replace_metadata(original, files, geometry,
                                       b'lang_name', b'lang_none')
    bad_marker = mutate_member(original, files['IMGEND.TST'], geometry,
        lambda payload: payload.__setitem__(slice(None), b'BAD'))
    missing_marker = bytearray(original)
    for offset in files['IMGEND.TST']['directory_offsets']:
        missing_marker[offset+1:offset+9] = b'NOEND   '
    cases = [
        ('dll_payload_changed_metadata_sum_stale', changed_dll, 1),
        ('signature_content_zeroed', zero_signature, 1),
        ('checksum_tag_zero', zero_checksum, 1),
        ('checksum_tag_missing', absent_checksum, 1),
        ('required_language_tag_missing', absent_language, 0),
        ('bad_END_marker', bad_marker, 0),
        ('missing_END_member', bytes(missing_marker), 0),
    ]
    results = [run(stock, row, data, kind, expected) for kind, data, expected in cases]
    require(not results[0]['metadata_matches_dll_byte_sum'], 'Stale sum control unchanged')
    require(results[1]['signature_sha256'] == sha(bytes(72)), 'SIG control not zeroed')
    require([r['parsed_checksum'] for r in results[2:4]] == [0, 0xffffffff],
            'Zero/missing checksum did not preserve the native parsed/default values')
    require(results[4]['metadata_parser_executed'], 'Required-field rejection bypassed parser')
    require(all(not r['metadata_parser_executed'] for r in results[5:]),
            'Bad END marker unexpectedly reached metadata parser')
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--diagnostic', action='store_true')
    args = parser.parse_args()
    stock = NativeImage()
    image = RuntimeImage(stock)
    static = {hex(a): trace(image, a, 2000) for a in FUNCTIONS}
    require(all(not f['instruction_limit_reached'] and not f['unresolved_exits']
                for f in static.values()), 'Unresolved bounded metadata CFG')
    require(image.read(0x388b22, 2) == b'\x70\x47', 'Noop wrapper changed')
    rows = [r for r in json.loads((ROOT/'evidence/firmware-analysis/tts-vpm-containers.json').read_text())['containers']
            if r['native_module_container']]
    if args.diagnostic:
        rows = rows[:1]
    cases = [run(stock, row, load=True) for row in rows]
    changed = [] if args.diagnostic else controls(stock, rows[0])
    dependencies = {str(Path(__file__).relative_to(ROOT)): sha(Path(__file__).read_bytes())}
    for module in list(sys.modules.values()):
        name = getattr(module, '__file__', None)
        if name and Path(name).resolve().parent == ROOT/'scripts' and name.endswith('.py'):
            path = Path(name).resolve()
            dependencies[str(path.relative_to(ROOT))] = sha(path.read_bytes())
    for path in [ROOT/'evidence/firmware-analysis/tts-vpm-containers.json',
                 *[ROOT/row['file'] for row in rows]]:
        dependencies[str(path.relative_to(ROOT))] = sha(path.read_bytes())
    out = {
        'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
        'all_passed': True, 'diagnostic_only': args.diagnostic,
        'cases': cases, 'memory_only_controls': changed,
        'static_functions': static, 'source_sha256': dependencies,
        'stock_high_level_metadata_entry': hex(METADATA),
        'original_codepage_conversion_and_numeric_parsers_executed': True,
        'pointer_query_wrapper_entry': '0x388804',
        'pointer_query_heap_descriptor_lookup_fixture': '0x388e92',
        'noop_compatibility_wrapper_entry': '0x388b22',
        'stock_metadata_function_uses_only_dllinfo_and_END_files': True,
        'dll_checksum_or_SIG_not_an_acceptance_gate_in_tested_metadata_function': not args.diagnostic,
        'outer_voice_enumeration_selection_and_signature_policy_verified': False,
        'modified_module_instructions_executed': False,
        'modified_vpm_saved': False, 'device_io': False, 'device_install_candidate': False,
        'limits': 'Fresh original DSK filesystem VMs execute stock275590 metadata/IMGEND checks, native codepage conversion, UTF16/numeric tag parsing and conditional-copy product label normalization. Three unmodified packages then execute the original DLL initializer with all five actual file callbacks and match independent original-loader runtime/40 trampolines. Four accepted RAM-only controls (stale DLL sum, zero SIG, zero/missing checksum tag) and three rejected controls (missing language, bad/missing END) characterize this metadata function only. Modified modules never execute. Underlying byte I/O, filesystem/cache inventory, heap allocation/release and descriptor lookup, mutex/IRQ/cache sync and nonblank ASCII CRT inventory remain fixtures. Original388804 is a pointer query and388B22 is BX LR; this is not native heap pinning or safe unload proof. Outer FAT/mapped-region setup, complete voice enumeration/selection/trust policy, modified-package execution, real UI/SEP/phone/hardware/navigation remain unverified. No device or backup writes.'
    }
    if not args.diagnostic:
        path = ROOT/'evidence/firmware-analysis/native-voice-metadata-emulation.json'
        path.write_text(json.dumps(out, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'diagnostic_only': args.diagnostic, 'original_voices': len(cases),
                      'memory_only_controls': len(changed), 'static_CFGs': len(static),
                      'dependencies': len(dependencies), 'all_passed': True}))


if __name__ == '__main__':
    main()
