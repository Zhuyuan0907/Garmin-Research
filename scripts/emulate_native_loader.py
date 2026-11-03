#!/usr/bin/env python3
"""Execute stock dllimg loader instructions with synthetic file callbacks.

No filesystem access by the emulated code, no navigator/Bluetooth I/O. A
synthetic ARM module returns 6; it is never written as a device module.
"""
import json
import struct
import hashlib
from datetime import datetime, timezone

import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_CPU_ARM_1176, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
                               UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import INIT, DESCRIPTOR, IMAGE, STUBS

RETURN = 0x10000
HANDLE = 0x12345678
CALLBACKS = {0x1fb2f8: 'close', 0x1fb304: 'open', 0x1fb3a2: 'read',
             0x1fb3ce: 'seek', 0x1fb3e4: 'tell'}


def simulate(stock, kind, *, module_bytes=None, module_ram_bytes=None,
             export_targets=None, poison_module_ram=False, return_session=False):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
    # Only the actual stock code needed by this experiment is mapped.
    for page in (0x23c000, 0x3b3000, 0x391000, 0x38a000, 0x235000):
        uc.mem_map(page, 4096)
        uc.mem_write(page, stock.read(page, 4096))
    for address in (*CALLBACKS, 0x221d2c, 0x278964):
        page = address & ~4095
        if page not in (0x23c000, 0x3b3000, 0x391000, 0x38a000, 0x235000):
            # Each callback page is unique apart from the five file callbacks.
            try: uc.mem_map(page, 4096)
            except unicorn.UcError as error:
                if page != 0x1fb000: raise error
        # Stub returns after hook; strcmp is ARM, others are Thumb.
        uc.mem_write(address, b'\x1e\xff\x2f\xe1' if address == 0x278964 else b'\x70\x47')
    uc.mem_map(0xf00000, 0x73000)
    uc.mem_write(0xf00000, stock.read(0xcb1980, 0x7224c))
    uc.mem_map(0x304b000, 4096)
    module_end = (IMAGE + (module_ram_bytes or 0x2000) + 4095) & ~4095
    uc.mem_map(0x2d4b000, max(0x4000, module_end - 0x2d4b000))
    uc.mem_map(0x02000000, 0x10000)
    uc.mem_map(RETURN, 4096)
    # b +0 skips the word at offset 4; mov r0,#6; bx lr.
    module = struct.pack('<4I', 0xea000000, 16, 0xe3a00006, 0xe12fff1e)
    file_length = 0x300004 if kind == 'file_over_limit' else len(module)
    if kind == 'header_over_limit':
        module = struct.pack('<4I', 0xea000000, 0x300004, 0xe3a00006, 0xe12fff1e)
    if kind == 'module_return_5':
        # First entry requests retry; the second image returns 6.
        module = struct.pack('<4I', 0xea000000, 16, 0xe3a00005, 0xe12fff1e)
    if kind in ('register_exports', 'register_exports_minor_mismatch'):
        # Synthetic ARM entry invokes the real Thumb registration callback
        # in loader[44], passing a local module descriptor and two exports.
        words = [0xea000000, 84,
                 0xe92d4010, 0xe1a04000, 0xe59f1008, 0xe594c02c,
                 0xe12fff3c, 0xe8bd8010, IMAGE+36,
                 0x50001 if kind.endswith('mismatch') else 0x50000,
                 0, 0, IMAGE+60, 0, 2, IMAGE+68, IMAGE+76,
                 0xe3a00023, 0xe12fff1e, 0xe3a00042, 0xe12fff1e]
        module = struct.pack('<21I', *words)
        file_length = len(module)
    if module_bytes is not None:
        if kind not in ('compiled_decoder', 'original_voice', 'extended_voice') or not module_ram_bytes:
            raise ValueError('Compiled payload requires its manifest and export targets')
        if kind == 'compiled_decoder' and not export_targets:
            raise ValueError('Decoder export targets must be specified')
        module = module_bytes
        file_length = len(module)
        if poison_module_ram:
            uc.mem_write(IMAGE, b'\xa5' * module_ram_bytes)
    events, visited = [], []
    position, open_count, module_calls = 0, 0, 0
    registration = []

    def c_string(address):
        result = bytearray()
        for offset in range(64):
            value = bytes(uc.mem_read(address+offset, 1))[0]
            if value == 0: return result.decode('ascii')
            result.append(value)
        raise ValueError('Unterminated synthetic string')

    def result(value, set_zero=False):
        uc.reg_write(UC_ARM_REG_R0, value)
        if set_zero:
            flags = uc.reg_read(UC_ARM_REG_CPSR)
            flags = (flags | (1 << 30)) if value == 0 else (flags & ~(1 << 30))
            uc.reg_write(UC_ARM_REG_CPSR, flags)

    def hook(emulator, address, size, user_data):
        nonlocal position, open_count, module_calls, module, export_targets
        visited.append(address)
        args = [uc.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
        if address in CALLBACKS:
            event = {'callback': CALLBACKS[address]}
            if event['callback'] == 'open':
                open_count += 1
                name, mode = c_string(args[0]), c_string(args[1])
                if name != 'dllimg.bin' or mode != 'rb': raise ValueError('Unexpected emulated file open')
                event.update(filename=name, mode=mode)
                if open_count == 2 and kind == 'module_return_5':
                    module = struct.pack('<4I', 0xea000000, 16, 0xe3a00006, 0xe12fff1e)
                result(0 if kind == 'missing_file' else HANDLE, set_zero=True)
            elif event['callback'] == 'seek':
                if args[0] != HANDLE: raise ValueError('Wrong file handle')
                position = file_length if args[2] == 2 else args[1]
                event.update(offset=args[1], origin=args[2])
                result(0)
            elif event['callback'] == 'tell':
                event['position'] = position
                result(position)
            elif event['callback'] == 'read':
                if args != [IMAGE, 1, len(module), HANDLE]:
                    raise ValueError('Unexpected file read arguments')
                uc.mem_write(args[0], module)
                event.update(destination=hex(args[0]), bytes=len(module),
                             module_sha256=hashlib.sha256(module).hexdigest())
                if len(module) <= 128: event['synthetic_module_hex'] = module.hex()
                result(len(module))
            else:
                if args[0] != HANDLE: raise ValueError('Wrong close handle')
                result(0)
            events.append(event)
        elif address == 0x221d2c:
            # Model the executable-image effect of the native CP15 cache
            # synchronization. Unicorn otherwise retains the first image's
            # translated block when the retry overwrites its instructions.
            uc.ctl_remove_cache(IMAGE, IMAGE+max(4096, len(module)))
            events.append({'hook': 'cache_sync_intercepted', 'emulator_image_cache_invalidated': True})
            result(0)
        elif address == 0x278964:
            left, right = c_string(args[0]), c_string(args[1])
            events.append({'hook': 'strcmp', 'left': left, 'right': right})
            result(0 if left == right else 1)
        elif address == IMAGE:
            module_calls += 1
            if args[0] != DESCRIPTOR: raise ValueError('Wrong module entry argument')
            events.append({'module_entry': hex(address), 'r0_descriptor': hex(args[0]),
                           'isa': 'ARM', 'payload_kind': kind})
        elif address == 0x2356bc:
            version, _, _, table, _, count = struct.unpack('<6I', uc.mem_read(args[1], 24))
            if not 0 < count <= 40: raise ValueError('Unexpected module export count')
            targets = list(struct.unpack('<'+'I'*count, uc.mem_read(table, count*4)))
            registration.append({'version': hex(version), 'module_descriptor': hex(args[1]),
                                 'export_table': hex(table), 'count': count,
                                 'targets': [hex(v) for v in targets]})
            if kind in ('original_voice', 'extended_voice'):
                if any(not IMAGE <= (value & ~1) < IMAGE+len(module) for value in targets):
                    raise ValueError('Original voice export outside loaded executable image')
                export_targets = targets
        elif address == RETURN:
            uc.emu_stop()

    hook_handle = uc.hook_add(UC_HOOK_CODE, hook)
    uc.reg_write(UC_ARM_REG_SP, 0x0200f000)
    uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
    try:
        uc.emu_start(INIT | 1, RETURN+2, timeout=5000000,
                     count=300000 if kind in ('compiled_decoder', 'original_voice', 'extended_voice') else 20000)
    except unicorn.UcError as error:
        raise RuntimeError(f'{kind}: {error}; PC={uc.reg_read(UC_ARM_REG_PC):#x}; '
                           f'last instructions={[hex(x) for x in visited[-12:]]}') from error
    if not visited or visited[-1] != RETURN:
        raise ValueError(f'Stock initializer failed to return: kind={kind}, '
                         f'PC={uc.reg_read(UC_ARM_REG_PC):#x}, instructions={len(visited)}, '
                         f'timeout={bool(uc.query(unicorn.UC_QUERY_TIMEOUT))}, '
                         f'last={[hex(v) for v in visited[-8:]]}')
    status = uc.reg_read(UC_ARM_REG_R0)
    import_storage = struct.unpack('<40I', stock.read(stock.runtime_to_load(0xf092c4, 160), 160))
    checks = []
    for index, pointer_storage in enumerate(import_storage):
        pointer = struct.unpack('<I', uc.mem_read(pointer_storage, 4))[0]
        words = struct.unpack('<3I', uc.mem_read(STUBS+index*12, 12))
        expected_target = (IMAGE+68+8*index) if kind.startswith('register_exports') and index < 2 else 0
        if kind in ('compiled_decoder', 'original_voice', 'extended_voice') and export_targets and index < len(export_targets):
            expected_target = export_targets[index]
        if pointer != STUBS+index*12 or words[:2] != (0xe59fc000, 0xe12fff1c) or words[2] != expected_target:
            raise ValueError('Trampoline generation differed from static model')
        checks.append({'slot': index, 'storage': hex(pointer_storage), 'trampoline': hex(pointer),
                       'target_word': hex(words[2])})
    descriptor_version = struct.unpack('<I', uc.mem_read(DESCRIPTOR, 4))[0]
    expected_status = {'valid_module': 11, 'missing_file': 0,
                       'file_over_limit': 4, 'header_over_limit': 9,
                       'module_return_5': 6, 'register_exports': 11,
                       'register_exports_minor_mismatch': 11, 'compiled_decoder': 11,
                       'original_voice': 11, 'extended_voice': 11}[kind]
    expected_calls = {'valid_module': 1, 'missing_file': 0,
                      'file_over_limit': 0, 'header_over_limit': 0,
                      'module_return_5': 2, 'register_exports': 1,
                      'register_exports_minor_mismatch': 1, 'compiled_decoder': 1,
                      'original_voice': None, 'extended_voice': None}[kind]
    if status != expected_status or (expected_calls is not None and module_calls != expected_calls):
        raise ValueError(f'Unexpected loader result in {kind}: {status}, {module_calls}')
    if kind in ('original_voice', 'extended_voice') and (not registration or not 1 <= module_calls <= 3):
        raise ValueError('Original voice did not register exports within the ABI retry range')
    if kind == 'module_return_5' and descriptor_version != 0x40000:
        raise ValueError('Retry did not decrement descriptor version')
    initializer_instructions_count = len(visited)
    exported_calls = []
    if kind.startswith('register_exports'):
        for index, expected in enumerate((0x23, 0x42)):
            visited.clear()
            uc.reg_write(UC_ARM_REG_SP, 0x0200f000)
            uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
            uc.emu_start(STUBS+index*12, RETURN+2, timeout=1000000, count=100)
            if not visited or visited[-1] != RETURN or uc.reg_read(UC_ARM_REG_R0) != expected:
                raise ValueError('Registered ARM export failed through stock trampoline')
            exported_calls.append({'slot': index, 'returned': expected,
                                   'instructions': [hex(x) for x in visited]})
    report = {'name': kind, 'status': status, 'expected_status': expected_status,
            'synthetic_module_entries': module_calls, 'opens': open_count,
            'descriptor_word_0': hex(descriptor_version), 'events': events,
            'trampolines_verified': checks, 'exported_calls': exported_calls,
            'module_export_registration': registration,
            'initializer_instructions_executed': initializer_instructions_count, 'passed': True}
    if return_session:
        uc.hook_del(hook_handle)
        return uc, report
    return report


def main():
    stock = NativeImage()
    names = ['valid_module', 'missing_file', 'file_over_limit', 'header_over_limit',
             'module_return_5', 'register_exports', 'register_exports_minor_mismatch']
    results = [simulate(stock, name) for name in names]
    output = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'emulator': 'Unicorn', 'version': unicorn.__version__, 'cpu_model': 'ARM1176',
              'stock_initializer_executed': hex(INIT), 'cases': results, 'all_passed': True,
              'device_io': False, 'filesystem_callbacks_synthetic': True,
              'cache_sync_intercepted': True, 'string_compare_intercepted': True,
              'real_caller_conditions_tested': False, 'native_on_device_verified': False,
              'limitations': 'Exact stock initializer/read/executor/trampoline/export-registration instructions and stock ARM memcpy run in emulation. File callbacks, cache synchronization and strcmp are controlled hooks. ARM payloads are synthetic return functions; two benign exports are registered/called but none implement the original component APIs. No device installation location, reachable user trigger, full module ABI, GUI or speaker playback is verified. Do not install these dummy images: required original component API stubs remain zero.'}
    path = ROOT / 'evidence/firmware-analysis/native-loader-emulation.json'
    path.write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'cases_passed': len(results),
                      'stock_loader_emulated': True, 'native_on_device_verified': False,
                      'device_io': False}))


if __name__ == '__main__':
    main()
