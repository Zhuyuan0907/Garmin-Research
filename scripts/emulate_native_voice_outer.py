#!/usr/bin/env python3
"""Original outer binding/activation/region I/O with a virtual file backend.

Directory listing, a filesystem driver's open/read/close callbacks, heap/kernel
and initialized inventories are explicit fixtures. Original generic file API,
mapped region lifecycle and the complete activation wrapper execute unmodified.
No physical storage, Bluetooth, update image or device installation is involved.
"""
from datetime import datetime, timezone
import json
import struct
from pathlib import Path
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_tts_vpm import parse_image, sha, require
from emulate_native_voice_metadata import VoiceMetadata
from emulate_native_voice_selection import SelectionVM, APP, PACKAGE
from emulate_native_voice_registry import REGS, STACK, HEAD
from emulate_native_vpm_filesystem import DRIVE, REGION, VOLUMES
from analyze_native_loader import INIT, IMAGE, DESCRIPTOR, STUBS
from emulate_native_loader import simulate

DRIVES = 0x08020000
OUTER_FILES = 0x08021000
OPS = 0x08022000
CHILDREN = 0x08024000
FILE_OPEN, FILE_READ, FILE_CLOSE = 0x10200, 0x10220, 0x10240
BOUND = 0x105e424
REGION_TABLE = 0x105e624
CACHE_NAMES = 0x10425dc


class OuterVM(SelectionVM):
    def __init__(self, stock, inventory, *, open_errors=(), selected_voice=''):
        self.backend_events = []
        self.backend_children = {}
        self.open_errors = list(open_errors)
        self.native_bound_calls = []
        self.native_activation_calls = []
        super().__init__(stock, inventory)
        for page in [0x1042000, 0x105e000, 0x1057000]:
            self.uc.mem_map(page, 4096)
        self.hooks.pop(0x2d3380)
        # These are initialized inventories, not recovered board driver tables.
        self.uc.mem_write(0xf001a4, b'\0')
        self.uc.mem_write(0xf001a8, b'\x01')
        self.put(0xf001ac, DRIVES)
        self.put(0xf0019c, 4)
        self.put(0xf001a0, OUTER_FILES)
        self.uc.mem_write(DRIVES, b'\x01\x00\x00\x01')
        self.put(DRIVES + 0x18, OPS)
        for offset, target in [(0, FILE_OPEN), (4, FILE_CLOSE), (8, FILE_READ)]:
            self.put(OPS + offset, target | 1)
        if selected_voice:
            # Cached settings are explicit fixture data, not a recovered
            # settings initializer or a measured live device preference.
            require(len(selected_voice) < 19, 'Fixture selection ID too long')
            self.uc.mem_write(0xf09638, (selected_voice + '\0').encode('utf-16le'))

    def summarize(self):
        return {
            'native_entries_executed': {hex(a): self.visits[a] for a in
                [0x2d3166, 0x2d32de, 0xfea50, 0x2d3380, 0x31d09a,
                 0x31d032, 0x31cfe4, 0x24e790, 0x1fdc0c, 0x31cf22,
                 0x1fde12, 0x31d1ce, 0x1fdeb2, 0x31d2e0, 0x1fe010,
                 0x31cf5c, 0x31ce8c, 0x1fdaca, 0x31e3be, 0x1fdb8e,
                 0x1c0600, 0x1c0624, 0x358d24]},
            'driver_open_close_events': [e for e in self.backend_events
                                       if e['operation'] != 'driver_read_fixture'],
            'driver_read_count': sum(e['operation'] == 'driver_read_fixture' for e in self.backend_events),
            'mapped_region_state': list(self.uc.mem_read(BOUND + REGION * 2, 2)),
            'pool_count': self.uc.mem_read(0xf001a4, 1)[0],
            'activation_calls': self.native_activation_calls,
            'generic_API_binding_activation_region_read_unhooked': True,
            'directory_driver_callbacks_heap_kernel_tables_are_fixtures': True,
        }

    def verify_released(self):
        self.verify_closed_files()
        require(not any(self.mutexes.values()), 'Native flow left a fixture mutex held')
        require(self.uc.reg_read(UC_ARM_REG_SP) == STACK, 'Native SP changed')
        retained = {r['handle'] for r in self.registry()}
        for handle, entry in self.handles.items():
            require(entry['freed'] == (handle not in retained), 'Temporary outer handle not released')
            p, n = entry['pointer'], entry['length']
            require(bytes(self.uc.mem_read(p - 32, 32)) == b'\xa5' * 32 and
                    bytes(self.uc.mem_read(p + n, 32)) == b'\xa5' * 32, 'Outer heap guard changed')
        require(all(row['closed'] for row in self.backend_children.values()), 'Virtual file retained')
        require(not any(self.uc.mem_read(OUTER_FILES + 72 * i, 1)[0] for i in range(4)),
                'Original generic file object remained active')
        require(not self.word(CACHE_NAMES + DRIVE * 4), 'Activation wrapper pathname retained')
        require(not self.uc.mem_read(BOUND + REGION * 2, 1)[0], 'Mapped region remained bound')
        require(all(bytes(self.uc.mem_read(a, len(raw))) == raw for a, raw in self.code_images),
                'Original code modified')

    def select_component(self, binary, ram_bytes, app=None):
        require(self.mount(), 'Complete activation wrapper failed before native readback')
        status, handle = self.open('dllimg.bin')
        require(status == 0, 'Original embedded binary open failed')
        readback = self.read_file(handle)
        self.close(handle)
        require(readback == binary, 'Native readback mismatch before execution')
        # Preread is a validation pass, not selector setup: original1D8514
        # requires an unused mapping and returns false on already-bound2.
        # Release its real activation cache/file before the native selector.
        self.call(0xfea50, (DRIVE, 0))
        self.call(0x2d32de, (REGION,))
        self.verify_released()
        self.allow_module_execution = True
        self.uc.mem_write(IMAGE, b'\xa5' * ram_bytes)
        self.call(0x240498, (0, 0))
        require(self.word(0xf095b0) == 0 and self.loader_return == 11 and self.init_calls == 1,
                'Original selector did not load once and return11')
        control, baseline = simulate(self.stock, 'extended_voice', module_bytes=binary,
            module_ram_bytes=ram_bytes, poison_module_ram=True, return_session=True)
        loaded = bytes(self.uc.mem_read(IMAGE, ram_bytes))
        require(loaded == bytes(control.mem_read(IMAGE, ram_bytes)), 'Runtime differs from loader control')
        require(bytes(self.uc.mem_read(STUBS, 40 * 12)) == bytes(control.mem_read(STUBS, 40 * 12)),
                'Original40 trampolines changed')
        require(IMAGE + ram_bytes <= DESCRIPTOR, 'Original reservation exceeded')
        if app:
            state = app['symbols']['app_component_state']['address']
            require(struct.unpack('<Iii', self.uc.mem_read(state, 12)) == (1, 11, 0), 'Private entry state differs')
            table = app['symbols']['app_component_api']['address']
            require(list(struct.unpack('<12I', self.uc.mem_read(table, 48))) ==
                [app['symbols'][n]['address'] for n in app['private_api']], 'Private12 table differs')
        compatible = self.call(0x222a34, (0,))
        diagnostic = list(self.diagnostics)
        enabled = self.uc.mem_read(0xf0968a, 1)[0]
        # Explicit offline cleanup after synchronous initialization only.
        # No worker/callback has been started; this is not safe unload proof.
        self.call(0xfea50, (DRIVE, 0))
        self.call(0x2d32de, (REGION,))
        self.verify_released()
        return {'loader_result': self.loader_return, 'independent_control_result': baseline['status'],
            'runtime_sha256': sha(loaded), 'runtime_bytes': ram_bytes,
            'original40_trampolines_and_runtime_match_control': True,
            'private12_initialized_without_workers_or_music_registration': app is not None,
            'native_compatibility_result': compatible, 'selection_diagnostics': diagnostic,
            'original_success_path_enabled_byte': enabled,
            'current_selection_cache_is_fixture_not_live_preference': True,
            'execution_budget_same_VM_resumes': self.execution_resumes,
            'cleanup_only_after_synchronous_INIT_not_safe_worker_unload': True,
            'original_code_registry_heap_SP_and_closed_objects_verified': True,
            'outer': self.summarize()}

    def observe(self, uc, address, size, unused):
        if address in [0x2d3166, 0xfea50, 0x2d32de]:
            if address == 0x2d3166:
                self.native_bound_calls.append([uc.reg_read(r) for r in REGS])
            elif address == 0xfea50:
                self.native_activation_calls.append([uc.reg_read(r) for r in REGS[:2]])
            # Bypass only the older harness's high-level fixtures; execute
            # the original instruction at this address, including region I/O.
            return VoiceMetadata.observe(self, uc, address, size, unused)
        if address in [FILE_OPEN, FILE_READ, FILE_CLOSE, 0x38853c,
                       0x3887a6, 0x300934, 0x3008a0]:
            self.visits[address] += 1
            args = [uc.reg_read(r) for r in REGS]
            if address == FILE_OPEN:
                drive, obj = args[:2]
                require(drive == DRIVES, 'Unexpected virtual driver ABI')
                name = self.wide(self.handles[self.word(obj + 4)]['pointer'])
                row = next((r for r in self.inventory if name == '/Garmin/Voice/' + r['name']), None)
                require(row is not None, 'Virtual file path absent from immutable inventory')
                error = self.open_errors.pop(0) if self.open_errors else 0
                self.backend_events.append({'operation': 'driver_open_fixture', 'path': name,
                    'mode': struct.unpack('<H', uc.mem_read(obj + 2, 2))[0], 'result': error})
                if error:
                    self.ret(error)
                    return
                child = CHILDREN + len(self.backend_children) * 128
                require(child + 128 <= 0x08028000, 'Virtual driver child inventory exhausted')
                self.backend_children[child] = {'data': row['data'], 'closed': False}
                uc.mem_write(child, b'\x01\x00\x01\x00')
                self.put(child + 0x20, len(row['data']))
                self.put(child + 0x2c, DRIVES)
                self.put(obj + 0xc, child)
                self.ret()
                return
            if address == FILE_READ:
                child, destination, low, high = args
                count = self.word(uc.reg_read(UC_ARM_REG_SP))
                row = self.backend_children[child]
                require(not row['closed'] and high == 0 and 0 < count <= 4096,
                        'Unexpected virtual read or closed file')
                require(0x08000000 <= destination and destination + count <= 0x08600000,
                        'Virtual read destination outside fixture RAM')
                data = row['data'][low:low + count]
                uc.mem_write(destination, data)
                self.backend_events.append({'operation': 'driver_read_fixture',
                    'offset': low, 'requested': count, 'returned': len(data)})
                self.ret(len(data))
                return
            if address == FILE_CLOSE:
                row = self.backend_children[args[0]]
                require(not row['closed'], 'Virtual driver double close')
                row['closed'] = True
                self.backend_events.append({'operation': 'driver_close_fixture'})
                self.ret()
                return
            if address == 0x38853c:
                length, kind, output = args[:3]
                require(0 < length <= 4096 and kind in [0, 1], 'Unexpected heap allocation')
                handle = 0xd0000000 + len(self.handles) + 1
                pointer = self.next_heap
                self.next_heap += (length + 127) & ~63
                require(self.next_heap < 0x080f0000, 'Heap exhausted')
                uc.mem_write(pointer - 32, b'\xa5' * (length + 64))
                self.handles[handle] = {'pointer': pointer, 'length': length,
                                       'locks': 0, 'freed': False}
                self.allocations.append({'length': length, 'kind': kind})
                if output:
                    self.put(output, handle)
                self.ret(handle)
                return
            if address == 0x3887a6:
                self.ret(self.handles[args[0]]['length'])
                return
            if address == 0x300934:
                self.mutexes[args[0]] += 1
                self.ret(1)
                return
            self.ret()
            return
        return super().observe(uc, address, size, unused)

    def mount(self):
        if not self.uc.mem_read(BOUND + REGION * 2, 1)[0]:
            path = 0x0802c000
            self.uc.mem_write(path, ('0:/Garmin/Voice/' + self.inventory[0]['name'] + '\0').encode('utf-16le'))
            require(self.call(0x2d3166, (0, REGION, path)) == 0, 'Original binding failed')
        self.call(0xfea50, (DRIVE, 1))
        return self.uc.mem_read(VOLUMES + DRIVE * 116, 1)[0] == 1


def main():
    stock = NativeImage()
    package = json.loads((ROOT / PACKAGE).read_text())
    app = json.loads((ROOT / APP).read_text())
    inventory = json.loads((ROOT / 'evidence/firmware-analysis/tts-vpm-containers.json').read_text())['containers']
    rows = [r for r in inventory if r['native_module_container']]
    cases = []
    for row in rows:
        data = (ROOT / row['file']).read_bytes()
        vm = OuterVM(stock, [{'name': Path(row['file']).name, 'data': data}])
        result = vm.enumerate()
        require(len(result['registry']) == 1, 'Native outer flow did not register voice')
        vm.verify_released()
        cases.append({'name': 'outer_original_' + Path(row['file']).stem, 'passed': True,
            'package_sha256': sha(data), 'registry': result['registry'], 'outer': vm.summarize(),
            'original_code_heap_SP_all_outer_objects_released': True})
    data = (ROOT / package['original_package']).read_bytes()
    path = 0x0802c000
    for name, errors, expected, busy, pool in [
        ('native_bind_close', (), 0, False, 0),
        ('native_bind_second_open_readonly_fallback', (9, 0), 0, False, 0),
        ('native_bind_existing_mapping_returns2', (), 2, True, 0),
        ('native_bind_deferred_missing_file_returns3', (2, 2), 3, False, 0),
        ('native_bind_failed_driver_opens_return1', (9, 9), 1, False, 0),
        ('native_bind_full32_pool_skips_open', (), 1, False, 32)]:
        vm = OuterVM(stock, [{'name': 'Chinese_Big5_MeiLing.vpm', 'data': data}], open_errors=errors)
        vm.uc.mem_write(path, '0:/Garmin/Voice/Chinese_Big5_MeiLing.vpm\0'.encode('utf-16le'))
        vm.uc.mem_write(0xf001a4, bytes([pool]))
        first = vm.call(0x2d3166, (0, REGION, path))
        actual = vm.call(0x2d3166, (0, REGION, path)) if busy else first
        require(actual == expected, name + ': unexpected native status')
        bound = list(vm.uc.mem_read(BOUND + REGION * 2, 2))
        record = bytes(vm.uc.mem_read(REGION_TABLE + bound[1] * 36, 36)) if bound[0] else None
        vm.call(0x2d32de, (REGION,))
        vm.verify_released()
        cases.append({'name': name, 'passed': True, 'native_status': actual, 'state_before_unbind': bound,
            'record_before_unbind_hex': record.hex() if record else None,
            'original_code_heap_SP_all_outer_objects_released': True, 'outer': vm.summarize()})
    for name, package_path, selected, changed in [
        ('full_outer_original_selected_compatible', package['original_package'], 'mei-lingb', False),
        ('full_outer_preserving_component_selected_compatible', package['package'], 'mei-lingb', True),
        ('full_outer_original_empty_cached_selection_diagnostic409', package['original_package'], '', False)]:
        data = (ROOT / package_path).read_bytes()
        vm = OuterVM(stock, [{'name': 'Chinese_Big5_MeiLing.vpm', 'data': data}], selected_voice=selected)
        vm.enumerate()
        files, _ = parse_image(data)
        binary = files['DLLIMG.BIN']['content']
        result = vm.select_component(binary, struct.unpack_from('<I', binary, 4)[0], app if changed else None)
        require(result['native_compatibility_result'] == bool(selected), 'Compatibility control differs')
        require((not result['selection_diagnostics']) == bool(selected), 'Diagnostic control differs')
        require(result['original_success_path_enabled_byte'] == bool(selected), 'Original success branch differs')
        cases.append({'name': name, 'passed': True, 'package_sha256': sha(data), 'selection': result})
    deps = [Path(__file__), ROOT / 'scripts/emulate_native_voice_selection.py',
        ROOT / 'scripts/emulate_native_voice_registry.py', ROOT / 'scripts/emulate_native_voice_metadata.py',
        ROOT / 'scripts/emulate_native_vpm_filesystem.py', ROOT / 'scripts/analyze_native_sections.py',
        ROOT / 'scripts/analyze_tts_vpm.py', ROOT / 'scripts/analyze_native_loader.py',
        ROOT / 'scripts/emulate_native_loader.py', ROOT / 'scripts/build_native_voice_package_fixture.py']
    evidence = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'MAIN_sha256': EXPECTED,
        'all_passed': True, 'case_count': len(cases), 'cases': cases,
        'source_sha256': {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in deps},
        'package_manifest': PACKAGE, 'package_manifest_sha256': sha((ROOT / PACKAGE).read_bytes()),
        'component_manifest': APP, 'component_manifest_sha256': sha((ROOT / APP).read_bytes()),
        'generic_file_API_region_binding_read_unbind_full_activation_execute_original': True,
        'original_current_task_helpers_are_mutex_not_IRQ_save_restore': True,
        'native_TCB_helper358D24_executed_not_timestamp_fixture': True,
        'cached_voice_selection_fixture_removes_diagnostic_without_helper_override': True,
        'actual_filesystem_driver_table_board_storage_cache_settings_initializer_verified': False,
        'real_modified_package_acceptance_or_signature_policy_verified': False,
        'App_UI_phone_radio_speaker_or_worker_safe_unload_verified': False,
        'device_io': False, 'backup_modified': False, 'device_install_candidate': False,
        'limits': 'Original enum/generic open/driver dispatch/mapped-region bind-read-unbind/fullFEA50 activation and pathname cache/embedded parser/metadata/selector/loader execute. Directory inventory, virtual driver open/read/close, initialized file/drive tables, heap/kernel remain fixtures; not actual FAT/board registration. Cached current voice ID seeded explicitly, not a recovered settings initializer/live preference. Matching original selection passes unchanged language/version check and executes success byte update; empty selection yields diagnostic409. Synchronous INIT preserves40/private12 but starts no worker or music endpoint. No installation/signature/global-policy/UI/phone/speaker/safe-unload proof.'}
    out = ROOT / 'evidence/firmware-analysis/native-voice-outer-emulation.json'
    out.write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'evidence': str(out.relative_to(ROOT)), 'case_count': len(cases), 'all_passed': True}))


if __name__ == '__main__':
    main()
