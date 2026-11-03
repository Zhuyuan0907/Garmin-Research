#!/usr/bin/env python3
"""Native read/XOR/path/seek tests over exact raw backup font bytes."""
import struct
from emulate_native_player_menu_selection import SQL_OUT
from emulate_native_vpm_filesystem import require


def run(vm):
    pathbuf, buffer = SQL_OUT+0x2000, SQL_OUT+0x2200
    controls = []

    def open_file(logical):
        vm.uc.mem_write(pathbuf, logical.encode('ascii')+b'\0')
        return vm.invoke(0x14093f, (pathbuf, 0))

    def read_sample(handle, element_bytes, elements, offset):
        file = vm.external_files[handle]
        raw = vm.raw_font_sources[file['path']]
        requested = element_bytes*elements
        available = min(requested, max(0, len(raw)-offset))
        vm.uc.mem_write(buffer-32, b'\xa5'*(64+32))
        returned = vm.invoke(0x14098d, (buffer, element_bytes, elements, handle))
        actual = bytes(vm.uc.mem_read(buffer, available))
        expected = bytes(b^0x76 for b in raw[offset:offset+available])
        require(actual == expected and returned == available//(element_bytes or 1),
            'Native raw read/XOR/element return differs')
        require(bytes(vm.uc.mem_read(buffer-32, 32)) == b'\xa5'*32 and
            bytes(vm.uc.mem_read(buffer+available, 64-available)) == b'\xa5'*(64-available),
            'Native read transformed unreturned bytes or crossed sample buffer')
        require(vm.invoke(0x1409d1, (handle,)) == offset+available, 'Native tell differs')
        return dict(element_bytes=element_bytes, elements=elements, requested_bytes=requested,
            returned_bytes=available, returned_elements=returned, byte_offset=offset,
            native_decoded_bytes=actual.hex(), native_XOR_matches_independent_bytes=True,
            canaries_and_all_unreturned_bytes_unchanged=True)

    for logical in sorted(vm.raw_font_sources):
        handle = open_file(logical)
        require(handle in vm.external_files, 'Original font wrapper failed to open exact backup')
        header = read_sample(handle, 1, 16, 0)
        require(bytes.fromhex(header['native_decoded_bytes'])[:4] == b'\x00\x01\x00\x00',
            'Original XOR did not restore sfnt header')
        require(vm.invoke(0x1409bf, (handle, 7, 0)) == 0, 'Original absolute seek failed')
        sample = read_sample(handle, 1, 13, 7)
        require(vm.invoke(0x140937, (handle,)) == 0 and vm.external_files[handle]['closed'],
            'Original font close wrapper failed')
        controls.append(dict(path=logical, header=header, nonzero_unaligned_offset=sample,
            closed_through_original_wrapper=True))
    logical = next(p for p in vm.raw_font_sources if p.endswith('006-D0952-01.bin'))
    handle = open_file(logical)
    length = len(vm.raw_font_sources[logical])
    require(vm.invoke(0x1409bf, (handle, 0xfffffff9, 2)) == 0, 'Original signed EOF-relative seek failed')
    partial = read_sample(handle, 4, 3, length-7)
    require(partial['returned_elements'] == 1 and partial['returned_bytes'] == 7, 'Partial element control differs')
    eof = read_sample(handle, 1, 16, length)
    zero = read_sample(handle, 0, 3, length)
    vm.invoke(0x140937, (handle,))
    missing = []
    for logical in sorted(set(vm.backup_paths)-set(vm.raw_font_sources)):
        require(open_file(logical) == 0, 'Absent exact backup font accepted')
        missing.append(dict(path=logical, returned=0, backup_file_present=False))
    require(len(controls) == 8 and len(missing) == 2 and
        all(e['closed'] for e in vm.external_files.values()), 'Read controls leaked a file or inventory differs')
    return dict(name='eight_original_font_path_read_XOR_seek_close_headers_and_EOF_controls',
        passed=True, original_read_transform='0x14098c', original_XOR_instruction='0x1409a8',
        raw_source_control_count=8, controls=controls, signed_EOF_relative_partial_element=partial,
        EOF_zero_return=eof, zero_element_size_return=zero, missing_file_controls=missing,
        generic_file_manager_inventory_IO_is_fixture=True, host_decoded_font_bytes_supplied=False,
        original_path_conversion_and_XOR_and_element_division_executed=True,
        all_control_files_closed_before_font_initializer=True, device_io=False)
