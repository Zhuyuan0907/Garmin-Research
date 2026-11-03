#!/usr/bin/env python3
"""Stock font file wrappers/byte transform backed by read-only USB backup.

Only generic file-manager inventory/read/seek/close/tell boundaries are supplied.
Native path conversion, XOR14098C, font parser and glyph queries execute unchanged.
This is not a physical filesystem, boot sequence, displayed UI or installation.
"""
from datetime import datetime, timezone
import hashlib
import json
import struct
import sys
from pathlib import Path
import unicorn
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_SP
from analyze_native_sections import NativeImage, ROOT
from emulate_native_player_text import TextVM
from emulate_native_player_grid import GridVM
from emulate_native_vpm_filesystem import REGS, require

STAGE = ROOT/'staging/native-player-external-fonts'
BUILD = 'staging/native-player-text/manifest.json'
FONT_IO = {0x31d09a: 'open', 0x31cf22: 'read', 0x31d1ce: 'seek',
    0x31ce8c: 'close', 0x31d2e0: 'tell'}


class ExternalFontVM(TextVM):
    def __init__(self, stock, build):
        self.external_files = {}
        self.external_file_requests = []
        self.native_font_file_calls = []
        self.raw_font_sources = {}
        self.backup_paths = {}
        self.external_IO_active = False
        super().__init__(stock, build)
        table = stock.runtime_to_load(0xf088b0, 13*16)
        for n in range(13):
            pointer, kind, length, flags = struct.unpack('<4I', stock.read(table+16*n, 16))
            if kind != 2:
                filename = stock.read(pointer+50, 100).split(b'\0', 1)[0].decode('ascii')
                path = ROOT/'backups/20261002T154458Z/files/.System/ExtData'/filename
                logical = '0:/.System/ExtData/'+filename
                self.backup_paths[logical] = path
                if path.is_file():
                    self.raw_font_sources[logical] = path.read_bytes()

    def observe(self, uc, address, size, data):
        if address in [0x14093e, 0x14098c, 0x1409be, 0x140936, 0x1409d0,
            0x14f034, 0x14f084, 0x266a82, 0x2654e4, 0x26887a]:
            self.native_font_file_calls.append(dict(entry=hex(address),
                arguments=[uc.reg_read(r) for r in REGS], caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1)))
        kind = FONT_IO.get(address)
        if self.external_IO_active and kind:
            args = [uc.reg_read(r) for r in REGS]
            if kind == 'open':
                path = self.wide(args[0])
                require(path in self.backup_paths and args[1] == 1, 'Unexpected font open path/mode')
                if path in self.raw_font_sources:
                    handle = 0x09110000+len(self.external_files)*0x40
                    self.external_files[handle] = dict(path=path, position=0, closed=False)
                    self.put(args[2], handle)
                    result = 0
                else:
                    handle = 0
                    self.put(args[2], 0)
                    result = 1
                row = dict(operation=kind, path=path, handle=hex(handle), result=result,
                    original_font_path_conversion_executed=True,
                    absent_file_is_absent_from_exact_backup=not bool(handle))
            else:
                handle = args[0]
                require(handle in self.external_files, 'Unknown virtual font file handle')
                entry = self.external_files[handle]
                require(not entry['closed'], 'Use of closed virtual font file')
                raw = self.raw_font_sources[entry['path']]
                row = dict(operation=kind, handle=hex(handle), path=entry['path'],
                    position_before=entry['position'])
                if kind == 'read':
                    require(0 < args[2] <= 0x100000, 'Unexpected font file read size')
                    available = min(args[2], max(0, len(raw)-entry['position']))
                    chunk = raw[entry['position']:entry['position']+available]
                    if chunk:
                        uc.mem_write(args[1], chunk)
                    entry['position'] += available
                    result = available
                    row.update(requested_bytes=args[2], returned_bytes=available,
                        destination=hex(args[1]), supplied_raw_bytes_SHA256=hashlib.sha256(chunk).hexdigest(),
                        host_decoded_font_bytes_supplied=False)
                elif kind == 'seek':
                    offset = args[2]+(args[3]<<32)
                    if offset >= 1<<63:
                        offset -= 1<<64
                    origin = self.word(uc.reg_read(UC_ARM_REG_SP))
                    require(origin in [0, 1, 2], 'Unexpected font seek origin')
                    position = [0, entry['position'], len(raw)][origin]+offset
                    require(0 <= position <= len(raw), 'Font seek outside exact backup file')
                    entry['position'] = position
                    result = 0
                    row.update(signed_offset=offset, origin=origin, position_after=position)
                elif kind == 'tell':
                    result = entry['position']
                    uc.reg_write(REGS[1], 0)
                else:
                    entry['closed'] = True
                    result = 0
            self.visits[address] += 1
            row.update(boundary=hex(address), generic_file_manager_fixture=True,
                caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1))
            self.external_file_requests.append(row)
            self.ret(result)
            return
        return super().observe(uc, address, size, data)

    def verify_released(self):
        # Preserve frozen TextVM ownership rules with a new output path;
        # never rewrite the old proof's development inventory artifact.
        handles = self.handles
        released = {int(r['handle'], 16) for r in self.font_release_records}
        live = set()
        for handle in self.font_handles:
            entry = handles[handle]
            p, n = entry['pointer'], entry['length']
            if entry['freed']:
                require(entry['locks'] == 0 and handle in released, 'Font temporary release differs')
            else:
                require(entry['locks'] == 0 and
                    any(int(r['handle'], 16) == handle for r in self.font_pointer_queries),
                    'Font bookkeeping or original pointer query differs')
                require(self.word(p) == handle and 0 < self.word(p+4) <= n-8, 'Original font malloc prefix differs')
                live.add(handle)
            require(bytes(self.uc.mem_read(p-32, 32)) == b'\xa5'*32 and
                bytes(self.uc.mem_read(p+n, 32)) == b'\xa5'*32, 'Font allocation canary differs')
        self.handles = {h: e for h, e in handles.items() if h not in live}
        try:
            GridVM.verify_released(self)
        finally:
            self.handles = handles


def main():
    require(unicorn.__version__ == '2.1.4' and unicorn.uc_version() == (2, 1, 33621247),
        'Use isolated Unicorn2.1.4')
    vm = ExternalFontVM(NativeImage(), json.loads((ROOT/BUILD).read_text()))
    result = dict(device_io=False, sounds_emitted=False, original_external_font_loading_parameter=1,
        original_font_byte_transform_executed=False, host_decoded_font_bytes_supplied=False)
    try:
        if '--full-load' in sys.argv:
            print(json.dumps(dict(phase='before_original_outer_loader')), flush=True)
            result['outer_load'] = vm.load()
        vm.external_IO_active = True
        vm.invoke(0x4df249, ())
        result['phase'] = 'before_original_external_font_runtime_initializer'
        print(json.dumps(dict(phase=result['phase'])), flush=True)
        status = vm.invoke(0x4de237, (1,))
        result.update(phase='original_external_font_runtime_initializer_returned',
            original_return=status, fonts=vm.fonts(), current_context=hex(vm.word(0xf071f0)))
        result['glyphs'] = []
        for row in vm.fonts():
            if row['metadata_flags'][1]:
                context = int(row['context'], 16)
                glyphs = {hex(ord(c)): vm.invoke(0x26849f, (context, ord(c))) for c in 'Pi播放器竺原'}
                result['glyphs'].append(dict(font_index=row['index'], native_glyph_indices=glyphs))
        for pointer, entry in vm.raw_allocations.items():
            vm.verify_guard(pointer, entry)
        vm.verify_released()
        result.update(completed=True, guards_checked=True,
            original_font_byte_transform_executed=bool(vm.visits[0x14098c]))
    except Exception as error:
        result.update(completed=False, error=str(error), recent=list(vm.recent), invalid_accesses=vm.invalid_accesses,
            registers={vm.uc.reg_name(r): hex(vm.uc.reg_read(r)) for r in REGS+(UC_ARM_REG_LR, UC_ARM_REG_SP)})
    result.update(updated_utc=datetime.now(timezone.utc).isoformat(), native_file_calls=vm.native_font_file_calls,
        generic_file_manager_requests=vm.external_file_requests, font_calls=vm.font_calls,
        allocator_calls=vm.font_allocator_records, active_file_handles=vm.external_files,
        font_handles=[dict(handle=hex(h), **vm.handles[h]) for h in sorted(vm.font_handles)],
        original_GUI_once_writes=vm.conditional_region_writes, startup_zero_pages=vm.zero_pages)
    (STAGE/'development-probe.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ['native_file_calls',
        'generic_file_manager_requests', 'font_calls', 'allocator_calls', 'active_file_handles',
        'font_handles', 'startup_zero_pages', 'fonts']}, ensure_ascii=False), flush=True)
    if not result['completed']:
        sys.exit(1)


if __name__ == '__main__':
    main()
