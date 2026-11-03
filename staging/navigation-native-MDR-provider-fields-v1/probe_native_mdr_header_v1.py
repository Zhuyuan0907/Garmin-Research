#!/usr/bin/env python3
"""Bounded stock native MDR-header parser, with explicit synthetic file I/O.

Executes original parser/read-wrapper/string/memzero/division instructions.
Only filesystem open/read are supplied by a header-only synthetic file; no
query, map availability, sorting policy, producer or result hooks are used.
Stop before any subsequent extension-data section access.
"""
import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
sys.path.insert(0, str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.arm_const import *

HERE = Path(__file__).resolve().parent
CTX, FILE, STACK, RET = 0x09000000, 0x09001000, 0x09010000, 0x09004000
STOP = 0x2CD49E
PAGES = [0x1C8000, 0x2CC000, 0x2CD000, 0x2D9000, 0x332000,
         0x349000, 0x359000, 0x35B000, 0x373000, 0x38C000, 0x391000]


def invoke(image, header, name):
    u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    u.ctl_set_cpu_model(UC_CPU_ARM_1176)
    code_pages = []
    for page in PAGES:
        raw = image.read(page, 4096)
        u.mem_map(page, 4096)
        u.mem_write(page, raw)
        u.mem_protect(page, 4096, UC_PROT_READ | UC_PROT_EXEC)
        code_pages.append(dict(address=hex(page), bytes=4096,
                               sha256=hashlib.sha256(raw).hexdigest()))
    u.mem_map(CTX, 0x3000)
    u.mem_map(STACK, 0x4000)
    u.mem_map(RET, 0x1000)
    u.mem_write(RET, b'\x70\x47')
    u.mem_protect(RET, 4096, UC_PROT_READ | UC_PROT_EXEC)
    u.mem_write(CTX, b'00004171\0')
    # Synthetic existing-open file ABI expected by original kind0 readwrapper.
    u.mem_write(FILE, bytes(64))
    u.mem_write(FILE+11, b'\x40')
    trace, reads, cursors, divisions, opens = [], [], [], [], []
    stop_reached = False

    def readword(address):
        return struct.unpack('<I', u.mem_read(address, 4))[0]

    def code(uc, address, size, _):
        nonlocal stop_reached
        trace.append(dict(pc=hex(address), bytes=bytes(uc.mem_read(address,size)).hex(),
                          thumb=bool(uc.reg_read(UC_ARM_REG_CPSR)&32)))
        if address == STOP:
            stop_reached = True
            uc.emu_stop()
        elif address == RET:
            uc.emu_stop()
        elif address == 0x1C8682:
            # Only open is mocked; recorded ABI, filename and result descriptor.
            destination = uc.reg_read(UC_ARM_REG_R1)
            opens.append(dict(callee='0x1c8682', output_descriptor=hex(destination),
                              input_map_handle=hex(uc.reg_read(UC_ARM_REG_R0)),
                              synthetic=True))
            uc.mem_write(destination, struct.pack('<2I', FILE, 0))
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif address == 0x3324B8:
            # Real readwrapper set/kept FILE+0x10 cursor before reaching this I/O.
            file_pointer = uc.reg_read(UC_ARM_REG_R0)
            destination = uc.reg_read(UC_ARM_REG_R1)
            count = uc.reg_read(UC_ARM_REG_R2)
            if file_pointer != FILE:
                raise ValueError('Unrecognized synthetic file handle')
            offset = readword(FILE+0x10)
            if not (0 <= offset <= len(header)-count):
                raise ValueError(f'Header-only file read outside bounds: {offset:#x}+{count:#x}')
            payload = header[offset:offset+count]
            uc.mem_write(destination, payload)
            uc.mem_write(FILE+0x10,struct.pack('<I',offset+count))
            reads.append(dict(offset=offset, bytes=count, source_bytes_hex=payload.hex(),
                              destination=hex(destination), synthetic_file_read=True))
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        elif address in [0x2CD376,0x2CD3F4,0x2CD446,0x2CD450,0x2CD47A]:
            sp = uc.reg_read(UC_ARM_REG_SP)
            cursors.append(dict(pc=hex(address), r0=uc.reg_read(UC_ARM_REG_R0),
                                header_cursor_stack8c=readword(sp+0x8c),
                                real_file_cursor=readword(FILE+0x10)))
        elif address == 0x38C168:
            divisions.append(dict(pc='0x38c168', numerator=uc.reg_read(UC_ARM_REG_R0),
                                  denominator=uc.reg_read(UC_ARM_REG_R1),
                                  native_instructions_executed=True,
                                  caller_LR=hex(uc.reg_read(UC_ARM_REG_LR))))

    u.hook_add(UC_HOOK_CODE, code)
    u.reg_write(UC_ARM_REG_CPSR, 0x3f)
    u.reg_write(UC_ARM_REG_SP, STACK+0x3000)
    u.reg_write(UC_ARM_REG_LR, RET|1)
    u.reg_write(UC_ARM_REG_R0, CTX)
    try:
        u.emu_start(0x2CC44D, RET+2, count=180000, timeout=2000000)
    except Exception as exc:
        return dict(name=name, success=False, exception=repr(exc),
                    last_pc=hex(u.reg_read(UC_ARM_REG_PC)),
                    last_instructions=trace[-32:], reads=reads, cursors=cursors)
    context = bytes(u.mem_read(CTX,0x408))
    return dict(name=name, success=stop_reached, stop_reached=stop_reached,
                instructions=len(trace), last_pc=hex(u.reg_read(UC_ARM_REG_PC)),
                header_bytes=len(header), header_sha256=hashlib.sha256(header).hexdigest(),
                synthetic_file_open=opens, synthetic_file_reads=reads,
                original_native_cursor_observations=cursors,
                original_native_divisions=divisions,
                native_context_codepage=struct.unpack_from('<H',context,0x28)[0],
                native_context_sort_ids=list(struct.unpack_from('<2H',context,0x2a)),
                native_context_offset2b8=struct.unpack_from('<I',context,0x2b8)[0],
                native_context_offset2c0=struct.unpack_from('<I',context,0x2c0)[0],
                native_context_slice280_2c4=context[0x280:0x2c4].hex(),
                code_pages=code_pages,
                instruction_trace_sha256=hashlib.sha256(json.dumps(trace,sort_keys=True).encode()).hexdigest())


def main():
    dependency = ROOT/'staging/navigation-stock-address-schema-v1/stock-address-schema-evidence.json'
    data = json.loads(dependency.read_text())
    image = NativeImage()
    cases = []
    for item in data['public_mdr_headers']:
        header = bytes.fromhex(item['public_header_hex'])
        if hashlib.sha256(header).hexdigest() != item['header_sha256']:
            raise ValueError('Stock header receipt mismatch')
        cases.append(invoke(image,header,item['path']))
    result=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        stock_MAIN_sha256=EXPECTED,
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        dependency=dict(path=str(dependency.relative_to(ROOT)),
                        sha256=hashlib.sha256(dependency.read_bytes()).hexdigest()),
        entry='0x2cc44c', stop='0x2cd49e', cases=cases,
        all_cases_reached_stop=all(c['success'] for c in cases),
        policy_hooks=[], synthetic_filesystem_IO_hooks=['0x1c8682','0x3324b8'],
        device_IO=False, physical_query_verified=False,
        scope='Original headerparser/string/memzero/readwrapper/division; header-onlysyntheticfilesystem, not mapdiscovery/UIquery/door-numberlookup.')
    output=HERE/'native-MDR-header-fields-proof-v1.json'
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(output),all_cases_reached_stop=result['all_cases_reached_stop'],
        cases=[dict(name=c['name'],success=c['success'],exception=c.get('exception'),
                    context2b8=c.get('native_context_offset2b8'),context2c0=c.get('native_context_offset2c0')) for c in cases])))
    if not result['all_cases_reached_stop']:
        raise SystemExit(1)


if __name__=='__main__':
    main()
