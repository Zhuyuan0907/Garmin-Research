#!/usr/bin/env python3
"""Original text-reference choice after a successful packed record reader.

Uses frozen observed outputs and explicit synthetic context codepage. The run
stops before the original kind-7 text getter; no metadata or string result is
substituted. Includes two codepage countercontrols, without replaying readers.
"""
import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm_const import *

CTX, DIR, STRING, STACK = 0x09000000, 0x09002000, 0x09004000, 0x09010000
ENTRY, STOP = 0x044B1554, 0x044B158C


def main():
    dep = ROOT/'staging/navigation-native-AP-packed-records-v1/original-packed-records-proof-v2.json'
    sha = hashlib.sha256(dep.read_bytes()).hexdigest()
    if sha != 'd56e53bf77fa604597d670a61df108f3331e4404df8e2f167395dae6b2d2bc53':
        raise ValueError('Frozen raw output dependency mismatch')
    records = json.loads(dep.read_text())['cases']
    image = NativeImage()
    def rd(a, n):
        try:
            a = image.runtime_to_load(a, n)
        except ValueError:
            pass
        return image.read(a, n)
    if rd(ENTRY, 8).hex() != '0798854903906069':
        raise ValueError('Original text selection signature mismatch')
    cases = []
    controls = [(r, 950, 'stock_CP950') for r in records]
    controls += [(records[0], 65001, 'synthetic_CP65001_city_countercontrol'),
                 (records[2], 65001, 'synthetic_CP65001_street_countercontrol')]
    for source, cp, scope in controls:
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        u.ctl_set_cpu_model(UC_CPU_ARM_1176)
        rawcode = rd(0x044B1000, 4096)
        u.mem_map(0x044B1000, 4096)
        u.mem_write(0x044B1000, rawcode)
        u.mem_protect(0x044B1000, 4096, UC_PROT_READ | UC_PROT_EXEC)
        u.mem_map(CTX, 0x6000)
        u.mem_map(STACK, 0x4000)
        sp = STACK+0x3000
        raw = bytes.fromhex(source['native_32byte_output_hex'])
        u.mem_write(sp+0x14, raw)
        u.mem_write(DIR+0x154, struct.pack('<I', CTX))
        u.mem_write(CTX+0x28, struct.pack('<H', cp))
        for reg, value in [(UC_ARM_REG_CPSR, 0x3f), (UC_ARM_REG_SP, sp), (UC_ARM_REG_R4, DIR+0x140),
                           (UC_ARM_REG_R5, STRING), (UC_ARM_REG_R6, 0x97)]:
            u.reg_write(reg, value)
        trace, call = [], []
        def observe(uc, pc, size, unused):
            if pc == STOP:
                descriptor = struct.unpack('<2I', uc.mem_read(sp+0xc, 8))
                call.append(dict(mapordinal=descriptor[0], selected_reference=descriptor[1],
                    r0_context_pointer=hex(uc.reg_read(UC_ARM_REG_R0)),
                    r1_reference_pair_pointer=hex(uc.reg_read(UC_ARM_REG_R1)),
                    r2_getter_kind=uc.reg_read(UC_ARM_REG_R2), r3_output_buffer_pointer=hex(uc.reg_read(UC_ARM_REG_R3)),
                    stack_string_length=struct.unpack('<I', uc.mem_read(sp, 4))[0],
                    stack_flags=struct.unpack('<I', uc.mem_read(sp+4, 4))[0],
                    getter_callee_not_executed=True))
                uc.emu_stop()
                return
            trace.append(dict(pc=hex(pc), bytes=bytes(uc.mem_read(pc, size)).hex()))
        u.hook_add(UC_HOOK_CODE, observe)
        u.emu_start(ENTRY|1, STOP+4, count=100, timeout=100000)
        fields = source['native_unnamed_fields']
        expected = fields['+10'] if cp in [950, 936] or fields['+1c'] == 0xffffffff else fields['+1c']
        if len(call) != 1 or call[0]['mapordinal'] != fields['+08'] or call[0]['selected_reference'] != expected or call[0]['r2_getter_kind'] != 7:
            raise ValueError('Original text-selection result mismatch')
        cases.append(dict(scope=scope, parent_explicit_level=source['explicit_level'], parent_lowID=source['explicit_low28_ID'],
            explicit_synthetic_context_codepage=cp, input_frozen_raw_output_hex=raw.hex(),
            original_pregetter_call=call[0], original_instruction_trace=trace, original_instructions_executed=len(trace),
            original_RX_page_sha256=hashlib.sha256(rawcode).hexdigest(), metadata_or_result_or_policy_hooks=[]))
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    snippets = []
    for address, size, purpose in [(ENTRY, STOP+4-ENTRY, 'native codepage-conditioned reference choice'),
                                  (0x001AFC7C, 0x26, 'kind dispatcher and embedded branch table'),
                                  (0x001AFCA6, 0x18, 'kind7 dispatch target'),
                                  (0x001AFB4E, 0x52, 'mapordinal metadata, selected-reference handling and text getter delegation')]:
        raw = rd(address, size)
        snippets.append(dict(start=hex(address), bytes=size, purpose=purpose, raw_hex=raw.hex(),
            instructions=[dict(pc=hex(i.address), bytes=i.bytes.hex(), instruction=i.mnemonic+' '+i.op_str) for i in cs.disasm(raw, address)]))
    veneer = rd(0x0448EAA0, 8)
    table = rd(0x001AFC94, 17)
    if veneer.hex() != '04f01fe57dfc1a00' or 0x001AFC94 + 2*table[7] != 0x001AFCA6:
        raise ValueError('Original text getter dispatcher changed')
    result = dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), stock_MAIN_sha256=EXPECTED,
        dependency=dict(path=str(dep.relative_to(ROOT)), sha256=sha, old_reader_not_replayed=True),
        all_cases_passed=True, actual_original_fragment_cases=cases, source_instruction_ranges=snippets,
        original_ARMveneer=dict(address='0x0448eaa0', raw_hex=veneer.hex(), target='0x001afc7d'),
        original_kind7_dispatch=dict(table_address='0x001afc94', table_hex=table.hex(), entry7=table[7],
            computed_PC_base='0x001afc94', target='0x001afca6', delegated_callee='0x001afb3e'),
        observed_reference_choice='CP950 and CP936 use packed output +10; other codepages prefer +1C when it is not 0xFFFFFFFF; +08 supplies mapordinal.',
        delegated_reference_contract='For nonnegative selected-reference the original callee masks 22 bits and delegates through 2BF5F4 with kind5 after metadata lookup; this is static evidence only.',
        actual_label_text_decoded=False, physical_query_verified=False, fullgetter_or_query_executed=False,
        no_new_IMG_reads_here=True, device_IO=False,
        limits=['The original successful-reader continuation is executed with frozen output values and explicit synthetic context/frame input.',
                'The kind7 getter, mapregistry/metadata lookup and final text reader are not executed or given fake success values.',
                '+10 and +1C are text-reference inputs at this call site; their exact underlying LBL storage/address scaling has not been established here.',
                'CP65001 controls only demonstrate this local native branch and do not prove CP65001 address-query compatibility.'])
    path = HERE/'original-text-reference-consumer-proof-v1.json'
    if path.exists():
        raise ValueError('Refuse overwrite proof')
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(dict(output=str(path), all_passed=True, cases=len(cases),
        selected=[dict(level=c['parent_explicit_level'], codepage=c['explicit_synthetic_context_codepage'],
                       reference=c['original_pregetter_call']['selected_reference']) for c in cases], actual_label_text_decoded=False)))


if __name__ == '__main__':
    main()
