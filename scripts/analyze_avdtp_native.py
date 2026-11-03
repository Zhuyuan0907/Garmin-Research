#!/usr/bin/env python3
"""Read-only Thumb analysis of the exact Taiwan 8.00 AVDTP implementation."""
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

ROOT = Path(__file__).resolve().parents[1]
BASE = 0x50000
EXPECTED = '10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'


def main():
    data = (ROOT / 'evidence/firmware-analysis/main_02bd.bin').read_bytes()
    if hashlib.sha256(data).hexdigest() != EXPECTED:
        raise RuntimeError('Requires the verified HWID 1352 software 8.00 MAIN image')
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True

    def word(address):
        return struct.unpack_from('<I', data, address-BASE)[0]

    def prologue(reference):
        # A bounded candidate, not a proven global function boundary.
        for address in range(reference & ~1, max(BASE, reference-512), -2):
            value = struct.unpack_from('<H', data, address-BASE)[0]
            if value & 0xff00 == 0xb500:
                return address
        return None

    def trace(start, limit=256):
        pending = [start]
        seen = set()
        records = []
        while pending and len(seen) < limit:
            address = pending.pop()
            while start <= address < start+4096 and address not in seen and len(seen) < limit:
                seen.add(address)
                inst = next(md.disasm(data[address-BASE:address-BASE+4], address, count=1), None)
                if inst is None:
                    break
                item = {'address': hex(address), 'instruction': inst.mnemonic+' '+inst.op_str}
                if inst.mnemonic == 'ldr' and len(inst.operands) == 2:
                    operand = inst.operands[1]
                    if operand.type == ARM_OP_MEM and operand.mem.base == ARM_REG_PC:
                        literal = ((address+4) & ~3)+operand.mem.disp
                        item['literal_address'] = hex(literal)
                        item['literal_value'] = hex(word(literal))
                elif inst.mnemonic == 'adr':
                    target = ((address+4) & ~3)+inst.operands[1].imm
                    item['address_value'] = hex(target)
                    offset = target-BASE
                    if 0 <= offset < len(data):
                        raw = data[offset:offset+180].split(b'\0', 1)[0]
                        if raw and all(32 <= b < 127 or b in (10, 13) for b in raw):
                            item['string'] = raw.decode('ascii')
                if inst.mnemonic in ('bl', 'blx') and inst.operands[0].type == ARM_OP_IMM:
                    item['direct_call'] = hex(inst.operands[0].imm)
                records.append(item)
                if inst.mnemonic == 'bx' or (inst.mnemonic == 'pop' and 'pc' in inst.op_str):
                    break
                if inst.mnemonic.startswith('b') and inst.mnemonic not in ('bl', 'blx', 'bic', 'bics'):
                    if inst.operands and inst.operands[0].type == ARM_OP_IMM:
                        pending.append(inst.operands[0].imm)
                    if inst.mnemonic == 'b':
                        break
                address += inst.size
        return sorted(records, key=lambda r: int(r['address'], 16))

    source_refs = []
    needle = b'../../../private/protocols/avdtp/avdtp_init.c\0'
    cursor = 0
    while (offset := data.find(needle, cursor)) != -1:
        target = BASE+offset
        for address in range(max(BASE, target-1020), target, 2):
            value = struct.unpack_from('<H', data, address-BASE)[0]
            if value & 0xf800 == 0xa000 and ((address+4) & ~3)+(value & 0xff)*4 == target:
                source_refs.append({'source_string': hex(target), 'adr': hex(address),
                                    'prologue_candidate': hex(p) if (p := prologue(address)) else None})
        cursor = offset+len(needle)
    entries = sorted({int(r['prologue_candidate'], 16) for r in source_refs if r['prologue_candidate']})
    traces = {hex(entry): trace(entry) for entry in entries}
    # These RAM bases are recovered from initialization loops, without reading
    # or changing actual device RAM. Their structure semantics remain unknown.
    pools = {}
    for target in [0x03a88fb0, 0x03a88eb8, 0x03a89028, 0x03a88ef0, 0x03a88f50]:
        refs = []
        cursor = 0
        encoded = struct.pack('<I', target)
        while (offset := data.find(encoded, cursor, 0xbd0000-BASE)) != -1:
            cursor = offset+4
            literal = BASE+offset
            if literal % 4:
                continue
            for address in range(max(BASE, literal-1020), literal, 2):
                value = struct.unpack_from('<H', data, address-BASE)[0]
                if value & 0xf800 == 0x4800 and ((address+4) & ~3)+(value & 0xff)*4 == literal:
                    refs.append({'literal': hex(literal), 'ldr': hex(address),
                                 'prologue_candidate': hex(p) if (p := prologue(address)) else None})
        pools[hex(target)] = refs
    output = {'stock_sha256': EXPECTED, 'base': BASE,
              'method': 'Thumb ADR/LDR encodings, bounded PUSH-LR candidates, branch traversal',
              'limitations': 'Static candidate locations only. RAM pools are not assigned SEP semantics. No device memory or firmware changes.',
              'source_references': source_refs, 'functions': traces, 'ram_base_references': pools,
              'psm_25_initialization_candidate': '0x4ccc3c',
              'psm_25_evidence': 'movs r0,#0x19 followed by callbacks and calls to 0x50c138/0x50c150; error text names Register AVDTP PSM to L2CAP'}
    path = ROOT / 'evidence/firmware-analysis/avdtp-native-functions.json'
    path.write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({'functions': len(traces), 'instructions': sum(map(len, traces.values())),
                      'ram_reference_counts': {k: len(v) for k, v in pools.items()}, 'output': str(path)}))


if __name__ == '__main__':
    main()
