#!/usr/bin/env python3
"""Recover the exact cold profile sentinel writer, never change device state."""
import sys, json, hashlib
from pathlib import Path
from datetime import datetime, timezone
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage
from capstone.arm import ARM_OP_MEM, ARM_REG_PC

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def create(p, data):
    with p.open('x') as f:
        json.dump(data, f, indent=2); f.write('\n')

def main():
    image = NativeImage()
    functions = []
    for name, start, end in [('cold_profile_loop', 0x269ec0, 0x269f00),
                             ('same_profile_guard', 0x277d26, 0x277d78),
                             ('install_and_publish', 0x277dae, 0x277e20),
                             ('channel_object_construction', 0x26a016, 0x26a0d0)]:
        rows = []
        for i in image.instructions(start, end):
            row = dict(PC=i.address, opcode_hex=i.bytes.hex(), mnemonic=i.mnemonic, operands=i.op_str)
            for op in i.operands:
                if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                    literal = ((i.address+4)&~3)+op.mem.disp
                    row.update(literal_address=literal, literal_value=image.word(literal))
            rows.append(row)
        functions.append(dict(name=name, start=start, end=end, instructions=rows))
    exact = {i.address: (i.bytes.hex(), i.mnemonic, i.op_str)
             for i in image.instructions(0x269ec0, 0x269ef2)}
    assert exact[0x269ec8] == ('0226', 'movs', 'r6, #2')
    assert exact[0x269ed0] == ('ff21', 'movs', 'r1, #0xff')
    assert exact[0x269ed4] == ('5e31', 'adds', 'r1, #0x5e')
    assert exact[0x269ed6] == ('0e54', 'strb', 'r6, [r1, r0]')
    assert exact[0x269ee4] == ('0df01fff', 'bl', '#0x277d26')
    assert image.word(0x26a0f8) == 0x034e6f08
    assert 0xff+0x5e == 0x15d
    # This is the native source of the sentinel that earlier queue harnesses
    # explicitly supplied. It remains a cold global loop, not a warm App API.
    sources = [Path(__file__), ROOT/'scripts/analyze_native_sections.py',
               ROOT/'evidence/firmware-analysis/main_02bd.bin',
               ROOT/'staging/native-player-session-native-call/emulate_queue_call.py',
               ROOT/'scripts/emulate_native_audio_registration.py',
               ROOT/'staging/native-player-warm-probe/profile0-noop-readiness-boundary-contract-v1.json']
    data = dict(all_passed=True, kind='Exact original static sentinel provenance',
                functions=functions, sentinel_writer=0x269ed6, sentinel_value=2,
                sentinel_offset=0x15d, record_base=0x034e6f08, record_stride=0x208,
                native_channel_loop_count=18, queue_callback_offset=0x160,
                original_queue_callback=0x277c6b, bounded_guest_stop_before=0x269ef2,
                cold_loop_also_clears_old_callback_at_offset=0x18c,
                old_HOST_fixture_not_invalidated='Earlier tests declared the same sentinel2 input; this static writer explains its native cold-loop provenance, without upgrading those tests to cold boot.',
                warm_scope='Do not execute this whole18-channel reset in a resident App; observe the real selected channel and ownership instead.',
                remaining='The channel constructor calls native condition/Timer creation. This contract does not execute it or prove real warm scheduling, heap, speaker, exclusive channel or App.',
                source_sha256={str(p.relative_to(ROOT)):sha(p) for p in sources},
                guest_execution=False, device_IO=False, updated_utc=datetime.now(timezone.utc).isoformat())
    create(BASE/'original-cold-profile-sentinel-contract-v1.json', data)
    print(json.dumps(dict(all_passed=True, sentinel_writer=hex(0x269ed6), offset=hex(0x15d), value=2, device_IO=False)))

if __name__ == '__main__': main()
