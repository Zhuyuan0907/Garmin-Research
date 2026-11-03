#!/usr/bin/env python3
"""Record exact mixed ARM/Thumb event operations without assuming a task ABI."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace


def main():
    stock = NativeImage()
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    ranges = (
        ('post_interrupt_marker_arm', 0x2fce38, 0x2fcef0),
        ('post_arm_entry', 0x2fcf44, 0x2fcf6c),
        ('post_preemption_context_save', 0x2fcfb0, 0x2fcfec),
        ('wait_arm_entry', 0x2fd03c, 0x2fd050),
        ('wait_empty_context_save', 0x2fd06c, 0x2fd0a8),
        ('wait_return_arm', 0x2fd0c4, 0x2fd0d0),
        ('post_return_arm', 0x2fd01c, 0x2fd028),
    )
    parts = {name: [{'address': hex(i.address), 'instruction': i.mnemonic+' '+i.op_str}
                    for i in md.disasm(stock.read(begin, end-begin), begin)]
             for name, begin, end in ranges}
    for name, address in (('post_thumb_paths', 0x2fcf6c),
                          ('post_preemption_thumb_tail', 0x2fcfec),
                          ('wait_thumb_paths', 0x2fd050),
                          ('wait_empty_thumb_tail', 0x2fd0a8),
                          ('wait_return_thumb', 0x2fd0d0),
                          ('post_return_thumb', 0x2fd028)):
        parts[name] = trace(stock, address, 120)
    result = {
        'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
        'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'event_post': '0x2fcf44', 'event_post_entry_mode': 'ARM',
        'event_wait': '0x2fd034', 'event_wait_entry_mode': 'Thumb',
        'current_ready_list': '0xf09090',
        'interrupt_context_marker': '0xf09094',
        'interrupt_marker_post': '0x2fce38',
        'interrupt_marker_post_mode': 'ARM',
        'observations': [
            'Normal-context post uses r0=TCB, r1=event bits, merges TCB+4, removes bit0x8 from stored mailbox and can insert a blocked task into the priority-ordered ready list.',
            'Wait reads the current task mailbox. An empty mailbox removes the current ready head and saves context before restore0x358ec4. A nonempty mailbox returns its bits.',
            'TCB+8 affects acknowledgement: a nonzero value preserves mailbox bit0x2. Descriptor word1 is copied to TCB+8 by the builder; it must not be assumed to be a normal entry argument.',
            'The stock PCM worker0x33f94a loops through this event wait and branches on bits0x1/0x4.',
            'A nonzero marker0xf09094 selects the all-ARM post0x2fce38 branch. It merges mailbox bits, inserts a woken task by priority, saves/restores CPSR and SB, and returns without the normal post context-save/restore sequence. True IRQ exit scheduling is outside this branch.',
        ],
        'instructions': parts,
        'arm_range_hashes': {name: hashlib.sha256(stock.read(begin, end-begin)).hexdigest()
                            for name, begin, end in ranges},
        'runtime_event_operations_emulated': False,
        'live_event_delivery_or_scheduling_verified': False, 'device_io': False,
        'limitations': 'Exact-firmware static instruction analysis only. Known ARM/Thumb transitions and the all-ARM interrupt-marker post branch are recorded separately; the Thumb trace helper does not traverse those transitions or callees. This artifact itself does not execute event operations, true IRQ entry/exit or scheduling. Runtime evidence belongs to the separate media-worker/media-consumer emulation artifacts; this static analysis alone does not establish a working on-device worker.',
    }
    path = ROOT/'evidence/firmware-analysis/native-task-event-static.json'
    path.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'device_io': False}))


if __name__ == '__main__': main()
