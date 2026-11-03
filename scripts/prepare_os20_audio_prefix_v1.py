#!/usr/bin/env python3
"""Seal a journal-reconstructed terminal endpoint; execute no old guest code."""
import sys
sys.dont_write_bytecode = True
import gzip
import hashlib
import json
from pathlib import Path
import probe_os20_audio_source_v1 as A

OUT = A.ROOT / 'staging/native-os20-audio-prefix-v1'
PARENT = A.ROOT / 'staging/native-os20-audio-source-v1/terminal-failure.json.gz'


def main():
    assert not OUT.exists()
    failure = json.load(gzip.open(PARENT, 'rt'))
    receipt = json.loads((PARENT.parent / 'terminal-tool-receipt.json').read_text())
    assert receipt['actual_terminal_result']['exit_code'] == 1
    assert failure['registers']['GP16'][15] == 0x212104
    assert all(A.sha(A.ROOT / p) == h for p, h in failure['source_sha256'].items())
    build = json.loads(A.BUILD.read_text())
    reference = json.loads(A.I.REFERENCE.read_text())
    elf = A.load(A.ROOT / 'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py', 'prefix_audio_elf').ELF32(A.ROOT / build['ELF'])
    model = A.AudioSource(A.L.R.R.NativeImage(), elf, build, reference)
    initial_ordinal = model.ordinal
    assert model.fixtures == failure['declared_fixture_mutations'][:len(model.fixtures)]
    initial = {str(a): bytes(model.uc.mem_read(a, n)).hex() for a, n, _ in model.zones}
    events = sorted(failure['CPU_store_journal'] + failure['declared_fixture_mutations'], key=lambda r: r['ordinal'])
    assert len({r['ordinal'] for r in events}) == len(events)
    gates_installed = False
    checked_stores = checked_fixtures = 0
    for row in events:
        if row['ordinal'] <= initial_ordinal:
            continue
        if not gates_installed and row['phase'] == 'original exit-list constructor':
            model.install_tail_gate(); model.install_route_gates(); model.install_provider_gates(); model.install_alias_gates(); model.install_writer_gates()
            gates_installed = True
        address = int(row['address'], 16) if isinstance(row['address'], str) else row['address']
        before = bytes.fromhex(row['before_hex'])
        assert bytes(model.uc.mem_read(address, len(before))) == before, ('journal preimage', row['ordinal'], hex(address))
        if row['event_type'] == 'actual_CPU_store':
            pc = int(row['PC'], 16)
            opcode = bytes.fromhex(row['opcode_hex'])
            assert bytes(model.uc.mem_read(pc, len(opcode))) == opcode, ('journal store opcode', row['ordinal'], hex(pc))
            after = (row['value'] & ((1 << (8 * row['size'])) - 1)).to_bytes(row['size'], 'little')
            checked_stores += 1
        else:
            after = bytes.fromhex(row['after_hex'])
            checked_fixtures += 1
        assert len(before) == len(after)
        model.uc.mem_write(address, after)
        model.ordinal = row['ordinal']
    assert gates_installed and model.ordinal == failure['registers']['ordinal']
    assert model.word(A.B.READY_TASKS) == failure['registers']['current_TCB']
    assert model.word(A.WORK + 0x18) == A.PRIVATE
    # CPU/fixture journals, not a complete instruction semantics replay.
    # Preserve this distinction and the terminal GP/CPSR as explicit inputs.
    payload = dict(all_passed=True, failure= A.rel(PARENT), failure_sha256=A.sha(PARENT),
        source_sha256=failure['source_sha256'], boundary=failure['registers'],
        original_helper_returns=failure['original_returns'], original_open_frames=failure['original_open_frames'],
        CPU_store_journal=failure['CPU_store_journal'], declared_fixture_mutations=failure['declared_fixture_mutations'],
        native_instruction_observations=failure['native_instructions'], heap_constructor=failure['heap_constructor'],
        zones=model.zones, whole_initial=initial,
        whole_final={str(a): bytes(model.uc.mem_read(a, n)).hex() for a, n, _ in model.zones},
        guest_patches=model.patches, initial_ordinal=initial_ordinal,
        checked_store_opcodes_and_preimages=checked_stores, checked_later_fixture_preimages=checked_fixtures,
        original_or_compiled_guest_instructions_reexecuted=False,
        full_instruction_semantics_or_store_EA_replay_claimed=False, model_SCTLR=model.sctlr,
        full_CP15_cache_capture=False, device_IO=False)
    OUT.mkdir()
    path = OUT / 'journal-reconstructed-prefix.json.gz'
    A.zipped(path, payload)
    result = dict(all_passed=True, prefix=A.rel(path), prefix_sha256=A.sha(path),
        source_sha256={A.rel(Path(__file__)): A.sha(Path(__file__)), A.rel(PARENT): A.sha(PARENT),
                       A.rel(A.BUILD): A.sha(A.BUILD), A.rel(A.ROOT / build['ELF']): A.sha(A.ROOT / build['ELF'])},
        checked_stores=checked_stores, checked_later_fixtures=checked_fixtures,
        boundary_PC=0x212104, whole_regions=len(model.zones), old_guest_reexecuted=False,
        full_instruction_semantics_or_store_EA_replay_claimed=False, device_IO=False)
    A.save(OUT / 'FILE-prefix-proof.json', result)
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
