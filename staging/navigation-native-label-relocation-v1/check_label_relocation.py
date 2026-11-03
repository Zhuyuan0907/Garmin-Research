"""New small format/limit controls; uses no original IMG, source ledger or device."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from relocate_lbl_pool import relocate_pool


OUT = Path(__file__).resolve().parent


def fixture(pool_bytes=32):
    raw = bytearray(1024 + pool_bytes + 16)
    raw[2:12] = b'GARMIN GMP'
    struct.pack_into('<I', raw, 33, 64)
    h = 64
    struct.pack_into('<H', raw, h, 661)
    raw[h + 2:h + 12] = b'GARMIN LBL'
    struct.pack_into('<II', raw, h + 21, 1024, pool_bytes)
    raw[h + 29:h + 31] = bytes([3, 10])
    struct.pack_into('<H', raw, h + 170, 950)
    raw[1024:1032] = b'6\xb8\xb9\0\0\0\0\0'
    raw[-16:] = b'UNKNOWN-TABLEEND'
    return bytes(raw)


def rejected(fn):
    try:
        fn()
    except ValueError:
        return True
    raise AssertionError('A rejected control was accepted')


def main():
    destination = OUT / 'new-controls-proof.json'
    if destination.exists():
        raise ValueError('Refuse overwrite of a completed control')
    source = fixture()
    plan = relocate_pool(source, ('新正路', '6號', '999之7號'))
    rebuilt = bytearray(plan.component[:len(source)])
    rebuilt[64 + 21:64 + 29] = source[64 + 21:64 + 29]
    assert bytes(rebuilt) == source
    assert plan.component[plan.new_pool_offset:plan.new_pool_offset + 32] == source[1024:1056]
    assert plan.component[len(source) - 16:len(source)] == source[-16:]
    assert [row['reference'] for row in plan.labels] == [4, 0, 5]
    assert plan.labels[1]['reused_existing']
    assert not plan.labels[0]['reused_existing']
    controls = []
    def check(name, fn):
        assert rejected(fn)
        controls.append(name)
    check('mutable_component', lambda: relocate_pool(bytearray(source), ('路',)))
    check('empty_labels', lambda: relocate_pool(source, ()))
    check('duplicate_labels', lambda: relocate_pool(source, ('路', '路')))
    check('embedded_NUL', lambda: relocate_pool(source, ('路\0名',)))
    check('control_character', lambda: relocate_pool(source, ('路\n名',)))
    check('unencodable_emoji', lambda: relocate_pool(source, ('路😀',)))
    check('overlong_text', lambda: relocate_pool(source, ('路' * 64,)))
    check('reused_only_no_relocation', lambda: relocate_pool(source, ('6號',)))
    for name, at, replacement in [('unsupported_shift', 64 + 29, b'\x04'),
                                  ('unsupported_encoding', 64 + 30, b'\x09'),
                                  ('unsupported_codepage', 64 + 170, b'\xe4\x04'),
                                  ('bad_GMP_signature', 2, b'X'),
                                  ('bad_LBL_signature', 64 + 2, b'X')]:
        raw = bytearray(source)
        raw[at:at + len(replacement)] = replacement
        check(name, lambda raw=bytes(raw): relocate_pool(raw, ('路',)))
    maxpool = ((1 << 19) - 1) * 8
    check('reserved_reference_capacity', lambda: relocate_pool(fixture(maxpool), ('新正路',)))
    raw = bytearray(source)
    struct.pack_into('<I', raw, 64 + 25, 33)
    check('unaligned_old_pool', lambda: relocate_pool(bytes(raw), ('路',)))
    proof = dict(schema='garmin-CP950-label-relocation-controls/v1',
                 created_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
                 positive_cases=1, guard_cases=len(controls), controls=controls,
                 source_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 primitive_sha256=hashlib.sha256((OUT / 'relocate_lbl_pool.py').read_bytes()).hexdigest(),
                 original_prefix_restored_exact=True, original_pool_copied_exact=True,
                 unknown_trailing_table_kept_at_original_offset=True,
                 original_IMG_read=False, source_ledger_read=False, native_CPU_executed=False,
                 device_IO=False, new_IMG_created=False, installable=False)
    with destination.open('x') as f:
        json.dump(proof, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print(json.dumps(dict(all_passed=True, guards=len(controls), positive_cases=1)))


if __name__ == '__main__':
    main()
