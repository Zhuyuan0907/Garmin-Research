"""Offline CP950/GMP label-pool relocation, never an IMG or device installer.

Keep the original GMP prefix and every relative label reference. A new arena
after the whole original component avoids moving unknown trailing LBL tables.
Only header+21/start and +25/length change in the original prefix.
"""
from dataclasses import dataclass
import struct


def need(value, message):
    if not value:
        raise ValueError(message)


def aligned(value):
    return (value + 7) & ~7


@dataclass(frozen=True)
class RelocatedPool:
    component: bytes
    lbl_header_offset: int
    original_pool_offset: int
    original_pool_bytes: int
    new_pool_offset: int
    new_pool_bytes: int
    labels: tuple[dict, ...]


def relocate_pool(component, labels):
    need(type(component) is bytes and 57 <= len(component) <= 8_000_000,
         'A bounded immutable GMP component is required')
    need(component[2:12] == b'GARMIN GMP', 'GMP signature differs')
    lbl_at = struct.unpack_from('<I', component, 33)[0]
    need(57 <= lbl_at and lbl_at + 661 <= len(component), 'Bounded LBL header')
    header = component[lbl_at:lbl_at + 661]
    need(struct.unpack_from('<H', header)[0] == 661 and
         header[2:12] == b'GARMIN LBL' and header[13] == 0,
         'Only the observed unprotected 661-byte LBL header is supported')
    need((header[29], header[30], struct.unpack_from('<H', header, 170)[0]) == (3, 10, 950),
         'Only the observed shift3/encoding10/CP950 profile is supported')
    start, length = struct.unpack_from('<II', header, 21)
    maximum = ((1 << 19) - 1) * 8  # Reserve the all-ones reference sentinel.
    need(lbl_at + 661 <= start < start + length <= len(component), 'Original pool extent')
    need(length % 8 == 0 and length <= maximum, 'Original pool alignment/reference limit')
    need(type(labels) is tuple and 1 <= len(labels) <= 64, 'Explicit bounded label tuple')
    pool = component[start:start + length]
    added = bytearray()
    plans = []
    seen = set()
    for text in labels:
        need(type(text) is str and text and text not in seen, 'Nonempty distinct text is required')
        need(not any(ord(c) < 32 or ord(c) == 127 for c in text), 'Control characters are rejected')
        try:
            encoded = text.encode('cp950', errors='strict')
        except UnicodeEncodeError as exc:
            raise ValueError('Text is outside strict CP950') from exc
        need(1 <= len(encoded) <= 126 and encoded.decode('cp950') == text,
             'Bounded round-trip CP950 text is required')
        seen.add(text)
        wire = encoded + b'\0'
        found = pool.find(wire)
        while found != -1 and found % 8:
            found = pool.find(wire, found + 1)
        reused = found != -1
        if reused:
            ref = found // 8
        else:
            offset = length + len(added)
            need(offset % 8 == 0 and offset // 8 < (1 << 19) - 1, 'New reference overflows/sentinel')
            amount = aligned(len(wire))
            need(offset + amount <= maximum, 'Label arena exhausts the 19-bit profile')
            ref = offset // 8
            added.extend(wire + bytes(amount - len(wire)))
        plans.append(dict(text=text, reference=ref, reused_existing=reused,
                          cp950_hex=encoded.hex(), wire_bytes=len(wire)))
    need(added, 'No new labels; relocation is unnecessary')
    target = aligned(len(component))
    arena = pool + added
    result = bytearray(component)
    struct.pack_into('<II', result, lbl_at + 21, target, len(arena))
    result.extend(bytes(target - len(component)))
    result.extend(arena)
    for row in plans:
        offset = target + row['reference'] * 8
        wire = bytes.fromhex(row['cp950_hex']) + b'\0'
        need(result[offset:offset + len(wire)] == wire, 'Final reference must resolve exact wire text')
    return RelocatedPool(bytes(result), lbl_at, start, length, target, len(arena), tuple(plans))
