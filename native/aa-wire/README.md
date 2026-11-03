# Android Auto outer wire framer (host prototype)

This directory contains a new, bounded, portable C parser for the outer frames
used by the older pinned aasdk implementation. It is not an Android Auto
receiver, a Google Maps port, or a Garmin-installable binary. The reference is
not an official or current Google protocol guarantee; hashes and licenses are
recorded in `provenance.json` and `COPYING`.

## Wire boundary

A frame starts with channel and flags (one byte each), then an unsigned
big-endian 16-bit **wire payload length**. If `flags & 3 == FIRST`, an additional
big-endian 32-bit **plaintext message length** follows. That latter value is only
metadata here. It is never compared with ciphertext length. FIRST is an 8-byte
header; MIDDLE, LAST and BULK are 4-byte headers. Zero-length LAST is valid at
this layer. A LAST without a preceding FIRST is also delivered: message order
belongs to the decrypted-message assembler, which this parser does not provide.

Only the low four flags bits are accepted under the pinned old-source policy.
Payload bytes, including TLS ciphertext, remain opaque. There is no encryption,
authentication, fragment assembly, acknowledgement, channel state or USB driver.

## Ownership and backpressure

The serialized caller allocates the parser and a buffer with capacity 0..65535
bytes. The buffer bounds each **wire frame**, not the total plaintext message.
No allocator or system API is used by `wire.c`. Inputs are copied before being
reported consumed. Do not overlap parser, storage, input, consumed or callback
state, or access the parser concurrently.

The frame-view structure is callback-local and must never be retained. The
caller must not write the payload storage while the parser owns a frame.

A callback runs only after the complete header and payload are copied. Return
`AA_WIRE_OK` after accepting/copying/processing it, or `AA_WIRE_PAUSED` without
accepting it. On PAUSED the same stable frame is offered again at the start of
the next feed, before consuming new input. Passing `NULL, 0` retries a pending
frame. The exact consumed count includes the paused frame but excludes any
trailing frame bytes; re-feed only the unconsumed tail.

After callback OK, payload storage can be overwritten immediately within the
same feed invocation. An accepted callback must not retain the view or pointer.
A paused callback can inspect data but must not enqueue it and then return
PAUSED; such side effects would be repeated on retry. Callback errors stop the
stream; no automatic resynchronization occurs. Feed/reset/finish reentry is
rejected. Init is only for a fresh/quiescent context and must never be called
from its callback. Explicit reset intentionally discards partial or unaccepted
pending bytes and requires downstream quiescence.

`aa_wire_finish` checks transport EOF: partial header or payload is a terminal
truncation error, pending delivery returns PAUSED without calling the callback,
and successful EOF rejects further nonempty feeds until reset.

## Host verification

From the repository root:

```sh
python3 -B scripts/test_aa_wire_host.py
```

The script compiles only this directory's C implementation and C tests for the
running Linux host. It runs ordinary and ASan/UBSan variants, plus three deliberately
wrong host-parser variants that the same literal test vectors must reject. The
C harness checks all two/three chunk boundaries, random coalescing/splitting,
4 KiB transfers carrying maximum 65,535-byte opaque payloads, zero-length LAST,
FIRST totals different from ciphertext lengths, truncated inputs, capacity and
flag errors, callback reentry, EOF, and backpressure byte counts and ownership.
Actual compile/run receipts, source hashes and scope are saved in
`evidence/android-auto-wire-host-v1.json`. Compiled test executables are deleted.

This does **not** execute the previous ARMv6 prototype, a CPU emulator, Garmin
firmware, TLS, USB, phone, Bluetooth, speaker or modified firmware callsite.
