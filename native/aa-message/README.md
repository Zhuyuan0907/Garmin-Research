# Already-decrypted Android Auto message assembler

This new portable C component receives complete **plaintext fragments** plus
channel/flags metadata and copies them into caller-owned message storage. It
assembles one message at a time and calls the consumer only after BULK or an
exact-length LAST completes it. It has no TLS, wire framing, USB, Garmin API or
message-ID dispatch. ENCRYPTED in metadata records the origin of a fragment; it
does not demonstrate TLS authentication. Callers must supply authenticated,
already-decrypted plaintext when the wire origin is encrypted.

The older aasdk commit and relevant public sources are pinned in
`provenance.json`; GPL-3.0-or-later attribution and `COPYING` are preserved.
This implementation enforces **stricter sequencing** than that old source. It
is not an official/current Google wire contract or proof of Pixel compatibility.

## Policy

- FIRST or BULK starts a message; only MIDDLE/LAST continues it. No channel
  intertwining, FIRST restart or interrupting BULK is guessed away.
- Channel and ENCRYPTED/CONTROL properties remain identical across fragments.
  Upper flag bits are rejected under the old pinned-model policy.
- FIRST has the total **plaintext message bytes**. It may differ from the wire
  ciphertext length, which this component never receives. Only FIRST may carry
  that total field. LAST must land exactly at the plaintext total; MIDDLE can
  reach the total first, followed by an empty LAST.
- Caller capacity bounds the entire message and may exceed 65,535 bytes.
  Capacity is at most UINT32_MAX; a zero-capacity NULL buffer accepts only empty
  messages. max_fragments also bounds endless zero-byte fragments.
- Empty BULK or FIRST(total=0) plus empty LAST is allowed. One-byte messages are
  allowed too. A downstream dispatcher must check the two-byte message ID;
  the assembler does not invent that dispatcher requirement.
- Malformed sequencing is terminal until an explicit new-stream reset.
  Rejections happen before copying/accepting the bad fragment.

## Ownership, accepted status and retry

Each `aa_message_push` receives exactly one complete plaintext fragment.
`accepted` is always initialized to 0. If it becomes 1, all of that fragment has
been copied and the caller **must not send it again**, even when the return is
PAUSED or a callback error. PAUSED with accepted=1 means complete message
delivery is blocked, while its contents are already owned by the assembler.

Use `aa_message_retry` without payload to retry complete message delivery.
During pending delivery, a new push returns PAUSED with accepted=0 and does not
even inspect its fragment metadata/payload. Retry first, then push the unaccepted
new fragment once delivery resumes. In a wire/TLS pipeline, pop/dequeue the
already accepted final fragment and retry the complete message; never feed its
ciphertext through TLS twice.

The callback's view structure is callback-local and must never be retained.
Payload remains stable during PAUSED retries. After callback OK, a later push
may overwrite it. Copy/process before OK. PAUSED means the callback has not
accepted or queued the complete message. Do not mutate caller-owned storage
while the parser owns its contents. All operations require one serialized
owner; parser/storage/input/accepted/callback state must not overlap.
Push/retry/finish/reset callback reentry is rejected. Init is for a fresh or
quiescent context and must never be called from its callback.

`aa_message_finish` converts an incomplete message into sticky TRUNCATED,
returns PAUSED for owned pending delivery without calling the callback, or
closes an idle stream. Closed streams reject new pushes until explicit reset.
Reset intentionally discards partial/pending data after downstream quiescence;
it does not establish a TLS reset, peer resynchronization or native cleanup.

## Verify

```sh
python3 -B scripts/test_aa_message_host.py
```

Only the new code is compiled for the running Linux host. The tests use
independent literal fragments and expected complete payloads, all three-part
split positions, fixed-seed fragment patterns, 128 KiB messages, source-buffer
reuse, empty LAST, backpressure/accepted status, strict sequencing failures,
bounds, EOF and callback reentry. Normal and ASan/UBSan variants must pass;
deliberately broken host-only variants must fail an assertion. Executables are
deleted, while hashes and actual subprocess receipts are kept in
`evidence/android-auto-message-host-v1.json`.

This is not a native firmware install candidate. No original Garmin code or
instruction, ARM guest, emulator, TLS handshake, USB/phone, Bluetooth or speaker
is read or executed, and current Pixel behavior remains unverified.
