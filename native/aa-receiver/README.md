# Android Auto receiver data path: Linux host prototype

This is our post-handshake C data receiver, not a Garmin installation package.
It joins the existing wire parser and TLS adapter to a new plaintext message
assembler. No Garmin instructions, ARM guest, phone, USB controller, screen or
speaker are involved in its verification.

The serialized caller supplies an already-active TLS context and separate wire,
plaintext and message buffers. Wire callbacks copy into two owned 32-KiB queue
slots. `step` feeds ciphertext once, drains authenticated plaintext, and passes
the complete fragment to the assembler. The assembler copies it again before
publishing a complete message. A paused message callback retries the owned
message; it does not repeat the TLS input or decrypt the same record twice.

`feed` reports exactly how many transport bytes it has consumed, including a
complete frame retained in the wire parser when both queue slots are full.
After `step` frees a slot, retry `feed(NULL, 0)` or supply only the unconsumed
tail. The input transport storage may be overwritten after consumption.
Accepted callback payloads must be copied/processed before returning. A paused
callback must not accept the message before returning `PAUSED`.

The behavioral reference is aasdk commit
`046b3b381595509d0939fa84b14a90978f46ff63`, especially `Cryptor::encrypt` and
`MessageOutStream::compoundFrame`. It encrypts each AA fragment and drains the
entire output BIO. This receiver therefore requires complete TLS1.2 application
records within each encrypted frame. It rejects record splitting across AA
frames, other record kinds and renegotiation. Message fragments use stricter
sequence/channel/flags/declared-plaintext-total checks than the old SDK. Neither
policy has been tested with a current Pixel; outer metadata is not covered by
TLS record authentication. Empty LAST is supported; message-ID validation
belongs to a future dispatcher.

Run `python3 scripts/test_aa_receiver_host.py` from the workspace. It requires
the existing verified host TLS library and component proofs, regenerates private
local certificate fixtures, builds ordinary Linux C, and uses a real local
OpenSSL TLS1.2 peer. The evidence file is
`evidence/android-auto-pipeline-host-v1.json`. Its 27 categories include queue
saturation, source-buffer overwrite, delivery pause, 40-KiB fragmented messages,
80 sequential messages, integrity failure, malformed fragment metadata,
capacity, EOF, callback reentry, stale sessions and serialized stop. Component
ASan/UBSan results are separate; the integrated pipeline makes no ASan claim.

The next missing layer is AA version/SSL_HANDSHAKE/AUTH_COMPLETE and channel
negotiation. USB host/VBUS/AOA, native entropy/time/ABI, protobuf/media ACKs,
H.264/display/touch/audio, UI installation, realtime performance and a real phone
session remain unverified. `stop` discards buffers in serialized host execution;
it does not prove hardware mute or asynchronous task cancellation. The full
Garmin Android Auto/Google Maps objective remains incomplete.

SPDX: GPL-3.0-or-later. License text: `../aa-wire/COPYING`.
