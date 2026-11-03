# Small post-handshake host sender

New own C for complete control messages of 2..8192 bytes. It copies plaintext,
uses the caller's already verified TLS adapter for encrypted output, validates
complete TLS1.2 application records, then emits one legacy BULK wire frame.
All receiver/sender/TLS calls are serialized. No socket, USB, original Garmin
code, native ABI or current-phone compatibility is supplied.

Stable `tx_peek` views and exact partial successful `tx_commit` calls separate
TLS generation from actual transport completion. DONE is reached only at the
last successful byte. The owner may then commit the matching control token and
release the sender for another message. Zero success is no progress; invalid
lengths do not move the cursor; failures are terminal and wipe owned buffers.

The TLS context must have no earlier pending write or undrained output. This
sender rejects stale bytes instead of assigning them to a new message/channel.
There is no outgoing media fragmentation or arbitrary-large-message support.

Every Stop abandons the ENTIRE TLS session. Discarding encrypted output cannot
undo its record sequence advance. The generic TLS adapter does not enforce
this owner obligation: fresh sender init can succeed but the next record is
unusable at the peer. The runtime negative control explicitly demonstrates
that failure. Owner must free/discard TLS and establish a fresh verified
session before reuse. Stop is neither safe single-message cancellation,
asynchronous quiescence, nor hardware mute.

`scripts/test_aa_control_host.py` tests this sender through real local TLS and
plain ping output, queue completion gates, partial commits, failure, stale
session/output and the negative mid-output-stop case. No sender ASan, real
USB/DMA completion, phone, hardware or native-performance claim is made.
