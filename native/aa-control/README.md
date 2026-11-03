# Legacy Android Auto host control prototype

This is newly written Linux-host C, using the exact pinned public aasdk schema
and a bounded nanopb runtime. It does not execute original Garmin instructions,
provide an installable Garmin component, or prove current Pixel/Google acceptance.

The serialized owner connects `aa_control_message_callback` to the verified
receiver, drives `aa_control_step`, and sends queue-head views through the C
sender. Only after the sender commits the last successful transport byte may
the owner commit the matching control token. Discovery, channel open, setup,
input binding, media sessions, ACKs, focus and shutdown use this boundary.
The caller is responsible for reporting actual transport completion correctly.

The supplied service response must describe actual provider capabilities. The
subset allows input channel 1, video 3, media audio 4, speech 5 and system 6.
It does not manufacture microphone, Bluetooth, sensor or navigation services.
Tests advertise fixture providers, not Garmin hardware. Protobuf schema bounds
are separate from the 8190-byte encoded discovery limit; successful encoding
into that buffer is required before the profile is accepted.

`ChannelDescriptor` is not a schema `oneof`. This implementation explicitly
rejects multiple service kinds in one descriptor as a local profile policy.
Channel-open body `channel_id=0` (also the proto3 absent default) is permitted;
a conflicting nonzero body channel is rejected. Unknown message IDs terminate
this subset rather than guessing an extension. Unknown protobuf fields follow
the pinned runtime's skip policy. Plaintext is restricted to channel-0 ping;
the symmetric responder and these stricter gates are local policies inferred
from the old plaintext pinger, not verified Google/current-phone requirements.

The provider must copy/own complete media before returning OK. PAUSED means
not accepted and must have no irreversible side effect. Exactly one ACK is
queued for each accepted complete media message, with its signed int32 session
and value 1. A second message is paused until the previous ACK's entire wire
output is committed. ACK is an acceptance signal, not decode/render/sound proof.
Media ID 0 carries a BE64 timestamp followed by opaque bytes; ID 1 carries
opaque bytes. No H.264 decoder, PCM output or touch-event sender is supplied.

Video setup produces deferred focus only after setup output completion and
provider acceptance. A newer explicit focus request supersedes that default.
Audio focus mappings are local provider-gated policy. Stop waits for pending
media ACK, invokes the provider, clears the media session and permits a new
start. Control teardown merely discards its buffers: platform backends must
be stopped/quiesced separately. There is no task/IRQ or asynchronous unload
guarantee, jitter handling or performance measurement.

Host verification: `python3 scripts/test_aa_control_host.py`. It uses the real
local OpenSSL mutual TLS peer, the previously verified C bootstrap/receiver,
this C dispatcher/sender and independent Python protobuf decoding. The peer
and media provider are fixtures; the latter only makes owned copies. Test
certificates and private keys stay in private staging directories.

Reference: `evidence/android-auto-control-source-review-v1.json` contains pinned
public source hashes and line references. Nanopb static bounds are described
in its [official concepts documentation](https://jpa.kapsi.fi/nanopb/docs/concepts.html).
