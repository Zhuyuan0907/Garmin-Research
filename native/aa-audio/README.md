# Linux host PCM provider

This is our own bounded C provider for the pinned, old public aasdk/OpenAuto
audio protocol profile. It is a software prerequisite. It is not installed on
Garmin, does not access a sound device, and has not been tested with a Pixel.
No original Garmin instructions or guest program participate in these tests.

## Reference and fixed profile

aasdk commit `046b3b381595509d0939fa84b14a90978f46ff63` assigns control 0,
media audio 4, speech audio 5, and system audio 6. Its audio channel removes the
eight-byte timestamp from message ID 0 and forwards the body of message ID 1.
OpenAuto commit `aa90412bf93b5a5078495ea85ac9270c6297d369` creates media as
48,000 Hz/two-channel/16-bit and speech/system as 16,000 Hz/mono/16-bit. Its Qt
backend explicitly specifies signed little-endian PCM. Its service ACK value
is one per delivered indication; the indication is not defined as one PCM
sample frame. Its RtAudio buffer sizes are described as observations.

The caller must advertise only configured, real backend capabilities. The
provider fixes config index zero to these three formats. There is no automatic
capability discovery, device opening, conversion, mixing, resampling or DSP.
The caller supplies complete already-parsed PCM indication bodies, without
message IDs or timestamps in the body; the transport/control layer handles
TLS, protobuf and ACK serialization separately. OPEN metadata is already
parsed by that control layer and is accepted without copying or retaining it.
START preserves every signed int32 media session, including -1; phase, rather
than a session sentinel, identifies whether a route is streaming.

## Ownership and bounded storage

Allocate `aa_audio_context_bytes()` fresh zeroed bytes with at least eight-byte
alignment. The context owns two 16,384-byte input slots and one 4,096-byte
output buffer per route, including disabled routes. Caller limits can reduce
accepted packet/output sizes, not the fixed context allocation. The provider
itself allocates no heap memory. Backend heap or hardware buffer allocations
are outside this bound. Calls are serialized; this is not a multithread lock.
Callback reentry is rejected.

MEDIA OK means the entire nonempty indication was copied into an owned slot.
Queue-full PAUSED accepts zero bytes and changes no state: retry the same body.
The control layer may send its whole-indication ACK after OK. That ACK means
owned compressed/protocol data acceptance in other providers, and owned PCM
bytes here; it does not assert physical audio playback. A queue slot remains
occupied until every byte has been assembled into owned output/carry storage.
Backend work happens only when the caller explicitly invokes `step` or
`retry`. Any byte boundary is permitted, including a stereo sample split
between indications. Up to three remaining bytes await the next indication.

Backend views contain packed S16LE bytes and aligned sample frames (four bytes
for stereo, two for mono). They do not use native-endian int16 pointer casts.
The view structure is callback-local; do not retain the structure pointer.
Its data belongs to this context and remains valid for a pending unaccepted
suffix. A backend returns OK/PAUSED and an exact frame-aligned accepted prefix.
PAUSED zero retries the same pointer/length/data; a positive prefix advances
once and the next callback contains only its suffix. OK zero is also treated
as paused, to prevent a busy loop. Any other return or invalid consumption is
a sticky per-route backend error. Other routes can still be stepped.

`frame_offset` advances per accepted sample frame from each START. Timestamp is
opaque: it identifies the indication containing the first byte of this output
chunk's first sample frame. It stays attached when retrying a suffix; no
unknown clock unit or sample-time increment is invented. `focus_type` is the
snapshot at output assembly. Queue acceptance also records the most recent
indication timestamp in route statistics.

## Focus and lifecycle are explicit host policy

These are configurable host policies, not a claim about physical focus or
navigation sound ownership. The grant mask permits the caller to refuse any
GAIN, TRANSIENT, NAVI or RELEASE request before changing state.

* Notify-only routes every stream and attaches focus metadata.
* Gate permits all on GAIN; on TRANSIENT/NAVI permits speech and system only;
  RELEASE and the initial zero state permit no PCM delivery.

A blocked media route retains its queue/carry/pending suffix; it does not
block speech/system. Round-robin step skips paused and finished routes before
trying other routes. Pending output is gated using the current focus. After
GAIN it resumes with its original assembly metadata. This policy neither
mixes streams nor ducks amplitudes, and does not decide Garmin navigation
coexistence. A backend that cannot consume simultaneous routes must supply
its own declared scheduling policy.

The sequence is OPEN, SETUP, START, MEDIA, STOP. STOP discards queued/pending
bytes and incomplete sample carry for that route and returns to SETUP; another
START establishes a new stream and resets its frame cursor. This is stricter
than old OpenAuto's backend suspend. It does not mute or retract bytes already
accepted by a backend. Wrong active media session is rejected. Missing control
payload/session metadata cannot prove a late wire body belongs to an earlier
stream: the AA MEDIA body itself contains no session token.

Explicit `finish(channel)` marks EOF, then step drains owned complete frames.
An incomplete final sample is terminal TRUNCATED and is never padded or
silently accepted. Empty EOF is valid. FINISHED is per channel, visible in
statistics; subsequent step skips that channel. STOP can clear its errors.
`aa_audio_stop` tears down all routes and rejects subsequent calls until fresh
init. It does not release caller context or pending hardware audio ownership.

Direct worker/finish/stats/stop APIs validate a transport-session token. The
control-provider callback signature has no transport token: the caller must
bind it to a live context and invalidate old callbacks before reusing context
storage. Reentry/session checks do not establish asynchronous quiescence.

## Host verification

Run `python3 scripts/test_aa_audio_host.py`. It builds our C code as ordinary
Linux host code and with ASan/UBSan, exercises API/queue ownership and negative
controls, and compares routed PCM to independently packed Python little-endian
samples. It writes raw fixture files, without playback. Source/archive hashes,
actual compiler/run receipts and exact case counts are saved in the proof.
This test does not exercise real TLS/control integration; that belongs to
the separate root integration harness. Bluetooth music, Garmin speaker output,
native UI, live phone interoperability and Garmin native installation remain
outside this proof.
