# Legacy Android Auto startup: host prototype

This C module starts with an initialized, unhandshaken TLS client and sends the
pinned legacy AA version/SSL_HANDSHAKE/AUTH_COMPLETE envelopes. It is our Linux
host code, not Garmin firmware or an installable App. Current Pixel/Google
acceptance and all physical USB/native platform behavior remain unverified.

The model is public aasdk commit `046b3b381595509d0939fa84b14a90978f46ff63` and
OpenAuto commit `aa90412bf93b5a5078495ea85ac9270c6297d369`. Their three startup
messages use channel 0, PLAIN and SPECIFIC (no CONTROL bit). Default requested
version is 1.1 in the tests; this module requires an exact configured response
and zero match status. SSL_HANDSHAKE is message ID 3 followed by raw TLS bytes.
AUTH_COMPLETE is ID 4 plus proto2 required enum status=OK: `08 00`, not an empty
protobuf message. No general protobuf dispatcher or service discovery exists.

The TLS context has one serialized owner during startup. All pending TLS output
is drained into message ID 3, including after handshake success, before AUTH.
Output uses a borrowed `tx_peek` view and a separate `tx_commit` confirmation.
The caller must report exactly the successful completed transport bytes, not
bytes merely queued; zero/partial completion cannot move startup to READY.
AUTH's last byte must be committed before the next owner uses the active TLS
context. This completion gate is our stricter policy, not a Google guarantee.

`feed` stops immediately after one complete incoming control message. The
remaining input is untouched while `step` drives handshake/output. After READY,
`feed` returns READY with zero consumption. Once that call has returned, stop
the bootstrap and transfer the exact unconsumed tail to the data receiver, with
the same TLS context/session. Never initialize TLS again or discard a transport
completion containing both the final handshake and an encrypted frame/header.

Raw TLS headers may span several SSL_HANDSHAKE messages. Application-data
records hidden inside a handshake envelope are rejected because their outer
AA channel/message metadata would be lost at handoff. This is another explicit
legacy-model policy, not evidence of current phone behavior. Startup input is
parsed bytewise for a precise handoff; native performance is unmeasured.

Run `python3 scripts/test_aa_bootstrap_host.py`. It requires the previously
verified TLS/receiver host libraries and current source hashes, creates private
local certificate fixtures, and drives real local OpenSSL mutual TLS1.2. Its
29 categories cover normal/bytewise/fragmented startup, independent protobuf
required-field validation, transmission commits, version/certificate failures,
same-chunk encrypted-tail handoff, deadlines, malformed records, EOF and stop.
One separately labelled pending-output API control injects synthetic bytes
after real TLS success to check ordering; it is not a real final TLS flight or
phone session. The first protobuf-fixture compatibility failure is retained.

Evidence: `evidence/android-auto-startup-host-v1.json`. Public-source review:
`evidence/android-auto-startup-source-review-v1.json` (22 static source checks,
zero runtime protocol tests). No bootstrap ASan/native ABI/performance claim.

Next: general control/protobuf/service discovery, channel and media negotiation,
ACK/flow control, actual USB host/VBUS/AOA, native platform/entropy/time,
H.264/display/touch/audio and UI loading. Garmin Android Auto/Google Maps remain
incomplete. Serialized stop only clears buffers; it does not prove asynchronous
quiescence, TLS transport closure, hardware mute or safe module unloading.

SPDX: GPL-3.0-or-later. License text: `../aa-wire/COPYING`.
