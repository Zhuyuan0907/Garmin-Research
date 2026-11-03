# Serialized composition of the Android Auto host core

This Linux-host module routes actual C control callbacks to the separate input,
video and PCM audio providers. It does not discover a Garmin platform, load an
App, claim a physical device capability, or perform USB/phone I/O. Profile
construction must accurately describe the supplied software backends.

The bridge owns exactly one existing `aa_sender` and one verified TLS session.
It selects control or input queue heads, copies the selected message into the
sender and remembers both its originating queue and token. When both queues
have work it alternates them; bounded control traffic cannot indefinitely starve
input. Zero and partial wire completions leave the originating queue uncommitted.
Only DONE after the final successful wire byte permits source commit and sender
release. Queue tokens may coincide across owners, so token equality alone never
selects a queue. External code must not peek/commit these source queues or use
the sender independently while the bridge owns them.

The caller separately drives receiver/control deferred work, video decoding and
audio consumption, serially. This module does not create an OS task or prove
cross-context cancellation. Child contexts remain owned and retained by the
caller. Each stop/error requires discarding the whole TLS session, including any
unsent cipher records. A delivered shutdown reply returns CLOSED; the owner must
then stop child providers, release their resources and dispose of TLS. Sending
that reply does not mute audio or quiesce hardware callbacks.

The integration test must demonstrate actual encrypted input and control
messages through the same local peer, independent protobuf decoding, H264/YUV
and PCM reference comparisons, partial/failed completions and restart behavior.
Local software video and accepted PCM still do not establish native GarminOS
execution, current Pixel/Google interoperability, a working touchscreen or an
audible speaker. The most important subsequent gates are recorded in
`docs/android-auto-platform-gates-v1.md`.
