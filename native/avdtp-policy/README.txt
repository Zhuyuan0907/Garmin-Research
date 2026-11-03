This is an offline ARMv6 prototype, not an installable Garmin application.

Build: python3 scripts/build_native_music_policy.py
Verify: python3 scripts/emulate_native_music_policy.py

The configuration validator consumes the complete AVDTP SetConfiguration body
before any acceptance reply. It supports only MediaTransport plus audio/SBC,
44.1/48 kHz, one selected format, and bitpool 2..53. These are this prototype's
supported subset, not limits of the complete SBC specification. Other services
are explicitly rejected. Output is written only after successful validation.
No native pre-accept hook or reject sender has been connected.

The guard retains a strictly increasing session counter across unbind/rebind.
The caller must initialize it to zero once, serialize ownership, capture each
callback's original session before queueing, and stop old work before reclaiming
storage. LCID reuse itself cannot identify old events. The coherent native view
must be captured under the proper native lock. Do not fabricate a session from
the current LCID when processing an older queued event.

Packet admission requires stock state8, pending0, the configured codec/SEIDs,
a matching SEP/channel, raw-media type255, ready channel flags16, and a bounded
local receive MTU. The local receive limit comes from the endpoint's receive
configuration (stock SEP+0xC in the offline fixture), not the peer receive MTU
stored at channel+2; those values limit opposite directions of traffic.

The frame guard checks the selected SBC format, negotiated bitpool range and
complete first-frame length. It returns consumed bytes, so several frames may
share the input. It does not check CRC or decode audio. The existing decoder
must verify CRC and produce PCM; RTP parsing, fragments, jitter/loss, dispatcher
hooks, existing decoder/output workers and ownership are not wired here.

The executable tests place immutable policy code beside the exact stock ARM1176
firmware in one synthetic VM. Python calls policy before the stock configuration
handler and after receiving stock media callbacks. This does not run an embedded
policy wrapper, activate SDP/SEP on the navigation device, load a modified voice
module, build native UI, or test a real phone/speaker. Link placement is emulator
only and makes no claim of free RAM on the actual navigation device.
