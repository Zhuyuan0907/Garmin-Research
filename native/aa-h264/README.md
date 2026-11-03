# Ordinary host H.264 decoder prerequisite

This adapter links the official Cisco OpenH264 software decoder/common
source at merged master commit `1a0073f0322c8b74cbcb75ca1bb1c3d19d75538d`
(2026-09-23), descended from release 2.6.0. It does not load,
inspect, or execute Garmin code, use a Garmin guest, perform cross-compilation,
or access devices. It is not an installable Garmin application or evidence of
a working Pixel Android Auto session. OpenH264's license is retained verbatim
in `LICENSE.openh264`.

The official commit archive is pinned by the observed SHA-256
`3e021e6046dcd79f70fa7842896a85cb2205575ea6170db023c4318fafcb0040`.
The selected source files are checked against the archive before compilation.
No separate publisher archive digest was found; the evidence distinguishes
observed archive hashing from independent publisher-digest verification.

## API and ownership

`h264.h` exports a C ABI implemented in C++. The caller supplies aligned
context storage and a workspace whose required size is queried from the
configuration. Initialize once, then `start` or `reset` before feeding.
`feed` accepts an Annex-B stream split at arbitrary byte boundaries. Its
exact `consumed` value counts accepted bytes, which must not be resubmitted.
Input is copied into the workspace; no source pointer survives the call.

The parser retains split three/four-byte start codes, NAL payloads, SPS/PPS
state, and complete access units. It identifies picture changes using frame
number, PPS, IDR, reference status, and picture-order fields; it never assumes
that an Android Auto media indication is a complete access unit. Baseline,
Main, and 8-bit High progressive YUV420 are accepted by the policy. Multiple
slices must arrive in ascending macroblock order, beginning at zero. AVCC,
FMO/ASO, interlaced pictures, SVC/MVC, unsupported NAL types and other chroma
or bit depths are terminal unsupported input. Malformed/capacity errors are
sticky until reset and never trigger a guessed resynchronization.

Every SPS is parsed and checked for both coded and cropped dimensions before
it can reach the decoder. The configuration permits at most 800 by 480 coded
pixels and at most 16 reference frames; cropped display size cannot expand
those dimensions. NAL and access-unit byte limits are separately enforced.
These checks bound wrapper storage and advertised geometry, not every internal
decoder allocation. No complete OpenH264 allocator instrumentation or native
memory/performance claim is made.

The wrapper sends one assembled access unit to `DecodeFrameNoDelay` in
synchronous thread-count-zero mode, with error concealment disabled. It checks
the return status and output buffer status separately. Decoder-owned Y/U/V
planes are copied row by row using the decoder's actual strides into one
bounded owned frame. The callback sees tight strides: width for Y and half
width for U/V. Returning OK consumes the frame view, which can immediately be
overwritten. Returning PAUSED retains all copied pixels and metadata; `retry`
calls the callback again without decoding the access unit a second time.
While a frame is pending, feeding accepts zero new bytes.

`finish` marks EOF, processes the final NAL/access unit, sets the decoder EOS
option, and drains reordered frames using `FlushFrame`. Each call clears its
buffer-info structure and requires a bounded, decreasing remaining-frame
count. EOF without a complete NAL is truncated. `stop` discards owned pending
data and uninitializes/destroys the underlying decoder. A subsequent `start`
constructs a fresh decoder and forgets all prior SPS/PPS/reorder references.
Calls are serialized; callback reentry is rejected. Caller storage must remain
alive through `destroy`.

The timestamp associated with a picture is the timestamp of the chunk
containing its first VCL NAL byte, then passes through the codec's output
timestamp field. This is a transparent test policy, not a proven mapping of
current Android Auto indication timestamps to picture presentation timestamps.

## Building and evidence

`scripts/build_aa_h264_host.py` compiles 37 upstream C++ files and the wrapper,
without an encoder or assembly optimizations. It preserves the official GNU
build's `-fno-strict-aliasing` requirement. Both static and shared ordinary
libraries, and fully instrumented ASan/UBSan variants, are recorded with hashes
and command receipts under `staging/android-auto-h264-host-v1/build.json`.

`scripts/test_aa_h264_host.py` uses actual ffmpeg/libx264 streams and an
independent ffmpeg H.264 decoder as the YUV420 byte oracle. It exercises byte
splits, merged input, per-frame PAUSED ownership, reset, limits, malformed
parameter sets, geometry, and profile/B-picture behavior. Test evidence and
any observed interoperability failures belong in
`evidence/android-auto-h264-host-v1.json`; compilation alone is not test
success. The initial strict-aliasing build and failed Main B-frame comparison
are retained as diagnostics rather than relabeled as a successful test.

Release 2.6.0 B-frame pixel mismatches were also reproduced with its official
C-only make build and its official native Linux ARM64 NEON build. The current
source includes merged upstream PR 4004 correcting B-slice 16x8/8x16 prediction.
Unmerged PR 4045 is not applied. The evidence records any remaining byte-oracle
differences explicitly; accepting a Main/High SPS does not establish complete
profile conformance. Picture-order type 1/2 and other untested modes are not
claimed conformant merely because the framing parser can read their headers.
