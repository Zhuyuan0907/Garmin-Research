SBC decoder experiment for the Taiwan nuvi 2565RT research

Build: python3 scripts/build_native_sbc.py
Verify: python3 scripts/emulate_native_sbc.py
Both commands run locally on the Pi and have no Garmin/Bluetooth I/O.

The build links unmodified upstream libsbc 2.1 with a small wrapper and a
bounded, single-context allocator. It targets ARM1176JZF-S, ARM state,
little-endian PCM, soft float, and does not require a Linux runtime.
The cross compiler name includes linux-gnueabi, but the resulting ELF has
no dynamic interpreter, unresolved functions, Linux syscalls, or libc link.
Compiler integer division helpers are statically linked. Unexpected division
by zero traps; it is not converted to silence or a Linux signal.

decoder.h defines an experimental AAPCS interface, not a discovered Garmin
interface. garmin_sbc_reset must precede playback. Each decode consumes one
complete SBC frame and produces all its interleaved signed 16-bit PCM.
Changing the negotiated format requires resetting; changing bitpool does
not. CRC errors reset the decoder. Truncated frames and small output buffers
are rejected without advancing synthesis state. Callers must provide valid,
non-overlapping pointers and serialize calls; pointer validation and concurrency
are outside this prototype. It does not parse RTP or fragmented A2DP packets.

The verification uses a matching Debian libsbc 2.1 encoder/decoder reference,
32 format configurations, stateful multi-frame streams, bitpool changes,
invalid frames and guarded output buffers. ARM1176 emulation compares PCM
bytes with the reference. Input/output buffers end at unmapped guard pages;
leading output canaries are also checked. Memory-access hooks are not used
to infer complete access traces with the installed Unicorn engine.
The matrix is not exhaustive,
external interoperability is untested, and emulator instruction counts are
not measurements of timing or performance on Garmin hardware.

All addresses in emulation.ld are synthetic emulator mappings. This ELF/bin
is NOT an installable Garmin application, a Garmin update file, or a firmware
patch. No native loading mechanism, screen button, A2DP endpoint callbacks,
speaker mixer interface, physical CPU ABI, or recovery path is verified by
this experiment. Do not copy it to the navigator expecting execution.

Upstream URL: https://www.kernel.org/pub/linux/bluetooth/sbc-2.1.tar.xz
Upstream SPDX license: LGPL-2.1-or-later
Original source and copyright notices: sources/deep-research/sbc-2.1/
Upstream COPYING and COPYING.LIB are included in staging/native-sbc/.
Keep source, notices, build commands and relinkable object files together
when preparing any future distribution; this experiment is local only.

Build hashes: staging/native-sbc/manifest.json
Verification: evidence/firmware-analysis/native-sbc-emulation.json

Native component integration (emulation only)

Build: python3 scripts/build_native_sbc_component.py
Verify: python3 scripts/emulate_native_sbc_component.py
The stock loader reads the resulting component-emulation.bin through synthetic
file callbacks, and its own registration callback fills the ARM trampolines.
All decoder calls pass through pointers installed by the stock loader. Six
formats, 59 decoded frames, rejected-frame recovery and bitpool changes match
the reference. Module RAM is poisoned before load; the component entry clears
its own BSS before registration. No direct ELF mapping supplies its code.

This component's two decoder exports replace only two of the original forty
APIs. It is not a device installation candidate. Its filename deliberately
differs from dllimg.bin; copying/renaming it for the device would invalidate
the other component APIs. No installation script is supplied.

The original backup has three TTS voice packages with internal DLLIMG.BIN,
DLLINFO.TXT and DLLIMG.SIG files. Their byte-sum checksums match the metadata.
analyze_tts_vpm.py extracts/checks them; emulate_original_tts_modules.py runs
their original bootstraps, which each register all forty exports. This confirms
the loader/component relationship offline. Signature enforcement and modified
VPM acceptance are still unknown, as are the original API signatures and PCM
speaker path. Do not infer acceptance of a replacement from these tests.

Combined evidence: evidence/firmware-analysis/native-sbc-component-emulation.json
Original evidence: evidence/firmware-analysis/original-tts-module-emulation.json

Original PCM callback/ring integration (emulation only)

Build: python3 scripts/build_native_sbc_component.py --audio-route
Verify: python3 scripts/emulate_native_sbc_pcm.py
The separate component_audio.c variant has three experimental exports; its
submit export decodes 16 kHz mono SBC and calls the original host API slot 0
itself. Other sampling rates/channels are rejected until conversion exists.
The original host callback, buffer reservation/commit, ARM memcpy and reader
execute their original instructions. Three starting offsets exercise wrapping
and draining; 540 frames read back exactly match upstream PCM. Seven rejected
frame, reader and scheduling cases also pass.

The PCM ring state is synthetic. OS scheduling, priority and channel operations
are controlled hooks. Physical sample clock, mixer/DAC/speaker, startup, blocking
backpressure and navigation/audio concurrency are NOT verified. A stock sequence
predicate can discard audio while its callback returns zero; four successive
empty drains clear the initialization flag. Maintain buffered samples and trace
real priority/startup before treating callback success as playback.

Evidence: evidence/firmware-analysis/native-sbc-pcm-emulation.json
Manifest: staging/native-sbc-pcm-emulation/manifest.json
This variant still does not preserve the original 40 TTS APIs or implement
A2DP reception/UI. It remains local, emulator-only and NOT an install candidate.

Original TTS and decoder coexistence (emulation only)

Build: python3 scripts/build_native_voice_extension.py --voice all
Verify: python3 scripts/emulate_native_voice_extension.py
This separate experiment appends code after each original DLLIMG's RAM extent.
Only header words 0/4/8 change; the original bootstrap runs at its unchanged
address and registers its original forty exports. Decoder calls use a separate
local table. Original export contents/targets, main import pointers/trampolines,
relocated file bytes after the header and RAM tail match unmodified execution.
The temporary export descriptor is a stack object; its address changes because
of the wrapper frame. One benign original query API is called in both sessions;
the other original functions and speech synthesis are not exercised.

Three original voice modules preserve these invariants; 72 decoded frames and
90 mono16k frames routed through the stock PCM code match upstream byte for byte.
No VPM is generated, no SIG is changed, and no modified package acceptance is
tested. This does not make the binary safe to install or prove navigation speech.
Evidence: evidence/firmware-analysis/native-voice-extension-emulation.json

Stock incoming AVDTP media callback (emulation only)

Verify dispatch: python3 scripts/emulate_avdtp_media.py
Build combined callback: python3 scripts/build_native_voice_extension.py --voice all --media
Verify combined path: python3 scripts/emulate_native_voice_media.py
The --media variant uses its own staging/native-voice-media-extension-emulation
directory and retains the original forty exports. It appends a compiled callback
with the five-argument ABI derived from stock handler 0x50bbc0. Exact stock LCID
lookup and BX R7 veneer call it with raw media bytes and length. Synthetic RAM
supplies endpoint/channel/context state; no real SEP is registered. The callback
parses RTP CSRC/extension/padding and complete non-fragmented SBC packets, then
uses the previous mono16k host callback/ring route. Mutex/logger and original
OS policies are controlled hooks. Physical hardware/Bluetooth remain unused.

Three original voices each retain their forty exports/import trampolines and
original post-header RAM. Five RTP layout cases per voice route 102 accepted
packets / 540 frames in total; stock reader output matches upstream PCM exactly.
Eighteen packet/state guard cases per voice pass. Those successful-frame counts
exclude the deliberately tested one-frame prefix before a later CRC rejection.

Frames are processed in arrival order. Fragment reassembly, jitter buffering,
duplicate/reorder/loss handling, codec negotiation, lifecycle, real scheduling,
44.1/48 kHz stereo conversion and native UI are not supplied. A CRC failure in
a later frame can leave an already-submitted prefix, explicitly recorded by
counters/tests. Stock dispatch ignores callback return values; never interpret
its success as proof that a packet decoded or reached the speaker.

Evidence: evidence/firmware-analysis/avdtp-media-dispatch-emulation.json
Evidence: evidence/firmware-analysis/native-voice-media-emulation.json
All variants remain local and emulator-only. Never rename/install these files.

Verified logical source format (emulation only)

Verify: python3 scripts/emulate_native_audio_format.py
The stock audio-method factory 0x437764 chooses the existing TTS reader
0x484c05 for audio kind17. Its format getter 0x484c49 returns channels1,
bits16, block alignment2, rate16000. The stock start routine requests the
same audio kind17. A separate raw control selects logical rate44100; an
invalid kind is rejected. This proves the logical source-format relationship,
not the physical DAC clock, mixer conversion, real startup or audible output.
Evidence: evidence/firmware-analysis/native-audio-format-emulation.json

Stereo downmix and rational sample conversion (standalone emulation only)

Build: python3 scripts/build_native_pcm_converter.py
Verify: python3 scripts/emulate_native_pcm_converter.py
pcm_converter.c is a freestanding ARMv6 integer converter for mono/stereo
S16_LE at16000/32000/44100/48000. Output is mono16k. Stereo is averaged with
truncation toward zero. Downsampling uses96-tap Q15 FIR kernels with a7kHz
cutoff and Kaiser beta8.6;44100 uses160 fractional phases. All kernels have
exact integer DC sum32768. Accumulation is64-bit; rounding is nearest with
half-integers away from zero and S16 saturation.16k bypasses the FIR.

Reset before use and serialize one stream. Each call accepts up to128 sample
frames and conservatively requires output capacity of at least frames*2 bytes.
Input/output/result pointers must be valid and non-overlapping. State is kept
across chunks; invalid arguments do not advance it. Initial history is zero,
the causal filter has a nominal47.5-input-sample delay, and there is no implicit tail
flush. A real stream lifecycle/flush policy remains to be integrated.

The verification compares emulated ARM output with independent stateless
convolution at absolute output positions, checks variable/uniform chunk
invariance, exact one-second44.1k-to16k count, opposite stereo/DC/extrema,
FIR overshoot saturation, actual-output passband/stopband tones, rejection
recovery and unmapped end pages/canaries. These are synthetic PCM tests, not
physical timing measurements, actual music listening or complete frequency
characterization. Test guards must run before constructing the long-lived
converter engine; the reverse order triggered a host segfault with this
Unicorn2.1 build. Memory hooks are not used for bounds claims.

The standalone ELF uses synthetic addresses. Its independent test alone does
not exercise SBC/AVDTP/stock PCM. The --convert variant below links the same
converter sources/tables into a preserving voice/media extension; its separate
integration evidence must be inspected before claiming that route is verified.
No real Bluetooth endpoint, native UI, modified VPM acceptance or installation
is provided. Evidence: evidence/firmware-analysis/native-pcm-converter-emulation.json
Manifest: staging/native-pcm-converter/manifest.json

Filter design references (not a claim of bit-identical SciPy output):
https://docs.scipy.org/doc/scipy/reference/generated/scipy.signal.resample_poly.html
https://docs.scipy.org/doc/scipy/reference/generated/scipy.signal.windows.kaiser.html

Converted voice/media integration (separate emulation variant)

Build converter tables first: python3 scripts/build_native_pcm_converter.py
Build: python3 scripts/build_native_voice_extension.py --voice all --media --convert
Verify: python3 scripts/emulate_native_voice_convert.py
The --convert variant uses staging/native-voice-convert-extension-emulation
and a new preserving entry wrapper. The original TTS bootstrap still registers
its original forty exports. A separate converted local table resets both the
codec and FIR, decodes SBC into a512-byte source buffer, downmixes/downsamples,
then submits mono16k PCM through the original host slot0. The original 16k-only
variant remains separate and is regression tested after shared framing changes.

The converted callback's preflight admits all four SBC rates/channel modes;
frame lengths include dual-channel payload multiplication and joint-stereo
join bits. CRC failure resets both decoder and converter history/phase. Format
changes require reset and are rejected without advancing either state. Output
written/rate/channels/sample-count metadata describe converted PCM; consumption,
frame-config and bitpool fields describe the source SBC frame.

The verifier compares stock-reader output with upstream SBC decoding followed
by an independent absolute-position convolution, checks all rates/modes/subbands
with varying blocks/allocation, packet grouping and bitpool changes, entry
initialization, argument/packet/state errors and CRC/format recovery. Original
post-header TTS RAM and all forty export/import/trampoline pointers are compared
with unmodified initialization before/after the new path. Some15-frame packets
need a larger bounded emulator instruction budget because they include FIR work;
these instruction counts are not physical performance/latency measurements.

Endpoint/channel/ring state and OS policies are still synthetic. No SEP
registration/negotiation, live phone input, fragment/jitter/reorder/loss handling,
real startup/backpressure or concurrency, FIR tail flushing, VPM signature
acceptance, actual TTS synthesis, UI or audible speaker output is provided.
Evidence: evidence/firmware-analysis/native-voice-convert-emulation.json
Verified on all three preserving voice builds:1,347 valid frames in747 packets,
32 rate/mode/subband configurations and17 error/state cases per build. Original
forty exports/imports/trampolines and original post-header RAM/tail match the
unmodified baseline. The Jill entry reuses the preserving SBC initialization;
299,368 instructions complete within the unchanged300,000 loader bound. These
counts cover synthetic streams and offline emulation, not a real phone/device.

Stock PCM flow control (offline observation)

Verify: python3 scripts/emulate_native_pcm_flow_control.py
Five stock start-request cases and three reservation/wait cases pass. An
already-initialized producer requests source kind17/flags6 at10,240 queued bytes;
the selector chooses channel5 or8. The stock host callback still returns0 when
the controlled channel-start result fails, and registration's return is not
checked before start. Reservation needs at least5,121 free bytes and returns a
5,120-byte capacity. With insufficient space, stock code repeats wait calls
(argument160, units unknown); controlled consumer progress permits return.
With fixed indices, three observed waits do not return. The harness bounds the
observation; it does not inject a timeout into the stock routine.

This supports separating the media callback from a serialized audio worker
with a bounded queue and cancellation, but the actual native task API is still
unknown. Producer/ring state is synthetic and preinitialized; channel policy,
registration/start and waiting are hooks. No cold initialization, concurrent
reader, physical scheduling/start/latency or audible output is tested. The
10,240-byte buffer corresponds to0.32 seconds of the verified logical mono16k
format; it is not measured speaker latency.
Evidence: evidence/firmware-analysis/native-pcm-flow-control-emulation.json

Native task ABI (offline construction and explicit entry invocation)

Verify: python3 scripts/emulate_native_task_creation.py
The stock direct creator0x521E5E accepts entry, argument, stack bytes, logical
priority, then name on the stack. The generic0x521F16 wrapper reorders those
arguments. Original0x358BF8 constructs an ARM/Thumb kernel task context; original
dispatch0x521E44 queries the current TCB, finds its wrapper slot and calls the
saved entry with its saved argument. Three cases cover2/4/8KiB requested stacks,
priorities0/12/15 and occupied-slot counts0/7/14. The original slot lookup has
15 slots/64-byte stride. The full valid priority domain is not established.
An exhausted lookup returns0; a null descriptor allocation makes the original
creator fault at0x521E98. Startup code needs a safe allocation/slot strategy.

The real kernel context builder, mutex initialization, descriptor registry,
IRQ save/restore, current-task query and callback dispatch execute. Allocation,
metadata/bookkeeping, wake requests and diagnostics are hooks. Dispatch is
invoked explicitly with a synthetic current TCB, not by a running scheduler.
No queue, cancellation, task-exit/cleanup, thread timing or actual device worker
is implemented or verified. This supplies a verified ABI for the next native
worker/queue investigation; it is not an installed App or music player.
Evidence: evidence/firmware-analysis/native-task-creation-emulation.json

Original task context restore and kernel self-exit (offline)

Verify: python3 scripts/emulate_native_task_lifecycle.py
Four restore cases execute the ARM entry0x358EC4, Thumb/ARM transitions,
original VFP disable0x20EBD4, SVC SPSR setup, banked-register restore and
exception return. Three initial contexts come from the original builder;
the fourth is an explicitly synthetic flag1 suspended context, verifying
r0-r12, saved CPSR, SP and LR restoration. The initial13-word/52-byte format
restores r4-r12, SP and LR. It does not initially load r0-r3; the original
dispatch retrieves the saved user argument through the current-task slot.
Self-exit runs through original0x358FA4 and0x1C06A4 in two additional cases.
Both remove the exiting TCB from the ready and all-task lists, mark state0x80
and restore a successor context. The all-task list is linked by two original
kernel-context constructions; ready-list membership is manually supplied.
Original mutex/priority changes, exit notification and timed-wait cleanup
execute without new hooks. One case removes two matching waits while keeping
an unrelated waiter, and registers/calls/removes a listener through the actual
0x3CC5C2/0x3CC624 routines, including duplicate/missing-node guards.

Listener registration ABI: list, node, order, callback, stack:argument.
Listener callback ABI: r0=exiting TCB, r1=registered argument. Node storage
and waiters are synthetic. The listener runs on the exiting task's stack
while the TCB remains in both lists; it cannot immediately free that stack
or unload its module. Both tested exits leave the wrapper slot's+48 TCB
pointer intact. Safe wrapper/allocation reclamation, cross-task cancellation
and unload quiescence still need investigation. The kernel's all-task head
is0xF0908C; its ready/current head is0xF09090.

Allocator/bookkeeping/wake are the prior creation hooks; context restore,
listener registration/removal and kernel self-exit are original instructions.
There is no live IRQ clock, actual wake/queue insertion, contended mutex,
navigation concurrency, physical task or installed App verification.
Evidence: evidence/firmware-analysis/native-task-lifecycle-emulation.json

Bounded media queue with preserving voice integration (offline)

Build: python3 scripts/build_native_media_queue.py
Verify: python3 scripts/emulate_native_media_queue.py
The standalone companion ELF uses4 preallocated4096-byte packet slots. Stock
AVDTP dispatch/LCID lookup/BX veneer calls its enqueue callback, which copies
the packet and returns without decoding or PCM output. The temporary stock
handle is not retained. Explicit media_queue_step calls consume through the
existing preserving voice callback, SBC/FIR converter and original PCM path.
Original IRQ save0x21B6CC/restore0x21B6DC protect metadata; copying/decoding
are outside critical sections. No allocation or Linux runtime is required.

Three original voices each pass mono16k, joint-stereo44.1k and stereo48k
streams:360 valid stream frames/63 packets, including cyclic queue reuse and
destroying the original source immediately after enqueue. PCM is identical
to upstream SBC plus independent absolute-position convolution. Original40
exports/imports/trampolines and all original RAM after the header match.
Twelve additional guard/interleaving cases run with Big5 MeiLing: full queue,
input guards, maximum4096-byte copy followed by deferred malformed-RTP error,
capacity deferral/cancellation, stop during copy, concurrent enqueue during
decode, second-consumer rejection, stop during decode and stop during reset.
Interleavings pause ARM execution outside an IRQ critical section, execute
a second API call on another stack, then restore the original CPU context.
They are deterministic tests, not a real concurrent IRQ scheduler.

With exclusive output-ring ownership, initialized state and at least8961
bytes free, the packet can produce at most15*256 bytes while retaining the
stock reserve's strict5121-byte minimum. Less room returns promptly without
decoding/reserving. Actual exclusive ownership, channel policy, cold init and
hardware timings remain unverified. Stop permits a selected packet to finish
submitting PCM, then discards pending packets. It does not mute/flush stock
audio. Restart is rejected during copy/decode/reset and resets codec/FIR after
quiescence. First initialization must occur before any active caller/worker.

This ELF is not merged into a DLLIMG or VPM. Work is explicitly invoked;
the OS worker/event loop, module/stack lifetime, real SEP/UI/phone transport,
fragmentation/jitter/loss handling and hardware speaker remain unfinished.
Evidence: evidence/firmware-analysis/native-media-queue-emulation.json

Task-event static follow-up: python3 scripts/analyze_native_task_events.py
Normal-context post0x2FCF44 starts ARM; wait0x2FD034 starts Thumb. Known mode
transitions and context-save tails are recorded separately. TCB+8 affects
mailbox acknowledgement, so descriptor word1 must not be assumed to be an
ordinary entry argument. No runtime event/wake or scheduler claim is made.
Evidence: evidence/firmware-analysis/native-task-event-static.json

Persistent native event worker (offline original kernel switching)

Build: python3 scripts/build_native_media_worker.py
Verify: python3 scripts/emulate_native_media_worker.py
The standalone ARMv6 companion links the unchanged queue with media_worker.c
and a preallocated16KiB stack. Original builder0x358BF8 constructs its TCB;
descriptor word1 is0, not an entry argument. Original descriptor registry
0x2FBBBE runs; construction bookkeeping0xF5030 is the only new kernel hook.
The compiled callback copies the packet then posts event1 via original ARM
0x2FCF44. Original Thumb wait0x2FD034, priority insertion, mixed-mode context
save/restore0x358EC4 drive its persistent entry. After draining the queue, the
worker blocks and resumes on the next event without restarting its entry.
Shutdown returns through original0x358FA4/0x1C06A4 and unlinks the task.

Three preserving voices each pass mono16k, joint-stereo44.1k and stereo48k:
252 valid stream frames/36 packets remain reference-identical after destroying
the caller's packet before yielding. Original40exports/imports/trampolines
and header-excluded original RAM remain identical. Queue work and PCM output
execute on the actual constructed worker TCB/stack. No test calls the work
step directly, fabricates an event-wait result or restores a Python CPU
context to drive scheduling. Initial controller/idle ready membership is
supplied; the idle sentinel is synthetic and no hardware IRQ clock exists.

Five additional controls cover coalesced events with4 packets/full rejection,
capacity deferral followed by explicit capacity notification, CRC recovery,
shutdown with pending work and a higher-priority worker preempting the post
caller then restoring the original callback. The priority control uses2
additional frames, outside the252 stream-frame total. Lower-priority worker36
is below controller16; preemption control uses worker3. These are selected
priorities, not evidence of all valid priorities or real device scheduling.

In the worker-only test, consumer capacity notification is not wired: after a deferral with
no new packet, media_worker_notify_capacity must be called once space returns.
The test releases capacity synthetically. Only normal-context post is tested;
IRQ-context alternate0x2FCE38, cold PCM init, actual ring ownership/navigation
policy and real-time hardware performance remain unknown. Stack/module are
retained after exit and unchecked reboot is rejected. First init requires
quiescence. Stop still does not immediately mute/flush original PCM.
This ELF is not merged into a DLLIMG/VPM or installed; real SEP/UI/phone
transport, package acceptance, module unloading and physical audio are absent.
Evidence: evidence/firmware-analysis/native-media-worker-emulation.json

Original audio-consumer capacity feedback (offline factory instance)

Build: python3 scripts/build_native_media_consumer.py
Verify: python3 scripts/emulate_native_media_consumer.py
media_consumer.c wraps one explicitly provided type17 method descriptor. The
original factory0x437764 and ARM memzero0x35B4F4 execute without new hooks.
Only descriptor offset20 changes; every other method stays identical. Attach
checks descriptor alignment/size and original read/format pointers; detach
restores the exact descriptor and rejects provider replacement. Neither
operation proves callback quiescence or safe unloading.

The wrapper calls original reader0x484C05, keeps its returned count/data and
uses original IRQ save/restore around metadata. With pending queue work,
initialized producer and at least8961bytes free, it automatically posts a
capacity event through the compiled worker and original kernel post. Three
preserving voices pass72stream frames/9packets (mono16k, joint-stereo44.1k,
stereo48k), plus13controls including one extra mono frame in the IRQ test.
Tests seed initial PCM once; only actual stock reads release capacity. A
read leaving8960bytes free does not wake the blocked worker; the next read
leaving8962bytes free does. Work resumes without another media packet or a
test call to notify_capacity. Seeded PCM plus decoded PCM are byte-identical
to the expected FIFO. All original40exports/imports/trampolines/RAM remain
preserved. No-queue, inactive-reader, detach/reattach and post-shutdown cases
do not generate inappropriate notifications.

The IRQ control sets synthetic marker0xF09094 and IRQ mode0x92/banked stack.
Original all-ARM post0x2FCE38 runs, retaining CPSR mode/mask and SB; it inserts
the lower-priority worker without switching CPU context. Synthetic normal
mode is then restored and normal original kernel wait runs the worker. This
does NOT test real hardware IRQ entry/exit, a higher-priority IRQ wake, timer
interrupts, navigation workload or actual registered audio callback reachability.
The added observers required30s host timeout for full15-frame FIR packets on
the Pi; the previous6M-instruction ceiling remains. Emulator wall time does
not measure device audio performance.

The method instance, initial ring/producer and prior policy/endpoint/kernel
construction controls are synthetic. Registration choosing this instance,
cold initialization, exclusive ring ownership, actual SEP/UI/phone stream,
VPM acceptance, callback lifetime and physical speaker remain unverified.
The companion is not merged into DLLIMG/VPM, installed or an install candidate.
Evidence: evidence/firmware-analysis/native-media-consumer-emulation.json

Shared queue/worker declarations are now in media_queue.h/media_worker.h.
The refactor preserves the prior queue and worker WHOLE ELF and flat binaries
byte-for-byte, not just symbol names or selected functions. Updated manifests
record both header hashes; prior runtime artifact evidence stays applicable.
Evidence: evidence/firmware-analysis/native-media-header-refactor-verification.json

Original source registration, selection and mixer pull (offline)

Verify: python3 scripts/emulate_native_audio_registration.py
The original host start request calls0x270458 rather than a registration hook.
Original0x277D26 installs queue-driver methods, registration0x277C6A and linked
queue0x277B38 create a kind17/flags6 entry. Original source selector0x2F9F2E
obtains kind/flags/parameters through0x277AC2/0x2777F0 and initializes the
source via0x4379D4 -> factory0x437764 -> prepare0x437A3E. The channel table is
0x034E6F08 with18slots/stride0x208. Methods occupy record+0xF4 (68bytes);
reader pointer is record+0x108, selected as0x484C05. This pointer is produced
by the original source selection, not injected by the test.

Original pull0x2F9CCA loads this pointer and calls it at0x2F9D1A. It copies
returned PCM to a second mixer ring with original memcpy, including the
cross-end path. Two routes (channel5/selector1, channel8/selector0) each
compare768bytes across3explicit pulls, and each mixer copy wraps once.
Source PCM producer is preinitialized, not cold-booted. Mixer descriptors,
ring and scratch are synthetic. The tests hook handle allocation/lock/
release, both mutexes, mixer pull priority and next-message delivery, and
retain prior busy/selector/sequence/start policy hooks. They do not run the
actual mixer worker/IRQ, hardware resampler or speaker. Channel mapping and
queue-driver initial state are supplied; real driver initialization/ownership
and navigation coexistence remain unknown.

Three guards exercise failed source allocation, channel18 out of range and
an unmapped channel. Failed allocation creates no source, and subsequent
source selection does not enter the factory, while the host callback still
returns success. The active flag in this failure control follows the retained
successful-start hook; it is NOT proof the live device starts after failure.

Two attachment controls call the compiled consumer against the descriptor
created by original source selection. Only the reader pointer changes.
Calling original selection again runs the factory and recreates all methods,
replacing the wrapper with stock0x484C05 while consumer metadata still says
installed. Detach detects provider replacement (-29) and leaves it alone.
Thus a single early attach cannot maintain this hook across source lifecycle.
A post-initialization rehook and callback quiescence/ownership contract are
still required. Consumer worker/queue are not booted in these attachment
controls; automatic capacity feedback through a registered mixer pull is
not tested here. The separate consumer-worker test remains its own scope.

Evidence: evidence/firmware-analysis/native-audio-registration-emulation.json
No real device I/O, firmware writes, installed App, SEP/phone stream or package
acceptance is established. These tests do not prove a safe install candidate.

Original mixer message dispatch and explicit post-selection refresh (offline)

Build: python3 scripts/build_native_media_consumer.py
Verify: python3 scripts/emulate_native_audio_messages.py
The exact readonly mapping at0xACB12C contains18rows of28bytes. Original
0x269F6C initializes all18channel records, and0x277E20 initializes global
source queues with current-source0xFFFF. The original profile-install loop
runs only through its pre-hardware endpoint; it is not full hardware startup.
After original host registration, queue-start primitive0x277536 selects0;
the test no longer supplies that current index directly. Mapping lookups use
source IDs, since table order differs from channel order at indices10..13.

Original mixer actor0x2FA0DC handles message13 by calling selector0x2F9F2E,
then message18 reaches the indirect PCM reader via original pull0x2F9CCA.
The actor stays at one entry across two selections and reads on each channel
5/8 route. Each copies512PCM bytes, including a mixer wrap, byte-identical
to the reference. The computed dispatch table is0x2FA260, but ADD PC is at
0x2FA25E and its PC base is0x2FA262; do not use aligned ADR table base as the
computed-PC base. Message13 targets0x2FA268; message18 targets0x2FA454 and
branches onward to0x2FA53C.

media_consumer_refresh_after_selection() is exported by the2736-byte ARMv6
companion. Original source reselection recreates the stock reader, and this
compiled function restores only method offset20. An already-wrapped reader
is accepted; missing attachment (-28) and unrelated reader/format (-27) are
rejected without changing the descriptor. Counters remain intact, and detach
restores all68bytes after refresh. The function does NOT install itself at
the actual selector-return site or prove callback lifetime/quiescence.

The test pauses the actor at post-selector0x2FA298 with no held synthetic
mutex, calls compiled attach/refresh on a separate stack, then Python restores
the actor CPU context. Wait and message-get are hooks, as are retained handle
services, mutexes, priority/message-send and hardware-start policies. Mixer
activation is explicitly supplied, not actual message14/hardware startup.
Decoder queue/worker are not booted here, so this test does not establish
registered-pull capacity feedback to that worker or real OS scheduling.

Message16 is CDC_SEEK / SEEK_SEND_RESET, not an ordinary music pause. Original
0x46CD78/0x1D8C60 enqueue HAM_RESET via the synthetic message-send hook; the
reset-pending byte gates later message18 reads. The actual hardware reset
actor, message17 RESET_DONE, seek completion and music stop/mute are untested.
Cold PCM initialization, navigation/ring ownership, true IRQ/live callbacks,
production rehook deployment, SEP/UI/phone input, package acceptance, safe
unload and physical speaker remain unverified. There is no device I/O and
the standalone companion remains an offline prototype, not an install file.
Consumer capacity and source-registration regression suites passed again
against the rebuilt companion; each retains its own scope above.
Evidence: evidence/firmware-analysis/native-audio-message-emulation.json

Original cold-producer initialization and shared-ring hazards (offline)

Verify: python3 scripts/emulate_native_pcm_initialization.py
This new test starts at the exact initialized-data context0xF09294: byte7 is
zero, byte3 is0x5D, and all indices are zero. Original host0x21C62A itself sets
byte7 before calling initializer0x33F342. No configure() supplies an initialized
producer. Original channel/global queue/profile init runs with the previous
pre-hardware bound. Two channel5/8 paths each initialize once, register kind17
at10240queued bytes, select the original factory and read10240bytes identical
to the PCM reference. Busy/start policy and heap/mutex services remain hooks.

Normal tests restore real priority0x25541C, selector0x2554CA and sequence
0x2554D6 getters. Their control RAM is synthetic. Original voice registry
count/selection/string-match/setting getters and original ARM VFP helpers run.
For a synthetic one-node voice registry at level60, channel levels0/60/100
produce volume commands0/36/60. Virtual CP10/11 access, FPEXC and FPSCR are
explicitly supplied; this does not prove live CPU configuration or hardware.
The unnamed environmental getter0x3D2E8C returns0 through an explicit control.
Fake module volume/reset exports only capture original wrapper requests;
actual VPM loading, complete TTS export behavior and physical output are absent.

Eight controls include those three volume cases, two lower-channel-state cases,
shared-ring caller/discard behavior, controlled priority reset, and the compiled
queue's cold/underrun gate. Original state3 on a lower channel sets context+9
and obtains hold budget800 or0 according to the explicitly controlled busy
return. Original0x2FD38E performs that budget calculation; units/live timing
are not established. Only the priority-reset case substitutes the priority
predicate. Original stop/message/module-reset wrappers then reset write/read
and request two module resets (initializer plus commit), discard the fixture
and new data, while host still returns0. Actual priority arbitration, hardware
preemption and real module resets are not proved.

Different host r0/r1 marker arguments do not partition audio: two128-byte
blocks append to the same global ring and read back in FIFO order. Original
discard0x33F314 sets write=read and drops all256pending bytes together. These
are test markers, not real navigation tasks; the result shows no ownership
isolation in this callback, rather than demonstrating live concurrency.

The unchanged compiled queue defers when context+7 is zero and never reaches
the original host initializer. Four real empty drains run0x33F520 and clear
byte7; an already pending packet again remains deferred. An explicit test host
call reinitializes and clears the gate. Queue consume/reset callbacks here are
stubs, with no decoder worker running. This demonstrates an unresolved startup/
underrun-recovery gap, not an implemented restart protocol or automatic repair.
Do not simply force the byte or flush the shared ring: navigation ownership
and lifecycle must be settled before using this path on the device.

All23original audio-factory kinds are also inventoried without a memset hook,
with descriptor canaries. Fourteen return successful method arrays, but only
the existing TTS path is fully selected/read above. Kinds1/2/5/18/19 share the
same0x48F091 reader and0x48F0A5 format; a real read returns256zero bytes with
mono16-bit/44100Hz format. These are silence placeholders, not alternate raw
PCM inputs. The other providers' initialization, registration, ownership and
playback have not been exercised by this inventory. No dedicated App source
is established. Next investigate independent mixer-source interfaces, or an
enforced shared-ring ownership/start/underrun protocol, while retaining the
original navigation audio. Existing companion/source artifacts are unchanged;
their prior evidence remains separate. No device I/O or install candidate.
Evidence: evidence/firmware-analysis/native-pcm-initialization-emulation.json

Independent original memory audio sources (offline)

Run python3 scripts/emulate_native_memory_audio.py. Kinds10/11 with flags12
use stock registration/queue/factory/IO constructor/prepare to install genuine
memory callbacks: init0x5E759E, read0x5E75BA. Four logical-format routes cover
mono16k and stereo44.1k, with3996PCM bytes identical through the original
indirect mixer pull, partial final read and wrapped mixer copy. Original
cleanup0x437A90 stops, releases the pool slot and clears channel methods.
The memory routes never call global TTS host0x21C62A; context and the entire
TTS ring remain unchanged. Stock caller0x2701DC/callsite0x270268 passes kind10,
flags12 and a0x20C-byte structure for mono16k; this caller is traced statically,
not established as a public App API. Kind11 uses a0x210-byte parameter struct.

Four controls prove sequential independent instances, isolated cleanup and
slot reuse, and data-state separation from the actual cold TTS writer/read/
discard. These are not concurrent navigation tasks or hardware scheduling.
Memory IO borrows the caller PCM pointer: changing its backing bytes after
selection changes later read results, despite the copied parameter handle.
The production output adapter must pin immutable data until true source
completion/callback exit, not merely until register/select returns.

Each kind has five576-byte instance records. The pools are adjacent at
0x034E3CF4 and0x034E4834. Five occupied kind10 records followed by selection
on channel5 makes the allocator returnFFFF without writing the output.
Original constructor prefilled that output with channel5; its failure cleanup
then calls free(index5), clearing kind11 slot0 used marker in synthetic BSS.
The source remains unprepared and constructor returnsFFFF, but outer selector
returns0 and emits events27/23. Occupied kind10 records and the adjacent inner
IO state stay unchanged. Reserve capacity and check the actual source state;
do not enqueue a sixth source or assume selector success proves preparation.

Handles/mutexes/priority/message/hardware controls remain synthetic; PCM pages
and mixer RAM are fixtures. Companion integrity is checked and inherited test
setup loads it, but no compiled worker/queue/consumer is invoked or changed.
The existing compiled pipeline still writes shared TTS PCM, with its previous
startup/underrun and ownership limitations. Next trace original completion/
advance, implement bounded pinned memory-source output and capacity signaling,
then connect decoder/worker without changing navigation host imports. Neither
logical format nor data isolation proves hardware resampling/DAC/speaker or
actual navigation audio coexistence. Modified package acceptance, App/UI and
registered A2DP reception are still absent; no device I/O/install candidate.
Evidence: evidence/firmware-analysis/native-memory-audio-emulation.json

Original memory-source FIFO completion and notification boundaries (offline)

Run python3 scripts/emulate_native_memory_completion.py. Six source nodes are
enqueued before any provider slot is consumed. The real mixer actor selects
with13, reads with18, stops with15 and cleans with19; original0x277674 then
removes the source-list node.3482PCM bytes match, slot0 is reused six times,
and the global TTS context/ring remain unchanged. Hardware activation and the
small mixer/scratch are explicit fixtures; message14 hardware configuration
and actual drain/end triggers are not exercised. No production auto-advance
adapter or SBC/worker/output integration has been added.

EOF leaves the source prepared, provider slot occupied and list node live.
Provider cleanup produces report events26/25/22 and clears methods/releases
the slot; node removal separately reports23. Report mask6 selects22/23, then
original0x455B64/wrappers translate to broad main event0x246 with flags2/8.
Report-filter bits differ from translated main flags. The main dispatcher
0x330B48 is a capture stub: actual client routing/registration is unknown.
All metadata identifiers are synthetic markers, not validated App IDs.

Four controls establish limits for future buffer lifetime decisions:
- Removing the list node and delivering23 does not stop the reader: it still
  returns the original borrowed PCM while prepared/slot-used remain set.
- Delayed25/26 use packet+4 metadata, whereas22/23 wrappers reload current
  channel record+0x1B0. After selecting another source, these fields differ.
  Do not assume the translated identifier preserves a per-block generation.
- Mask0 filters all reports without preventing cleanup/deletion; mask6 emits
  only22/23 and translates to2/8. A listener needs the appropriate mask.
- Notice23 is emitted BEFORE node unlock/release and count/current update.
  Pausing original removal at0x2775E6 permits explicit notice translation on
  another stack while node lock/count remain live; restoring Python context
  then completes the original removal. This is not actual OS preemption or
  live callback quiescence. Controller calls preserve the paused actor stack.

Next identify actual main-event client/listener registration or a preserving
raw-notice observer. Establish source-callback exit, list-remove completion
and generation-aware immutable-buffer pinning before recycling slots. Keep
source-pool reservation/exhaustion guards; queue-node count is not provider
slot count. Existing compiled queue still writes global TTS PCM and has not
been redirected; companion is checked/loaded by inherited fixture setup but
not invoked or modified in these tests. Original wait/get/message, handles,
mutexes and priority remain controlled, and Python restores actor contexts.
Native App/SEP/UI/phone reception, accepted component loading, actual speaker/
resampling/navigation coexistence and Google Maps are still absent.
Evidence: evidence/firmware-analysis/native-memory-completion-emulation.json

Raw notice observer and original broad main dispatch (offline prototype)
----------------------------------------------------------------------
Run python3 scripts/build_native_memory_notice.py, then
python3 scripts/emulate_native_memory_notice.py. The standalone ARMv6 image
is860 bytes with140-byte loader-cleared BSS, no unresolved symbols or OS
runtime. It is not merged into a VPM, installed or an App registration API.

memory_notice_dispatch copies a selected original20-byte report BEFORE
forwarding its pointer/control to original0x455B65, then journals the owned
copy. The original return is preserved. Four slots filter one channel and
event21..33 mask; full drops newest with a counter. Input destruction after
return, FIFO wrap and event/channel filters are verified. Configure rejects
invalid channel/mask or in-flight observer calls; disarm clears queued data
and cancels an in-flight snapshot without stopping original dispatch.
Configuration epochs reject overflow but are NOT source/stream generations.
Disarm/overflow/notice23 do not prove reader exit, safe PCM recycle or unload.

The earlier main capture stub is removed in this test. Original0x330B48 and
early subsystem handlers execute; only optional context query0x27811E is
controlled as0/1. Both event246 routes reach default0x330EDE (incidental main
return320, original notice-dispatch return0). Restoring the whole query enters
filesystem0x26A300 then faults at0x26A24C in the incomplete fixture. This is
not a device failure or proof that no native clients/App mechanisms exist.

Two original kind10/flags12 queued sources deliver984PCM bytes and8 notices
through selection/read/stop15/cleanup19/remove. After new-source selection,
raw packet metadata stays old while original22/23 wrappers keep their native
current-channel translation. Identifiers are synthetic test markers, not
validated client IDs. Full TTS context/ring stays unchanged. Three control
groups cover overflow/wrap/filter, invalid output/configuration and2-byte
unknown-event page boundary, IRQ mode/masks, and paused in-flight disarm plus
epoch overflow. Controlled interleavings use separate stacks/Python restore;
they do not establish real IRQ scheduling or source callback quiescence.

Inherited setup calls existing consumer_init as a fixture; no consumer audio
reader/notification, decoder, queue or worker pipeline is called or changed.
Original source actor still uses controlled wait/get/message/handles/mutex/
priority and supplied activation/mixer/scratch; real message14/hardware drain
is absent. Next build bounded immutable PCM ownership/pinning, serialized
reader exit and complete list removal, pool reservation/checks and wakeup;
then redirect decoder output without changing navigation TTS host imports.
Actual report hook, native UI/client/SEP/SDP, accepted VPM and phone/speaker/
navigation coexistence remain required. No device I/O or install candidate.
Evidence: evidence/firmware-analysis/native-memory-notice-emulation.json

Owned finite PCM output (offline prototype, serialized actor contracts)
---------------------------------------------------------------------
Run python3 scripts/build_native_memory_output.py, then
python3 scripts/emulate_native_memory_output.py. The new2440-byte freestanding
ARMv6 companion has144-byte loader-cleared metadata and4 separate4096-byte
PCM pages. Tests map gaps as unmapped protection pages. It supports mono16k
16-bit PCM initially; no actual hardware format/conversion is established.

memory_output_submit copies into a FREE slot before publishing anything and
returns a private positive generation/index ticket. Four owned buffers can
wait READY, but only one original kind10/flags12 source is registered at once.
Original registration uses NULL metadata: private tickets are NOT native App
identifiers. Original actor13 selects, explicit after_selection wraps only
the exact borrowed-buffer kind10 reader and preserves other methods; actor18
calls the compiled in-flight wrapper and original reader. Original stop15,
cleanup19 and complete list-remove return must precede release. Native source
prepared/method/pool/mixer/list state and entered-reader counters gate recycle.
Generation overflow rejects submit; stale tokens fail after storage reuse.

Four blocks5592PCM bytes match after caller input destruction, every original
provider uses slot0 serially, and global navigation TTS context/ring remains
unchanged. Full owned storage rejects another submit. The4096-byte case stalls
at1792 bytes with no consumer in the2048-byte mixer; test explicitly advances
its read index after that proof and each later chunk. This is a supplied
consumer fixture, not actual DMA/drain/capacity-wakeup/speaker validation.

Five control groups cover invalid ranges/overlap/methods/reconfiguration and
ticket overflow, original node allocation failure followed by same-ticket
retry, five original kind10 providers already occupied while an original
kind11 provider stays unchanged, early report23 before remove returns, and
an entered wrapper paused before original read. In the last control original
cleanup/removal run on another stack, but release remains blocked by the
counter until original read (return0 after cleanup) and compiled wrapper exit.
These interleavings use Python CPU restore, not actual OS preemption. NULL
metadata filters transport; the notice observer/main client is not exercised.

IMPORTANT: one serialized actor, exclusive ownership of this channel list
and exclusion of allocation interleaving at the guard boundary are REQUIRED
caller contracts, not outcomes of these tests. Pool inspection is NOT native
cross-actor reservation. Counters see entered calls only, cannot exclude an
old reader pointer loaded before entry and do not permit real safe unload.
Post-selector/release/lifecycle boundaries are explicit test calls; no hook,
automatic FIFO start/advance, live task scheduling, stop/restart or wakeup is
installed. Hardware/message14, navigation coexistence and accepted VPM remain
unverified. Inherited handles/mutex/priority/messages/activation/mixer/scratch
remain controlled. Existing consumer_init runs only as fixture setup; its
audio/decoder/queue/worker pipeline is not called or changed.

Next gate decode on private free-buffer capacity and notify after serialized
release, then connect preserving SBC/FIR queue/worker without modifying original
navigation TTS imports. Establish real allocation/actor/lifetime ownership and
hardware consumption, native UI/SEP/SDP/phone/speaker and package acceptance.
No device I/O or install candidate; the full modernization goal remains open.
Evidence: evidence/firmware-analysis/native-memory-output-emulation.json

Whole-packet SBC/FIR -> owned native memory source (offline integration)
--------------------------------------------------------------------
Run python3 scripts/build_native_owned_media.py, then
python3 scripts/emulate_native_owned_media.py. The50488-byte ARMv6 standalone
links codec/FIR, memory_output, bounded queue and worker. Metadata BSS17816.
The builder generates owned_queue.c from unchanged media_queue.c replacing
ONLY output_ready: private PCM availability replaces the global TTS-ring gate.
Existing queue/worker/consumer artifacts are unchanged. memory_output.h moves
shared declarations without changing the baseline output ELF; all five old
output controls have been rerun successfully.

Original AVDTP dispatch/lookup/BX veneer routes synthetic packets to compiled
queue. Three source formats mono16k, joint-stereo44.1k and stereo48k convert
54 normal frames through whole-packet gather and owned finite PCM; original
kind10 actor selects/reads/stops/cleans/removes each source. Full recovery
streams match upstream SBC plus independent absolute convolution. Original
TTS context/full ring stays unchanged, including a cold producer flag. This
does not exercise original voice bootstrap/import interfaces or navigation.

Four held PCM slots defer the fifth compressed packet BEFORE codec/FIR state
advances. Release plus an explicit test step handles pending work. Whole
packet gather means a later CRC failure publishes no prefix; reset recovers
the next packet. A15-frame maximum packet yields3840 matching PCM bytes.
Paused stop before decode/during private submit cancels tentative FIFO commit;
stops AFTER commit still retain old PCM, and new begin waits for its drain.
Parser submitted counters describe internal conversion, not committed or
physically played output. There is no immediate mute or generic pause claim.

Steps, actor post-selection/release and consumer-index advancement are test
calls, not installed hooks or real DMA. Worker/release-post support is linked
but no decoder task is booted or kernel capacity wakeup exercised here. The
native serialized actor/exclusive channel-list/allocation contracts are still
required, not cross-actor reservation or future callback exclusion/unload.
Controlled stop uses another stack and Python restore. The unchanged16-page
synthetic allocator services both temporary RTP handles and source nodes;
phase boundaries reuse it only after every handle/source/queue retires, with
guard verification first. Format routes use independent sessions.

Next integrate real kernel decoder work and release-driven wakeup, resolve
shared native wait/get fixtures and trace the original audio actor/allocation
scheduling domain. Then automate FIFO native lifecycle, prove ownership,
hardware14/consumption/format policy, preserving package acceptance and actual
native UI/SEP/SDP/phone/speaker. No device I/O or install candidate; Google Maps
and the full modernization goal remain open.
Evidence: evidence/firmware-analysis/native-owned-media-emulation.json

Owned decoder on original kernel events (offline follow-up)
----------------------------------------------------------
Run python3 scripts/emulate_native_owned_worker.py. It uses the unchanged
owned-media ELF and boots its compiled decoder with the original kernel
builder, registration, post/wait, priority/context switching and exit shim.
Four routes cover mono16k, joint-stereo44.1k and stereo48k at priority36,
plus mono16k at priority3. All40 frames/20 packets/6904 PCM bytes match the
independent codec/convolution reference; output remains mono16k/16-bit.
Every decoder step must run on the scheduled worker's guarded16KiB stack.

Four held private PCM buffers cause the fifth compressed packet to defer.
Complete original source cleanup/removal and compiled owned release post
an original capacity event. No explicit queue step, capacity notification
or new packet drives recovery. Priority36 resumes when the controller
waits; priority3 preempts inside the release post. Each worker enters once,
defers once, completes self-exit to TCB state0x80 and refuses another boot.
Its stack, TCB and module remain allocated; this is not safe unload/reuse.

Normal System mode0x1F is an explicit fixture. The inherited source harness
defaults to SVC, which is unsuitable for a parked task restored via the
kernel's user/system SP/LR bank. Restore stock wait bytes for actual task
waiting; redirect only the controlled mixer wait to a separate Thumb
BX-LR veneer using an odd PC. Generic mutex lock/unlock remain inherited
hooks, including any kernel callers using those addresses. Controller/idle
construction/membership, bookkeeping and initial state are fixtures.

The source actor still executes via supplied messages and Python CPU restore;
it is not another booted native kernel task in this test. Post-selection,
release/lifecycle boundaries and mixer consumption index are supplied. No
automatic FIFO actor adapter, real IRQ/hardware14/DMA/performance, accepted
module/UI/SEP/phone or physical speaker/navigation coexistence is proved.
Original TTS context/full ring stays unchanged, not true navigation speech.
Evidence: evidence/firmware-analysis/native-owned-worker-emulation.json

Per-channel mixer tasks and shared source allocator (offline finding)
-------------------------------------------------------------------
Run python3 scripts/emulate_native_mixer_creation.py. The original0x3B9B66
initializer builds and registers separate tasks for channel5 and8 via the
original kernel. Both use entry0x2FA0DC, but have distinct TCBs,8192-byte
stacks and240-byte message storage. Descriptor initial priority is23.
Allocation/lock/name/bookkeeping are controlled and execution stops before
the original wake at0x3B9C1E. Neither mixer task has run its message loop;
other channels/callers, later priorities and scheduler exclusion are unknown.
Do not infer a single global actor from the common entry address.

Original kind10 allocator0x48EE68 references shared pool0x034E3CF4. A
controlled instruction interleaving pauses the first call at0x48EE80 after
its free-slot test; a second original call obtains slot0, then the resumed
first also returns success/slot0. Adjacent pool guards remain intact. This
is a separate-stack/Python-context counterexample to INTERNAL atomicity,
not an actual OS/IRQ preemption or proven live race. It does not disprove
caller locks, IRQ masking or scheduling exclusion, nor establish that
two default priority23 actors can interleave here on real hardware.

Next boot the original mixer task with native wait/message semantics and
automate FIFO start/select/attach/read/stop/cleanup/remove/release. Trace all
source allocation callers and dynamic priority/exclusion; establish shared
pool admission and channel ownership plus future callback lifetime before
reusing PCM/unloading code. Then prove hardware drain/format conversion,
preserving accepted module/UI/SEP/SDP/phone/speaker. No device I/O or install
candidate. Native Google Maps remains deferred and the full goal remains open.
Evidence: evidence/firmware-analysis/native-mixer-creation-emulation.json

Original kernel mixer actor and native message FIFO (offline follow-up)
---------------------------------------------------------------------
Run python3 scripts/emulate_native_mixer_worker.py. This boots the original
per-channel mixer initializer/registration/wake and restores the original
message post0x37BCE4/get0x37BC00. Decoder and mixer use original kernel
post/wait/context switching; no Python actor CPU restore or fake transport.
The actor enters once on its own8192-byte stack at priority23, alongside
the priority36 decoder and priority16 synthetic controller.

Three formats mono16k/joint-stereo44.1k/stereo48k cover30 frames/15 packets
and4344 PCM bytes, matching codec plus independent absolute convolution.
Output remains mono16k/16-bit.95 native messages copy/order/wrap correctly
in the original20-slot,12-byte,240-byte FIFO. Sent input is destroyed after
post, but the original getter still retrieves the copied data. Fixture
admission reserves one empty slot; original full/error handling is unknown.

The original pull0x2F9CCA self-posts read18 via0x2F9E2E while mixer space
remains.20 self-posted reads occur in the normal routes. One external read
can therefore produce multiple chunks; do not use the old fake-transport
aggregate256-byte bound. Each actual pull return0x2FA576 is checked against
its own256-byte scratch and ring guards before aggregating. Scratch canaries
are reseeded at each pull entry. The original getter drains copied messages
then the actor blocks with an empty mailbox rather than restarting its entry.

A maximum15-frame packet produces one3840-byte source. The native actor
reads1792 bytes until controlled mixer space is insufficient and blocks.
After explicit consumer-index advancement plus read18, it reads1792 then
256 bytes, followed by EOF0. All PCM matches,20 FIFO messages wrap, and
stack/FIFO/scratch/ring/private-code guards hold. This tests native reading
with supplied hardware consumption/rearm, not true DMA/capacity IRQ.

Initializer allocations/locking/names/bookkeeping and external audio
timing/state hint0x46CC7A remain fixtures. Generic mutex/priority/busy/start
and buffer/scratch/activation are still controlled. Inherited setup_mixer
writes a fake mixer+0x78 task handle; restore the actual TCB before native
posts. Source queue start, selection attachment, cleanup15/19, node removal
and owned release remain explicit serialized controller boundaries. Only
one audio channel actor runs here; shared allocation exclusion, channel-list
ownership and future callback lifetime are not proven production contracts.

Decoder self-exits but its stack/TCB/module remain allocated. Mixer stays
blocked with pinned original stack/message allocations. Neither permits
unload/reuse. TTS context/full ring unchanged is not navigation concurrency.
Next connect automatic source start/attach/stop/cleanup/remove/release and
stop/restart/drain policy, trace hardware14/DMA/format/end/capacity events,
restore remaining policies and establish all caller exclusion/lifetime.
Preserving accepted module/UI/real SEP/SDP/phone/speaker and deferred Google
Maps still remain. Compiled components unchanged; no device I/O or install
candidate. Evidence: evidence/firmware-analysis/native-mixer-worker-emulation.json

Original START14 and scratch lifetime (offline follow-up)
------------------------------------------------------
Run python3 scripts/emulate_native_mixer_start.py. Original mixer message14
executes the kind10 block-size getter0x48EE9E, which returns4096. The actor
calls allocate/lock for that scratch size, sets active state and performs
its first source pull. Message15 calls unlock/free and clears the scratch
handle/pointer. This replaces the previous controller-supplied activation
and256-byte scratch. The heap/handle services themselves are still fixtures.

Three source formats cover30 frames/15 packets/4344 PCM bytes and75 native
FIFO messages.15 scratch allocations each receive a corresponding original
STOP15 release. Decoder and original audio actor execute native scheduling;
PCM matches codec plus independent absolute convolution. Output descriptor
and8192-byte ring are virtual, with matching16kHz output to isolate the
no-resampler branch. Neither a physical output driver nor DAC rate/start,
resampling, DMA, IRQ, actual timer/clock or hardware drain is proved.

The6144-byte virtual-ring control copies all3840 bytes of a maximum15-frame
source, then blocks its next EOF probe: remaining2304 bytes are not greater
than the source's4096-byte read block. Explicit consumer advancement/read18
reaches EOF. EOF leaves the actor active, provider prepared, scratch locked
and source node present. Stop alone or cleanup alone still refuses owned
release; explicit15/19/remove/release completes controlled retirement.
These are serialized controller boundaries, not automatic source switching.
Evidence: evidence/firmware-analysis/native-mixer-start-emulation.json

Original capacity-event response (offline follow-up)
--------------------------------------------------
Run python3 scripts/emulate_native_mixer_capacity.py. Controller posts the
original kernel event0x200 twice, without sending any read18. Original
actor0x2FA0DC obtains its channel from current TCB via0x2FA0B4, checks ring
space, and does not enqueue/read while space is insufficient. After explicit
virtual consumer advancement, the second event makes the actor self-post
read18 through the original FIFO and probe EOF. Kernel post/get/wait and
guarded stacks/scratch/ring remain original; full reference PCM is identical.
Nonpreempting post preserves target r0; actual mailbox/ready-state checks
replace the incorrect assumption that every post returns success1. A
preempting post can instead resume a parked wait returning its event bits.

Event arrival and virtual consumer index remain explicit fixtures. This
does not execute original timer expiry or establish an actual DMA/IRQ/event
source. Trace original timer scheduling0x353BD4 and output-driver command
queue0x1D8C60 with wrappers0x46CD08/0x46CD78 next. Event0x100 is progress
polling; message20 is synchronization, neither source retirement. Restore
true format/resampler/start/drain, automatic FIFO lifecycle and remaining
mutex/priority/hardware policies. Cross-channel source pool/list ownership,
future callbacks, preserving accepted module/UI/SEP/phone/speaker and safe
unload still remain. TTS ring unchanged is not real navigation concurrency.
All compiled ELFs unchanged; no device I/O or install candidate. Deferred
Google Maps and the full modernization objective remain open.
Evidence: evidence/firmware-analysis/native-mixer-capacity-emulation.json

Original timer capacity expiry (offline follow-up)
------------------------------------------------
Run python3 scripts/emulate_native_mixer_timer.py. Original descriptor
initializer0xF6E48 and create0x353D3C build the priority1 timer task with its
original static stack ending0x02D22834. Original schedule0x353BD4 and insert
0x353E48, ARM tick0x353CE0, IRQ-safe post0x2FCE38 and expiry loop0x353D78
execute. Timer sends0x204 to the audio task; controller sends neither audio
capacity0x200 nor read18. Audio's original response checks space and posts
its own read through the native FIFO. No Python CPU-context restore is used.

Two15-frame/3840-byte routes(total30frames/7680bytes) test early tick, exact
deadline, insufficient-space reschedule, available-space EOF and32-bit
epoch rollover. All reference PCM and private/source/scratch/ring/stack/FIFO
guards hold; TTS context/full ring unchanged is not navigation concurrency.
Interval34 is the original arithmetic with this synthetic output format;
physical tick units have not been measured. The original timer remains
blocked with retained static storage after the controlled source finishes.

Tick arrival is virtual, delivered after the controller's original wait.
A separate virtual event stack preserves every task's suspended context.
When the tick makes a higher-priority task ready, explicitly calling original
restore hands off from the idle sentinel; this is not physical IRQ entry/exit
or proof of its live dispatcher. Do not use READY's new TCB as a caller stack
before restore: helper calls can overwrite the very context being restored.
Entry0x353D78 is also a wait-loop head, and context flag0 also occurs for a
compact suspended wait frame. Initial-dispatch count uses the saved entry PC,
one per route; repeated wait-loop visits are not task restarts.

Output consumer/descriptor and heap/locks/mutex/priority/hardware hints remain
fixtures; source selection/attachment/14/15/19/remove/release are controller
boundaries. No real output driver allocation/format/resampler/start/DMA/end
drain, automatic source transition, cross-channel ownership/future callback
exclusion, accepted module/UI/SEP/phone/speaker/navigation or unload is proved.
ELFs unchanged; no device I/O or install candidate. Full objective stays open.
Evidence: evidence/firmware-analysis/native-mixer-timer-emulation.json

Central source control and output driver (static inventory)
---------------------------------------------------------
Run python3 scripts/analyze_native_output_driver.py. Exact pointer literals
identify output manager ROM descriptor0xA0A694/entry0x436C65, initializer
0x40CA80 and TCB global0xF29320. Its56-byte20-slot FIFO and priority22 differ
from per-channel mixer actors. Central source controller descriptor0xACB324,
entry0x3BA037 and TCB global0xF29360 use12-byte15-slot FIFO/priority92;
notice descriptor0xACB338/entry0x455C43 uses20-byte30-slot FIFO/priority93.
Both latter descriptors are installed by0x30EE62.

Output command dispatcher0x1D9084 has an eleven-entry computed Thumb table.
Outcome wrappers0x1D9140/0x1D9160 send messages11/12 to central controller
global0xF29360, not directly to mixer START14. Trace central request wrapper
0x30EDFE/message dispatcher0x3B9F84 and the hooked start0x36B720 to automate
source boundaries correctly. Driver-channel table has19 slots/84-byte stride;
do not assume all match the18 logical source channels.

The inventory executes none of these tasks and reads no physical RAM. ROM
priorities do not establish all dynamic priorities or shared allocation/list
exclusion. Physical driver configuration, format/mixing/resampling, playback
completion/drain and real clock/IRQ/DMA remain open. Accepted module, App UI,
true SDP/SEP/phone/speaker and deferred Google Maps remain required.
Evidence: evidence/firmware-analysis/native-output-driver-inventory.json

Original central source start and synchronization (offline follow-up)
-------------------------------------------------------------------
Run python3 scripts/emulate_native_source_controller.py. Original initializer
0x30EE62 creates central and notifier tasks from ROM descriptors, using native
TCBs0x034EB3C0/0x034EBC70, priorities92/93 and12x15/20x30 message FIFOs.
Public source-start0x36B720 calls original queue-start and synchronous request
0x30EDFE. Original condition wait/ack and central source selection/prepare
execute; controller no longer calls queue-start/mixer-init or enqueues14.
Original output wrappers request commands1/0/4. The original allocation
callback0x2F998E publishes the descriptor and posts mixer START14 itself.
Driver outcome wrappers11/12 execute and central consumes their packets
without starting a source. Notifier enters once but receives no packets:
owned registration uses NULL metadata; this is not an App listener proof.

Three routes decode19frames/4198PCMbytes, identical to independent references:
15-frame mono16k capacity/timer control and2-frame44.1k joint/48k stereo.
After inherited cold setup, real kernel mutex lock/unlock bodies and condition
blocking/drop-owner run. Restoring previously executed hook bytes also needs
Unicorn translation-cache invalidation; entry-byte checks alone are inadequate.
Cold condition init and hardware-ready source state1 remain explicit inputs.
The auxiliary lower stack canary1KiB below each end is a test boundary, not a
recovered original allocation extent. All guarded PCM/TTS/FIFO checks hold.

Physical request1D8C60, arbitration4C2800, power query276148 and power3E0088
remain fixtures. Driver completion invocation, matching16k output descriptor,
virtual ring and consumer are supplied. Reader attachment,15/19/remove/release
are explicit boundaries; no true output-manager/DAC/resampler/DMA/IRQ/end/drain
or automatic next-source playback is proved. A15-frame44.1k stereo attempt
did not reach the inherited30s/6M-instruction emulator endpoint (PC0880202C);
which budget limited it remains unmeasured, not a Garmin failure/deadline.
Successful stereo controller cases cover2frames, not maximum stereo packets
or realtime throughput. Modules/tasks remain pinned; ELFs unchanged, no device
I/O or install candidate. Cross-channel ownership/future callback exclusion,
accepted module/App UI/SEP/phone/speaker/navigation/unload and the full goal
remain open. Google Maps remains deferred by the user.
Evidence: evidence/firmware-analysis/native-source-controller-emulation.json

Run python3 scripts/analyze_native_source_control_flow.py for the exact
13-entry central table. Table address3B9FBC differs from ADD-PC branch base
3B9FBE. Opcodes11/12 share default acknowledgment; allocation1D8B74 actually
calls START14 callback2F998E at1D8C58. Stop3 sends driver stop and moves to
source state5; completion7 has separate cleanup/reselection. They have not
been integrated into a verified automatic source lifecycle. Next connect real
output-manager/driver allocation and stop completion, then automatic15/19,
source removal/release and next-source, restoring arbitration/format policies.
Evidence: evidence/firmware-analysis/native-source-control-flow.json

Stock output manager and natural source retirement (offline)
-----------------------------------------------------------
Run python3 scripts/emulate_native_output_manager.py. Original40CA80 creates
output TCB034E2DC8/priority22,20-slot56-byte FIFO and entry436C64. Restored
request1D8C60/cache executes direct allocation or original transport; original
1D8B74 builds a32000-byte output ring and calls2F998E, publishing its actual
driver-record+14 descriptor and START14 without controller callback injection.
Stock format1FB85E/gain1FB4E0 operate on explicit cold source mask1/gain100 and
physical0 stereo16k/4480-byte frame inventory. Heap allocation/release remain
fixtures, not production driver heap validation.

Three bounded input routes (mono16k5x2 frames; joint44.1k/stereo48k2 frames
each) decode14frames/7packets/2918monoPCMbytes identical to independent
references. Original source-frame436E5E on the output task stack produces
5836bytes in the virtual stereo16k buffer, identical to duplicated mono samples.
Its R2 argument is FIRST-SOURCE FLAG1, not frame/sample count: stock437688
sets1 then0 for subsequent sources; count comes from physical record+4 bytes,
and the return counts16-bit samples. The virtual ARM peripheral veneer uses
this ABI and4480-byte guarded storage, bypassing stock multi-source dispatch.
Only gain100/matching16k/one source is checked, not resampling/gain variants/
multi-source mixing or real DAC/IRQ/clock/DMA/speaker output.

Seven native source lifetimes drain through the original helper, central
end6/driver stop/STOP15, held-ring retirement1D8C98, completion7/CLEANUP19
and next-selection removing the only source node, returning state1. Natural
selection uses INTERNAL277596 directly rather than PUBLIC277674; deletion
must be nonempty/once per allocation on the original mixer task. An all()
predicate on an empty removal log is insufficient. Owned release then wakes
the native decoder from four-held-slot capacity deferral without explicit
step/notify/new packet. Controller still registers and starts each published
PCM block, attaches reader late and releases owned tickets; native next is
list depletion, not automatic selection of the next published PCM block.
First original reads precede attachment with PCM statically pinned. There is
no pre-first-read production lifetime hook, cross-channel pool/list ownership,
future-callback exclusion or safe unloading. Old fixed mixer descriptor is
only a read-only observation shadow, never copied back to original data.
Power/arbitration/startup/frame events remain fixtures. Notifier boot/wait
only, no App notifications. Tasks/modules pinned, ELFs unchanged, no device I/O.
Evidence: evidence/firmware-analysis/native-output-manager-emulation.json

Stock public stop does not delete the queued source (offline)
----------------------------------------------------------
Run python3 scripts/emulate_native_output_stop.py after the output baseline.
Stock public36AF74(channel,1) dispatches central3/driver6/source5 but leaves
provider/mixer/scratch/list alive while stop is pending. Two virtual frames
execute original fade-state logic/scratch stop and driver release/central7
cleanup: source1/driver0, provider inactive,68-byte methods cleared, output
ring and scratch freed. Central messages are11/12/1/3/7; the queue node is
still present and immutable owned PCM remains held. Release correctly returns
-25 at every stage, including after completion. This test deliberately leaves
node/PCM/task/module storage pinned; it is not a complete cancellation adapter.

The bounded source is mono16k/two frames with writer EOF already present,
stopped before first virtual peripheral consumption. Long streams, pending
producer cancellation, audible fade/mute and restart are unproved. Compiled
selection_guard accepts only QUEUED; a stopped source remains ACTIVE, so
restart/reader reattachment needs a characterized serialized contract, not
test state overwrites. Next build the pre-first-read lifetime boundary and
public stop/cancel/restart/next-published-source coordinator, then restore
hardware/arbitration/format policy and integrate accepted native module/UI,
registered SEP/SDP, actual phone packets/speaker/navigation. Original full
goal stays open, Google Maps deferred by the user. No install candidate.
Evidence: evidence/firmware-analysis/native-output-stop-emulation.json

Compiled before-START reader attachment and retained-source replay (offline)
-------------------------------------------------------------------------
Run python3 scripts/build_native_playback_control.py then
python3 scripts/emulate_native_playback_control.py. New836-byte ARMv6 module
with32-byte BSS imports the unchanged owned-media ELF's PRIVATE control/slots/
after_selection addresses. The old owned/memory-output/consumer artifacts stay
unchanged. Virtual08A00000 layout/private absolute imports are not deployment
addresses or public Garmin ABI; this is not an accepted native package.

The emulator explicitly patches10 bytes at original allocation callback2F998E
to the native ARM shim. Original caller stack is preserved; only the new C call
is8-byte aligned. On the actual central task, compiled before_start attaches
memory_output_read BEFORE original START14 posts or first reads. The shim
replays displaced Thumb30b5020000255057ff21 semantics, then BX resumes original
Thumb2F9998 (pointer2F9999). Original body remains unchanged. Patch identity is
checked during runtime; it is removed/cache-invalidated only after native
FIFOs block/empty for inherited unchanged-entry checks. Do not report that the
original entry was never patched. This hook exists in emulator RAM only.

Three routes decode19frames/4198sourcePCMbytes: mono16k15frames and joint44.1k/
stereo48k2frames each. All12 original reader calls across initial play/replay
traverse the compiled reader from the very first read, with paired counts and
immutable/reference PCM checks; controller makes no late after_selection call.
Original public stop retains node/PCM after provider/scratch/ring cleanup.
Compiled playback_rearm checks original idle source1/driver0, provider/methods/
mixer inactive, node count1, matching pool inactive and no private in-flight
calls. It transitions only PRIVATE ACTIVE->QUEUED, resets installed/instance,
never rewrites native state or recycles PCM. Original guard/start reselects
the retained node and replays it; virtual stereo replay8396bytes matches the
duplicated mono reference. Original natural end then deletes node/releases
native resources, allowing owned release. TTS context/full ring unchanged.

Control guards reject invalid ticket0, active play, pending stop, repeated
queued rearm, deleted node and released stale ticket. Full ARM shim rejects
NULL descriptor-20 without entering original callback. Unrelated source bypass
and invalid owned attachment/error cancellation are not exercised. Failure
keeps native allocations pinned for reconciliation. Sources already reach
writer EOF before stop (mono0.24s and2-frame stereo), not long stream/pending
producer cancellation/automatic next-published-PCM or audible fade/mute proof.
IRQ exclusion/private state checks do not establish not-yet-entered callback
quiescence or cross-channel pool/list reservation; serialized exclusive owner
and pinned modules remain required. Inherited physical inventory/gain/heap/
frame/peripheral/power/arbitration fixtures remain. No actual IRQ/clock/DMA/
DAC/speaker/realtime/navigation/App/UI/loading/SEP/SDP/phone/Android Auto/
Google Maps or safe unload. Full goal open, Maps deferred, no device I/O.
Evidence: evidence/firmware-analysis/native-playback-control-emulation.json
Manifest: staging/native-playback-control/manifest.json

Compiled source pump and full queued-data cancellation (offline, polled)
----------------------------------------------------------------------
Run python3 scripts/build_native_media_coordinator.py then
python3 scripts/emulate_native_media_coordinator.py. New1468-byte ARMv6 module
has60-byte BSS and virtual08B00000 layout. Eight private imports bind the exact
unchanged owned-media ELF; previous owned/memory-output/consumer/playback
artifacts remain unchanged. Original current-TCB helper358D24 readsF09090 in
normal context/returns0 with IRQ nestingF09094;2FA0B4 further maps TCB to mixer
channel and is not the same query. Init captures the caller actor; pump/cancel
check that identity/private busy. This is not global ownership/quiescence.

Three routes decode30frames/15packets/4344PCMbytes;8688virtual stereo bytes
match independent references, and all30 original reads go through the frozen
before-START reader guard. Compiled pump registers, calls stock admission/
public source start, fully releases each completed source and picks the next
published block. Four PCM slots holding data defer the fifth compressed
packet; compiled owned release posts the original kernel capacity wake, and
decoder processes it without controller step/notify/new packet. Each route
retires five sources via stock natural end/mixer node removal and C release.
Host still supplies packets/virtual frames and polls pump7 times per route.
No coordinator worker/publication/completion wake, infinite stream or seamless
audio/timing claim. Lower peripheral startup helpers share the inherited
virtual frame bridge, not a real hardware clock.

Compiled cancel stops the synthetic producer queue, discards one pending
compressed packet and waits original public stop/resource cleanup. It holds
PRIVATE native_calls through the ENTIRE original public remove277674 (mutex
lock3009A0/internal277596/unlock3008B0/return), with IRQ exclusion released
before calling blocking native code. Original early report23 sees nodecount1/
native_calls1; public-return boundary sees nodecount0/native_calls1, then C
decrements its hold and invokes owned release. Cancellation clears four held
PCM blocks. Three never-selected READY buffers are registered then removed
without reads, using the already-characterized QUEUED release path, not direct
FIFO/native-state resets. Internal cancel removal runs on captured coordinator
actor; only the older harness's must-be-mixer assertion is replaced by actual
cancel actor/state/counter checks, original instruction body unchanged.

Queue running is field4, not read-index field0. Corrected explicit running0,
late valid synthetic packet not committed, compressed/owned counts0/four slots
FREE and repeated cancellation checks pass. Producer is idle/finite source
already has writer EOF. Wrong actor/reentrant/busy-producer cancellation,
failed-owned before-START reconciliation, unrelated channel bypass/long streams
are untested. Heap/frame/physical inventory/gain/startup/power/arbitration
remain fixtures, TTS snapshots unchanged not true navigation coexistence.
Modules/tasks retained, no global reservation/future callback exclusion/safe
unload. No real loader/App/UI/SEP/phone/speaker/DAC/DMA/IRQ/Android Auto/Google
Maps or device installation. Next connect native coordinator worker and
publication/completion events at characterized safe boundaries, then accepted
module/UI/real SEP/phone/speaker/hardware integration. Full goal open/Maps deferred.
Evidence: evidence/firmware-analysis/native-media-coordinator-emulation.json
Manifest: staging/native-media-coordinator/manifest.json

Native source coordinator task and after-return event hooks (offline):
source_worker.c/source_event_hooks.S build as a separate1104-byte ARMv6 module,
72-byte BSS and retained16KiB stack at virtual08C00000. Frozen five artifacts
unchanged. Stock kernel create/register/post/wait schedules the coordinator on
its captured owner task. The owned consume ARM hook forwards the fifth stack
argument and preserves result; it notifies after whole-packet return/busy0.
The stock3B9DFC Thumb hook notifies only after the full completion function
returns. Exact displaced prologues and preserved bodies are checked. Durable
pending flags retain notifications received during synchronous native calls.
Six format/priority cases (source40/28, decoder36),60frames/30packets,
8688sourcePCMbytes/17376virtual stereo bytes and60guarded reads match reference.
All30 stock source-start returns require original condition signal and prepared
source;12 publications occur while that condition waiter is present. No host
coordinator pump/notify/register/start/remove/release. Native event cancellation
retires4committed buffers (3unplayed), discards1pending compressed packet and
rejects late stopped packets. Empty shutdown adds a second cancel counter.
Both custom tasks reach stock exit state80; all-task lists not separately
traversed this run. Stacks/TCBs/modules stay pinned, no safe unload.
Four aggregate-stereo chunks hit query-confirmed30s emulator timeouts; resume
same PC/CPU/banked stack/kernel call without resetting or posting a new event.
This is not hardware performance evidence. All6 cases plus cancel passed on a
fresh final run. Entry hooks exist only in emulator RAM and are restored after
idle native FIFOs/custom exit; all incoming packets/peripheral frames remain
synthetic. No accepted VPM/App/UI/SEP/phone/speaker/navigation/Android Auto/Maps.
Next prioritize real preserving-component acceptance/UI/RAM placement, then
in-flight cancellation/restart/error recovery and actual hardware/SEP/music.
Evidence: evidence/firmware-analysis/native-source-worker-emulation.json
Manifest: staging/native-source-worker/manifest.json

Combined preserving component (offline, original reserved RAM)
app_component_entry.c and build_native_app_component.py integrate the decoder,
playback controller, coordinator and both workers for each of three stock
voice placements, retaining all40 original TTS exports and using12 private
API pointers. Only the first12 stock DLL header bytes change. No VPM/SIG
package is generated; no tasks/hook/UI/SEP activation at load.
Appended code54048B/BSS17992B; extension fixed footprint163840B plus alignment.
Everything stays inside original loader IMAGE02D4BB74..DESCRIPTOR0304BB74,
3MiB reservation, not an inferred free global-RAM area. Combined RAM:
Big5 2462860B, GB2565260B, Jill2028684B. Headroom682868/580468/1117044B.
Entry clears word-aligned extension BSS/PCM/queue/stacks, calls original
bootstrap and resets decoder. Original runtime file-backed bytes and BSS
tail match baseline, original40 pointers/trampolines retained, all12 private
pointers point to new code. Three formats/two rawSBC frames per voice,
18frames total, match upstream; original benign slot39 query0/1 also matches.
This does not execute full relocated workers/event hooks/playback. Prior
6route playback evidence uses old virtual placements; it is not proof of
the full new combined component. Original speech, reload/unload, native UI,
real VPM mount/signature acceptance/SDP/SEP/phone/speaker remain unverified.
Old300k instruction budget stopped new startup; word clearing reduces clear
instructions but Jill still exceeds it. New experiment's original/combined
controls use identical1M/30s bounds; final initializers230841/230827/325328.
No changes to frozen old loader/source tests. Not hardware performance data.
analyze_native_voice_mount.py traces voice-selection→mount→DLL, metadata
dll_chksum atrecord+764. Volume IDs are20UTF16 units/40B, filenames255units.
Lower31D09A filesystem checker and ARM366ABC metadata processing still open.
Evidence: evidence/firmware-analysis/native-app-component-emulation.json
          evidence/firmware-analysis/native-voice-mount-static.json
Builds: staging/native-app-component-emulation/*/manifest.json
Next: execute full relocated worker/events/playback; establish accepted
VPM/native UI and voice reload/hook lifetime, then actual Bluetooth/hardware.

Same-VM complete component playback (subsequent verified stage)
emulate_native_loaded_playback.py prepares the inherited stock kernel/output
fixture, stops its unused old decoder, restores old entry patches, then runs
the original DLL loader in the SAME emulator. It reuses mapped pages and
does not recopy initial data over the live kernel;99 stock imports checked.
Full new decoder/source workers, coordinator, queues/PCM and stacks reside
in original3MiB reservation. Runtime checks reject old virtual custom code.
Shared BSS uses reserved padding guards; separate-component canaries must
not overwrite neighboring new legitimate state. Original voice RAM and40
TTS pointers remain unchanged; benign slot39 queried before/after each case.
Fresh6 rotating format/priority cases over3 placements (not18cross-product):
60frames/30packets/8688sourcePCMbytes/17376virtual stereo bytes/60guarded reads,
30 real native ACK checks,12 publications during native condition wait.
3cancel cases release12committed blocks,9unplayed/unread, discard3pending
compressed packets and reject late packets. Native tasks end at0x80,
retained/pinned.4UC30s timeout chunks resume SAME call/register/stack state.
Actual voice runtime/code/BSS and API pointers preserved; entry hooks restored
only after both new tasks exit and native FIFOs block/drain. No safe unload,
real VPM/SIG acceptance, actual registered SDP/SEP/phone or hardware/UI/App.
All packet/virtual frame/heap/inventory/gain/power/arbitration fixtures remain.
Metadata366ABC resolves toconditional04401034:13product-ID display-name
branches, not a module acceptance result.31D09A generic file-open dispatches
through runtime driver tableF001A8/F001AC (64Brecords), filesystem open call
1FDCB8. Actual VPM driver registration/checksum/signature handling remains open.
Evidence: evidence/firmware-analysis/native-loaded-playback-emulation.json
          evidence/firmware-analysis/native-voice-acceptance-static.json
Next: actual VPM mount/acceptance, native UI and voice reload/hook lifetime,
then registered Bluetooth stream/physical speaker and navigation coexistence.
