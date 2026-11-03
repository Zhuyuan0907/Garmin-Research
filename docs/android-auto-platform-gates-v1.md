# Android Auto host core and GarminOS platform gates

This note describes the Taiwan nüvi 2565RT, HWID 1352, software 8.00. It does
not transfer conclusions from a 2585 or a foreign HWID 1371. The complete Android
Auto / Google Maps objective remains active and incomplete. Current user
priority is Bluetooth music and a GarminOS player App. Navigation repair
and the microphone feature were stopped by the user.

The published checkpoint at 2026-10-08 08:46:23 Taiwan time records a Linux-host
video path: legacy startup with a real local TLS peer, receiver/control, an owned
compressed queue, OpenH264 decoding, and a software RGB565 surface. Its 20
integration/guard categories and the independent decoder's 76 comparisons have
their own scopes. They do not establish a current Pixel session, Garmin memory
or performance, physical display, touch, sound, installation or Google Maps.

The generated 480×272 report image is a decoded local H.264 test pattern. It is
neither a photograph of the Garmin display nor a Google Maps screenshot. The
report embeds its exact PNG bytes in HTML because the existing server exposes
no standalone PNG route.

The checkpoint published at 2026-10-08 09:09:03 Taiwan time adds outbound input
and owned PCM providers to that same local TLS path. Thirteen integration cases
passed, including final-byte binding gates, equal tokens owned by distinct
source queues, partial PCM delivery, stop/restart and whole-session failure.
The independent input suite has 10 categories, 628 assertions and 33 protobuf
events per normal/sanitized build. The audio suite has 77 runtime cases per
normal/sanitized build and two expected-failing mutation controls. These are
distinct test scopes; the full integration pipeline has no sanitizer claim.
The input model uses one pointer with PRESS, RELEASE and DRAG, plus keys/wheel.
It does not establish CANCEL or multitouch. Synthetic pointer events do not
prove the Garmin touchscreen path, and copied PCM does not prove speaker
playback. The audio receiver does not open a physical audio device.

## The gates that determine whether a Garmin installation is possible

1. **A real transport endpoint.** Establish whether this precise unit can supply
   a supported USB-host controller, VBUS policy, enumeration and AOA bulk
   transfer. Its working USB mass-storage connection proves device-mode data
   transfer only. A microUSB connector, an OTG adapter or a powered hub does not
   establish host capability or a safe simultaneous power/data path. Record the
   actual supported platform endpoint and power policy before designing wiring.
2. **A reachable, compatible execution endpoint.** Establish a supported loader
   and invocation path that can preserve existing Garmin services and register
   the needed platform providers. Historical TTS/DLL loader experiments are not
   an App installation API. There is no installable AA receiver or verified
   menu entry. The interrupted original-native branch remains a read-only
   boundary; new host code does not authorize retrying or bypassing it.
3. **A current-phone session.** After a valid transport exists, validate the
   actual authorized Pixel's version/handshake, discovery, channel profiles,
   codecs, timestamps and reconnect behavior. The local peer implements a
   pinned legacy model; passing it does not establish Pixel or Google
   acceptance. Google Maps and its offline behavior require their own real
   session evidence.

The first two gates take priority over additional synthetic fixture coverage.
If either has no usable endpoint, report that concrete limit and retain the
host core as a research artifact. Do not reinterpret a Pi-based display/music
path as native Garmin Android Auto.

The current primary-source review narrows these gates. Garmin's exact Taiwan
manual documents computer-facing mass-storage mode, mount power input and a
dedicated GDR10 connector. It does not establish generic peripheral hosting,
host VBUS output, hub enumeration or AOA on PCB 105-01927-00. A bounded official
service/schematic search did not retrieve the required exact-board evidence;
this is not proof that the capability or documentation does not exist.
[Garmin manual](https://download.garmin.com/tw/download/manuals/nuvi2555_2565T_2565RT_TW_0B.pdf)
and [Android accessory roles](https://developer.android.com/develop/connectivity/usb/accessory).

The fetched official Connect IQ device list does not include this nüvi. It
therefore supplies no supported SDK/install target for the proposed App.
This finding does not rule out custom native execution: the historical
physical diagnostic sequence 2.10 → WFFF → 2.10 already demonstrated a modified
voice diagnostic and its restoration. That limited execution result does not
establish a running player, menu entry, durable audio ownership or AA receiver.
[Supported Connect IQ devices](https://developer.garmin.com/connect-iq/compatible-devices/).

The earlier static inspection of six AA host libraries shows ELF64 AArch64
shared objects, not ARMv6 Garmin modules. Those earlier tested artifacts remain
unchanged. A separate H.264 host-port checkpoint at 09:44:53 now replaces runtime
allocation, clocks, CPU queries, threading and logging with explicit caller
contracts. Its ordinary shared object has no dynamic runtime imports or
DT_NEEDED entries; the checker build intentionally uses ASan/UBSan. The 76 ABI
and 36 platform-control cases passed against fresh FFmpeg references. Hosted
Linux headers/private types remain. This is not a freestanding ARM32 build,
Garmin loading proof or complete AA platform port. See
[the codec checkpoint](android-auto-codec-port-checkpoint-v1.md).

## Route and residency constraints

Android Auto presents phone applications on a compatible car receiver;
Android Automotive OS is a separate Android system installed in the vehicle.
A receiver running on GarminOS would still require actual phone projection;
this does not establish that a Google Maps APK runs natively on GarminOS.
[Official platform distinction](https://developer.android.com/training/cars).

The official wireless route requires 5 GHz Wi-Fi capability and starts with
Bluetooth pairing. The historical HFP music connection therefore cannot serve
as evidence of a complete wireless AA transport. On 2026-10-08 the user
confirmed this unit has Bluetooth and no built-in Wi-Fi; this is a user
hardware confirmation, not a new independent board inventory. The built-in
Bluetooth interface alone does not support the wireless AA route. The wired
AOA route separately requires the accessory to act as
USB host and supply 5 V/500 mA; these are AOA requirements, not Garmin support
or Google acceptance.
[AA requirements](https://support.google.com/androidauto/answer/6348019?hl=en),
[setup](https://support.google.com/androidauto/answer/6348029?hl=en), and
[AOA specification](https://source.android.com/docs/core/interaction/accessories/protocol).

The manufacturer-authored STA2064 brief identifies VUSB as a 3.3 V pad supply
and describes USB-data/UART pin muxing. Neither establishes a board-level 5 V
VBUS output or an active USB-host driver. Its LCD format support is not a real
framebuffer ABI. The selected brief documents JPEG acceleration, but provides
no H.264 acceleration proof; this is not a proof of hardware absence. The
exact Garmin chip identity and board routing remain unverified.
[ST data brief, distributor mirror](https://mm.digikey.com/Volume0/opasdata/d220001/medias/docus/581/STA2064.pdf).

The historical combined voice/menu fixture uses 2,462,860 bytes of a
3,145,728-byte module reservation. Its 682,868-byte remainder is image/BSS
accounting, not available runtime heap. The new host decoder's tested peak of
12,340,820 requested backing bytes is a separate measurement with a different
ABI and scope. Neither may be used as a Garmin free-memory measurement.
Module residency, caller workspace and codec heap each need explicit owners;
GUI callbacks and a continuous receiver pump also need an invocation context
and a shutdown barrier before unloading. The physical WFFF diagnostic and
restored 2.10 remain valid limited execution evidence, not those lifetime rules.

Google Maps phone offline guidance requires the entire route inside downloaded
areas and excludes traffic and alternate-route information. It does not by
itself prove AA offline cold start, search, voice or reconnect behavior; those
remain current-phone tests. Guidance for Maps built into a vehicle is a
different product and does not close this gap.
[Phone offline Maps](https://support.google.com/maps/answer/6291838?hl=en&co=GENIE.Platform%3DAndroid).

## Platform-provider contracts still required

| Provider | Required GarminOS evidence | Current limit |
| --- | --- | --- |
| USB / AOA transport | Supported host controller, VBUS ownership, descriptor negotiation, completion/error/cancel callbacks and bulk transfer | No real Garmin USB-host/AOA session |
| TLS services | Trustworthy entropy and wall clock; verified ARM ABI, allocation, deadlines and lifetime | Real local TLS on Linux only |
| Memory / decoder | Separate module/workspace/codec-heap budgets, total heap/stack availability, fragmentation and worst-case decode throughput | Host callback backing cap excludes other memory; image reservation is not heap; Linux results are not Garmin performance |
| Display | Reachable surface/framebuffer API, pixel format, stride, cache visibility, presentation completion and exclusive/shared ownership | Owned RGB565 software bytes only |
| Input | Real touch event API and coordinates, single-pointer transitions, physical key mapping, authenticated outbound delivery and reconnect state | Synthetic events only; CANCEL/multitouch unproven |
| Audio | Actual PCM format/clock, source registration, mixer ownership, asynchronous consumption/backpressure, focus and output completion | Owned host PCM is not a DAC or speaker |
| Scheduler / teardown | Serialized ownership, task/IRQ rules, bounded queue processing, cancellation and callback quiescence before freeing storage | Host serialized guards do not prove native scheduling or safe unload |
| App / UI | Valid module loading, reachable menu activation, lifecycle, resource budget and coexistence with navigation | No native AA App or menu entry |

Media ACK means the compressed indication was accepted by an owned provider;
it does not mean a frame was presented or PCM was heard. A completed host sink
callback does not establish physical completion. On transport stop, the current
sender contract requires the owner to discard the whole TLS session and start
a fresh one; reusing advanced record sequence state is unsafe.

The known Pixel → Pi → Garmin 60-second music test remains historical physical
evidence, with HFP's 8 kHz mono audio and call screen. Android APK v5 has
passed API35 compilation, DEX, min-API28 signing and 40 host policy cases. Its
new preflight requires a selected-device HEADSET connection snapshot before
creating a local incoming call, with canceled/late-result and ownership
controls. It remains without a verified Pixel-to-Garmin session. Direct phone
A2DP and a GarminOS music App remain incomplete. The report's 37% figure is an
unchanged historical engineering estimate, not an Android Auto completion rate.

Hardware checks wait for the user to announce availability. At that point,
establishing and maintaining an authorized Bluetooth pairing takes priority
over report work. Until then, do not query devices, request presence or cables,
place simulated calls, play sound, write firmware or claim a device test.

Evidence: `evidence/android-auto-interactive-host-v1.json`,
`evidence/android-auto-input-host-v1.json`,
`evidence/android-auto-audio-host-v1.json`, the prior
`evidence/android-auto-video-host-v1.json` and
`evidence/android-auto-h264-host-v1.json`, and the preserved control/startup/
pipeline/TLS/wire checkpoint history. Each checkpoint retains its own actual
scope and terminal receipts; no host result establishes native installation.
The new static gate evidence is
`evidence/android-auto-usb-board-primary-review-v1.json`,
`evidence/android-auto-host-portability-v1.json`, and
`evidence/android-auto-native-port-contract-review-v1.json`. Static counts are
not additional runtime cases. Required platform support and native performance
remain unknown; the interrupted original-native branch is not retried.
