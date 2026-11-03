# Genuine OS20 Source bridge v1 — offline research

This new translation unit retains the exact warm Source data, copied-media,
typed PCM FIFO and native retirement loop from the frozen leaf-writers player.
Only the include/prototype, ready notification and raw Source boot function
change. `source-derivation-v1.json` records byte-exact reconstruction of all
other Source text. The other 37 object inputs and the original 40-export TTS
prefix remain in the linked image. No guest or device executes in this build.

Bind `mh_bind_ready_controller(controller_tcb)` from that original controller,
then call `mh_boot_source()`. It invokes the recovered five-argument Thumb
creator at 0x521E5F with a valid short ASCII name, requested workspace 16 KiB
and priority index 7 (native byte 89). The original creator adds 152 bytes.
The controller priority is expected to be 16. Boot returning a TCB does not
mean Source initialization has run: execute original WAIT and receive event
0x400, then inspect `mh_initialize_result` and `mh_os20_ready_status`.

The argument-compatible callback records the native CURRENT TCB at 0x358D25,
publishes/checks `mh_source_tcb` before the unchanged Source initialization,
and executes its persistent entry. After initialization, ready_posts increases
before original POST; ready_post_returns increases only after POST fully
returns. A controller awakened by POST may observe the former before the
latter. The creator caller checks adapter+48 and publishes the adapter only
after the full original creator return. Separate publication counters expose
both checks. Callback arguments reference a fixed compiled context, never a
host-filled task handle or fabricated guard owner.

Old `source_stack` and `source_descriptor` symbols remain observable, but the
new worker uses allocator-owned OS20 workspace. No cancellation completion,
OS20 slot reclamation, stack free, claim yield or module unload is added.
Original allocator OOM/slot exhaustion checks remain unresolved. Selected
route/provider/backend/writer barriers remain bounded; all-writer ownership,
navigation coexistence, physical heap/MMU/cache, radio SEP publication, audio
hardware, direct phone playback, App menu and Android Auto are unverified.

Build once in a new namespace:

    python3 scripts/build_os20_audio_source_v1.py

The resulting combined binary is **EMULATION-ONLY**, not an installable VPM.
