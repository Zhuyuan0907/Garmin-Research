# Exact HWID1352/SW8.00 bounded session component

This NEW component implements an admission and lifetime mechanism. It does not
install an App, prove a certified native reservation, execute original audio
instructions, accept a modified VPM, or emit sound. Existing published scopes
retain their no-MAIN-patch claims. All new state/code remains resident; there is
no reset, unload, destroy, stack release, or second component bootstrap.

The original source actor still owns coordinator pump/cancel. New owning TUs
include the immutable original memory output, coordinator, and stream exactly
once, replacing those three objects in a future single-bootstrap image. The
memory-output TU retains its original static anchor and accessor. Cancel result
0 must come from complete original coordinator return and the existing source
worker's returned-cancel barrier; this component never clears that barrier,
active audio, or issues STOP_DONE. Source9 and HFP90005 receive no new binding.

Actual local RAM wiring available in a new image:

* Original profile277D26 writes channel record+160 through277DBC; the native
  public registration270458 reads that slot2704A4 and BLX2704B2 with list at
  record+1A8. `mcs_install_queue_callback` checks original277C6B and writes only
  the channel8 slot. It preserves original7-argument queue writer/result and
  rejects nonowned requests with original unavailable8. Register permits bind
  owner TCB, controller generation, one exact anchor/type10 request, ticket,
  and normal context. A profile rewrite makes register_begin fail closed.
* Original factory4379D4 initializes record+F4, calls prepare with output
  record+F0 through437A02, and builds reader at+108. New after_selection reads
  exact provider busy+0C/active+1C/anchor+10/length+14/format and installs the
  leased reader only on the matched anchor. Capture currently requires the
  persistent source owner. An actual mixer-TCB callback cannot be substituted
  for that owner without a separately characterized safe handoff.
* New stream TU retains native AV mutex5523DE/5523FC, configuration/SBC checks,
  session/queue epochs, source8 lifecycle and native cancel. Controller media
  and wholecallback leases cover original callback/consumer full returns.
  Queue generation is captured under original AV lock, before decoder post.
  Event17/F1 and consumer are denied after local Stop. Cleanup/disconnect
  callbacks remain deliverable and pinned. `mcs_prepare_session` arms reception
  without manufacturing an AVDTP session. Existing native streaming resume
  requires coherent original session under that AV lock and an empty/unbusy
  queue/private owned FIFO; it does not invent remote START or native state.

Whole reader borrowing requires an additional real caller redirection:

* Original mixer actor2FA572 directly BLs MAIN Thumb2F9CCA. Its r0 is channel;
  the borrowed reader method/index are loaded anew inside2F9CCA at2F9D16/18.
  Earlier caller2FA54A index load is diagnostic and is not a reader argument.
* `mcs_pull_bridge` is an ARM wrapper, not installed by these sources. It
  captures typed media+wholecallback leases BEFORE invoking any original pull
  descriptor/method/index loads, and keeps them through full original return.
  The wrapper saves r0-r3/r4-r8/LR, aligns SP8, owns an independent80-byte frame,
  preserves original R0 and restores original saved registers/SP/LR. Its
  Thumb thunk copies only f1b5/8ab0, then BX2F9CCF. Original native64-byte frame
  comprises PUSH24+SUB40; ADD44/POP20 at2F9E32/34 restores it independently.
* The new reader accepts only the current actor's active full-pull frame with
  matching ticket/generation/reservation epoch/provider index and live core
  lease. A matching reused pool index alone is never sufficient.
* No characterized RAM callback replaces the direct BL2FA572. Repointing an
  export/import on a TTS DLL cannot change this internal MAIN direct branch.
  A native installable mechanism remains UNKNOWN. A runtime code veneer at
  2F9CCA or replacing BL2FA572 would alter original MAIN executable bytes;
  both are forbidden in the published no-MAIN-patch proofs and are not done.
  This MAIN function is not one of the optional044/054 startup-copy segments.

Reservation limits and precise next callsite:

`mcs_native_ownership_snapshot` always returns -200 and leaves its output
untouched. The RAM queue gate does not cover direct277C6A/list277B38 calls,
source reprofile277D26/selection/lifecycle writers, provider allocator48EE68 or
release48EE58 from other actors, or not-yet-entered callbacks bypassing the
whole-pull bridge. No idle record, pool state, counter, transient mutex, or
coverage boolean turns these paths into an exclusive witness. Navigation
channels retain their original queue slots and original pull path. Our scoped
mutation guard excludes borrows only from the newly wrapped coordinator calls.

The next bounded native integration point is actual BLX2704B2 into the new
channel8 RAM queue callback, with original native7-argument provenance and
original writer277C6A return. Separately establish the real source-owner
selector-return handoff before first pull and a legal full-pull redirection;
then cover original lower writer/provider allocator paths before enabling
ownership_snapshot. Modified-code package acceptance remains unresolved.

Future link requirements:

Replace old memory_output_owner, media_coordinator and stream objects with the
three NEW owning objects; add guard/native_context/pull_bridge. Keep the
existing common bootstrap, original40 TTS interfaces/imports, owner source
loop and cleanup11-site plan unchanged. Regenerate ALL map-derived imports and
addresses in a new build. KEEP `.mcs_output_api`, `.mcs_coordinator_api`,
`.mcs_stream_api` and wrapper code; do NOT KEEP/export original renamed
`.output_api`/`.coordinator_api` arrays or internal unleased helpers. No frozen
absolute image address is reused. New writable data must remain outside
file_end/BSS zero span according to the frozen single-image recipe. This REL
is not a full ELF/image and does not itself patch code, write native RAM,
bootstrap a task, execute the original caller, or return a success witness.

Validation scope:

HOST controls compile actual immutable controller and new guard; actor/IRQ,
native records, provider fields, queue callback and cancel request are declared
mocks/input fixtures. They never produce native ownership or STOP_DONE. ARM
crosscompilation and relocation inspection establish instruction availability
and ABI shape only. No Unicorn/guest/device/BT/USB/VPM/sound is used here.
