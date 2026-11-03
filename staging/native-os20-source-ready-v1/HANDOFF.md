Native OS20 Source readiness → existing typed FIFO initialization

Exact target: Taiwan nüvi 2565RT HWID1352/SW8.00. The new bounded case has an
actual guest EXIT 0 and a no-VM FILE replay EXIT 0. Frozen old contracts,
37 other object inputs, warm ELF, forty-export voice package, canonical
reports and device remain unchanged. This scope establishes execution of
the previously build-only OS20 Source ready bridge. Native App/menu player
and direct authorized Android phone A2DP remain the music objective.

The original warm run's allocation failure is at Thumb 0x212104, the LDRB in
bit-scan helper 0x2120F0. It reads the original 64-byte flash table at
0xC7F9FC; the old VM maps MAIN only through 0xC00000. The new runner resumes
the hash-pinned journal-reconstructed failure endpoint and adds a read-only
0xC7F000 page containing unchanged original MAIN bytes. The helper and
allocator execute; no allocation pointer or return result is supplied.
The completed warm loader/profile/Timer/heap prefix is never rerun.

The original named creator now fully returns. Frozen `mh_boot_source` checks
and publishes adapter 0x03A1B294 only after that return, with native TCB
0x183140A0 at adapter+48. Workspace is 0x18310078, 16,536 bytes. A new guest-C
continuation begins once on the current original controller TCB 0x09503F90.
It checks the creator publication, tests wrong-actor binding=-401, then
executes original WAIT. All later switching is the original scheduler.

Original OS20 dispatcher calls the unchanged Source callback with its exact
compiled context. The callback records CURRENT and publishes the same TCB.
The Source's `mw_attach_stage1` executes original mutex acquisition/release
and calls the compiled warm initializer. Six actual complete zero returns
link Source to the existing typed backend:

- `memory_output_configure`
- `owned_media_init`
- `media_queue_begin`
- `aas_pcm_initialize`
- `aas_initialize`
- `mw_attach_stage1`

Only after the last complete initializer return does Source store
`mh_initialized=1`, increment `ready_posts`, then original-POST controller
event 0x400. The higher-priority controller actually resumes through original
restore while `ready_post_returns=0`. Its next original WAIT runs Source,
which fully returns from POST, increments that counter to 1 and blocks in
its persistent Source loop. Original restore then reaches native idle.
Observed destinations are Source → controller → Source → idle.

There is one callback entry, one Source entry, two publication cross-checks,
zero publication errors and ready status 0. Typed FIFO control is initialized
on channel 8, all four slots remain empty, and copied-media queue is running
at epoch 1 with count 0. The measured Source C stack minimum 0x18313F30 lies
inside the allocated workspace. Only compiled Source instruction frames enter
that minimum; scheduler banked-SP transition values have a separate scope.
The entire original voice runtime prefix and all 480 bytes of the forty MAIN
ARM jump entries remain byte-identical to the inherited actual loader state.

Evidence:

- `contract-v1.json` and `SEAL-v1.json`: exact boundary and hashes.
- `build/manifest.json`: only a new 104-byte-observation controller is compiled;
  frozen warm Source is reused unchanged. New controller ELF SHA-256
  `b9ca849913e259d56a2d253f0fb4016660088c0d86f27311ff40de2325a894b2`.
- `guest-v3/ready-proof.json.gz` (102,020 bytes): 33,288 new instructions,
  11,440 CPU stores, four native restore destinations, 96 scoped complete
  helper returns; rolling opcode digest, no whole instruction trace.
  Proof SHA-256
  `048cdbd42a7fea3741797d7d4524c7b12c92d239fb3aee15629ce989ad8b3d07`.
- `guest-v3/terminal-tool-receipt.json`: initial chunk 8d3850/session 63853;
  terminal a2fb93, EXIT 0.
- `file-v1/FILE-proof.json`: replays all 11,440 new CPU store preimages and
  final region hashes; checks 96 helper ABI returns, six initializer returns,
  native restore pairs and exact creator/initializer/flag/POST/return store
  ordering. No VM imports. Receipt initial 723983/session 24914;
  terminal f7a4c3, EXIT 0.

Failed new attempts and receipts remain frozen. Guest v1 reached the real
`mh_boot_source` return but its observer did not stop before fetching the
legacy RW-only terminal address. Guest v2 completed actual Source readiness
but included a banked-SP zero during native restore in its Source C stack
minimum. Guest v3 corrects only those observer boundaries. No callback,
initializer, mutex, creator or native return is hooked, and no old VM global
monkeypatch is imported. Inherited guest-only gate/call-site patches from the
frozen warm player are listed exactly in the contract; new MAIN patches=0.

Scope/lifetime remains explicit. The inherited current/idle initial ready
membership, software heap extents/MMU tables, Timer and preexisting-channel
state are fixtures. The prefix is a checked CPU-journal reconstruction,
without a complete instruction interpreter. Physical heap/cache/MMU, clock,
IRQ entry, all-writer ownership and real boot admission are unproved. The
new C controller's one entry at the actual current controller is a declared
test-caller boundary; it does not manufacture a Source context switch.

This case sends no media packet and executes no factory/selector/mixer pull
or hardware driver. Source readiness means successful logical warm Source
and typed FIFO initialization. Speaker/phone/UI/package acceptance remains
false. Exclusive native witness stays **−200**, **STOP_DONE=false**, and all
workspace/TCB/adapter/FIFO/module storage remains pinned. There is no reclaim,
unload or physical installation candidate. FILE replay checks byte preimages
and final hashes; it does not independently decode every instruction's
effective address or prove complete memory-access boundaries.

Next smallest integration: deliver one copied RTP/SBC packet to this true
OS20 Source, require producer work on TCB 0x183140A0, then follow its actual
native registration/factory and scheduled mixer selector/reader caller. Keep
the Source ready ordering, actual task provenance and full-return lifetimes;
separate hardware service fixtures from physical readiness. Use a new
namespace and preserve this success, the typed-FIFO success and all prior
closed prefixes.
