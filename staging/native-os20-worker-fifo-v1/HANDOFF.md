Native OS20 resident worker → copied-media queue → typed PCM FIFO

Exact target: Taiwan nüvi 2565RT, HWID 1352, software 8.00. This new scope is
closed by an actual guest EXIT 0 plus two bounded file controls. No device,
USB, Bluetooth or playback service operation occurred. Navigation remains
the first priority; native App/menu/music and direct authorized Android phone
A2DP remain the required music outcome. AA/Google Maps stay deferred and the
microphone work stays cancelled.

The new C controller copies each 85-byte RTP/SBC packet through the existing
`media_queue_callback`, then overwrites its source packet with A5 before
waking the same OS20 worker. The original POST, WAIT, CURRENT and context
restore instructions run. The worker executes existing `media_queue_step` →
`owned_media_consume` → packet parser → sealed SBC decoder → unchanged
16 kHz mono converter bypass → `memory_output_submit`. Existing typed FIFO
buffer slot 0 is reused with actual tickets 4, 8, 12 and 16. The other native
controller task calls existing `continuous_media_read` as a private consumer.

Four actual READY publications contain 1,024 PCM bytes identical to the
closed libsbc reference. Five complete consumer copies read 896 of those
bytes. A partial read keeps the READY slot and offset; `in_flight=1` remains
set through the actual unlocked memcpy return, then clears. After the final
128-byte partial read, Stop closes queue admission, advances queue epoch and
leaves ticket 16 READY with 128 bytes still pending. Stopped callback=-22,
stopped work=-11, duplicate active START=-16, pending-PCM START=-25 and stale
ticket discard=-28 all execute. Odd/null reads return zero without writes.
Two successful STARTs reset codec/FIR; the worker enters once and its TCB,
adapter and occupied OS20 slot persist.

The closed creation/restore prefix is initialized once from its sealed
endpoint. Its 3,865 instructions are never reexecuted. Three new Thumb RX
veneers preserve that endpoint's entry addresses: worker 0x09050000,
controller 0x090501E4 and idle 0x090502F8. They branch into the new C image.
Original MAIN bytes remain unchanged; no shared observer/source monkeypatch
exists. Every command and acknowledgment after dispatch is guest C plus
original scheduling. The 350,000-instruction bound covers a new 310,316-
instruction tail: 3,960 original MAIN instructions, 257,831 sealed decoder
instructions and 48,525 new compiled instructions. There are 31 original
restore destinations and 304 scoped complete helper returns. A rolling opcode
digest replaces a whole instruction trace; compressed proof size is 86,701
bytes.

Evidence and exact receipts:

- `contract-v1.json` states the complete boundary and hashes all primary artifacts.
- `build-v3/manifest.json`: ARMv6 freestanding ELF, no undefined symbols,
  separate RX/RW segments; ELF SHA-256
  `0672031ea20d8243205f75f2d8846f38904a67021864e5444dbe57e5ecbdda08`.
- `guest-v3/guest-proof.json` and `guest-v3/tail-proof.json.gz`: actual guest
  success. Proof SHA-256
  `ac05009edf22e2337212ca4a86b8e96357204de4ebe4879428de72e7a457b658`.
- `guest-v3/terminal-tool-receipt.json`: initial exec chunk 2b57bc,
  session 67438; terminal chunk 3c5bcc, EXIT 0.
- `file-v2/FILE-proof.json`: no VM import/execution. Replays 5,907 new
  ELF/job CPU store preimages across four new RW regions and the job; checks
  final hashes, 304 helper ABI returns, five copy leases and 31 native restore
  destination pairs. Actual terminal chunk 6e85ef, EXIT 0.
- `file-publications-v1/FILE-publications-proof.json`: no VM execution.
  Reconstructs each COPYING→READY publication from actual CPU stores and
  compares all four 256-byte payloads to the closed reference. Actual terminal
  chunk 15b05f, EXIT 0.

Successful inputs/outputs are frozen. The build/guest/file attempt directories
retain failed versions and actual receipts: missing converter coefficient
include; freestanding libgcc division-zero fallback needing a local trap;
observer initially treating intentional IRQ-mask changes as an ABI violation;
observer reading a recorded result pointer from the wrong nesting; static
verifier initially missing the frozen decoder's RX mapping. The successor
build/observers fix those boundaries without modifying original queue/FIFO,
decoder or any sealed prior success. The division-zero trap was never reached.

Explicit fixtures and remaining lifetime/ownership gaps:

- Three TCBs came from original creation code in the closed prefix. Initial
  controller/idle ready membership, heap extent backing and software MMU table
  bytes are fixtures. Physical heap/MMU/cache, real clocks and live IRQ entry
  are unproved. New ELF BSS/queue/gather/FIFO pages come from the test loader.
- The consumer is the original-created controller test task and writes a RAM
  output page. No original Source record, kind10 factory, native mixer actor,
  hardware driver/ring or speaker is installed or exercised in this tail.
- Native channel/anchor/backend writer ownership is not established;
  exclusive witness stays **−200**. Source/mixer handoff and all-writer
  navigation coexistence still require their own execution boundary.
- Stop acknowledges queue admission closure, preserving partial PCM and all
  storage. Native **STOP_DONE=false**. There is no stack/adapter/module/PCM
  reclaim, unload, speaker drain/mute or radio shutdown claim.
- This tiny companion does not merge/load the preserving forty-export voice
  package. It is **EMULATION-ONLY**, with install/App/UI/direct-phone/live
  speaker acceptance false. Journal replay validates final new-state bytes;
  it does not independently reconstruct every instruction/effective address
  or prove complete memory-access boundary coverage.

Next concrete scope: bind this scheduled copied-media producer to the existing
OS20 Source bridge's initialized record and actual original mixer selector/
reader paths. Carry the original worker TCB, queue epoch and FIFO tickets
through Source readiness and retained session/anchor capabilities, then test
all writer ownership and complete audio Stop before package integration or
physical acceptance. Keep this namespace frozen; use a new namespace for
that integration and retain all native lifetimes.
