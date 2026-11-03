# Loaded-v2 controller lifecycle: file-only review

This path has real controller C and a direct umc_adapters initializer in audio_session_driver_v4.c, with original-address IRQ/current/POST wrappers, local prepare_scoped and first init→READY→start→service. It is not correct to say this path has no core merely because an older adapter table was not linked. Current source body pins and line/function evidence are in provider-ledger.json and source-pins.json. Parent owns the separate compiled-manifest comparison.

The substantive incomplete chain is cancellation/retirement: request_cancel and observe_stop explicitly return -200. The selected Source WAIT loop handles command/data but does not call controller service on later wakes. Command5 localStop plus mixer16/17/18 does not provide native completion. In the selected twelve files, publication/cleanup core APIs have no callers; this is a bounded selected-set finding, not whole-project absence. Core STOPPED requires complete owner-bound native cleanup evidence that these providers do not supply.

Guard epoch/controller generation/admission epoch differ from FIFO tickets/queue epoch and remote pause epoch. Source/mixer TCB/descriptor/provider/full-frame guards are implemented C, but guest-only redirections and live original/full returns were not run or proved here. Copied ingress releases typed leases before POST/full foreign callback return, with residency as an explicit assumption. FIFO cancel_ready's Source-after-cleanup comment is a caller precondition; its body does not enforce actor or native cleanup/record/epoch provenance.

Warm startup is held: driver supplies resident=1/cookie0x1352, while the Source stage1 caller resets global queues and all18 channels and labels itself a cold offline caller. READY checks owner/BOOTING and relies on caller-observed initialization/decoder evidence. Parent independently reviews passive resident entry/output ownership; this scope does not activate it.

12 files /79,152 B actual ordinary reads, cbf88a and6122dd EXIT0. Metadata/name preflights b7c800/5a7f90/ea0693 are separate, with no source bodies and no complete filesystem-I/O claim. All handles closed. No native/producer import, compile/test, guest/firmware/binary/RAM/device/query/audio/shared mutation. No interrupted guest retry. No full artifact readback claim: hashes bind emitted bytes plus actual size/stat. Sealer terminal receipt is saved separately after actual return.

Native ownership, STOP_DONE, native App, direct phone A2DP, speaker and installability remain false. Finite review completed; STOP.
