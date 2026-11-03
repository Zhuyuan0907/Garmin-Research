One new packet reached the real OS20 Source and typed FIFO. The original
mixer initializer failed in the original allocator; no native mixer TCB,
selector, factory, reader or mixer-output success is claimed.

`probe_v2.py` actually ran once: initial tool chunk `52edc4`, session `5912`,
terminal chunk `8604d1`, EXIT 1. Its frozen failure proof contains 79,246 new
instructions, 7,111 CPU stores, two original context destinations and 113
complete scoped helper returns. No old warm/37-input/40-export/READY suite was
rerun. The only new host caller entry was on the actual inherited idle TCB.
Observers performed no guest register/memory mutation after dispatch, no
original native helper was suppressed, and no new MAIN patch was applied.
Inherited guest-only gates remain declared in the READY prefix.

Original builder/registry created producer TCB `0x0B023F90`, priority 16.
Producer ingress copied one synthetic 85-byte RTP/SBC packet, then destroyed
its own packet bytes with A5 before WAIT. Original POST/WAIT/restore scheduled
Source TCB `0x183140A0`, priority 89. Source decoded the copied single mono
16 kHz SBC frame and published FIFO ticket 4 READY, 256 bytes identical to the
closed libsbc reference. The original registration `0x270458`, existing guarded
registration wrapper and original queue-start `0x277536` all fully returned.
The READY Source initializer counters remained one; no initializer rerun.

Original `0x3B9B66` then requested mixer stack allocation through `0x38853C`
with `(8192, 2, 0)`, actual caller LR `0x3B9B95`. The inherited software public
extent was one page: head `0x18308000`, node `[0,4096]`, cached head zero.
Original page-pop `0x38806C` consumed that sole page at CPU store `0x3880A8`.
On a subsequent page requirement, both heads `0x03A7F174` and `0x03A7F178`
were zero, and original `0x388084` called diagnostic `0x23D6E8` with code
`0x6E5D800F`, severity 2, original request caller `0x3B9B95`, request 8192.
The real diagnostic switched stacks through original `0x358BC4`; its push at
`0x358BD8` faulted on unmapped diagnostic stack address `0x014A77D8`.
Mapping that stack would not repair the exhausted allocator page pool.
The exact reason that flag 2 needs these mapping pages remains a next analysis
scope, rather than a claimed complete allocator model.

`verify_failure_files_v1.py` actually passed once, tool chunk `bf88bd`, EXIT 0.
It replayed all 7,111 captured store preimages/values/opcodes, all 52 final
region hashes, the 113 helper ABI returns, original context destinations,
caller-buffer destruction, exact FIFO bytes and native diagnostic inputs.
It imports no VM; it does not recompute effective addresses or all non-store
instruction semantics. TTS runtime and RX hashes stayed unchanged.

The compiled new C includes a declared lower driver descriptor/ring/scratch
fixture and one original copied mixer-message caller, but neither branch was
reached because the allocator failed. There was no private controller read.
The FIFO remains READY and pinned. Source/adapter/stack/module/native heap
lifetime remains resident; no successful Stop, retirement, yield or reclaim.
Native all-writer ownership witness stays -200; STOP_DONE, installation, App,
direct phone A2DP and speaker acceptance remain false. No device I/O occurred.

Next: a NEW narrow allocator scope should inspect original `0x38806C` and
flag-2 page/mapping requirements and find an original allocator API for any
additional declared software extent. Preserve this exact exhausted countercase;
do not reset the existing warm allocator, overwrite its bitmap or suppress its
diagnostic. Physical memory availability is unknown.

The setup-only v1 failure (`dc1dc2`, EXIT 1) used an incorrect reference filename
before VM creation. Its runner and receipt remain preserved.
