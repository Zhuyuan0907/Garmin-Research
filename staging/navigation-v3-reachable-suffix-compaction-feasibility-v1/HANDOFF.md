# Reachable-suffix compaction: bounded attempt stopped before MDR stream

The actual attempt exited **1**, terminal **9ada66**, at the new Python
program's own `rss()` assertion. This was **not** a tool-platform refusal,
automatic approval rejection, system cyberrisk interruption, or native guest
failure. `actual-stderr.txt` preserves the actual Python traceback; the source
and `actual-failure.json` remain unchanged.

`rss()` calls `resource.getrusage(resource.RUSAGE_SELF).ru_maxrss`, then checks
the value against **384*1024 KiB**. It measures process historical peak RSS,
not the current resident set. Across exec, this historical peak may reflect
the launcher; this scope did not distinguish that from newly allocated RSS.
The actual value was not persisted before the assertion, so it remains
**unknown**. This failure does not establish that physical RAM was exhausted.
The program's cap was not increased, the source was not relaxed, and the
attempt was not rerun.

Static source units are consistent on this Linux host: `ru_maxrss` is compared
in KiB with `384*1024` KiB. No multiplication/unit mismatch was found in this
source check. Root's separate ordinary allocation diagnostic
`navigation-compaction-host-RSS-measurement-v1/proof.json` (SHA
`8c0f93d10217bd4aa9ed1fc5efe22ad15c4d49cc0929380b0fda8c7e40b19a69`)
observed about76MiB for a64175632-byte buffer. It did not rerun this algorithm
or recover this failed run's value, and does not prove the full algorithm's
peak. It supports keeping the physical-RAM shortage claim unproved.

The failure occurred immediately after allocating L3/L4/L5 first/count/rawflags
arrays and before the first MDR stream chunk. Their fixed payload size is
**64,175,632 bytes** (4-byte first, 2-byte count, 2-byte flags for each
one-based record plus one unused slot per table). Original counts were taken
from the sealed small original-profile proof: L4 **2133948**, L5 **2341096**,
L6 **1973316**. Current V3 counts are **4896236 / 3077845 / 2062771**.
The actual country-v2 and V3 L3 profile is **23/112**, with unchanged
L4/L5/L6 strides **128/126/68**.

Only the actual V3 header/FAT metadata parser ran. The source handle was inside
a Python `with` and was closed on the exception. The read counter and rolling
receipt were not persisted at this early failure, so this scope does not claim
an exact actual metadata byte count. The parser's strict extent limit proves
**at most200000 bytes** of metadata reads; source identity and its sealed73728
metadata extent would imply70144 bytes for this executed path, but that number
is a derived count, not a saved actual counter. **MDR streaming bytes:0**.
This is below the160000000-byte task cap. No IMG whole hash was repeated.

`finite-plan-and-gap.json` preserves the intended one-pass data method:

- Keep every stock lower-prefix record/ID and all47870 L3 roots.
- Store only child first/count/flags arrays, mark complete child intervals
  in bitsets, and conservatively retain suffixes on invalid/unclassified
  encodings. Preserve unknown flag bits rather than normalize them.
- Count reachable poststock records, validate interval aliases/contiguity,
  derive dense first-pointer remaps with fixed stock IDs, and calculate
  six-component4K allocation with unchanged GMP/JAI L3 IDs.
- Also report the stricter variant preserving every current-v2 lower-prefix
  record, using the same in-memory fields and no second IMG stream.

None of these reachability, alias or size results were executed or proved.
**No compacted counts, pointer-remap counts, successful128MiB projection or
install/fix readiness are reported.** External lower-ID references in the
MDR prefix, other components and native query caches remain unknown even if a
future first/count reachability analysis succeeds. JAI L3 ID preservation
alone cannot resolve those consumers.

The next separately authorized scope could measure cold ordinary-process
baseline current RSS/ru_maxrss without an IMG scan, then design a lower-memory
ordinary data scanner with appropriate current-memory receipts. No audio,
allocator/admission guest, patched firmware or previously system-interrupted
guest is needed or reused. This handoff does not authorize raising this
closed assertion or rerunning its attempt.

Source IMG remains153346048B, inherited complete-readback SHA
`1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360`.
Current source inode/size/mtime/ctime/nlink are captured by stat only; no IMG
bytes were reread during finalization. MAIN/CPU/PBF/sourceledger/device0;
no full tables, IMG, record remap, backup, report or canonical modification.
This finite failed-attempt scope is sealed and stopped.

The first evidence-sealer preparation invocation had a SyntaxError before
entering its main function (`6f3a82`, EXIT1). The invalid Python identifier was
corrected in the sealer only; `sealer-preparation-failure.json` preserves that
receipt. The compaction source and its RSS guard were not changed or rerun.
