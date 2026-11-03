# Prepared current-address-space memory guard, scanner unexecuted

Normal DATA source `observed_analyzer.py`, **22702B**, SHA
`ad46dda03730cab4a73e39346fd597b13bc91604a811147840499a123baa3e04`.
This scope did **not run the scanner**, open an IMG, allocate table arrays or
execute runtime guard cases. Only syntax/AST relationships were checked.

Exact CLI, requiring root's later actual-run decision and independent review:

```sh
python3 /root/garmin/staging/navigation-v3-reachable-suffix-compaction-current-mm-v4/observed_analyzer.py
```

The numerical cap stays **393216KiB /384MiB**. V4 changes the enforced metric
to `max(VmRSS,VmHWM)` from `/proc/self/status` in the post-exec current address
space. Both must be at or below the cap. Missing, duplicate or malformed
fields, non-`kB` units and read failures persist a diagnostic row, then fail
closed; there is no fallback to the inherited `ru_maxrss`. Historical
`ru_maxrss` is still recorded unchanged as diagnostic evidence. No RSS/HWM
counter is reset, no extra process/context retry is spawned, and the numerical
cap/read budget are not increased.

Local `getrusage(2)` explicitly says resource metrics survive exec. Primary
Linux `task_mem` derives VmRSS/VmHWM from current `mm`, with pages converted
to KiB; `exec_mmap` replaces that `mm` while preserving the old peak in the
process usage counter. These facts justify a current-address-space budget
instead of charging a prior executable's historical peak to this scanner.
See `memory-measurement-evidence.json` for exact local hashes and primary URLs.
This is an ordinary-data engineering measurement revision, not a platform
approval or system-risk bypass. The old V1/V2/root-V3 failures remain sealed.

The local man pages also state VmRSS/VmHWM accounting can be approximate and
snapshots can be inconsistent. This is a sampled process-accounting guard,
not a byte-accurate allocator cap or kernel-enforced memory limit. No physical
RAM shortage or full scanner peak is inferred from the earlier414.3MiB
historical versus17.4MiB current observations.

`static-source-review.json` proves all module constants and eleven unrelated
top-level functions/classes are AST-identical to the sealed observed program.
Only `Observer` and measurement descriptions/failure reporting changed. The
external RAM SOURCE and ordinary mapper remain exactly pinned; original mains
are never executed. The160000000B IMG cap, single149220356B MDR stream, table
counts/strides, stock-prefix roots, rank/alias algorithm and dense mapping
logic remain unchanged. Durable phase/individual-array/read-counter evidence
remains present, including actual threshold/value/error on failure.

Known graph-analysis qualification, source intentionally unchanged: after
`force_all`, earlier newly retained parents might not be visited again.
Whole-suffix retention makes capacity conservative and rank mappings identity,
but `range_alias_analysis_complete` alone can overstate the range census.
Do not treat it as complete reachability when anomaly/force_all flags are set.
External lower-ID refs in the MDR prefix/components/native caches remain
unknown even when a future active-tree arithmetic result fits4K. L3/JAI IDs
remain fixed in the plan; no search/UI/renderer/install completion is claimed.

Preparation source/pins/docs are sealed in `prepared-files.json`; they certify
only this source revision. Actual output needs a separate execution receipt
and seal. MAIN/guest/PBF/audio/device/IMG0, all own handles closed. This scope
stops with a prepared source, not a completed reachability result.
