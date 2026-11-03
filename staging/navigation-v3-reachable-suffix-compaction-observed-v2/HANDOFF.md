# Observed preparation: exact initial historical-RSS guard stop

New ordinary data program actual **EXIT1**, terminal **90fb2a**. It stopped at
its **first persisted observation**, before any source-input read/parse,
mapper construction, field array allocation or IMG open:

| Initial observed metric | KiB |
| --- | ---: |
| `resource.getrusage(RUSAGE_SELF).ru_maxrss` | 424240 |
| `/proc/self/status VmRSS` | 17824 |
| `/proc/self/status VmHWM` | 17824 |
| `/proc/self/status VmSize` | 28608 |
| `/proc/self/status VmPeak` | 28672 |
| Unchanged RSS guard | 393216 |

The guard remains **384*1024KiB**, and still compares Linux `ru_maxrss` in KiB.
The exception is the program's own `OwnBudgetError`, **not** a tool-platform,
automatic approval or system cyberrisk interruption. The observed historical
peak is414.3MiB while current VmRSS/HWM is17.4MiB. That divergence predates
this program's parsers/arrays. It does not prove which launcher/prior exec
produced the peak, nor establish the actual full algorithm's memory use.
No memory-cause claim was derived from the planned64,175,632-byte array size.

`actual-phase-observations.jsonl` contains two durable actual rows: the initial
observation and the exception snapshot. Both include the exact threshold,
value, current VmRSS/VmHWM, planned fixed counts, phase and reader budget.
`actual-failure.json` saves the same real measurements and traceback status.
The failure handler did not lose or infer any counter: **IMG0bytes/0ops**,
**no source IMG handle ever opened**, **no MDR stream**, **no arrays allocated**.

The new source `observed_analyzer.py` includes before/after observations for
each small input, mapper parsing and each individual field array. It adds
durable observations around bitset/rank/range sorting allocations, and saves
exact threshold/value/budget on all caught ordinary failures. Those later
phases were **not reached**, so their measured memory/reachability/capacity
results remain unknown. It does not execute either closed historical main.

The original failed scope remains unchanged and sealed. Its source is pinned
as `a1a7a9c94df6a8b715eca28366a9c94ed8895d6e0176fd05a4f076d506beb274`;
the ordinary allocation mapper is pinned as
`a20877fce09cbfe36f1f5621144f2ade44a031c26e4c6d330d07b2a1b86c4095`.
The manual preparation pin check is distinct from the failed program's
initial guard: the latter never got to its source-pinning/parsing phases.
Root's independent64MB buffer diagnostic is a different scope and does not
prove this scanner's full memory peak.

The two requested plans remain **uncomputed**: original-stock-prefix plus
active all47870-L3 tree, and whole-current-v2-prefix plus active tree.
No poststock active counts, alias/contiguity results, pointer-remap totals or
128MiB projection is claimed. Current23/112 L3 and128/126/68 lower profiles,
stock-prefix ID preservation, full L3/JAI ID preservation and external lower-ID
reference limits remain the planned analysis contract.

No guard was raised, removed or relaxed; no retry was made. A future separately
authorized design decision may need to distinguish current address-space RSS
from historical `ru_maxrss`, while retaining the384MiB numerical budget. This
handoff does not change that rule or authorize another run. MAIN, native CPU,
audio, PBF, sourceledgers, IMG output, devices and shared canonicals were not
touched. Only small observation/proof/source/seal artifacts were produced;
all own handles are closed. This scope is sealed and stopped.
