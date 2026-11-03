# Host codec platform adapter preparation

This is our own caller-provided platform adapter for the pinned public
OpenH264 decoder. It replaces Linux runtime services in a new Linux aarch64
host build. The previous codec wrapper and upstream source tree stay frozen.
The adapter has not been built for 32-bit ARM, GarminOS, or an original-device
ABI. The retained upstream private headers still contain Linux pthread and
semaphore types, even though no such runtime operation is supported here.

The public adapter ABI is `port.h`; `port.cpp` supplies its implementation.
There is one serialized process-global binding. `bind` requires version 1,
reserved zero, a nonzero strictly increasing session, all four callbacks and
a backing-byte cap larger than the allocation prefix. No allocator, clock,
stdio or operating-system fallback exists. `unbind` rejects live allocations.
The same ended session remains queryable through `stats_get`, until the next
binding replaces its statistics. This is not a lock, a task scheduler,
multiple-decoder lifecycle manager, or asynchronous callback quiescence. The
caller must bind one decoder lifecycle, destroy it, then unbind.

Allocation callbacks supply the exact requested writable bytes with 16-byte
alignment. The returned payload also has that alignment. Each allocation has
a private prefix (reported by `allocation_overhead`) and stays in an owned
linked list until free; a free outside this list is fatal. The deallocation
callback receives the original base, byte count and alignment, not the user
payload pointer. The upstream Wels allocator's additional alignment and size
prefix is included in the backing-byte count tracked by this adapter.

`max_live_bytes` is a cap on outstanding callback-requested backing bytes. It
includes the adapter's prefix but not the caller allocator's private padding,
metadata, or committed heap pages. It is not a claim about overall RSS or
device RAM. Statistics count attempts/failures, successful backing bytes,
frees, live allocation count, and peak live requested bytes. Invalid callback
alignment is fatal before its memory is interpreted as an allocation prefix.

Every allocation failure, including a cap or integer-overflow rejection, uses
the caller fatal callback. It is not reported as recoverable OpenH264 OOM:
the pinned constructor writes its new context array without a NULL guard.
The fatal callback must not return; if it does, the adapter traps. Fatal tests
belong in isolated host subprocesses. Do not use longjmp to continue with
partially constructed codec state. A fatal callback may take a read-only stats
snapshot before terminating. Rebinding/unbinding during allocator, free,
clock or fatal callbacks returns REENTRANT. Recursively invoking a runtime
hook is fatal; no callback recursion is supported.

The clock callback supplies nonnegative, nondecreasing microseconds. Negative
or decreasing values are fatal. This clock is for the decoder's elapsed-time
statistics; no real wall-clock source, system sleep or inferred performance
measurement is supplied. The decoder's source timestamp/reordering metadata
still follows the unchanged public decoder API.

CPU count is deliberately fixed to one. Every thread, mutex, event, semaphore,
thread-self, join, naming or sleep API counts the attempted forbidden call and
terminates through the caller fatal handler. Return values never announce
successful synchronization. Operation IDs 1..15 identify the public Wels
common thread APIs in their definition order; 101..111 identify decoder
EventCreate/Post/Wait/Reset/Destroy, SemCreate/Wait/Release/Destroy and
ThreadCreate/Wait. `reject_thread` exposes the same failure path for deliberate
host negative controls. A zero forbidden count in a tested workload proves
only that workload did not touch a stub.

Logging policy is explicit discard with a counter: no formatting, trace
callback, stdout/stderr output, file I/O or PSNR calculation. Trace setter
fields are retained for class layout compatibility, but no log text is
delivered. This deliberately differs from the pinned public default logger.
The adapter supplies its own byte-loop memcpy, memset, memmove and memcmp,
plus allocation/new/delete, assertion and pure-virtual fatal handlers.
Its local integer `abs` handles the temporal-direct decoder's clipped value;
the unrepresentable `INT_MIN` result terminates with the assertion reason.
The linked `log` and `ceil` definitions always terminate with
`FATAL_UNSUPPORTED` (reason 10). Their only selected upstream call site is the
FMO slice-group branch; the unchanged AA wrapper already rejects FMO PPS data
before passing it to the decoder. These functions do not implement libm or
add FMO support. A tested predecoder rejection does not prove that the hidden
math termination functions themselves were executed.

## New build overlay contract

Use unchanged source files from public commit
`1a0073f0322c8b74cbcb75ca1bb1c3d19d75538d`, verified against its exact archive.
Exclude these upstream CPP files and replace their needed definitions with
`port.cpp`:

* `codec/common/src/WelsTaskThread.cpp`
* `codec/common/src/WelsThread.cpp`
* `codec/common/src/WelsThreadPool.cpp`
* `codec/common/src/WelsThreadLib.cpp`
* `codec/common/src/crt_util_safe_x.cpp`
* `codec/common/src/utils.cpp`
* `codec/common/src/welsCodecTrace.cpp`
* `codec/decoder/core/src/wels_decoder_thread.cpp`

In the new overlay copy only, add `#include "port.h"` to
`codec/common/inc/measure_time.h` and replace its non-Windows `WelsTime` body
with `return aa_h264_port_clock_us();`. The original header stays byte-identical.
No memory allocator overlay is needed: actual local malloc/free definitions
must bind upstream calls to the callback implementation. Keep
OUTPUT_BIT_STREAM, MEMORY_CHECK and motion-vector debug dumps disabled.

Compile with `-fno-exceptions -fno-rtti -fno-threadsafe-statics -fcheck-new`,
`-fno-builtin` and the existing required `-fno-strict-aliasing`. The complete
Linux host build uses hosted system headers: GCC 14's public C++ math header
rejects `-ffreestanding` in this source closure. The earlier standalone shim
syntax compile used that flag, but does not establish a freestanding decoder
build. The full host link uses `-nostdlib --no-undefined` and audits actual
imports; this is a host link policy, not a freestanding or target ABI proof.
The builder must use hidden visibility, explicitly export
the AA public APIs, localize standard new/delete with a link version script,
and bind internal definitions with `-Wl,-Bsymbolic-functions`; otherwise host
symbol interposition can silently bypass the callbacks. GCC's built-in
new/delete declarations do not permit conflicting per-function hidden
attributes, so their localization is a link contract.

The separate root build/test harness must verify actual import removal,
callback ownership/counters/cap failures, and independent FFmpeg YUV output.
Compiling this adapter alone is syntax evidence only. No Garmin instructions,
native guest, ARM crosscompiler, Bluetooth or hardware audio/video I/O are
part of this preparation.
