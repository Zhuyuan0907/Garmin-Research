/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef AA_H264_PORT_H
#define AA_H264_PORT_H
#include <stddef.h>
#include <stdint.h>
#if defined(__GNUC__)
#define AA_H264_PORT_API __attribute__((visibility("default")))
#else
#define AA_H264_PORT_API
#endif
#ifdef __cplusplus
extern "C" {
#endif
enum { AA_H264_PORT_OK=0, AA_H264_PORT_ARGUMENT=-800001,
       AA_H264_PORT_SESSION=-800002, AA_H264_PORT_BOUND=-800003,
       AA_H264_PORT_LIVE=-800004, AA_H264_PORT_REENTRANT=-800005 };
enum { AA_H264_PORT_FATAL_UNBOUND=1, AA_H264_PORT_FATAL_ALLOCATION=2,
       AA_H264_PORT_FATAL_THREAD=3, AA_H264_PORT_FATAL_REENTRY=4,
       AA_H264_PORT_FATAL_ALIGNMENT=5, AA_H264_PORT_FATAL_FREE=6,
       AA_H264_PORT_FATAL_CLOCK=7, AA_H264_PORT_FATAL_ASSERT=8,
       AA_H264_PORT_FATAL_PURE_VIRTUAL=9, AA_H264_PORT_FATAL_UNSUPPORTED=10 };
enum { AA_H264_PORT_ALIGNMENT=16, AA_H264_PORT_VERSION=1 };
/* alloc must supply writable bytes aligned as requested, or NULL. dealloc
 * receives the identical base, backing-byte count and alignment. No fallback.
 * A failing alloc is fatal, never a recoverable OpenH264 OOM claim. */
typedef void *(*aa_h264_port_alloc)(void *,size_t,size_t);
typedef void (*aa_h264_port_dealloc)(void *,void *,size_t,size_t);
typedef int64_t (*aa_h264_port_clock)(void *); /* nonnegative, nondecreasing microseconds */
typedef void (*aa_h264_port_fatal)(void *,uint64_t,uint32_t); /* MUST NOT RETURN */
struct aa_h264_port_hooks {
    uint32_t version,reserved;
    uint64_t max_live_bytes; /* exact backing bytes incl allocation headers */
    aa_h264_port_alloc alloc;
    aa_h264_port_dealloc dealloc;
    aa_h264_port_clock clock_us;
    aa_h264_port_fatal fatal;
    void *user;
};
struct aa_h264_port_stats {
    uint64_t session;
    uint64_t allocation_calls,deallocation_calls,allocation_failures;
    uint64_t live_allocations,live_bytes,peak_live_bytes;
    uint64_t allocated_bytes,freed_bytes;
    uint64_t clock_calls,cpu_queries,suppressed_log_calls;
    uint64_t forbidden_count,fatal_count;
    uint32_t last_fatal,last_forbidden;
    uint32_t bound,in_callback;
};
/* One process-global binding, serialized by caller. Each binding requires a
 * strictly increasing nonzero session; stale handles cannot unbind/rebind it.
 * bind refuses another active binding. unbind refuses live allocations.
 * Mutating callback reentry is rejected; stats snapshots may be read within
 * callbacks. This does not establish threads, quiescence or safe longjmp.
 * Caller binds one decoder lifecycle and destroys it before unbinding. */
AA_H264_PORT_API int aa_h264_port_bind(uint64_t,const struct aa_h264_port_hooks *);
AA_H264_PORT_API int aa_h264_port_unbind(uint64_t);
AA_H264_PORT_API int aa_h264_port_stats_get(uint64_t,struct aa_h264_port_stats *);
AA_H264_PORT_API size_t aa_h264_port_allocation_overhead(void);
AA_H264_PORT_API int64_t aa_h264_port_clock_us(void);
/* All actual platform thread/event/semaphore stubs route here and never
 * succeed. Also callable as a deliberate host failure-control entry point. */
AA_H264_PORT_API void aa_h264_port_reject_thread(uint32_t);
#ifdef __cplusplus
}
#endif
#endif
