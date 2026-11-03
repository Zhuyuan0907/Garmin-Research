/* SPDX-License-Identifier: BSD-2-Clause */
#include "port.h"
#include "WelsThreadLib.h"
#include "wels_decoder_thread.h"
#include "welsCodecTrace.h"
#include "utils.h"
#include <limits.h>
#include <new>

#define LOCAL __attribute__((visibility("hidden")))
namespace {
struct alignas(16) allocation {
    allocation *next,*previous;
    uint64_t session,payload,backing,tag;
};
static_assert(sizeof(allocation)%AA_H264_PORT_ALIGNMENT==0,"allocation prefix alignment");
struct state {
    aa_h264_port_hooks hooks;
    aa_h264_port_stats stats;
    allocation *head;
    int64_t last_clock;
    bool clock_seen,fatal_active;
};
state current={};
const uint64_t MAGIC=UINT64_C(0x414148323634414C);
[[noreturn]] void panic(uint32_t reason){
    ++current.stats.fatal_count;current.stats.last_fatal=reason;
    if(current.stats.bound && current.hooks.fatal && !current.fatal_active){
        current.fatal_active=true;current.stats.in_callback=1;
        current.hooks.fatal(current.hooks.user,current.stats.session,reason);
    }
    /* The caller's fatal contract is non-returning; no OOM unwind/recovery. */
    __builtin_trap();
}
void require_bound(){
    if(!current.stats.bound)panic(AA_H264_PORT_FATAL_UNBOUND);
    if(current.stats.in_callback)panic(AA_H264_PORT_FATAL_REENTRY);
}
[[noreturn]] void allocation_failure(){
    ++current.stats.allocation_failures;panic(AA_H264_PORT_FATAL_ALLOCATION);
}
void count_log(){require_bound();++current.stats.suppressed_log_calls;}
[[noreturn]] void thread_failure(uint32_t op){aa_h264_port_reject_thread(op);__builtin_trap();}
}

extern "C" int aa_h264_port_bind(uint64_t session,const aa_h264_port_hooks *hooks){
    if(current.stats.in_callback)return AA_H264_PORT_REENTRANT;
    if(current.stats.bound)return AA_H264_PORT_BOUND;
    if(!session || session<=current.stats.session)return AA_H264_PORT_SESSION;
    if(!hooks || hooks->version!=AA_H264_PORT_VERSION || hooks->reserved ||
       !hooks->alloc || !hooks->dealloc || !hooks->clock_us || !hooks->fatal ||
       hooks->max_live_bytes<=sizeof(allocation))return AA_H264_PORT_ARGUMENT;
    current.hooks=*hooks;current.stats=aa_h264_port_stats{};
    current.stats.session=session;current.stats.bound=1;current.head=nullptr;
    current.last_clock=0;current.clock_seen=current.fatal_active=false;return AA_H264_PORT_OK;
}
extern "C" int aa_h264_port_unbind(uint64_t session){
    if(current.stats.in_callback)return AA_H264_PORT_REENTRANT;
    if(!session || session!=current.stats.session)return AA_H264_PORT_SESSION;
    if(!current.stats.bound)return AA_H264_PORT_BOUND;
    if(current.stats.live_allocations || current.stats.live_bytes || current.head)return AA_H264_PORT_LIVE;
    current.stats.bound=0;current.hooks=aa_h264_port_hooks{};return AA_H264_PORT_OK;
}
extern "C" int aa_h264_port_stats_get(uint64_t session,aa_h264_port_stats *out){
    if(!session || session!=current.stats.session)return AA_H264_PORT_SESSION;
    if(!out)return AA_H264_PORT_ARGUMENT;
    *out=current.stats;return AA_H264_PORT_OK;
}
extern "C" size_t aa_h264_port_allocation_overhead(void){return sizeof(allocation);}
extern "C" int64_t aa_h264_port_clock_us(void){
    require_bound();++current.stats.clock_calls;current.stats.in_callback=1;
    int64_t value=current.hooks.clock_us(current.hooks.user);current.stats.in_callback=0;
    if(value<0 || (current.clock_seen && value<current.last_clock))panic(AA_H264_PORT_FATAL_CLOCK);
    current.clock_seen=true;current.last_clock=value;return value;
}
extern "C" void aa_h264_port_reject_thread(uint32_t op){
    require_bound();++current.stats.forbidden_count;current.stats.last_forbidden=op;
    panic(AA_H264_PORT_FATAL_THREAD);
}

/* Real local implementations, bound to this library's own callers. No host
 * allocation/stdio/time fallback. Public upstream memory_align still owns its
 * additional alignment header; the bytes here include that whole allocation. */
extern "C" LOCAL void *malloc(size_t bytes) noexcept {
    require_bound();++current.stats.allocation_calls;
    if(!bytes)bytes=1;
    if(bytes>SIZE_MAX-sizeof(allocation))allocation_failure();
    size_t backing=bytes+sizeof(allocation);
    if(backing>current.hooks.max_live_bytes-current.stats.live_bytes ||
       backing>UINT64_MAX-current.stats.allocated_bytes)allocation_failure();
    current.stats.in_callback=1;
    void *base=current.hooks.alloc(current.hooks.user,backing,AA_H264_PORT_ALIGNMENT);
    current.stats.in_callback=0;
    if(!base)allocation_failure();
    if(reinterpret_cast<uintptr_t>(base)%AA_H264_PORT_ALIGNMENT){
        ++current.stats.allocation_failures;panic(AA_H264_PORT_FATAL_ALIGNMENT);
    }
    allocation *a=::new(base) allocation;
    a->next=current.head;a->previous=nullptr;a->session=current.stats.session;
    a->payload=bytes;a->backing=backing;a->tag=MAGIC;
    if(current.head)current.head->previous=a;
    current.head=a;++current.stats.live_allocations;current.stats.live_bytes+=backing;
    current.stats.allocated_bytes+=backing;
    if(current.stats.live_bytes>current.stats.peak_live_bytes)current.stats.peak_live_bytes=current.stats.live_bytes;
    return reinterpret_cast<uint8_t*>(a)+sizeof(allocation);
}
extern "C" LOCAL void free(void *pointer) noexcept {
    if(!pointer)return;
    require_bound();allocation *a=current.head;
    while(a && reinterpret_cast<uint8_t*>(a)+sizeof(allocation)!=pointer)a=a->next;
    if(!a || a->tag!=MAGIC || a->session!=current.stats.session ||
       a->backing>current.stats.live_bytes || !current.stats.live_allocations)panic(AA_H264_PORT_FATAL_FREE);
    if(a->previous)a->previous->next=a->next;else current.head=a->next;
    if(a->next)a->next->previous=a->previous;
    size_t bytes=static_cast<size_t>(a->backing);a->tag=0;
    ++current.stats.deallocation_calls;--current.stats.live_allocations;
    current.stats.live_bytes-=bytes;current.stats.freed_bytes+=bytes;
    current.stats.in_callback=1;
    current.hooks.dealloc(current.hooks.user,a,bytes,AA_H264_PORT_ALIGNMENT);
    current.stats.in_callback=0;
}
/* GCC's built-in new/delete declarations have default visibility. The link
 * version script localizes these definitions; Bsymbolic binds codec callers. */
void *operator new(size_t bytes){return malloc(bytes);}
void *operator new[](size_t bytes){return malloc(bytes);}
void operator delete(void *pointer) noexcept {free(pointer);}
void operator delete[](void *pointer) noexcept {free(pointer);}
void operator delete(void *pointer,size_t) noexcept {free(pointer);}
void operator delete[](void *pointer,size_t) noexcept {free(pointer);}
extern "C" LOCAL void __cxa_pure_virtual(){panic(AA_H264_PORT_FATAL_PURE_VIRTUAL);}
extern "C" LOCAL void __assert_fail(const char *,const char *,unsigned,const char *) noexcept {
    panic(AA_H264_PORT_FATAL_ASSERT);
}

extern "C" LOCAL void *memcpy(void *destination,const void *source,size_t n) noexcept {
    uint8_t *out=static_cast<uint8_t*>(destination);const uint8_t *in=static_cast<const uint8_t*>(source);
    for(size_t i=0;i<n;++i)out[i]=in[i];
    return destination;
}
extern "C" LOCAL void *memset(void *destination,int value,size_t n) noexcept {
    uint8_t *out=static_cast<uint8_t*>(destination);
    for(size_t i=0;i<n;++i)out[i]=static_cast<uint8_t>(value);
    return destination;
}
extern "C" LOCAL int memcmp(const void *first,const void *second,size_t n) noexcept {
    const uint8_t *a=static_cast<const uint8_t*>(first),*b=static_cast<const uint8_t*>(second);
    for(size_t i=0;i<n;++i)if(a[i]!=b[i])return int(a[i])-int(b[i]);
    return 0;
}
extern "C" LOCAL void *memmove(void *destination,const void *source,size_t n) noexcept {
    uint8_t *out=static_cast<uint8_t*>(destination);const uint8_t *in=static_cast<const uint8_t*>(source);
    uintptr_t d=reinterpret_cast<uintptr_t>(out),s=reinterpret_cast<uintptr_t>(in);
    if(d>s && d-s<n){for(size_t i=n;i>0;--i)out[i-1]=in[i-1];}
    else {for(size_t i=0;i<n;++i)out[i]=in[i];}return destination;
}

/* The selected temporal-direct path uses abs on a clipped [-128,127] value.
 * INT_MIN has no representable positive int result: fail rather than overflow.
 * log/ceil only link from the FMO path rejected by the unchanged AA wrapper.
 * These definitions are deliberately unsupported, not approximations/libm. */
extern "C" LOCAL int abs(int value) noexcept {
    if(value==INT_MIN)panic(AA_H264_PORT_FATAL_ASSERT);
    return value<0 ? -value : value;
}
extern "C" LOCAL double log(double) noexcept {panic(AA_H264_PORT_FATAL_UNSUPPORTED);}
extern "C" LOCAL double ceil(double) noexcept {panic(AA_H264_PORT_FATAL_UNSUPPORTED);}

/* Intentional logging policy: count and discard without formatting or output.
 * Do not compile original utils/crt_util_safe_x/welsCodecTrace sources. */
void WelsLog(SLogContext *,int32_t,const char *,...){count_log();}
welsCodecTrace::welsCodecTrace():m_iTraceLevel(0),m_fpTrace(nullptr),m_pTraceCtx(nullptr){
    m_sLogCtx.pLogCtx=this;m_sLogCtx.pfLog=StaticCodecTrace;m_sLogCtx.pCodecInstance=nullptr;
}
welsCodecTrace::~welsCodecTrace(){}
void welsCodecTrace::SetCodecInstance(void *value){m_sLogCtx.pCodecInstance=value;}
void welsCodecTrace::SetTraceLevel(int32_t value){m_iTraceLevel=value;}
void welsCodecTrace::SetTraceCallback(WelsTraceCallback value){m_fpTrace=value;}
void welsCodecTrace::SetTraceCallbackContext(void *value){m_pTraceCtx=value;}
void welsCodecTrace::StaticCodecTrace(void *,int32_t,const char *,va_list){count_log();}
void welsCodecTrace::CodecTrace(int32_t,const char *,va_list){count_log();}

/* Fixed single-CPU policy is independent of host CPU-affinity queries. Header
 * types below remain upstream Linux private ABI; no target ABI claim. Every
 * synchronization function is a fail-closed counter, not emulated support. */
extern "C" int32_t GetCPUCount(){require_bound();++current.stats.cpu_queries;return 1;}
extern "C" WELS_THREAD_ERROR_CODE WelsQueryLogicalProcessInfo(WelsLogicalProcessInfo *info){
    require_bound();++current.stats.cpu_queries;if(!info)panic(AA_H264_PORT_FATAL_ASSERT);
    info->ProcessorCount=1;return WELS_THREAD_ERROR_OK;
}
extern "C" WELS_THREAD_ERROR_CODE WelsMutexInit(WELS_MUTEX *){thread_failure(1);}
extern "C" WELS_THREAD_ERROR_CODE WelsMutexLock(WELS_MUTEX *){thread_failure(2);}
extern "C" WELS_THREAD_ERROR_CODE WelsMutexUnlock(WELS_MUTEX *){thread_failure(3);}
extern "C" WELS_THREAD_ERROR_CODE WelsMutexDestroy(WELS_MUTEX *){thread_failure(4);}
extern "C" WELS_THREAD_ERROR_CODE WelsEventOpen(WELS_EVENT *,const char *){thread_failure(5);}
extern "C" WELS_THREAD_ERROR_CODE WelsEventClose(WELS_EVENT *,const char *){thread_failure(6);}
extern "C" WELS_THREAD_ERROR_CODE WelsEventSignal(WELS_EVENT *,WELS_MUTEX *,int *){thread_failure(7);}
extern "C" WELS_THREAD_ERROR_CODE WelsEventWait(WELS_EVENT *,WELS_MUTEX *,int &){thread_failure(8);}
extern "C" WELS_THREAD_ERROR_CODE WelsEventWaitWithTimeOut(WELS_EVENT *,uint32_t,WELS_MUTEX *){thread_failure(9);}
extern "C" WELS_THREAD_ERROR_CODE WelsMultipleEventsWaitSingleBlocking(uint32_t,WELS_EVENT *,WELS_EVENT *,WELS_MUTEX *){thread_failure(10);}
extern "C" WELS_THREAD_ERROR_CODE WelsThreadCreate(WELS_THREAD_HANDLE *,LPWELS_THREAD_ROUTINE,void *,WELS_THREAD_ATTR){thread_failure(11);}
extern "C" WELS_THREAD_ERROR_CODE WelsThreadSetName(const char *){thread_failure(12);}
extern "C" WELS_THREAD_ERROR_CODE WelsThreadJoin(WELS_THREAD_HANDLE){thread_failure(13);}
extern "C" WELS_THREAD_HANDLE WelsThreadSelf(){thread_failure(14);}
extern "C" void WelsSleep(uint32_t){thread_failure(15);}
extern "C" int EventCreate(SWelsDecEvent *,int,int){thread_failure(101);}
extern "C" void EventPost(SWelsDecEvent *){thread_failure(102);}
extern "C" int EventWait(SWelsDecEvent *,int32_t){thread_failure(103);}
extern "C" void EventReset(SWelsDecEvent *){thread_failure(104);}
extern "C" void EventDestroy(SWelsDecEvent *){thread_failure(105);}
extern "C" int SemCreate(SWelsDecSemphore *,long,long){thread_failure(106);}
extern "C" int SemWait(SWelsDecSemphore *,int32_t){thread_failure(107);}
extern "C" void SemRelease(SWelsDecSemphore *,long *){thread_failure(108);}
extern "C" void SemDestroy(SWelsDecSemphore *){thread_failure(109);}
extern "C" int ThreadCreate(SWelsDecThread *,LPWELS_THREAD_ROUTINE,void *){thread_failure(110);}
extern "C" int ThreadWait(SWelsDecThread *){thread_failure(111);}
