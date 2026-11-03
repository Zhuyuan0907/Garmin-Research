/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux host test only. The external test runtime uses normal host allocation;
 * the NEW production shared library must bind its own allocation to port.h. */
#include "port.h"
#include <map>
#include <limits>
#include <cinttypes>
#define main original_h264_host_harness_main
#include "../aa-h264/test_h264.cpp"
#undef main

struct backing_record {
    void *raw;
    size_t bytes,alignment;
};
struct host_tracker {
    std::map<void *,backing_record> allocations;
    uint64_t session=1,cap=UINT64_C(67108864),live_bytes=0,peak_bytes=0;
    uint64_t alloc_callbacks=0,free_callbacks=0,callback_guards=0;
    uint64_t fail_ordinal=0;
    int64_t clock_value=100;
    unsigned clock_mode=0;
    bool bad_alignment=false,return_fatal=false;
};
static host_tracker tracking;
static aa_h264_port_hooks hooks;

static aa_h264_port_stats snapshot() {
    aa_h264_port_stats s={};
    CHECK(aa_h264_port_stats_get(tracking.session,&s)==AA_H264_PORT_OK);
    return s;
}
static void callback_guards() {
    aa_h264_port_stats s=snapshot();
    CHECK(s.bound==1 && s.in_callback==1);
    CHECK(aa_h264_port_bind(tracking.session+1,&hooks)==AA_H264_PORT_REENTRANT);
    CHECK(aa_h264_port_unbind(tracking.session)==AA_H264_PORT_REENTRANT);
    aa_h264_port_stats ignored={};
    CHECK(aa_h264_port_stats_get(tracking.session+1,&ignored)==AA_H264_PORT_SESSION);
    ++tracking.callback_guards;
}
static void *host_alloc(void *,size_t bytes,size_t alignment) {
    callback_guards();
    aa_h264_port_stats s=snapshot();
    CHECK(s.live_bytes==tracking.live_bytes);
    CHECK(s.live_allocations==tracking.allocations.size());
    CHECK(bytes>aa_h264_port_allocation_overhead());
    CHECK(alignment==AA_H264_PORT_ALIGNMENT);
    CHECK(bytes<=tracking.cap-tracking.live_bytes);
    ++tracking.alloc_callbacks;
    if(tracking.fail_ordinal==tracking.alloc_callbacks)return nullptr;
    void *raw=nullptr;
    CHECK(posix_memalign(&raw,alignment,bytes+64)==0 && raw);
    std::memset(raw,0xa5,bytes+64);
    uint8_t *base=static_cast<uint8_t *>(raw)+32;
    if(tracking.bad_alignment)++base;
    CHECK(tracking.allocations.emplace(base,backing_record{raw,bytes,alignment}).second);
    tracking.live_bytes+=bytes;
    tracking.peak_bytes=std::max(tracking.peak_bytes,tracking.live_bytes);
    return base;
}
static void host_free(void *,void *base,size_t bytes,size_t alignment) {
    callback_guards();
    auto found=tracking.allocations.find(base);
    CHECK(found!=tracking.allocations.end());
    const backing_record r=found->second;
    CHECK(r.bytes==bytes && r.alignment==alignment && alignment==AA_H264_PORT_ALIGNMENT);
    CHECK(reinterpret_cast<uintptr_t>(base)%alignment==0);
    uint8_t *raw=static_cast<uint8_t *>(r.raw);
    CHECK(base==raw+32);
    for(size_t i=0;i<32;++i)CHECK(raw[i]==0xa5 && raw[32+bytes+i]==0xa5);
    aa_h264_port_stats s=snapshot();
    CHECK(s.live_bytes==tracking.live_bytes-bytes);
    CHECK(s.live_allocations+1==tracking.allocations.size());
    tracking.live_bytes-=bytes;
    tracking.allocations.erase(found);
    ++tracking.free_callbacks;
    std::free(r.raw);
}
static int64_t host_clock(void *) {
    callback_guards();
    if(tracking.clock_mode==1)return -1;
    if(tracking.clock_mode==2)return tracking.clock_value--;
    if(tracking.clock_mode==3)return aa_h264_port_clock_us(); /* deliberate recursion */
    if(tracking.clock_mode==4)return std::numeric_limits<int64_t>::max();
    if(tracking.clock_mode==5)return tracking.clock_value; /* equality allowed */
    return tracking.clock_value++;
}
static void host_fatal(void *,uint64_t session,uint32_t reason) {
    CHECK(session==tracking.session);
    callback_guards();
    aa_h264_port_stats s=snapshot();
    CHECK(s.fatal_count==1 && s.last_fatal==reason && s.in_callback==1);
    CHECK(s.peak_live_bytes<=tracking.cap && s.live_bytes<=tracking.cap);
    std::printf("{\"fatal\":true,\"reason\":%u,\"session\":%" PRIu64
                ",\"allocation_calls\":%" PRIu64 ",\"allocation_failures\":%" PRIu64
                ",\"alloc_callbacks\":%" PRIu64 ",\"free_callbacks\":%" PRIu64
                ",\"live_allocations\":%" PRIu64 ",\"live_bytes\":%" PRIu64
                ",\"peak_live_bytes\":%" PRIu64 ",\"cap\":%" PRIu64
                ",\"clock_calls\":%" PRIu64 ",\"forbidden_count\":%" PRIu64
                ",\"last_forbidden\":%u,\"fatal_count\":%" PRIu64
                ",\"callback_guards\":%" PRIu64 "}\n",
                reason,session,s.allocation_calls,s.allocation_failures,
                tracking.alloc_callbacks,tracking.free_callbacks,s.live_allocations,
                s.live_bytes,s.peak_live_bytes,tracking.cap,s.clock_calls,
                s.forbidden_count,s.last_forbidden,s.fatal_count,tracking.callback_guards);
    std::fflush(stdout);
    if(tracking.return_fatal)return; /* controlled violation must trap */
    _Exit(80+int(reason));
}
static void configure_hooks() {
    hooks=aa_h264_port_hooks{AA_H264_PORT_VERSION,0,tracking.cap,
                             host_alloc,host_free,host_clock,host_fatal,nullptr};
}
static void verify_clean() {
    aa_h264_port_stats s=snapshot();
    CHECK(s.live_allocations==0 && s.live_bytes==0);
    CHECK(tracking.live_bytes==0 && tracking.allocations.empty());
    CHECK(s.allocated_bytes==s.freed_bytes);
    CHECK(s.allocation_calls==s.deallocation_calls);
    CHECK(s.allocation_calls==tracking.alloc_callbacks);
    CHECK(s.deallocation_calls==tracking.free_callbacks);
    CHECK(s.peak_live_bytes==tracking.peak_bytes && s.peak_live_bytes<=tracking.cap);
    CHECK(s.allocation_failures==0 && s.forbidden_count==0 && s.fatal_count==0);
}
static void print_clean(const char *control) {
    verify_clean();
    aa_h264_port_stats s=snapshot();
    CHECK(aa_h264_port_unbind(tracking.session)==AA_H264_PORT_OK);
    aa_h264_port_stats ended=snapshot();CHECK(ended.bound==0 && ended.in_callback==0);
    std::printf("{\"port_pass\":true,\"control\":\"%s\",\"checks\":%u,"
                "\"session\":%" PRIu64 ",\"allocation_calls\":%" PRIu64
                ",\"deallocation_calls\":%" PRIu64 ",\"alloc_callbacks\":%" PRIu64
                ",\"free_callbacks\":%" PRIu64 ",\"live_allocations\":0,\"live_bytes\":0,"
                "\"allocated_bytes\":%" PRIu64 ",\"freed_bytes\":%" PRIu64
                ",\"peak_live_bytes\":%" PRIu64 ",\"cap\":%" PRIu64
                ",\"clock_calls\":%" PRIu64 ",\"cpu_queries\":%" PRIu64
                ",\"suppressed_log_calls\":%" PRIu64
                ",\"callback_guards\":%" PRIu64
                ",\"forbidden_count\":0,\"fatal_count\":0,\"unbound\":true}\n",
                control,checks,s.session,s.allocation_calls,s.deallocation_calls,
                tracking.alloc_callbacks,tracking.free_callbacks,s.allocated_bytes,s.freed_bytes,
                s.peak_live_bytes,tracking.cap,s.clock_calls,s.cpu_queries,s.suppressed_log_calls,
                tracking.callback_guards);
}
static void bind_controls() {
    aa_h264_port_stats before=snapshot(),s={};
    CHECK(aa_h264_port_bind(2,&hooks)==AA_H264_PORT_BOUND);
    CHECK(aa_h264_port_unbind(2)==AA_H264_PORT_SESSION);
    CHECK(aa_h264_port_stats_get(0,&s)==AA_H264_PORT_SESSION);
    CHECK(aa_h264_port_stats_get(1,nullptr)==AA_H264_PORT_ARGUMENT);
    CHECK(aa_h264_port_stats_get(1,&s)==0);
    CHECK(s.live_bytes==before.live_bytes && s.bound==before.bound && s.session==before.session);
    CHECK(aa_h264_port_unbind(1)==0);
    CHECK(aa_h264_port_unbind(1)==AA_H264_PORT_BOUND);
    CHECK(aa_h264_port_bind(1,&hooks)==AA_H264_PORT_SESSION);
    aa_h264_port_hooks bad=hooks;bad.version=2;
    CHECK(aa_h264_port_bind(2,&bad)==AA_H264_PORT_ARGUMENT);
    bad=hooks;bad.reserved=1;CHECK(aa_h264_port_bind(2,&bad)==AA_H264_PORT_ARGUMENT);
    bad=hooks;bad.alloc=nullptr;CHECK(aa_h264_port_bind(2,&bad)==AA_H264_PORT_ARGUMENT);
    bad=hooks;bad.dealloc=nullptr;CHECK(aa_h264_port_bind(2,&bad)==AA_H264_PORT_ARGUMENT);
    bad=hooks;bad.clock_us=nullptr;CHECK(aa_h264_port_bind(2,&bad)==AA_H264_PORT_ARGUMENT);
    bad=hooks;bad.fatal=nullptr;CHECK(aa_h264_port_bind(2,&bad)==AA_H264_PORT_ARGUMENT);
    bad=hooks;bad.max_live_bytes=aa_h264_port_allocation_overhead();
    CHECK(aa_h264_port_bind(2,&bad)==AA_H264_PORT_ARGUMENT);
    CHECK(aa_h264_port_bind(2,nullptr)==AA_H264_PORT_ARGUMENT);
    CHECK(aa_h264_port_bind(0,&hooks)==AA_H264_PORT_SESSION);
    tracking.session=2;CHECK(aa_h264_port_bind(2,&hooks)==0);
    CHECK(aa_h264_port_stats_get(1,&s)==AA_H264_PORT_SESSION);
    { instance d(false);
      CHECK(snapshot().live_allocations>0);
      CHECK(aa_h264_port_unbind(2)==AA_H264_PORT_LIVE);
      CHECK(aa_h264_stop(d.decoder)==0);verify_clean();
      CHECK(aa_h264_start(d.decoder)==0);
      CHECK(snapshot().live_allocations>0);
    }
    verify_clean();
}
static void lifecycle_controls(const char *path) {
    std::vector<uint8_t> input=read(path);
    { instance d(true);
      CHECK(deliver(d,input,1,true)==AA_H264_STOPPED);
      CHECK(d.output.frames==0 && d.output.attempts==1);
      CHECK(aa_h264_retry(d.decoder)==AA_H264_STOPPED);
      CHECK(aa_h264_finish(d.decoder)==AA_H264_STOPPED);
      CHECK(d.output.attempts==1);verify_clean();
      CHECK(aa_h264_start(d.decoder)==0);
      d.output.frames=d.output.attempts=0;d.output.waiting=false;
      CHECK(deliver(d,input,65535)==AA_H264_FINISHED);
      CHECK(d.output.frames==8 && d.output.attempts==16);
    }
    verify_clean();
    { instance d(false);
      size_t consumed=0;
      CHECK(aa_h264_feed(d.decoder,input.data(),input.size(),UINT64_MAX,&consumed)==0);
      CHECK(consumed==input.size() && d.output.frames==7);
      d.output.pause=true;
      CHECK(aa_h264_finish(d.decoder)==AA_H264_PAUSED);
      CHECK(d.output.frames==7 && d.output.waiting && d.output.index==7);
      uint64_t attempts=d.output.attempts;size_t ignored=99;
      CHECK(aa_h264_feed(d.decoder,input.data(),1,0,&ignored)==AA_H264_PAUSED && ignored==0);
      CHECK(d.output.attempts==attempts);
      CHECK(aa_h264_retry(d.decoder)==AA_H264_FINISHED);
      CHECK(d.output.frames==8 && d.output.attempts==attempts+1 && !d.output.waiting);
      CHECK(aa_h264_status(d.decoder)==AA_H264_FINISHED);
      CHECK(aa_h264_finish(d.decoder)==AA_H264_FINISHED);
      CHECK(d.output.attempts==attempts+1);
    }
    verify_clean();
}

int main(int argc,char **argv) {
    if(argc<2)return 3;
    const char *mode=argv[1];
    if(!std::strcmp(mode,"fatal-cap"))tracking.cap=aa_h264_port_allocation_overhead()+1;
    if(!std::strcmp(mode,"fatal-allocator")) {
        CHECK(argc==3);tracking.fail_ordinal=std::strtoull(argv[2],nullptr,10);
        CHECK(tracking.fail_ordinal>0);
    }
    if(!std::strcmp(mode,"fatal-alignment"))tracking.bad_alignment=true;
    if(!std::strcmp(mode,"fatal-return"))tracking.return_fatal=true;
    configure_hooks();
    CHECK(aa_h264_port_bind(0,&hooks)==AA_H264_PORT_SESSION);
    CHECK(aa_h264_port_bind(tracking.session,&hooks)==AA_H264_PORT_OK);
    if(!std::strcmp(mode,"controls"))bind_controls();
    else if(!std::strcmp(mode,"lifecycle")) {CHECK(argc==3);lifecycle_controls(argv[2]);}
    else if(!std::strcmp(mode,"clock-equal")) {
        tracking.clock_mode=5;CHECK(aa_h264_port_clock_us()==100);
        CHECK(aa_h264_port_clock_us()==100);
    } else if(!std::strcmp(mode,"clock-max")) {
        tracking.clock_mode=4;CHECK(aa_h264_port_clock_us()==INT64_MAX);
        CHECK(aa_h264_port_clock_us()==INT64_MAX);
    } else if(!std::strcmp(mode,"fatal-clock-negative")) {
        tracking.clock_mode=1;(void)aa_h264_port_clock_us();CHECK(false);
    } else if(!std::strcmp(mode,"fatal-clock-regression")) {
        tracking.clock_mode=2;CHECK(aa_h264_port_clock_us()==100);
        (void)aa_h264_port_clock_us();CHECK(false);
    } else if(!std::strcmp(mode,"fatal-reentry")) {
        tracking.clock_mode=3;(void)aa_h264_port_clock_us();CHECK(false);
    } else if(!std::strcmp(mode,"fatal-thread") || !std::strcmp(mode,"fatal-return")) {
        CHECK(argc==3);aa_h264_port_reject_thread(unsigned(std::strtoul(argv[2],nullptr,10)));CHECK(false);
    } else if(!std::strcmp(mode,"fatal-unbound")) {
        CHECK(aa_h264_port_unbind(tracking.session)==0);
        std::printf("{\"unbound_before_runtime_call\":true}\n");std::fflush(stdout);
        (void)aa_h264_port_clock_us();CHECK(false);
    } else if(!std::strcmp(mode,"fatal-cap") || !std::strcmp(mode,"fatal-allocator") ||
              !std::strcmp(mode,"fatal-alignment")) {
        instance d(false);CHECK(false); /* creation must terminate via fatal */
    } else {
        CHECK(!std::strcmp(mode,"guards") || !std::strcmp(mode,"decode"));
        CHECK(original_h264_host_harness_main(argc,argv)==0);
    }
    print_clean(mode);return 0;
}
