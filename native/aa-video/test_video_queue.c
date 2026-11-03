/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Linux-host contract tests. This deliberately synthetic H.264 dependency
 * neither parses nor decodes video, invokes Garmin code, nor uses hardware. */
#include "video.h"
#include "rgb565.h"
#include "control.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { SLOT_BYTES=262144, OWNER=0x71924u, MAX_ACTIONS=16 };
enum category { OWNERSHIP, PARTIAL, PAUSE, TIMESTAMP, INVALID_USED, EOF_HELD,
    LIFECYCLE, ERRORS, REENTRY, STOP_SERIAL, RGB_STRIDE, RGB_REJECT, CATEGORIES };
static const char *names[CATEGORIES]={
    "owned_two_slot_capacity_and_source_lifetime", "partial_consumption_tail",
    "paused_frame_no_duplicate_input", "signed_media_session_and_timestamp",
    "invalid_consumption_guard", "EOF_held_frame_retry_finished",
    "STOP_restart_stale_owner", "decoder_error_details",
    "dependency_callback_reentry_guards", "serialized_owner_stop",
    "RGB565_strides_canaries_padding", "RGB565_rejection_before_write"};
static unsigned counts[CATEGORIES],category,checks;
#define CHECK(x) do { ++checks; ++counts[category]; if(!(x)){ \
    fprintf(stderr,"check failed category=%s at %s:%d: %s\n",names[category],__FILE__,__LINE__,#x); exit(1); } } while(0)

struct action { const uint8_t *expected;size_t length,used;uint64_t timestamp;int result; };
enum hook { NO_HOOK, START_HOOK, FEED_HOOK, RETRY_HOOK, FINISH_HOOK, STOP_HOOK };
struct aa_h264 {
    struct action actions[MAX_ACTIONS];unsigned action_count,action_pos;
    unsigned starts,stops,feeds,retries,finishes,held_retries;
    size_t accepted;int held,eof,finish_hold,start_result,stop_result,retry_result;
    enum hook hook;void *owner;
};
struct fixture { uint8_t *allocation;void *owner;size_t bytes;struct aa_h264 decoder; };
static void reentry(struct aa_h264 *d,enum hook h){
    uint8_t data=91;struct aa_video_stats stats;
    if(d->hook!=h)return;
    d->hook=NO_HOOK; /* The negative control must fail, never recurse forever. */
    CHECK(aa_video_status(d->owner,OWNER)==AA_VIDEO_E_REENTRANT);
    CHECK(aa_video_control_provider(d->owner,3,AA_CONTROL_MEDIA_EVENT,-31,0,7,&data,1)==AA_VIDEO_E_REENTRANT);
    CHECK(aa_video_step(d->owner,OWNER)==AA_VIDEO_E_REENTRANT);
    CHECK(aa_video_finish(d->owner,OWNER)==AA_VIDEO_E_REENTRANT);
    memset(&stats,0xc7,sizeof(stats));
    CHECK(aa_video_stats_get(d->owner,OWNER,&stats)==AA_VIDEO_E_REENTRANT);
    CHECK(stats.accepted_packets==0 && stats.queued_packets==0);
    CHECK(aa_video_stop(d->owner,OWNER)==AA_VIDEO_E_REENTRANT);
}
int aa_h264_start(aa_h264 *d){++d->starts;reentry(d,START_HOOK);d->held=d->eof=0;return d->start_result;}
int aa_h264_stop(aa_h264 *d){++d->stops;reentry(d,STOP_HOOK);d->held=d->eof=0;return d->stop_result;}
int aa_h264_retry(aa_h264 *d){
    ++d->retries;reentry(d,RETRY_HOOK);if(d->retry_result)return d->retry_result;
    if(d->held){if(d->held_retries){--d->held_retries;return AA_H264_PAUSED;}d->held=0;}
    return d->eof?AA_H264_FINISHED:AA_H264_OK;
}
int aa_h264_feed(aa_h264 *d,const uint8_t *data,size_t n,uint64_t timestamp,size_t *used){
    struct action *a;
    ++d->feeds;reentry(d,FEED_HOOK);
    CHECK(!d->held && !d->eof);CHECK(d->action_pos<d->action_count);
    a=&d->actions[d->action_pos++];
    CHECK(n==a->length);CHECK(timestamp==a->timestamp);CHECK(!memcmp(data,a->expected,n));
    *used=a->used;if(a->used<=n)d->accepted+=a->used;
    if(a->result==AA_H264_PAUSED)d->held=1;
    return a->result;
}
int aa_h264_finish(aa_h264 *d){
    ++d->finishes;reentry(d,FINISH_HOOK);d->eof=1;
    if(d->finish_hold){d->held=1;return AA_H264_PAUSED;}
    return AA_H264_FINISHED;
}
static void add(struct fixture *f,const uint8_t *p,size_t n,size_t used,uint64_t ts,int result){
    struct aa_h264 *d=&f->decoder;CHECK(d->action_count<MAX_ACTIONS);
    d->actions[d->action_count++]=(struct action){p,n,used,ts,result};
}
static int event(struct fixture *f,uint32_t e,int32_t s,uint32_t config){
    return aa_video_control_provider(f->owner,3,e,s,config,0,NULL,0);
}
static int media(struct fixture *f,int32_t s,uint64_t ts,const uint8_t *p,size_t n){
    return aa_video_control_provider(f->owner,3,AA_CONTROL_MEDIA_EVENT,s,0,ts,p,n);
}
static void init(struct fixture *f){
    memset(f,0,sizeof(*f));f->bytes=aa_video_context_bytes();
    f->allocation=malloc(f->bytes+16);CHECK(f->allocation!=NULL);
    memset(f->allocation,0xa5,f->bytes+16);f->owner=f->allocation+8;f->decoder.owner=f->owner;
    CHECK(aa_video_init(f->owner,OWNER,&f->decoder)==0);
}
static void begin(struct fixture *f,int32_t s){
    CHECK(event(f,AA_CONTROL_OPEN_EVENT,s,0)==0);
    CHECK(event(f,AA_CONTROL_SETUP_EVENT,s,0)==0);
    CHECK(event(f,AA_CONTROL_START_EVENT,s,0)==0);
}
static struct aa_video_stats stats(struct fixture *f){
    struct aa_video_stats st;CHECK(aa_video_stats_get(f->owner,OWNER,&st)==0);return st;
}
static void done(struct fixture *f){
    size_t i;CHECK(aa_video_stop(f->owner,OWNER)==0);
    for(i=0;i<8;++i){CHECK(f->allocation[i]==0xa5);CHECK(f->allocation[f->bytes+8+i]==0xa5);}
    free(f->allocation);
}
static void ownership(void){
    struct fixture f;struct aa_video_stats before,after;size_t i;
    uint8_t *source=malloc(SLOT_BYTES),*a=malloc(SLOT_BYTES),*b=malloc(SLOT_BYTES);
    category=OWNERSHIP;CHECK(source&&a&&b);init(&f);begin(&f,-31);
    for(i=0;i<SLOT_BYTES;++i){a[i]=(uint8_t)(i*37u+11u);b[i]=(uint8_t)(i*19u+73u);}
    memcpy(source,a,SLOT_BYTES);CHECK(media(&f,-31,UINT64_MAX-10,source,SLOT_BYTES)==0);
    memcpy(source,b,SLOT_BYTES);CHECK(media(&f,-31,UINT64_MAX-9,source,SLOT_BYTES)==0);
    memset(source,0xdd,SLOT_BYTES);before=stats(&f);
    CHECK(before.queued_packets==2 && before.accepted_packets==2 && before.accepted_bytes==2u*SLOT_BYTES);
    CHECK(f.decoder.feeds==0 && f.decoder.accepted==0); /* MEDIA owns, never decodes. */
    CHECK(media(&f,-31,998,source,SLOT_BYTES)==AA_VIDEO_PAUSED);after=stats(&f);
    CHECK(!memcmp(&before,&after,sizeof(before)));CHECK(f.decoder.feeds==0);
    CHECK(media(&f,-31,9,source,SLOT_BYTES+1u)==AA_VIDEO_E_ARGUMENT);
    CHECK(media(&f,-31,9,NULL,1)==AA_VIDEO_E_ARGUMENT);CHECK(media(&f,-31,9,source,0)==AA_VIDEO_E_ARGUMENT);
    add(&f,a,SLOT_BYTES,SLOT_BYTES,UINT64_MAX-10,AA_H264_OK);
    add(&f,b,SLOT_BYTES,SLOT_BYTES,UINT64_MAX-9,AA_H264_OK);
    CHECK(aa_video_finish(f.owner,OWNER)==AA_VIDEO_PAUSED && f.decoder.finishes==0);
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PROGRESS);after=stats(&f);CHECK(after.queued_packets==1);
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PROGRESS);after=stats(&f);
    CHECK(after.queued_packets==0 && after.fed_bytes==2u*SLOT_BYTES);
    CHECK(aa_video_step(f.owner,OWNER)==0 && f.decoder.feeds==2);
    CHECK(aa_video_finish(f.owner,OWNER)==AA_VIDEO_FINISHED);done(&f);free(source);free(a);free(b);
}
static void partial(void){
    struct fixture f;uint8_t p[17];struct aa_video_stats st;size_t i;
    category=PARTIAL;for(i=0;i<sizeof(p);++i)p[i]=(uint8_t)(13u+i);init(&f);begin(&f,4);
    CHECK(media(&f,4,998877,p,sizeof(p))==0);
    add(&f,p,17,3,998877,0);add(&f,p+3,14,0,998877,AA_H264_PAUSED);add(&f,p+3,14,14,998877,0);
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PROGRESS);st=stats(&f);
    CHECK(st.fed_bytes==3 && st.queued_packets==1);
    f.decoder.held_retries=1;CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PAUSED);
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PAUSED && f.decoder.feeds==2);
    st=stats(&f);CHECK(st.fed_bytes==3 && st.queued_packets==1);
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PROGRESS);st=stats(&f);
    CHECK(st.fed_bytes==17 && st.queued_packets==0 && f.decoder.accepted==17);
    CHECK(aa_video_step(f.owner,OWNER)==0 && f.decoder.feeds==3);done(&f);
}
static void paused(void){
    struct fixture f;uint8_t a[5]={2,4,6,8,10},b[3]={11,13,15};struct aa_video_stats st;
    category=PAUSE;init(&f);begin(&f,12);CHECK(media(&f,12,27,a,5)==0);CHECK(media(&f,12,28,b,3)==0);
    add(&f,a,5,5,27,AA_H264_PAUSED);add(&f,b,3,3,28,0);f.decoder.held_retries=2;
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PAUSED);st=stats(&f);
    CHECK(st.queued_packets==1 && st.fed_bytes==5);
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PAUSED);CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PAUSED);
    CHECK(f.decoder.feeds==1 && f.decoder.accepted==5);
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PROGRESS && f.decoder.feeds==2);
    st=stats(&f);CHECK(st.fed_bytes==8 && st.queued_packets==0);done(&f);
}
static void timestamp(void){
    struct fixture f;uint8_t p=0xfe;struct aa_video_stats st;
    category=TIMESTAMP;init(&f);begin(&f,INT32_MIN);
    CHECK(media(&f,INT32_MIN+1,77,&p,1)==AA_VIDEO_E_STATE);
    CHECK(media(&f,INT32_MIN,UINT64_MAX,&p,1)==0);add(&f,&p,1,1,UINT64_MAX,0);
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PROGRESS);st=stats(&f);
    CHECK(st.media_session==INT32_MIN && st.last_timestamp==UINT64_MAX && st.accepted_packets==1);
    CHECK(event(&f,AA_CONTROL_STOP_EVENT,INT32_MIN+1,0)==AA_VIDEO_E_STATE);done(&f);
}
static void invalid_used(void){
    struct fixture f;uint8_t p[2]={67,89};
    category=INVALID_USED;init(&f);begin(&f,8);CHECK(media(&f,8,37,p,2)==0);
    add(&f,p,2,3,37,0);CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_E_DECODER);
    CHECK(aa_video_decoder_detail(f.owner,OWNER)==AA_H264_ARGUMENT);
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_E_DECODER && f.decoder.feeds==1);
    CHECK(media(&f,8,38,p,2)==AA_VIDEO_E_DECODER);done(&f);
}
static void eof_held(void){
    struct fixture f;uint8_t p=5;struct aa_video_stats st;
    category=EOF_HELD;init(&f);begin(&f,9);f.decoder.finish_hold=1;f.decoder.held_retries=1;
    CHECK(aa_video_finish(f.owner,OWNER)==AA_VIDEO_PAUSED && f.decoder.finishes==1);
    CHECK(media(&f,9,1,&p,1)==AA_VIDEO_E_STATE);
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PAUSED);
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_FINISHED);
    CHECK(aa_video_finish(f.owner,OWNER)==AA_VIDEO_FINISHED && f.decoder.finishes==1);
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_FINISHED);st=stats(&f);
    CHECK(st.queued_packets==0 && f.decoder.feeds==0);done(&f);
}
static void lifecycle(void){
    struct fixture f;uint8_t old[4]={1,2,3,4},fresh[2]={19,23};struct aa_video_stats st;
    category=LIFECYCLE;init(&f);
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_E_STATE);
    CHECK(event(&f,AA_CONTROL_SETUP_EVENT,6,0)==AA_VIDEO_E_STATE);begin(&f,6);
    CHECK(media(&f,6,10,old,4)==0);CHECK(event(&f,AA_CONTROL_STOP_EVENT,6,0)==0);
    st=stats(&f);CHECK(st.queued_packets==0 && st.media_session==-1 && st.accepted_packets==1);
    CHECK(media(&f,6,10,old,4)==AA_VIDEO_E_STATE);CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_E_STATE);
    CHECK(event(&f,AA_CONTROL_START_EVENT,-31,0)==0 && f.decoder.starts==2);
    CHECK(media(&f,6,10,old,4)==AA_VIDEO_E_STATE);CHECK(media(&f,-31,45,fresh,2)==0);
    add(&f,fresh,2,2,45,0);CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PROGRESS);
    st=stats(&f);CHECK(st.accepted_packets==2 && st.accepted_bytes==6 && st.fed_bytes==2);
    CHECK(aa_video_status(f.owner,OWNER+1)==AA_VIDEO_E_SESSION);
    CHECK(aa_video_step(f.owner,OWNER+1)==AA_VIDEO_E_SESSION);
    CHECK(aa_video_stop(f.owner,OWNER+1)==AA_VIDEO_E_SESSION);
    CHECK(aa_video_stop(f.owner,OWNER)==0);CHECK(aa_video_status(f.owner,OWNER)==AA_VIDEO_E_STATE);
    CHECK(event(&f,AA_CONTROL_START_EVENT,-31,0)==AA_VIDEO_E_STATE);
    CHECK(aa_video_init(f.owner,OWNER+1,&f.decoder)==0);
    CHECK(aa_video_status(f.owner,OWNER)==AA_VIDEO_E_SESSION);
    CHECK(aa_video_status(f.owner,OWNER+1)==0);CHECK(aa_video_stop(f.owner,OWNER+1)==0);
    for(size_t i=0;i<8;++i){CHECK(f.allocation[i]==0xa5);CHECK(f.allocation[f.bytes+8+i]==0xa5);}free(f.allocation);
}
static void errors(void){
    struct fixture f;uint8_t p=7;
    category=ERRORS;init(&f);begin(&f,6);CHECK(media(&f,6,11,&p,1)==0);
    add(&f,&p,1,1,11,AA_H264_MALFORMED);CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_E_DECODER);
    CHECK(aa_video_decoder_detail(f.owner,OWNER)==AA_H264_MALFORMED);done(&f);
    init(&f);f.decoder.start_result=AA_H264_CODEC;
    CHECK(event(&f,AA_CONTROL_OPEN_EVENT,0,0)==0);CHECK(event(&f,AA_CONTROL_SETUP_EVENT,0,0)==0);
    CHECK(event(&f,AA_CONTROL_START_EVENT,0,0)==AA_VIDEO_E_DECODER);
    CHECK(aa_video_decoder_detail(f.owner,OWNER)==AA_H264_CODEC);done(&f);
    init(&f);begin(&f,3);f.decoder.retry_result=AA_H264_FINISHED;
    CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_E_DECODER);
    CHECK(aa_video_decoder_detail(f.owner,OWNER)==AA_H264_FINISHED);done(&f);
}
static void callback_guards(void){
    struct fixture f;uint8_t p=81;
    category=REENTRY;init(&f);f.decoder.hook=START_HOOK;begin(&f,-31);
    CHECK(media(&f,-31,80,&p,1)==0);add(&f,&p,1,1,80,0);
    f.decoder.hook=RETRY_HOOK;CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PROGRESS);
    CHECK(media(&f,-31,81,&p,1)==0);add(&f,&p,1,1,81,0);
    f.decoder.hook=FEED_HOOK;CHECK(aa_video_step(f.owner,OWNER)==AA_VIDEO_PROGRESS);
    f.decoder.hook=FINISH_HOOK;CHECK(aa_video_finish(f.owner,OWNER)==AA_VIDEO_FINISHED);
    f.decoder.hook=STOP_HOOK;CHECK(event(&f,AA_CONTROL_STOP_EVENT,-31,0)==0);done(&f);
    category=STOP_SERIAL;init(&f);begin(&f,-31);f.decoder.hook=STOP_HOOK;
    CHECK(aa_video_stop(f.owner,OWNER)==0 && f.decoder.stops==1);
    CHECK(aa_video_status(f.owner,OWNER)==AA_VIDEO_E_STATE);
    for(size_t i=0;i<8;++i){CHECK(f.allocation[i]==0xa5);CHECK(f.allocation[f.bytes+8+i]==0xa5);}free(f.allocation);
}
static void rgb(void){
    uint8_t y[8+6*4+8],u[8+4*2+8],v[8+5*2+8],out[8+11*4+8];
    aa_h264_frame f={0};size_t sizes[3]={22,6,7};size_t i,row,col;uint16_t white=0xffff;
    category=RGB_STRIDE;memset(y,0xc3,sizeof(y));memset(u,0xc4,sizeof(u));memset(v,0xc5,sizeof(v));
    memset(out,0xd2,sizeof(out));f.width=f.height=4;f.planes[0]=y+8;f.planes[1]=u+8;f.planes[2]=v+8;
    f.strides[0]=6;f.strides[1]=4;f.strides[2]=5;
    for(row=0;row<4;++row)for(col=0;col<4;++col)y[8+row*6+col]=row<2?16:235;
    for(row=0;row<2;++row)for(col=0;col<2;++col){u[8+row*4+col]=128;v[8+row*5+col]=128;}
    CHECK(aa_rgb565_render(&f,sizes,out+8,41,4,4,11,AA_RGB565_BT601,AA_RGB565_LIMITED)==0);
    for(row=0;row<4;++row){for(col=0;col<4;++col){
        uint16_t got=(uint16_t)(out[8+row*11+2*col]|(uint16_t)out[8+row*11+2*col+1]<<8);
        CHECK(got==(row<2?0:white));}for(col=8;col<11;++col)CHECK(out[8+row*11+col]==0xd2);}
    for(i=0;i<8;++i){CHECK(out[i]==0xd2);CHECK(out[8+44+i]==0xd2);CHECK(y[i]==0xc3);CHECK(y[8+24+i]==0xc3);
        CHECK(u[i]==0xc4);CHECK(u[8+8+i]==0xc4);CHECK(v[i]==0xc5);CHECK(v[8+10+i]==0xc5);}
    memset(out,0xd2,sizeof(out));CHECK(aa_rgb565_render(&f,sizes,out+8,6,1,2,4,AA_RGB565_BT709,AA_RGB565_LIMITED)==0);
    CHECK(out[8]==0 && out[9]==0 && out[12]==0xff && out[13]==0xff);
    CHECK(out[10]==0xd2 && out[11]==0xd2);
    category=RGB_REJECT;
#define REJECT(expr,expected) do { memset(out,0xd2,sizeof(out));CHECK((expr)==(expected)); \
    for(i=0;i<sizeof(out);++i)CHECK(out[i]==0xd2); } while(0)
    for(size_t plane=0;plane<3;++plane){--sizes[plane];REJECT(aa_rgb565_render(&f,sizes,out+8,41,4,4,11,1,0),AA_RGB565_E_CAPACITY);++sizes[plane];}
    REJECT(aa_rgb565_render(&f,sizes,out+8,40,4,4,11,1,0),AA_RGB565_E_CAPACITY);
    REJECT(aa_rgb565_render(&f,sizes,out+8,41,4,4,7,1,0),AA_RGB565_E_ARGUMENT);
    REJECT(aa_rgb565_render(&f,sizes,out+8,41,4,4,11,9,0),AA_RGB565_E_ARGUMENT);
    REJECT(aa_rgb565_render(&f,sizes,out+8,41,4,4,11,1,9),AA_RGB565_E_ARGUMENT);
    REJECT(aa_rgb565_render(&f,sizes,out+8,SIZE_MAX,4,4,SIZE_MAX,1,0),AA_RGB565_E_CAPACITY);
    f.strides[0]=SIZE_MAX;REJECT(aa_rgb565_render(&f,sizes,out+8,41,4,4,11,1,0),AA_RGB565_E_CAPACITY);f.strides[0]=6;
    f.strides[1]=1;REJECT(aa_rgb565_render(&f,sizes,out+8,41,4,4,11,1,0),AA_RGB565_E_ARGUMENT);f.strides[1]=4;
    f.planes[2]=NULL;REJECT(aa_rgb565_render(&f,sizes,out+8,41,4,4,11,1,0),AA_RGB565_E_ARGUMENT);f.planes[2]=v+8;
    f.width=3;REJECT(aa_rgb565_render(&f,sizes,out+8,41,4,4,11,1,0),AA_RGB565_E_ARGUMENT);
#undef REJECT
}
int main(void){
    ownership();partial();paused();timestamp();invalid_used();eof_held();lifecycle();errors();callback_guards();rgb();
    printf("{\"pass\":true,\"assertions\":%u,\"categories\":[",checks);
    for(unsigned i=0;i<CATEGORIES;++i)printf("%s{\"name\":\"%s\",\"assertions\":%u}",i?",":"",names[i],counts[i]);
    printf("],\"decoder_dependency\":\"synthetic_C_stub_no_decoding\",\"device_IO\":false}\n");return 0;
}
