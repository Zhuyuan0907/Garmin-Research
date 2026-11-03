/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "audio.h"
#include "control.h"
#include <string.h>
#define MAGIC UINT32_C(0x41415043)
enum { OFFERED=0,OPEN=1,SETUP=2,STREAMING=3 };
struct slot { size_t bytes,offset; uint64_t timestamp; uint8_t data[AA_AUDIO_PACKET_CAPACITY]; };
struct route {
    uint32_t phase,head,count;
    int32_t media_session;
    int error,eof,finished;
    struct slot slots[2];
    uint8_t carry[4],output[AA_AUDIO_OUTPUT_CAPACITY];
    size_t carry_n,output_n,output_offset;
    uint64_t carry_ts,output_ts,stream_frame_offset;
    uint32_t output_focus;
    struct aa_audio_stats stats;
};
struct context {
    uint32_t magic,session,alive,busy,next,focus;
    struct aa_audio_config config;
    aa_audio_pcm_backend backend;
    void *arg;
    struct route routes[3];
};
uint32_t aa_audio_context_bytes(void){return (uint32_t)sizeof(struct context);}
static int get(void *p,uint32_t session,struct context **out){
    struct context *c=p;
    if(!c || (uintptr_t)c%8 || c->magic!=MAGIC)return AA_AUDIO_E_ARGUMENT;
    if(c->session!=session)return AA_AUDIO_E_SESSION;
    if(c->busy)return AA_AUDIO_E_REENTRANT;
    if(!c->alive)return AA_AUDIO_E_STATE;
    *out=c;return AA_AUDIO_OK;
}
static int index_of(struct context *c,uint8_t channel){
    if(channel<4 || channel>6)return -1;
    return (c->config.enabled_mask&(1U<<(channel-4)))?(int)channel-4:-1;
}
int aa_audio_init(void *p,uint32_t session,const struct aa_audio_config *cfg,aa_audio_pcm_backend backend,void *arg){
    struct context *c=p;unsigned i;
    if(!c || (uintptr_t)c%8 || !session || !cfg || !backend || !cfg->enabled_mask || cfg->enabled_mask>7 ||
       !cfg->packet_bytes_limit || cfg->packet_bytes_limit>AA_AUDIO_PACKET_CAPACITY ||
       cfg->output_bytes_limit<4 || cfg->output_bytes_limit>AA_AUDIO_OUTPUT_CAPACITY || cfg->output_bytes_limit%4 ||
       cfg->focus_policy>AA_AUDIO_FOCUS_GATE || (cfg->focus_grant_mask&~30U))return AA_AUDIO_E_ARGUMENT;
    if(c->magic==MAGIC && (c->busy || c->alive))return c->busy?AA_AUDIO_E_REENTRANT:AA_AUDIO_E_STATE;
    memset(c,0,sizeof(*c));c->magic=MAGIC;c->session=session;c->alive=1;c->config=*cfg;c->backend=backend;c->arg=arg;
    for(i=0;i<3;++i)c->routes[i].media_session=-1;
    return AA_AUDIO_OK;
}
static int route_error(struct route *r,int error){r->error=error;return error;}
static void discard(struct route *r){
    uint64_t bytes=r->carry_n+r->output_n-r->output_offset;unsigned i;
    for(i=0;i<r->count;++i){struct slot *s=&r->slots[(r->head+i)%2];bytes+=s->bytes-s->offset;}
    r->stats.discarded_bytes+=bytes;
    r->head=r->count=0;r->carry_n=r->output_n=r->output_offset=0;r->error=r->eof=r->finished=0;
    r->stream_frame_offset=0;
}
int aa_audio_control_provider(void *p,uint8_t channel,uint32_t event,int32_t media_session,
                              uint32_t config,uint64_t timestamp,const uint8_t *data,size_t bytes){
    struct context *c=p;struct route *r;int i,err;
    if(!c || (uintptr_t)c%8 || c->magic!=MAGIC)return AA_AUDIO_E_ARGUMENT;
    err=get(p,c->session,&c);if(err)return err;
    if(channel==0){
        if(event!=AA_CONTROL_AUDIO_FOCUS_EVENT || data || bytes || config<1 || config>4)return AA_AUDIO_E_PROTOCOL;
        if(!(c->config.focus_grant_mask&(1U<<config)))return AA_AUDIO_E_FOCUS;
        c->focus=config;return AA_AUDIO_OK;
    }
    i=index_of(c,channel);if(i<0)return AA_AUDIO_E_PROTOCOL;r=&c->routes[i];
    if(event==AA_CONTROL_STOP_EVENT){
        if(data || bytes || config || r->phase!=STREAMING)return AA_AUDIO_E_STATE;
        if(media_session!=r->media_session)return AA_AUDIO_E_SESSION;
        discard(r);r->phase=SETUP;r->media_session=-1;return AA_AUDIO_OK;
    }
    if(r->error)return r->error;
    switch(event){
    case AA_CONTROL_OPEN_EVENT:
        if(r->phase!=OFFERED)return AA_AUDIO_E_STATE;
        if(bytes && !data)return AA_AUDIO_E_PROTOCOL;
        /* Caller control has already parsed this callback-local OPEN payload.
         * Do not retain its pointer or re-parse a different protobuf policy. */
        r->phase=OPEN;return AA_AUDIO_OK;
    case AA_CONTROL_SETUP_EVENT:
        if(data || bytes || config || r->phase!=OPEN)return AA_AUDIO_E_STATE;
        r->phase=SETUP;return AA_AUDIO_OK;
    case AA_CONTROL_START_EVENT:
        if(data || bytes || config || r->phase!=SETUP)return AA_AUDIO_E_STATE;
        discard(r);r->media_session=media_session;r->phase=STREAMING;return AA_AUDIO_OK;
    case AA_CONTROL_MEDIA_EVENT:{
        struct slot *s;
        if(r->phase!=STREAMING || r->eof || config)return AA_AUDIO_E_STATE;
        if(media_session!=r->media_session)return AA_AUDIO_E_SESSION;
        if(!data || !bytes)return AA_AUDIO_E_PROTOCOL;
        if(bytes>c->config.packet_bytes_limit)return AA_AUDIO_E_CAPACITY;
        if(r->count==2)return AA_AUDIO_PAUSED;
        s=&r->slots[(r->head+r->count)%2];memcpy(s->data,data,bytes);s->bytes=bytes;s->offset=0;s->timestamp=timestamp;
        ++r->count;++r->stats.accepted_packets;r->stats.accepted_bytes+=bytes;r->stats.last_timestamp=timestamp;
        return AA_AUDIO_OK;
    }
    default:return AA_AUDIO_E_PROTOCOL;
    }
}
static int allowed(const struct context *c,unsigned i){
    if(c->config.focus_policy==AA_AUDIO_FOCUS_NOTIFY_ONLY)return 1;
    if(c->focus==1)return 1;
    return (c->focus==2 || c->focus==3) && i!=0;
}
static int eof_status(struct route *r){
    if(!r->eof || r->count || r->output_n)return AA_AUDIO_OK;
    if(r->carry_n)return route_error(r,AA_AUDIO_E_TRUNCATED);
    r->finished=1;return AA_AUDIO_FINISHED;
}
static int work_route(struct context *c,unsigned i){
    struct route *r=&c->routes[i];size_t block=i?2:4,n,ready;uint64_t last_ts;
    struct aa_audio_pcm_view view;size_t consumed=0;int result;
    if(r->error)return r->error;
    if(r->phase!=STREAMING)return AA_AUDIO_OK;
    if(!allowed(c,i))return (r->count || r->output_n || r->carry_n)?AA_AUDIO_PAUSED:eof_status(r);
    if(!r->output_n){
        n=r->carry_n;last_ts=r->carry_ts;r->output_ts=r->carry_ts;r->output_focus=c->focus;
        if(n)memcpy(r->output,r->carry,n);
        r->carry_n=0;
        while(n<c->config.output_bytes_limit && r->count){
            struct slot *s=&r->slots[r->head];size_t take=s->bytes-s->offset;
            if(take>c->config.output_bytes_limit-n)take=c->config.output_bytes_limit-n;
            if(!n)r->output_ts=s->timestamp;
            if(n%block==0 || (n+take-1)/block>n/block)last_ts=s->timestamp;
            memcpy(r->output+n,s->data+s->offset,take);n+=take;s->offset+=take;r->stats.assembled_bytes+=take;
            if(s->offset==s->bytes){r->head=(r->head+1)%2;--r->count;}
        }
        ready=n-n%block;r->carry_n=n-ready;r->carry_ts=last_ts;
        if(r->carry_n)memset(r->carry,0,r->carry_n);
        r->output_n=ready;r->output_offset=0;
        if(!ready)return eof_status(r);
    }
    memset(&view,0,sizeof(view));view.data=r->output+r->output_offset;view.bytes=r->output_n-r->output_offset;view.frames=view.bytes/block;
    view.sample_rate=i?16000:48000;view.channels=i?1:2;view.bit_depth=16;view.channel=(uint8_t)(i+4);
    view.media_session=r->media_session;view.focus_type=r->output_focus;view.timestamp=r->output_ts;view.frame_offset=r->stream_frame_offset;
    result=c->backend(c->arg,&view,&consumed);
    if(consumed>view.bytes || consumed%block)return route_error(r,AA_AUDIO_E_BACKEND);
    r->output_offset+=consumed;r->stream_frame_offset+=consumed/block;r->stats.backend_bytes+=consumed;r->stats.backend_frames+=consumed/block;
    if(r->output_offset==r->output_n)r->output_n=r->output_offset=0;
    if(result!=AA_AUDIO_OK && result!=AA_AUDIO_PAUSED)return route_error(r,AA_AUDIO_E_BACKEND);
    if(result==AA_AUDIO_PAUSED || !consumed)return AA_AUDIO_PAUSED;
    if(r->output_n)return AA_AUDIO_PROGRESS;
    result=eof_status(r);return result==AA_AUDIO_OK?AA_AUDIO_PROGRESS:result;
}
int aa_audio_step(void *p,uint32_t session){
    struct context *c;unsigned offset;int result=AA_AUDIO_OK,blocked=0,err=get(p,session,&c);if(err)return err;
    c->busy=1;
    for(offset=0;offset<3;++offset){unsigned i=(c->next+offset)%3;struct route *r=&c->routes[i];
        if(!(c->config.enabled_mask&(1U<<i)) || r->phase!=STREAMING || r->finished)continue;
        if(!r->count && !r->output_n && !r->eof)continue;
        result=work_route(c,i);
        if(result==AA_AUDIO_PAUSED){blocked=1;continue;}
        if(result!=AA_AUDIO_OK){c->next=(i+1)%3;c->busy=0;return result;}
    }
    c->busy=0;return blocked?AA_AUDIO_PAUSED:AA_AUDIO_OK;
}
int aa_audio_retry(void *p,uint32_t session){return aa_audio_step(p,session);}
int aa_audio_finish(void *p,uint32_t session,uint8_t channel){
    struct context *c;struct route *r;int i,err=get(p,session,&c);if(err)return err;
    i=index_of(c,channel);if(i<0)return AA_AUDIO_E_PROTOCOL;r=&c->routes[i];
    if(r->error)return r->error;
    if(r->phase!=STREAMING)return AA_AUDIO_E_STATE;
    r->eof=1;
    if(r->count || r->output_n)return AA_AUDIO_PAUSED;
    return eof_status(r);
}
int aa_audio_stats_get(void *p,uint32_t session,uint8_t channel,struct aa_audio_stats *stats){
    struct context *c;struct route *r;unsigned j;int i,err=get(p,session,&c);if(err)return err;
    if(!stats)return AA_AUDIO_E_ARGUMENT;
    i=index_of(c,channel);if(i<0)return AA_AUDIO_E_PROTOCOL;r=&c->routes[i];
    *stats=r->stats;stats->queued_packets=r->count;stats->queued_bytes=0;
    for(j=0;j<r->count;++j){struct slot *s=&r->slots[(r->head+j)%2];stats->queued_bytes+=(uint32_t)(s->bytes-s->offset);}
    stats->pending_bytes=(uint32_t)(r->output_n-r->output_offset);stats->carry_bytes=(uint32_t)r->carry_n;
    stats->media_session=r->media_session;stats->focus_type=c->focus;stats->streaming=r->phase==STREAMING;
    stats->finished=r->finished;stats->error=r->error;return AA_AUDIO_OK;
}
int aa_audio_status(void *p,uint32_t session){struct context *c;unsigned i;int err=get(p,session,&c);if(err)return err;
    for(i=0;i<3;++i)if(c->routes[i].error)return c->routes[i].error;
    return AA_AUDIO_OK;}
int aa_audio_stop(void *p,uint32_t session){
    struct context *c;unsigned i;int err=get(p,session,&c);if(err)return err;
    for(i=0;i<3;++i){discard(&c->routes[i]);c->routes[i].phase=OFFERED;c->routes[i].media_session=-1;}
    c->alive=0;return AA_AUDIO_OK;
}
