/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "video.h"
#include "control.h"
#include <string.h>
#define MAGIC 0x41565131u
#define PACKET_BYTES 262144u
#define SLOTS 2u
struct packet { size_t bytes,offset;uint64_t timestamp;uint8_t data[PACKET_BYTES]; };
struct video {
    uint32_t magic,session,head,count;
    aa_h264 *decoder;
    int error,detail,busy,opened,configured,streaming,ended,closed,focused,finish_requested;
    int32_t media_session;
    uint64_t accepted_packets,accepted_bytes,fed_bytes,last_timestamp;
    struct packet slots[SLOTS];
};
static void zero(void *p,size_t n){volatile uint8_t *b=p;while(n--)*b++=0;}
static int valid(struct video *v,uint32_t s){
    if(!v||v->magic!=MAGIC)return AA_VIDEO_E_ARGUMENT;
    if(v->session!=s)return AA_VIDEO_E_SESSION;
    if(v->busy)return AA_VIDEO_E_REENTRANT;
    if(v->error)return v->error;
    if(v->closed)return AA_VIDEO_E_STATE;
    return 0;
}
static int fail(struct video *v,int r){
    v->detail=r;v->error=AA_VIDEO_E_DECODER;zero(v->slots,sizeof(v->slots));v->count=0;
    return v->error;
}
static int start(struct video *v,int32_t s){
    int r;v->busy=1;r=aa_h264_start(v->decoder);v->busy=0;
    if(r)return fail(v,r);
    zero(v->slots,sizeof(v->slots));v->head=v->count=0;v->media_session=s;
    v->streaming=1;v->ended=0;v->finish_requested=0;return 0;
}
uint32_t aa_video_context_bytes(void){return sizeof(struct video);}
int aa_video_init(void *p,uint32_t s,aa_h264 *decoder){
    struct video *v=p;
    if(!v||!s||!decoder)return AA_VIDEO_E_ARGUMENT;
    memset(v,0,sizeof(*v));v->magic=MAGIC;v->session=s;v->decoder=decoder;
    v->media_session=-1;return 0;
}
int aa_video_control_provider(void *p,uint8_t ch,uint32_t event,int32_t session,
                             uint32_t config,uint64_t timestamp,const uint8_t *data,size_t n){
    struct video *v=p;int r=valid(v,v?v->session:0);struct packet *q;
    if(r)return r;
    if(ch!=3||config>2)return AA_VIDEO_E_PROTOCOL;
    switch(event){
    case AA_CONTROL_OPEN_EVENT:
        if(v->opened)return AA_VIDEO_E_STATE;
        v->opened=1;return 0;
    case AA_CONTROL_SETUP_EVENT:
        if(!v->opened||v->streaming||config!=0)return AA_VIDEO_E_STATE;
        v->configured=1;return 0;
    case AA_CONTROL_START_EVENT:
        if(!v->configured||v->streaming||config!=0)return AA_VIDEO_E_STATE;
        return start(v,session);
    case AA_CONTROL_STOP_EVENT:
        if(!v->streaming||session!=v->media_session)return AA_VIDEO_E_STATE;
        v->busy=1;r=aa_h264_stop(v->decoder);v->busy=0;
        if(r)return fail(v,r);
        zero(v->slots,sizeof(v->slots));v->head=v->count=0;v->streaming=v->ended=0;
        v->media_session=-1;v->finish_requested=0;return 0;
    case AA_CONTROL_VIDEO_FOCUS_EVENT:
        if(!v->configured||(config!=1&&config!=2))return AA_VIDEO_E_STATE;
        v->focused=config==1;return 0;
    case AA_CONTROL_MEDIA_EVENT:
        if(!v->streaming||v->ended||v->finish_requested||session!=v->media_session||config!=0)return AA_VIDEO_E_STATE;
        if(!data||!n||n>PACKET_BYTES)return AA_VIDEO_E_ARGUMENT;
        if(v->count==SLOTS)return AA_VIDEO_PAUSED; /* No acceptance / side effect. */
        if(v->accepted_packets==UINT64_MAX||n>UINT64_MAX-v->accepted_bytes)return AA_VIDEO_E_STATE;
        q=&v->slots[(v->head+v->count)%SLOTS];q->bytes=n;q->offset=0;q->timestamp=timestamp;
        memcpy(q->data,data,n);v->count++;v->accepted_packets++;v->accepted_bytes+=n;
        return 0;
    default:return AA_VIDEO_E_PROTOCOL;
    }
}
int aa_video_step(void *p,uint32_t s){
    struct video *v=p;struct packet *q;size_t used=0,remaining;int r=valid(v,s);
    if(r)return r;
    if(!v->streaming)return AA_VIDEO_E_STATE;
    if(v->ended)return AA_VIDEO_FINISHED;
    v->busy=1;r=aa_h264_retry(v->decoder);v->busy=0;
    if(r==AA_H264_PAUSED)return AA_VIDEO_PAUSED;
    if(r==AA_H264_FINISHED){
        if(v->count||!v->finish_requested)return fail(v,AA_H264_FINISHED);
        v->ended=1;return AA_VIDEO_FINISHED;
    }
    if(r)return fail(v,r);
    if(!v->count)return AA_VIDEO_OK;
    q=&v->slots[v->head];remaining=q->bytes-q->offset;
    v->busy=1;r=aa_h264_feed(v->decoder,q->data+q->offset,remaining,q->timestamp,&used);v->busy=0;
    if(used>remaining)return fail(v,AA_H264_ARGUMENT);
    q->offset+=used;v->fed_bytes+=used;v->last_timestamp=q->timestamp;
    if(r!=AA_H264_OK&&r!=AA_H264_PAUSED)return fail(v,r);
    if(q->offset==q->bytes){zero(q,sizeof(*q));v->head=(v->head+1)%SLOTS;v->count--;}
    return r==AA_H264_PAUSED?AA_VIDEO_PAUSED:AA_VIDEO_PROGRESS;
}
int aa_video_finish(void *p,uint32_t s){
    struct video *v=p;int r=valid(v,s);if(r)return r;
    if(!v->streaming)return AA_VIDEO_E_STATE;
    if(v->ended)return AA_VIDEO_FINISHED;
    if(v->count)return AA_VIDEO_PAUSED;
    v->finish_requested=1;
    v->busy=1;r=aa_h264_finish(v->decoder);v->busy=0;
    if(r==AA_H264_PAUSED)return AA_VIDEO_PAUSED;
    if(r!=AA_H264_OK&&r!=AA_H264_FINISHED)return fail(v,r);
    v->ended=1;return AA_VIDEO_FINISHED;
}
int aa_video_stats_get(void *p,uint32_t s,struct aa_video_stats *out){
    struct video *v=p;int r=valid(v,s);
    if(!out)return AA_VIDEO_E_ARGUMENT;
    memset(out,0,sizeof(*out));if(r)return r;
    out->accepted_packets=v->accepted_packets;out->accepted_bytes=v->accepted_bytes;
    out->fed_bytes=v->fed_bytes;out->last_timestamp=v->last_timestamp;
    out->media_session=v->media_session;out->queued_packets=v->count;return 0;
}
int aa_video_status(void *p,uint32_t s){return valid(p,s);}
int aa_video_decoder_detail(void *p,uint32_t s){
    struct video *v=p;
    if(!v||v->magic!=MAGIC)return AA_VIDEO_E_ARGUMENT;
    if(v->session!=s)return AA_VIDEO_E_SESSION;
    return v->detail;
}
int aa_video_stop(void *p,uint32_t s){
    struct video *v=p;int r;
    if(!v||v->magic!=MAGIC)return AA_VIDEO_E_ARGUMENT;
    if(v->session!=s)return AA_VIDEO_E_SESSION;
    if(v->busy)return AA_VIDEO_E_REENTRANT;
    v->busy=1;r=aa_h264_stop(v->decoder);v->busy=0;
    zero(v->slots,sizeof(v->slots));v->count=0;v->closed=1;v->streaming=0;
    return r?AA_VIDEO_E_DECODER:0;
}
