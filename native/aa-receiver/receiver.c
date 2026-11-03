/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "receiver.h"
#include "wire.h"
#include "tls.h"
#include <string.h>
#define RX_MAGIC UINT32_C(0x41525831)
#define QUEUE_SIZE 2u
#define FRAME_CAPACITY 32768u
#define WANT_READ (-0x6900)
#define WANT_WRITE (-0x6880)
struct queued_frame {
    uint8_t channel,flags;
    uint16_t bytes;
    uint32_t total;
    uint8_t data[FRAME_CAPACITY];
};
struct receiver {
    uint32_t magic,session;
    int closed,error,detail,in_step,message_paused,allow_plaintext;
    void *tls;
    struct aa_wire_parser wire;
    struct aa_message_parser message;
    struct queued_frame queue[QUEUE_SIZE];
    size_t head,count,decoded;
    int fed,ready;
    uint8_t *plain;
    size_t plain_capacity;
};
uint32_t aa_receiver_context_bytes(void){return sizeof(struct receiver);}
static int valid(struct receiver *p,uint32_t session)
{
    if(!p || p->magic!=RX_MAGIC)return AA_RECEIVER_E_STATE;
    if(!session || p->session!=session)return AA_RECEIVER_E_SESSION;
    if(p->in_step)return AA_RECEIVER_E_REENTRANT;
    return 0;
}
static void clear_owned(struct receiver *p)
{
    memset(p->queue,0,sizeof(p->queue));
    memset(p->plain,0,p->plain_capacity);
    memset(p->wire.storage,0,p->wire.capacity);
    if(p->message.capacity)memset(p->message.storage,0,p->message.capacity);
    p->head=p->count=p->decoded=0;
    p->fed=p->ready=p->message_paused=0;
}
static int fail(struct receiver *p,int error,int detail)
{
    p->error=error;p->detail=detail;clear_owned(p);return error;
}
static int enqueue(void *arg,const struct aa_wire_frame *frame)
{
    struct receiver *p=arg;
    struct queued_frame *q;
    if(p->count==QUEUE_SIZE)return AA_WIRE_PAUSED;
    q=&p->queue[(p->head+p->count)%QUEUE_SIZE];
    q->channel=frame->channel;q->flags=frame->flags;
    q->bytes=frame->payload_bytes;q->total=frame->total_plain_bytes;
    if(q->bytes)memcpy(q->data,frame->payload,q->bytes);
    ++p->count;return AA_WIRE_OK;
}
int aa_receiver_init(void *v,void *tls,uint32_t session,
                     uint8_t *wire,size_t wire_capacity,
                     uint8_t *plain,size_t plain_capacity,
                     uint8_t *message,size_t message_capacity,
                     uint32_t max_fragments,aa_message_callback callback,void *arg,
                     int allow_plaintext)
{
    struct receiver *p=v;
    int r;
    if(!p || ((uintptr_t)p&7u) || !session || !tls || !wire || !wire_capacity ||
       wire_capacity>FRAME_CAPACITY || !plain || plain_capacity<wire_capacity ||
       plain_capacity>FRAME_CAPACITY || !callback ||
       (allow_plaintext!=0 && allow_plaintext!=1))return AA_RECEIVER_E_ARGUMENT;
    if(p->magic)return AA_RECEIVER_E_STATE;
    if(aa_tls_status(tls,session)!=1)return AA_RECEIVER_E_TLS;
    memset(p,0,sizeof(*p));
    r=aa_message_init(&p->message,message,message_capacity,max_fragments,callback,arg);
    if(r)return AA_RECEIVER_E_ARGUMENT;
    r=aa_wire_init(&p->wire,wire,wire_capacity,enqueue,p);
    if(r)return AA_RECEIVER_E_ARGUMENT;
    p->tls=tls;p->session=session;p->plain=plain;p->plain_capacity=plain_capacity;
    p->allow_plaintext=allow_plaintext;p->magic=RX_MAGIC;return AA_RECEIVER_OK;
}
int aa_receiver_feed(void *v,uint32_t session,const uint8_t *data,size_t n,size_t *consumed)
{
    struct receiver *p=v;
    int r;
    if(consumed)*consumed=0;
    r=valid(p,session);if(r)return r;
    if(p->error)return p->error;
    if(p->closed)return AA_RECEIVER_E_STATE;
    r=aa_wire_feed(&p->wire,data,n,consumed);
    if(r==AA_WIRE_OK)return AA_RECEIVER_OK;
    if(r==AA_WIRE_PAUSED)return AA_RECEIVER_PAUSED;
    if(r==AA_WIRE_E_ARGUMENT || r==AA_WIRE_E_REENTRANT)
        return r==AA_WIRE_E_REENTRANT?AA_RECEIVER_E_REENTRANT:AA_RECEIVER_E_ARGUMENT;
    return fail(p,AA_RECEIVER_E_WIRE,r);
}
static int records_complete(const uint8_t *data,size_t n)
{
    size_t position=0,length;
    while(position<n){
        if(n-position<5 || data[position]!=23 || data[position+1]!=3 || data[position+2]!=3)
            return 0;
        length=((size_t)data[position+3]<<8)|data[position+4];
        if(!length || length>n-position-5)return 0;
        position+=5+length;
    }
    return 1;
}
static int process(struct receiver *p)
{
    struct queued_frame *q;
    struct aa_message_fragment fragment;
    int r,accepted=0;
    size_t remaining;
    uint8_t extra;
    if(p->message_paused){
        r=aa_message_retry(&p->message);
        if(r==AA_MESSAGE_PAUSED)return AA_RECEIVER_PAUSED;
        if(r)return fail(p,AA_RECEIVER_E_MESSAGE,r);
        p->message_paused=0;
        return AA_RECEIVER_PROGRESS;
    }
    if(!p->count)return AA_RECEIVER_OK;
    q=&p->queue[p->head];
    if(!p->ready){
        if(q->flags&AA_WIRE_ENCRYPTED){
            if(!p->fed){
                if(!records_complete(q->data,q->bytes))return fail(p,AA_RECEIVER_E_RECORD,0);
                if(aa_tls_status(p->tls,p->session)!=1)return fail(p,AA_RECEIVER_E_TLS,AA_TLS_BAD_STATE);
                r=aa_tls_feed(p->tls,p->session,q->data,q->bytes);
                if(r!=(int)q->bytes)return fail(p,AA_RECEIVER_E_TLS,r);
                p->fed=1;
            }
            if(q->bytes){
                for(;;){
                    remaining=p->plain_capacity-p->decoded;
                    r=aa_tls_read(p->tls,p->session,remaining?p->plain+p->decoded:&extra,
                                  remaining>16384?16384:(remaining?(uint32_t)remaining:1));
                    if(r==WANT_WRITE)return AA_RECEIVER_PAUSED;
                    if(r==WANT_READ)break;
                    if(r<=0)return fail(p,AA_RECEIVER_E_TLS,r);
                    if((size_t)r>remaining)return fail(p,AA_RECEIVER_E_CAPACITY,0);
                    p->decoded+=(size_t)r;
                }
            }
        }else{
            if(!p->allow_plaintext)return fail(p,AA_RECEIVER_E_POLICY,0);
            if(q->bytes)memcpy(p->plain,q->data,q->bytes);
            p->decoded=q->bytes;
        }
        p->ready=1;
    }
    fragment.channel=q->channel;fragment.flags=q->flags;
    fragment.total_plain_bytes=q->total;fragment.payload=p->plain;fragment.bytes=p->decoded;
    r=aa_message_push(&p->message,&fragment,&accepted);
    if(accepted){
        memset(q,0,sizeof(*q));memset(p->plain,0,p->decoded);
        p->head=(p->head+1)%QUEUE_SIZE;--p->count;
        p->decoded=0;p->fed=p->ready=0;
    }
    if(r==AA_MESSAGE_PAUSED){p->message_paused=1;return AA_RECEIVER_PAUSED;}
    if(r)return fail(p,AA_RECEIVER_E_MESSAGE,r);
    return AA_RECEIVER_PROGRESS;
}
int aa_receiver_step(void *v,uint32_t session)
{
    struct receiver *p=v;
    int r=valid(p,session);
    if(r)return r;
    if(p->error)return p->error;
    if(p->closed)return AA_RECEIVER_E_STATE;
    p->in_step=1;r=process(p);p->in_step=0;return r;
}
int aa_receiver_finish(void *v,uint32_t session)
{
    struct receiver *p=v;
    int r=valid(p,session);
    if(r)return r;
    if(p->error)return p->error;
    if(p->closed)return AA_RECEIVER_OK;
    if(p->count || p->message_paused)return AA_RECEIVER_PAUSED;
    r=aa_wire_finish(&p->wire);
    if(r==AA_WIRE_PAUSED)return AA_RECEIVER_PAUSED;
    if(r)return fail(p,AA_RECEIVER_E_WIRE,r);
    r=aa_message_finish(&p->message);
    if(r)return fail(p,AA_RECEIVER_E_MESSAGE,r);
    p->closed=1;return AA_RECEIVER_OK;
}
int aa_receiver_stop(void *v,uint32_t session)
{
    struct receiver *p=v;
    int r=valid(p,session);if(r)return r;
    clear_owned(p);p->closed=1;return AA_RECEIVER_OK;
}
int aa_receiver_status(void *v,uint32_t session)
{
    struct receiver *p=v;int r=valid(p,session);
    return r?r:(p->error?p->error:(p->closed?3:0));
}
int aa_receiver_error_detail(void *v,uint32_t session)
{
    struct receiver *p=v;int r=valid(p,session);return r?r:p->detail;
}
int aa_receiver_queued(void *v,uint32_t session)
{
    struct receiver *p=v;int r=valid(p,session);return r?r:(int)p->count;
}
