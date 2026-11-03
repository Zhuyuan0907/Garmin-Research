/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "message.h"
#define MESSAGE_MAGIC UINT32_C(0x4d534731)
#define IDLE 1
#define COLLECT 2
#define PENDING 3
#define FAILED 4
#define CLOSED 5
static int valid(const struct aa_message_parser *p)
{ return p && p->initialized==MESSAGE_MAGIC; }
static int fail(struct aa_message_parser *p,int why)
{ p->state=FAILED;p->error=why;return why; }
static void idle(struct aa_message_parser *p)
{
    p->state=IDLE;p->bytes=0;p->total_plain_bytes=0;p->fragments=0;
    p->channel=0;p->flags=0;
}
static int publish(struct aa_message_parser *p)
{
    struct aa_message_view view;
    int result;
    view.channel=p->channel;view.flags=p->flags;view.fragments=p->fragments;
    view.bytes=p->bytes;view.payload=p->storage;
    p->in_callback=1;
    result=p->callback(p->callback_arg,&view);
    p->in_callback=0;p->callback_status=result;
    if(result==AA_MESSAGE_PAUSED)return AA_MESSAGE_PAUSED;
    if(result!=AA_MESSAGE_OK)return fail(p,AA_MESSAGE_E_CALLBACK);
    idle(p);
    return AA_MESSAGE_OK;
}
int aa_message_init(struct aa_message_parser *p,uint8_t *storage,size_t capacity,
                    uint32_t max_fragments,aa_message_callback callback,void *arg)
{
    struct aa_message_parser fresh={0};
    if(!p || !callback || !max_fragments || capacity>UINT32_MAX ||
       (capacity && !storage))return AA_MESSAGE_E_ARGUMENT;
    fresh.storage=storage;fresh.capacity=capacity;fresh.max_fragments=max_fragments;
    fresh.callback=callback;fresh.callback_arg=arg;fresh.initialized=MESSAGE_MAGIC;
    *p=fresh;idle(p);return AA_MESSAGE_OK;
}
int aa_message_push(struct aa_message_parser *p,const struct aa_message_fragment *f,
                    int *accepted)
{
    uint32_t total, kind;uint8_t properties;size_t i;
    if(!accepted)return AA_MESSAGE_E_ARGUMENT;
    *accepted=0;
    if(!valid(p))return AA_MESSAGE_E_ARGUMENT;
    if(p->in_callback)return AA_MESSAGE_E_REENTRANT;
    if(p->state==FAILED)return p->error;
    if(p->state==PENDING)return AA_MESSAGE_PAUSED;
    if(p->state!=IDLE && p->state!=COLLECT)return AA_MESSAGE_E_STATE;
    if(!f || (f->bytes && !f->payload))return AA_MESSAGE_E_ARGUMENT;
    if(f->flags & 0xf0u)return fail(p,AA_MESSAGE_E_FLAGS);
    kind=f->flags & 3u;properties=f->flags & 12u;
    if(kind!=AA_MESSAGE_FIRST && f->total_plain_bytes)
        return fail(p,AA_MESSAGE_E_LENGTH);
    if(p->state==IDLE){
        if(kind!=AA_MESSAGE_FIRST && kind!=AA_MESSAGE_BULK)
            return fail(p,AA_MESSAGE_E_SEQUENCE);
        if(f->bytes>p->capacity)return fail(p,AA_MESSAGE_E_CAPACITY);
        total=kind==AA_MESSAGE_FIRST ? f->total_plain_bytes : (uint32_t)f->bytes;
        if(total>p->capacity)return fail(p,AA_MESSAGE_E_CAPACITY);
        if(f->bytes>total)return fail(p,AA_MESSAGE_E_LENGTH);
    }else{
        if((kind!=AA_MESSAGE_MIDDLE && kind!=AA_MESSAGE_LAST) ||
           f->channel!=p->channel || properties!=p->flags)
            return fail(p,AA_MESSAGE_E_SEQUENCE);
        total=p->total_plain_bytes;
        if(f->bytes>(size_t)total-p->bytes)return fail(p,AA_MESSAGE_E_LENGTH);
    }
    if(p->fragments>=p->max_fragments)return fail(p,AA_MESSAGE_E_FRAGMENTS);
    if(kind==AA_MESSAGE_LAST && f->bytes!=(size_t)total-p->bytes)
        return fail(p,AA_MESSAGE_E_LENGTH);
    /* Every rejection above precedes copying or accepting this fragment. */
    if(p->state==IDLE){
        p->channel=f->channel;p->flags=properties;p->total_plain_bytes=total;
    }
    for(i=0;i<f->bytes;++i)p->storage[p->bytes+i]=f->payload[i];
    p->bytes+=f->bytes;++p->fragments;*accepted=1;
    if(kind==AA_MESSAGE_LAST || kind==AA_MESSAGE_BULK){
        p->state=PENDING;return publish(p);
    }
    p->state=COLLECT;return AA_MESSAGE_OK;
}
int aa_message_retry(struct aa_message_parser *p)
{
    if(!valid(p))return AA_MESSAGE_E_ARGUMENT;
    if(p->in_callback)return AA_MESSAGE_E_REENTRANT;
    if(p->state==FAILED)return p->error;
    if(p->state==IDLE)return AA_MESSAGE_OK;
    if(p->state!=PENDING)return AA_MESSAGE_E_STATE;
    return publish(p);
}
int aa_message_finish(struct aa_message_parser *p)
{
    if(!valid(p))return AA_MESSAGE_E_ARGUMENT;
    if(p->in_callback)return AA_MESSAGE_E_REENTRANT;
    if(p->state==FAILED)return p->error;
    if(p->state==PENDING)return AA_MESSAGE_PAUSED;
    if(p->state==COLLECT)return fail(p,AA_MESSAGE_E_TRUNCATED);
    if(p->state==CLOSED)return AA_MESSAGE_OK;
    if(p->state!=IDLE)return AA_MESSAGE_E_STATE;
    p->state=CLOSED;return AA_MESSAGE_OK;
}
int aa_message_reset(struct aa_message_parser *p)
{
    if(!valid(p))return AA_MESSAGE_E_ARGUMENT;
    if(p->in_callback)return AA_MESSAGE_E_REENTRANT;
    idle(p);p->error=0;p->callback_status=0;return AA_MESSAGE_OK;
}
