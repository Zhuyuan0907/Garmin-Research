/* SPDX-License-Identifier: GPL-3.0-or-later
 * See framing.h, COPYING and provenance.json for upstream attribution.
 */
#include "framing.h"
#define FRAME_COLLECT 1u
#define FRAME_READY 2u
#define FRAME_FAILED 3u
#define MESSAGE_IDLE 1u
#define MESSAGE_COLLECT 2u
#define MESSAGE_READY 3u
#define MESSAGE_FAILED 4u
static uint32_t be16(const uint8_t *p) { return ((uint32_t)p[0]<<8)|p[1]; }
static uint32_t be32(const uint8_t *p)
{ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static void zero(void *p,uint32_t bytes)
{ uint32_t i;for (i=0;i<bytes;i++) ((uint8_t *)p)[i]=0; }
static int frame_fail(struct aa_frame_context *c,int reason)
{ c->state=FRAME_FAILED;c->failure=reason;return reason; }
static int message_fail(struct aa_message_context *c,int reason)
{ c->state=MESSAGE_FAILED;c->failure=reason;return reason; }
static int valid_pool(uint8_t *buffer,uint32_t capacity)
{ return buffer && capacity && capacity<=UINT32_MAX-(uintptr_t)buffer; }
int aa_frame_init(struct aa_frame_context *c,uint32_t session,uint8_t *buffer,uint32_t capacity)
{
    if (!c || !session || !valid_pool(buffer,capacity) || capacity>65535) return AA_E_ARGUMENT;
    zero(c,sizeof(*c));c->session=session;c->buffer=buffer;c->capacity=capacity;
    c->state=FRAME_COLLECT;c->header_needed=4;
    return AA_MORE;
}
int aa_frame_feed(struct aa_frame_context *c,const uint8_t *data,uint32_t bytes,uint32_t *consumed)
{
    uint32_t i,n;
    if (!consumed) return AA_E_ARGUMENT;
    *consumed=0;
    if (!c || (bytes && !data)) return AA_E_ARGUMENT;
    if (c->cancelled) return AA_E_CANCELLED;
    if (c->state==FRAME_FAILED) return c->failure;
    if (c->state==FRAME_READY) return AA_BUSY;
    if (c->state!=FRAME_COLLECT) return AA_E_STATE;
    for (;;) {
        while (c->header_used<c->header_needed && *consumed<bytes)
            c->header[c->header_used++]=data[(*consumed)++];
        if (c->header_used<c->header_needed) return AA_MORE;
        if (c->header_needed==4) {
            if (c->header[1]&0xf0) return frame_fail(c,AA_E_PROTOCOL);
            c->payload_bytes=be16(c->header+2);
            if (c->payload_bytes>c->capacity) return frame_fail(c,AA_E_BOUNDS);
            if ((c->header[1]&3)==AA_FIRST) { c->header_needed=8;continue; }
        }
        n=c->payload_bytes-c->payload_used;
        if (n>bytes-*consumed) n=bytes-*consumed;
        for (i=0;i<n;i++) c->buffer[c->payload_used+i]=data[*consumed+i];
        c->payload_used+=n;*consumed+=n;
        if (c->payload_used<c->payload_bytes) return AA_MORE;
        if (c->sequence==UINT32_MAX) return frame_fail(c,AA_E_SEQUENCE);
        c->sequence++;c->state=FRAME_READY;
        return AA_READY;
    }
}
int aa_frame_peek(const struct aa_frame_context *c,struct aa_frame_view *out)
{
    if (!c || !out) return AA_E_ARGUMENT;
    if (c->state!=FRAME_READY) return c->state==FRAME_FAILED?c->failure:AA_E_STATE;
    out->session=c->session;out->sequence=c->sequence;out->channel=c->header[0];out->flags=c->header[1];
    out->bytes=c->payload_bytes;out->total_plain_bytes=(c->header[1]&3)==AA_FIRST?be32(c->header+4):0;
    out->data=c->buffer;
    return AA_READY;
}
int aa_frame_release(struct aa_frame_context *c)
{
    if (!c) return AA_E_ARGUMENT;
    if (c->state!=FRAME_READY) return AA_E_STATE;
    if (c->cancelled) return frame_fail(c,AA_E_CANCELLED);
    c->state=FRAME_COLLECT;c->header_used=0;c->header_needed=4;c->payload_bytes=0;c->payload_used=0;
    return AA_MORE;
}
int aa_frame_cancel(struct aa_frame_context *c)
{
    if (!c) return AA_E_ARGUMENT;
    if (c->state!=FRAME_COLLECT && c->state!=FRAME_READY && c->state!=FRAME_FAILED) return AA_E_STATE;
    c->cancelled=1;
    if (c->state==FRAME_READY) return AA_E_CANCELLED;
    return frame_fail(c,AA_E_CANCELLED);
}
int aa_frame_encode(uint8_t *out,uint32_t capacity,uint32_t channel,uint32_t flags,
                    const uint8_t *data,uint32_t bytes,uint32_t total)
{
    uint32_t head=(flags&3)==AA_FIRST?8:4,i;
    if (!out || channel>255 || flags>15 || (bytes && !data) || bytes>65535 ||
        ((flags&3)!=AA_FIRST && total)) return AA_E_ARGUMENT;
    if (!(flags&AA_ENCRYPTED) && (flags&3)==AA_FIRST && total<bytes) return AA_E_PROTOCOL;
    if (capacity<bytes+head) return AA_E_BOUNDS;
    out[0]=(uint8_t)channel;out[1]=(uint8_t)flags;out[2]=(uint8_t)(bytes>>8);out[3]=(uint8_t)bytes;
    if (head==8) { out[4]=(uint8_t)(total>>24);out[5]=(uint8_t)(total>>16);out[6]=(uint8_t)(total>>8);out[7]=(uint8_t)total; }
    for (i=0;i<bytes;i++) out[head+i]=data[i];
    return (int)(head+bytes);
}
int aa_message_init(struct aa_message_context *c,uint32_t session,uint8_t *buffer,uint32_t capacity,uint32_t fragments)
{
    if (!c || !session || !valid_pool(buffer,capacity) || !fragments || fragments>1024) return AA_E_ARGUMENT;
    zero(c,sizeof(*c));c->session=session;c->buffer=buffer;c->capacity=capacity;c->max_fragments=fragments;
    c->state=MESSAGE_IDLE;
    return AA_MORE;
}
int aa_message_push(struct aa_message_context *c,const struct aa_frame_view *f)
{
    uint32_t kind,i;
    if (!c || !f || f->channel>255 || f->flags>15 || (f->bytes && !f->data)) return AA_E_ARGUMENT;
    if (c->cancelled) return AA_E_CANCELLED;
    if (c->state==MESSAGE_FAILED) return c->failure;
    if (c->state==MESSAGE_READY) return AA_BUSY;
    if (c->state!=MESSAGE_IDLE && c->state!=MESSAGE_COLLECT) return AA_E_STATE;
    if (f->flags&AA_ENCRYPTED) return AA_E_ENCRYPTED;
    if (c->last_sequence==UINT32_MAX) return message_fail(c,AA_E_SEQUENCE);
    if (c->session!=f->session || f->sequence!=c->last_sequence+1) return message_fail(c,AA_E_STALE);
    kind=f->flags&3;
    if (c->state==MESSAGE_IDLE) {
        if (kind!=AA_FIRST && kind!=AA_BULK) return message_fail(c,AA_E_PROTOCOL);
        c->channel=f->channel;c->flags=f->flags&AA_CONTROL;
        c->total=kind==AA_FIRST?f->total_plain_bytes:f->bytes;
        if (c->total>c->capacity) return message_fail(c,AA_E_BOUNDS);
    } else if ((kind!=AA_MIDDLE && kind!=AA_LAST) || f->channel!=c->channel ||
               (f->flags&AA_CONTROL)!=c->flags) return message_fail(c,AA_E_PROTOCOL);
    if (kind!=AA_FIRST && f->total_plain_bytes) return message_fail(c,AA_E_PROTOCOL);
    if (c->fragments==c->max_fragments) return message_fail(c,AA_E_FRAGMENTS);
    if (f->bytes>c->total-c->bytes) return message_fail(c,AA_E_BOUNDS);
    if ((kind==AA_LAST || kind==AA_BULK) && c->bytes+f->bytes!=c->total) return message_fail(c,AA_E_PROTOCOL);
    for (i=0;i<f->bytes;i++) c->buffer[c->bytes+i]=f->data[i];
    c->bytes+=f->bytes;c->fragments++;c->last_sequence=f->sequence;
    c->state=(kind==AA_LAST || kind==AA_BULK)?MESSAGE_READY:MESSAGE_COLLECT;
    return c->state==MESSAGE_READY?AA_READY:AA_MORE;
}
int aa_message_peek(const struct aa_message_context *c,struct aa_message_view *out)
{
    if (!c || !out) return AA_E_ARGUMENT;
    if (c->state!=MESSAGE_READY) return c->state==MESSAGE_FAILED?c->failure:AA_E_STATE;
    out->session=c->session;out->sequence=c->last_sequence;out->channel=c->channel;out->flags=c->flags;
    out->bytes=c->bytes;out->data=c->buffer;
    return AA_READY;
}
int aa_message_release(struct aa_message_context *c)
{
    if (!c) return AA_E_ARGUMENT;
    if (c->state!=MESSAGE_READY) return AA_E_STATE;
    if (c->cancelled) return message_fail(c,AA_E_CANCELLED);
    c->state=MESSAGE_IDLE;c->total=0;c->bytes=0;c->fragments=0;
    return AA_MORE;
}
int aa_message_cancel(struct aa_message_context *c)
{
    if (!c) return AA_E_ARGUMENT;
    if (c->state<MESSAGE_IDLE || c->state>MESSAGE_FAILED) return AA_E_STATE;
    c->cancelled=1;
    if (c->state==MESSAGE_READY) return AA_E_CANCELLED;
    return message_fail(c,AA_E_CANCELLED);
}
uint32_t aa_frame_context_bytes(void) { return sizeof(struct aa_frame_context); }
uint32_t aa_frame_view_bytes(void) { return sizeof(struct aa_frame_view); }
uint32_t aa_message_context_bytes(void) { return sizeof(struct aa_message_context); }
uint32_t aa_message_view_bytes(void) { return sizeof(struct aa_message_view); }
