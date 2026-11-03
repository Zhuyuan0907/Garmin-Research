/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "bootstrap.h"
#include "wire.h"
#include "message.h"
#include "tls.h"
#include <string.h>
#define MAGIC UINT32_C(0x41424231)
#define TLS_CHUNK 16382u
#define MAX_RX 32770u
#define WANT_READ (-0x6900)
#define WANT_WRITE (-0x6880)
struct bootstrap {
    uint32_t magic,session,deadline;
    uint16_t major,minor;
    int phase,error,detail,tls_complete,rx_pending;
    void *tls;
    struct aa_wire_parser wire;
    struct aa_message_parser message;
    uint8_t rx[MAX_RX],tx[TLS_CHUNK+6],record_header[5];
    size_t rx_bytes,tx_bytes,tx_offset,record_header_used,record_remaining;
    uint8_t rx_channel,rx_flags;
    int tx_kind;
};
uint32_t aa_bootstrap_context_bytes(void){return sizeof(struct bootstrap);}
static uint16_t read16(const uint8_t *p){return (uint16_t)(((uint16_t)p[0]<<8)|p[1]);}
static void write16(uint8_t *p,uint16_t n){p[0]=(uint8_t)(n>>8);p[1]=(uint8_t)n;}
static int valid(struct bootstrap *p,uint32_t session)
{
    if(!p || p->magic!=MAGIC)return AA_BOOT_E_STATE;
    if(!session || p->session!=session)return AA_BOOT_E_SESSION;
    return 0;
}
static void clear(struct bootstrap *p)
{
    memset(p->rx,0,sizeof(p->rx));memset(p->tx,0,sizeof(p->tx));
    memset(p->record_header,0,sizeof(p->record_header));
    memset(p->wire.storage,0,p->wire.capacity);
    memset(p->message.storage,0,p->message.capacity);
    p->rx_bytes=p->tx_bytes=p->tx_offset=p->record_header_used=p->record_remaining=0;
    p->rx_pending=0;
}
static int fail(struct bootstrap *p,int error,int detail)
{p->error=error;p->detail=detail;clear(p);return error;}
static void frame_output(struct bootstrap *p,uint16_t id,size_t body,int kind)
{
    p->tx[0]=0;p->tx[1]=AA_WIRE_BULK;
    write16(p->tx+2,(uint16_t)(body+2));write16(p->tx+4,id);
    p->tx_bytes=body+6;p->tx_offset=0;p->tx_kind=kind;
}
static int receive_message(void *arg,const struct aa_message_view *v)
{
    struct bootstrap *p=arg;
    if(p->rx_pending || v->bytes>sizeof(p->rx))return AA_MESSAGE_E_CAPACITY;
    if(v->bytes)memcpy(p->rx,v->payload,v->bytes);
    p->rx_bytes=v->bytes;p->rx_channel=v->channel;p->rx_flags=v->flags;
    p->rx_pending=1;return AA_MESSAGE_OK;
}
static int receive_frame(void *arg,const struct aa_wire_frame *f)
{
    struct bootstrap *p=arg;
    struct aa_message_fragment fragment;
    int accepted=0,r;
    fragment.channel=f->channel;fragment.flags=f->flags;
    fragment.total_plain_bytes=f->total_plain_bytes;
    fragment.payload=f->payload;fragment.bytes=f->payload_bytes;
    r=aa_message_push(&p->message,&fragment,&accepted);
    /* receive_message never pauses: accepting a wire frame is atomic here. */
    if(r || !accepted){p->detail=r?r:AA_MESSAGE_E_STATE;return AA_WIRE_E_CALLBACK;}
    return AA_WIRE_OK;
}
int aa_bootstrap_init(void *v,void *tls,uint32_t session,uint16_t major,uint16_t minor,
                      uint32_t now,uint32_t timeout,uint8_t *wire,size_t wire_capacity,
                      uint8_t *message,size_t message_capacity)
{
    struct bootstrap *p=v;
    int r;
    if(!p || ((uintptr_t)p&7u) || !tls || !session || !major || !timeout ||
       timeout>0x7fffffffu || !wire || !wire_capacity || wire_capacity>32768 ||
       !message || message_capacity<8 || message_capacity>MAX_RX)return AA_BOOT_E_ARGUMENT;
    if(p->magic)return AA_BOOT_E_STATE;
    if(aa_tls_status(tls,session)!=0)return AA_BOOT_E_TLS;
    memset(p,0,sizeof(*p));
    r=aa_message_init(&p->message,message,message_capacity,1024,receive_message,p);
    if(r)return AA_BOOT_E_ARGUMENT;
    r=aa_wire_init(&p->wire,wire,wire_capacity,receive_frame,p);
    if(r)return AA_BOOT_E_ARGUMENT;
    p->tls=tls;p->session=session;p->major=major;p->minor=minor;
    p->deadline=now+timeout;p->phase=AA_BOOT_VERSION_TX;p->magic=MAGIC;
    write16(p->tx+6,major);write16(p->tx+8,minor);frame_output(p,1,4,1);
    return AA_BOOT_OK;
}
int aa_bootstrap_feed(void *v,uint32_t session,const uint8_t *data,size_t n,size_t *consumed)
{
    struct bootstrap *p=v;
    size_t count;
    int r;
    if(consumed)*consumed=0;
    if(!consumed || (n && !data))return AA_BOOT_E_ARGUMENT;
    r=valid(p,session);if(r)return r;
    if(p->error)return p->error;
    if(p->phase==AA_BOOT_AUTH_READY)return AA_BOOT_READY;
    if(p->phase==AA_BOOT_STOPPED)return AA_BOOT_E_STATE;
    if(p->tx_bytes || p->rx_pending)return AA_BOOT_PAUSED;
    while(*consumed<n){
        r=aa_wire_feed(&p->wire,data+*consumed,1,&count);
        *consumed+=count;
        if(r)return fail(p,r==AA_WIRE_E_CALLBACK?AA_BOOT_E_MESSAGE:AA_BOOT_E_WIRE,
                         r==AA_WIRE_E_CALLBACK?p->detail:r);
        if(p->rx_pending)return AA_BOOT_PAUSED;
    }
    return AA_BOOT_OK;
}
/* Parse record headers across arbitrary SSL_HANDSHAKE envelope chunks. Reject
 * application-data records hidden in a handshake envelope, since their outer
 * channel/message metadata would otherwise be lost at receiver handoff. */
static int handshake_records(struct bootstrap *p,const uint8_t *data,size_t n)
{
    size_t i=0,used;
    while(i<n){
        if(p->record_remaining){
            used=p->record_remaining<n-i?p->record_remaining:n-i;
            p->record_remaining-=used;i+=used;continue;
        }
        while(p->record_header_used<5 && i<n)
            p->record_header[p->record_header_used++]=data[i++];
        if(p->record_header_used<5)break;
        if((p->record_header[0]!=20 && p->record_header[0]!=21 && p->record_header[0]!=22) ||
           p->record_header[1]!=3 || p->record_header[2]>3)return 0;
        p->record_remaining=read16(p->record_header+3);
        if(!p->record_remaining || p->record_remaining>18432)return 0;
        p->record_header_used=0;
    }
    return 1;
}
int aa_bootstrap_step(void *v,uint32_t session,uint32_t now)
{
    struct bootstrap *p=v;
    int r=valid(p,session),changed=0;
    if(r)return r;
    if(p->error)return p->error;
    if(p->phase==AA_BOOT_AUTH_READY)return AA_BOOT_READY;
    if(p->phase==AA_BOOT_STOPPED)return AA_BOOT_E_STATE;
    if((int32_t)(now-p->deadline)>=0)return fail(p,AA_BOOT_E_TIMEOUT,0);
    if(p->tx_bytes)return AA_BOOT_PAUSED;
    if(p->phase==AA_BOOT_WAIT_VERSION){
        if(!p->rx_pending)return AA_BOOT_PAUSED;
        if(p->rx_channel || p->rx_flags || p->rx_bytes!=8 || read16(p->rx)!=2)
            return fail(p,AA_BOOT_E_PROTOCOL,0);
        if(read16(p->rx+2)!=p->major || read16(p->rx+4)!=p->minor || read16(p->rx+6)!=0)
            return fail(p,AA_BOOT_E_VERSION,0);
        p->rx_pending=0;p->rx_bytes=0;memset(p->rx,0,sizeof(p->rx));
        p->phase=AA_BOOT_TLS;changed=1;
    }
    if(p->phase!=AA_BOOT_TLS)return AA_BOOT_E_STATE;
    if(p->rx_pending){
        if(p->rx_channel || p->rx_flags || p->rx_bytes<3 || read16(p->rx)!=3)
            return fail(p,AA_BOOT_E_PROTOCOL,0);
        if(!handshake_records(p,p->rx+2,p->rx_bytes-2))return fail(p,AA_BOOT_E_RECORD,0);
        r=aa_tls_feed(p->tls,session,p->rx+2,(uint32_t)(p->rx_bytes-2));
        if(r!=(int)p->rx_bytes-2)return fail(p,AA_BOOT_E_TLS,r);
        p->rx_pending=0;p->rx_bytes=0;memset(p->rx,0,sizeof(p->rx));changed=1;
    }
    if(!p->tls_complete){
        r=aa_tls_handshake(p->tls,session,now);
        if(r==1){
            if(aa_tls_verify_flags(p->tls,session)!=0)return fail(p,AA_BOOT_E_TLS,AA_TLS_BAD_STATE);
            p->tls_complete=1;
        }else if(r!=WANT_READ && r!=WANT_WRITE)return fail(p,AA_BOOT_E_TLS,r);
    }
    /* Always drain TLS output, even when the handshake just returned success. */
    r=aa_tls_take_out(p->tls,session,p->tx+6,TLS_CHUNK);
    if(r<0)return fail(p,AA_BOOT_E_TLS,r);
    if(r){frame_output(p,3,(size_t)r,3);return AA_BOOT_PROGRESS;}
    if(p->tls_complete){
        if(p->record_header_used || p->record_remaining)return fail(p,AA_BOOT_E_RECORD,0);
        p->tx[6]=8;p->tx[7]=0;frame_output(p,4,2,4);
        p->phase=AA_BOOT_AUTH_TX;return AA_BOOT_PROGRESS;
    }
    return changed?AA_BOOT_PROGRESS:AA_BOOT_PAUSED;
}
int aa_bootstrap_tx_peek(void *v,uint32_t session,const uint8_t **view,size_t *bytes)
{
    struct bootstrap *p=v;
    int r;
    if(view)*view=NULL;
    if(bytes)*bytes=0;
    if(!view || !bytes)return AA_BOOT_E_ARGUMENT;
    r=valid(p,session);if(r)return r;
    if(p->error)return p->error;
    if(p->phase==AA_BOOT_STOPPED)return AA_BOOT_E_STATE;
    if(p->tx_bytes){*view=p->tx+p->tx_offset;*bytes=p->tx_bytes-p->tx_offset;}
    return AA_BOOT_OK;
}
int aa_bootstrap_tx_commit(void *v,uint32_t session,size_t n,int status)
{
    struct bootstrap *p=v;
    int r=valid(p,session),kind;
    if(r)return r;
    if(p->error)return p->error;
    if(p->phase==AA_BOOT_STOPPED)return AA_BOOT_E_STATE;
    if(status)return fail(p,AA_BOOT_E_TRANSPORT,status);
    if(!p->tx_bytes || n>p->tx_bytes-p->tx_offset)return AA_BOOT_E_ARGUMENT;
    if(!n)return AA_BOOT_PAUSED;
    p->tx_offset+=n;
    if(p->tx_offset<p->tx_bytes)return AA_BOOT_PAUSED;
    kind=p->tx_kind;memset(p->tx,0,sizeof(p->tx));p->tx_bytes=p->tx_offset=0;
    if(kind==1)p->phase=AA_BOOT_WAIT_VERSION;
    if(kind==4){p->phase=AA_BOOT_AUTH_READY;return AA_BOOT_READY;}
    return AA_BOOT_OK;
}
int aa_bootstrap_status(void *v,uint32_t session)
{struct bootstrap *p=v;int r=valid(p,session);return r?r:(p->error?p->error:p->phase);}
int aa_bootstrap_error_detail(void *v,uint32_t session)
{struct bootstrap *p=v;int r=valid(p,session);return r?r:p->detail;}
int aa_bootstrap_finish(void *v,uint32_t session)
{
    struct bootstrap *p=v;int r=valid(p,session);
    if(r)return r;
    if(p->error)return p->error;
    if(p->phase==AA_BOOT_AUTH_READY)return AA_BOOT_READY;
    return fail(p,AA_BOOT_E_TRUNCATED,p->phase);
}
int aa_bootstrap_stop(void *v,uint32_t session)
{
    struct bootstrap *p=v;int r=valid(p,session);if(r)return r;
    clear(p);p->phase=AA_BOOT_STOPPED;return AA_BOOT_OK;
}
