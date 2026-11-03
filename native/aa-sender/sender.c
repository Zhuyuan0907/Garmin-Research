/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "sender.h"
#include "tls.h"
#include <string.h>
#define MAGIC 0x41535431u
#define WANT_READ (-0x6900)
#define WANT_WRITE (-0x6880)
enum { IDLE=0, WRITING=1, TX_READY=2, COMMITTED=3, STOPPED=4 };
struct sender {
    uint32_t magic, session, token;
    void *tls;
    int phase, error, detail, busy, write_started;
    uint8_t channel, flags;
    size_t plain_n, cipher_n, wire_n, wire_offset;
    uint8_t plain[8192], wire[16384];
};
static void zero(void *p,size_t n){volatile uint8_t *b=p;while(n--)*b++=0;}
static int valid(struct sender *s,uint32_t id){
    if(!s||s->magic!=MAGIC)return AA_SENDER_E_ARGUMENT;
    if(id!=s->session)return AA_SENDER_E_SESSION;
    if(s->busy)return AA_SENDER_E_REENTRANT;
    if(s->error)return s->error;
    if(s->phase==STOPPED)return AA_SENDER_E_STATE;
    return 0;
}
static int fail(struct sender *s,int e,int detail){
    zero(s->plain,sizeof(s->plain));zero(s->wire,sizeof(s->wire));
    s->wire_n=s->wire_offset=s->cipher_n=s->plain_n=0;
    s->error=e;s->detail=detail;return e;
}
static int records(const uint8_t *p,size_t n){
    size_t i=0, len;
    if(!n)return 0;
    while(i<n){
        if(n-i<5||p[i]!=23||p[i+1]!=3||p[i+2]!=3)return 0;
        len=((size_t)p[i+3]<<8)|p[i+4];
        if(!len||len>18432||len>n-i-5)return 0;
        i+=5+len;
    }
    return 1;
}
uint32_t aa_sender_context_bytes(void){return sizeof(struct sender);}
int aa_sender_init(void *p,void *tls,uint32_t session){
    struct sender *s=p;
    if(!s||!tls||!session)return AA_SENDER_E_ARGUMENT;
    if(aa_tls_status(tls,session)!=1||aa_tls_verify_flags(tls,session))return AA_SENDER_E_TLS;
    if(aa_tls_pending_bytes(tls,session))return AA_SENDER_E_TLS;
    memset(s,0,sizeof(*s));s->magic=MAGIC;s->session=session;s->tls=tls;
    return 0;
}
int aa_sender_submit(void *p,uint32_t id,const struct aa_message_view *v,uint32_t token){
    struct sender *s=p;int r=valid(s,id),n;
    if(r)return r;
    if(s->phase!=IDLE)return AA_SENDER_E_STATE;
    if(!v||!v->payload||v->bytes<2||v->bytes>sizeof(s->plain)||!token||
       (v->flags&~(AA_MESSAGE_CONTROL|AA_MESSAGE_ENCRYPTED)))return AA_SENDER_E_ARGUMENT;
    if(aa_tls_pending_bytes(s->tls,id))return fail(s,AA_SENDER_E_TLS,AA_TLS_BUSY);
    /* Reject undrained handshake/receiver output; never silently give it a
     * control-message channel label. Errors abandon this TLS session. */
    n=aa_tls_take_out(s->tls,id,s->wire,sizeof(s->wire));
    if(n)return fail(s,AA_SENDER_E_TLS,n);
    memcpy(s->plain,v->payload,v->bytes);s->plain_n=v->bytes;
    s->channel=v->channel;s->flags=v->flags;s->token=token;
    s->phase=WRITING;return 0;
}
int aa_sender_step(void *p,uint32_t id){
    struct sender *s=p;int r=valid(s,id),n,pending;size_t room;
    if(r)return r;
    if(s->phase==COMMITTED)return AA_SENDER_DONE;
    if(s->phase==IDLE)return 0;
    if(s->phase==TX_READY)return AA_SENDER_PAUSED;
    if(!(s->flags&AA_MESSAGE_ENCRYPTED)){
        memcpy(s->wire+4,s->plain,s->plain_n);s->cipher_n=s->plain_n;
    }else{
        s->busy=1;
        if(!s->write_started){
            n=aa_tls_write(s->tls,id,s->plain,(uint32_t)s->plain_n);
            s->write_started=1;
        }else n=aa_tls_retry_write(s->tls,id);
        s->busy=0;
        if(n<0&&n!=WANT_READ&&n!=WANT_WRITE)return fail(s,AA_SENDER_E_TLS,n);
        room=sizeof(s->wire)-4-s->cipher_n;
        if(!room)return fail(s,AA_SENDER_E_CAPACITY,0);
        r=aa_tls_take_out(s->tls,id,s->wire+4+s->cipher_n,(uint32_t)room);
        if(r<0)return fail(s,AA_SENDER_E_TLS,r);
        s->cipher_n+=(size_t)r;
        pending=aa_tls_pending_bytes(s->tls,id);
        if(pending<0)return fail(s,AA_SENDER_E_TLS,pending);
        if(pending)return n==0||n==WANT_READ?AA_SENDER_PAUSED:AA_SENDER_PROGRESS;
        if(!records(s->wire+4,s->cipher_n))return fail(s,AA_SENDER_E_RECORD,0);
    }
    s->wire[0]=s->channel;s->wire[1]=AA_MESSAGE_BULK|s->flags;
    s->wire[2]=(uint8_t)(s->cipher_n>>8);s->wire[3]=(uint8_t)s->cipher_n;
    s->wire_n=s->cipher_n+4;s->wire_offset=0;s->phase=TX_READY;
    zero(s->plain,sizeof(s->plain));s->plain_n=0;
    return AA_SENDER_PROGRESS;
}
int aa_sender_tx_peek(void *p,uint32_t id,const uint8_t **view,size_t *n){
    struct sender *s=p;int r=valid(s,id);
    if(!view||!n)return AA_SENDER_E_ARGUMENT;
    *view=0;*n=0;
    if(r)return r;
    if(s->phase==TX_READY){*view=s->wire+s->wire_offset;*n=s->wire_n-s->wire_offset;}
    return 0;
}
int aa_sender_tx_commit(void *p,uint32_t id,size_t n,int transport_status){
    struct sender *s=p;int r=valid(s,id);if(r)return r;
    if(s->phase!=TX_READY)return AA_SENDER_E_STATE;
    if(transport_status)return fail(s,AA_SENDER_E_TRANSPORT,transport_status);
    if(n>s->wire_n-s->wire_offset)return AA_SENDER_E_ARGUMENT;
    if(!n)return AA_SENDER_PAUSED;
    s->wire_offset+=n;
    if(s->wire_offset<s->wire_n)return AA_SENDER_PAUSED;
    zero(s->wire,sizeof(s->wire));s->wire_n=s->wire_offset=0;s->phase=COMMITTED;
    return AA_SENDER_DONE;
}
int aa_sender_token(void *p,uint32_t id,uint32_t *token){
    struct sender *s=p;int r=valid(s,id);
    if(!token)return AA_SENDER_E_ARGUMENT;
    *token=0;if(r)return r;
    if(s->phase==IDLE)return AA_SENDER_E_STATE;
    *token=s->token;return 0;
}
int aa_sender_release(void *p,uint32_t id,uint32_t token){
    struct sender *s=p;int r=valid(s,id);if(r)return r;
    if(s->phase!=COMMITTED||token!=s->token)return AA_SENDER_E_STATE;
    s->phase=IDLE;s->token=0;s->write_started=0;s->cipher_n=0;return 0;
}
int aa_sender_status(void *p,uint32_t id){
    struct sender *s=p;int r=valid(s,id);if(r)return r;
    return s->phase==COMMITTED?AA_SENDER_DONE:s->phase==IDLE?0:AA_SENDER_PAUSED;
}
int aa_sender_error_detail(void *p,uint32_t id){
    struct sender *s=p;if(!s||s->magic!=MAGIC)return AA_SENDER_E_ARGUMENT;
    if(id!=s->session)return AA_SENDER_E_SESSION;
    return s->detail;
}
int aa_sender_stop(void *p,uint32_t id){
    struct sender *s=p;
    if(!s||s->magic!=MAGIC)return AA_SENDER_E_ARGUMENT;
    if(id!=s->session)return AA_SENDER_E_SESSION;
    if(s->busy)return AA_SENDER_E_REENTRANT;
    zero(s->plain,sizeof(s->plain));zero(s->wire,sizeof(s->wire));
    s->wire_n=s->plain_n=s->cipher_n=s->wire_offset=0;s->phase=STOPPED;s->error=0;
    return 0;
}
