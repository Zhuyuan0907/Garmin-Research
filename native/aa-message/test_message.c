/* SPDX-License-Identifier: GPL-3.0-or-later
 * Meaningful host-only literal, ownership, sequence and capacity controls.
 */
#include "message.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned long assertions;
static unsigned categories;
#define CHECK(x) do { ++assertions; if(!(x)){fprintf(stderr,"FAIL:%s:%d:%s\n",__FILE__,__LINE__,#x);exit(2);} }while(0)
#define CATEGORY(n) do{++categories;printf("PASS %s\n",n);}while(0)
struct expected {uint8_t channel,flags;uint32_t fragments;size_t bytes;const uint8_t *payload;};
struct sink {const struct expected *expected;size_t count,accepted,attempts;unsigned pauses;int error,reenter;const uint8_t *paused;struct aa_message_parser *parser;};
static int callback(void *arg,const struct aa_message_view *v)
{
    struct sink *s=arg;const struct expected *e;int accepted=99;
    ++s->attempts;CHECK(s->accepted<s->count);e=s->expected+s->accepted;
    CHECK(v->channel==e->channel);CHECK(v->flags==e->flags);
    CHECK(v->fragments==e->fragments);CHECK(v->bytes==e->bytes);
    CHECK(!e->bytes || memcmp(v->payload,e->payload,e->bytes)==0);
    if(s->reenter){
        CHECK(aa_message_push(s->parser,NULL,&accepted)==AA_MESSAGE_E_REENTRANT);CHECK(accepted==0);
        CHECK(aa_message_retry(s->parser)==AA_MESSAGE_E_REENTRANT);
        CHECK(aa_message_finish(s->parser)==AA_MESSAGE_E_REENTRANT);
        CHECK(aa_message_reset(s->parser)==AA_MESSAGE_E_REENTRANT);
    }
    if(s->error)return s->error;
    if(s->pauses){
        if(s->paused)CHECK(v->payload==s->paused);
        s->paused=v->payload;--s->pauses;return AA_MESSAGE_PAUSED;
    }
    s->paused=NULL;++s->accepted;return AA_MESSAGE_OK;
}
static void setup(struct aa_message_parser *p,uint8_t *storage,size_t capacity,uint32_t limit,
                  struct sink *s,const struct expected *e,size_t count)
{
    memset(s,0,sizeof(*s));s->expected=e;s->count=count;s->parser=p;
    CHECK(aa_message_init(p,storage,capacity,limit,callback,s)==AA_MESSAGE_OK);
}
static struct aa_message_fragment frag(uint8_t c,uint8_t flags,uint32_t total,const uint8_t *data,size_t bytes)
{struct aa_message_fragment f={c,flags,total,data,bytes};return f;}
static void push(struct aa_message_parser *p,struct aa_message_fragment f)
{int accepted=99;CHECK(aa_message_push(p,&f,&accepted)==AA_MESSAGE_OK);CHECK(accepted==1);}
static void reject(struct aa_message_parser *p,struct aa_message_fragment f,int why)
{
    int accepted=99;CHECK(aa_message_push(p,&f,&accepted)==why);CHECK(accepted==0);
    CHECK(aa_message_push(p,NULL,&accepted)==why);CHECK(accepted==0);
    CHECK(aa_message_retry(p)==why);CHECK(aa_message_finish(p)==why);
}
static uint32_t rng(uint32_t *s){*s=*s*UINT32_C(1664525)+UINT32_C(1013904223);return *s;}
static void literal_tests(void)
{
    struct aa_message_parser p;struct sink s;uint8_t store[16];
    static const uint8_t full[]={0,1,0xaa,0xbb,0xcc,0xdd};
    struct expected e={0,4,1,6,full};setup(&p,store,16,10,&s,&e,1);
    push(&p,frag(0,7,0,full,6));CHECK(s.accepted==1);
    CHECK(aa_message_finish(&p)==AA_MESSAGE_OK);CATEGORY("literal-bulk-complete-message");
    static const uint8_t a[]={0,1},b[]={0xaa,0xbb},c[]={0xcc,0xdd};
    e=(struct expected){7,12,3,6,full};setup(&p,store,16,10,&s,&e,1);
    push(&p,frag(7,13,6,a,2));CHECK(s.attempts==0);
    push(&p,frag(7,12,0,b,2));CHECK(s.attempts==0);
    push(&p,frag(7,14,0,c,2));CHECK(s.accepted==1);
    CATEGORY("literal-first-middle-last-and-origin-flags");
    e=(struct expected){255,8,2,6,full};setup(&p,store,6,2,&s,&e,1);
    push(&p,frag(255,9,6,full,6));CHECK(s.attempts==0);
    push(&p,frag(255,10,0,NULL,0));CHECK(s.accepted==1);
    CATEGORY("empty-last-after-first-contains-whole-plaintext");
    e.fragments=3;setup(&p,store,6,3,&s,&e,1);
    push(&p,frag(255,9,6,full,2));push(&p,frag(255,8,0,full+2,4));
    CHECK(s.attempts==0);push(&p,frag(255,10,0,NULL,0));CHECK(s.accepted==1);
    CATEGORY("middle-reaches-total-before-empty-last");
    e=(struct expected){0,0,1,0,NULL};setup(&p,NULL,0,1,&s,&e,1);
    push(&p,frag(0,3,0,NULL,0));CHECK(s.accepted==1);CATEGORY("empty-bulk-allowed-with-no-storage");
    e=(struct expected){1,12,2,0,NULL};setup(&p,NULL,0,2,&s,&e,1);
    push(&p,frag(1,13,0,NULL,0));CHECK(s.attempts==0);
    push(&p,frag(1,14,0,NULL,0));CHECK(s.accepted==1);CATEGORY("empty-first-last-allowed");
    static const uint8_t one[]={0xaa};e=(struct expected){5,0,1,1,one};
    setup(&p,store,1,1,&s,&e,1);push(&p,frag(5,3,0,one,1));CHECK(s.accepted==1);
    CATEGORY("one-byte-message-dispatcher-checks-id-separately");
}
static void fragmentation_tests(void)
{
    static const uint8_t text[]={0,4,1,2,3,4,5,6,7,8,9,10,11,12,13};
    uint8_t store[17];struct aa_message_parser p;struct sink s;size_t a,b;
    const struct expected e={9,12,3,sizeof(text),text};
    for(a=0;a<=sizeof(text);++a)for(b=a;b<=sizeof(text);++b){
        memset(store,0xa5,sizeof(store));setup(&p,store+1,sizeof(text),3,&s,&e,1);
        push(&p,frag(9,13,sizeof(text),text,a));CHECK(s.attempts==0);
        push(&p,frag(9,12,0,text+a,b-a));CHECK(s.attempts==0);
        push(&p,frag(9,14,0,text+b,sizeof(text)-b));CHECK(s.accepted==1);
        CHECK(store[0]==0xa5 && store[16]==0xa5);
    }
    CATEGORY("every-first-middle-last-plaintext-split-including-empty-parts");
    uint32_t seed=UINT32_C(0x35617f91);uint8_t payload[257];size_t m,i,k,n,left,offset,lens[9];
    struct expected er;
    for(m=0;m<100;++m){
        for(i=0;i<sizeof(payload);++i)payload[i]=(uint8_t)rng(&seed);
        n=2+rng(&seed)%8;left=15;offset=0;
        for(k=0;k<n-1;++k){lens[k]=rng(&seed)%(left+1);left-=lens[k];}lens[n-1]=left;
        er=(struct expected){(uint8_t)rng(&seed),(uint8_t)(rng(&seed)&12u),(uint32_t)n,15,payload};
        setup(&p,store+1,15,9,&s,&er,1);
        for(k=0;k<n;++k){
            uint8_t kind=k==0?1:(k==n-1?2:0);
            push(&p,frag(er.channel,(uint8_t)(kind|er.flags),k==0?15:0,payload+offset,lens[k]));
            offset+=lens[k];CHECK(s.attempts==(k==n-1?1u:0u));
        }
        CHECK(s.accepted==1);CHECK(aa_message_finish(&p)==AA_MESSAGE_OK);
    }
    CATEGORY("fixed-seed-multi-message-fragment-patterns-and-properties");
    const size_t len=131072;uint8_t *original=malloc(len),*bigstore=malloc(len+2);
    CHECK(original && bigstore);memset(bigstore,0xa5,len+2);
    for(i=0;i<len;++i)original[i]=(uint8_t)(i*31+13);
    er=(struct expected){3,8,3,len,original};setup(&p,bigstore+1,len,3,&s,&er,1);
    push(&p,frag(3,9,(uint32_t)len,original,60000));CHECK(s.attempts==0);
    push(&p,frag(3,8,0,original+60000,60000));CHECK(s.attempts==0);
    push(&p,frag(3,10,0,original+120000,len-120000));CHECK(s.accepted==1);
    CHECK(bigstore[0]==0xa5 && bigstore[len+1]==0xa5);
    free(original);free(bigstore);CATEGORY("128k-message-larger-than-one-wire-frame");
}
static void ownership_tests(void)
{
    struct aa_message_parser p;struct sink s;uint8_t store[6],temporary[3];int accepted;
    static const uint8_t original[]={0,1,10,20,30,40};
    struct expected e={2,12,2,6,original};setup(&p,store,6,2,&s,&e,1);
    memcpy(temporary,original,3);push(&p,frag(2,13,6,temporary,3));memset(temporary,0xee,3);
    CHECK(s.attempts==0);memcpy(temporary,original+3,3);s.pauses=2;
    struct aa_message_fragment last=frag(2,14,0,temporary,3);
    CHECK(aa_message_push(&p,&last,&accepted)==AA_MESSAGE_PAUSED);CHECK(accepted==1);
    memset(temporary,0xee,3);CHECK(s.accepted==0);CHECK(s.attempts==1);
    CHECK(aa_message_finish(&p)==AA_MESSAGE_PAUSED);CHECK(s.attempts==1);
    /* New input isn't inspected: NULL is legal only because it is unaccepted
     * while complete delivery is pending. No same-LAST resend occurs. */
    CHECK(aa_message_push(&p,NULL,&accepted)==AA_MESSAGE_PAUSED);CHECK(accepted==0);
    CHECK(aa_message_retry(&p)==AA_MESSAGE_PAUSED);CHECK(s.attempts==2);
    CHECK(aa_message_retry(&p)==AA_MESSAGE_OK);CHECK(s.accepted==1);CHECK(s.attempts==3);
    CHECK(aa_message_retry(&p)==AA_MESSAGE_OK);CHECK(s.attempts==3);
    CHECK(aa_message_finish(&p)==AA_MESSAGE_OK);
    CATEGORY("copied-fragments-survive-input-reuse-and-owned-pending-retry");
    e=(struct expected){2,0,1,0,NULL};setup(&p,NULL,0,1,&s,&e,1);s.pauses=1;
    struct aa_message_fragment empty=frag(2,3,0,NULL,0);
    CHECK(aa_message_push(&p,&empty,&accepted)==AA_MESSAGE_PAUSED);CHECK(accepted==1);
    CHECK(aa_message_retry(&p)==AA_MESSAGE_OK);CHECK(s.accepted==1);
    CATEGORY("empty-message-backpressure");
    e=(struct expected){2,0,1,6,original};setup(&p,store,6,2,&s,&e,1);s.reenter=1;
    push(&p,frag(2,3,0,original,6));CHECK(s.accepted==1);
    CATEGORY("callback-reentry-push-retry-finish-reset-rejected");
    setup(&p,store,6,2,&s,&e,1);s.error=-77;
    struct aa_message_fragment bulk=frag(2,3,0,original,6);
    CHECK(aa_message_push(&p,&bulk,&accepted)==AA_MESSAGE_E_CALLBACK);CHECK(accepted==1);
    CHECK(p.callback_status==-77);CHECK(s.attempts==1);
    CHECK(aa_message_push(&p,&bulk,&accepted)==AA_MESSAGE_E_CALLBACK);CHECK(accepted==0);
    CHECK(aa_message_retry(&p)==AA_MESSAGE_E_CALLBACK);CHECK(s.attempts==1);
    CATEGORY("callback-terminal-error-keeps-accepted-fragment-status");
    setup(&p,store,6,2,&s,&e,1);s.error=2;
    CHECK(aa_message_push(&p,&bulk,&accepted)==AA_MESSAGE_E_CALLBACK);CHECK(accepted==1);
    CHECK(p.callback_status==2);CATEGORY("invalid-positive-callback-result-terminal");
    setup(&p,store,6,2,&s,&e,1);s.pauses=1;
    CHECK(aa_message_push(&p,&bulk,&accepted)==AA_MESSAGE_PAUSED);CHECK(accepted==1);
    CHECK(aa_message_reset(&p)==AA_MESSAGE_OK);push(&p,bulk);
    CHECK(s.accepted==1);CHECK(s.attempts==2);
    CATEGORY("explicit-reset-drops-unaccepted-owned-message");
}
static void malformed_tests(void)
{
    struct aa_message_parser p;struct sink s;uint8_t store[8];
    static const uint8_t data[]={0,1,2,3,4,5};
    unsigned property;
    setup(&p,store,6,10,&s,NULL,0);memset(store,0xa5,sizeof(store));
    reject(&p,frag(1,1,7,data,1),AA_MESSAGE_E_CAPACITY);
    CHECK(store[0]==0xa5);CATEGORY("first-total-exceeds-capacity-before-copy");
    setup(&p,store,5,10,&s,NULL,0);
    reject(&p,frag(1,3,0,data,6),AA_MESSAGE_E_CAPACITY);CATEGORY("bulk-exceeds-capacity");
    setup(&p,store,8,10,&s,NULL,0);
    reject(&p,frag(1,1,1,data,2),AA_MESSAGE_E_LENGTH);CATEGORY("first-payload-exceeds-plaintext-total");
    setup(&p,store,8,10,&s,NULL,0);push(&p,frag(1,1,6,data,2));
    reject(&p,frag(1,2,0,data+2,3),AA_MESSAGE_E_LENGTH);
    CHECK(p.bytes==2);CHECK(s.attempts==0);CATEGORY("short-last-no-partial-publication");
    setup(&p,store,8,10,&s,NULL,0);push(&p,frag(1,1,6,data,5));
    reject(&p,frag(1,2,0,data,2),AA_MESSAGE_E_LENGTH);CATEGORY("last-exceeds-remaining-total");
    setup(&p,store,8,10,&s,NULL,0);push(&p,frag(1,1,6,data,5));
    reject(&p,frag(1,0,0,data,2),AA_MESSAGE_E_LENGTH);CATEGORY("middle-exceeds-remaining-total");
    setup(&p,store,8,10,&s,NULL,0);
    reject(&p,frag(1,3,1,data,2),AA_MESSAGE_E_LENGTH);
    setup(&p,store,8,10,&s,NULL,0);push(&p,frag(1,1,6,data,2));
    reject(&p,frag(1,0,1,data,2),AA_MESSAGE_E_LENGTH);
    setup(&p,store,8,10,&s,NULL,0);push(&p,frag(1,1,6,data,2));
    reject(&p,frag(1,2,1,data,4),AA_MESSAGE_E_LENGTH);
    CATEGORY("total-field-forbidden-on-bulk-middle-last");
    setup(&p,store,8,10,&s,NULL,0);push(&p,frag(1,1,6,data,2));
    reject(&p,frag(2,2,0,data+2,4),AA_MESSAGE_E_SEQUENCE);CATEGORY("channel-switch-rejected");
    for(property=4;property<=8;property+=4){
        setup(&p,store,8,10,&s,NULL,0);push(&p,frag(1,(uint8_t)(1|property),6,data,2));
        reject(&p,frag(1,2,0,data+2,4),AA_MESSAGE_E_SEQUENCE);
    }
    CATEGORY("control-and-encryption-property-switches-rejected");
    setup(&p,store,8,10,&s,NULL,0);push(&p,frag(1,1,6,data,2));
    reject(&p,frag(1,1,6,data,2),AA_MESSAGE_E_SEQUENCE);CATEGORY("first-restart-rejected");
    setup(&p,store,8,10,&s,NULL,0);push(&p,frag(1,1,6,data,2));
    reject(&p,frag(1,3,0,data,2),AA_MESSAGE_E_SEQUENCE);CATEGORY("bulk-cannot-interrupt-active-message");
    setup(&p,store,8,10,&s,NULL,0);reject(&p,frag(1,0,0,data,2),AA_MESSAGE_E_SEQUENCE);
    setup(&p,store,8,10,&s,NULL,0);reject(&p,frag(1,2,0,NULL,0),AA_MESSAGE_E_SEQUENCE);
    CATEGORY("orphan-middle-and-last-rejected");
    setup(&p,store,8,10,&s,NULL,0);reject(&p,frag(1,0x13,0,NULL,0),AA_MESSAGE_E_FLAGS);
    CATEGORY("unknown-flags-terminal-no-resync");
    setup(&p,NULL,0,2,&s,NULL,0);push(&p,frag(1,1,0,NULL,0));push(&p,frag(1,0,0,NULL,0));
    reject(&p,frag(1,2,0,NULL,0),AA_MESSAGE_E_FRAGMENTS);CHECK(s.attempts==0);
    CATEGORY("zero-payload-fragment-count-bound");
    setup(&p,store,8,10,&s,NULL,0);
    reject(&p,frag(1,3,0,data,SIZE_MAX),AA_MESSAGE_E_CAPACITY);
    CATEGORY("extreme-claimed-length-rejected-before-pointer-access");
}
static void lifecycle_tests(void)
{
    struct aa_message_parser p;struct sink s;uint8_t store[4];int accepted=99;
    static const uint8_t data[]={0,1,2,3};const struct expected e={2,0,1,4,data};
    setup(&p,store,4,4,&s,&e,1);push(&p,frag(2,1,4,data,2));
    CHECK(aa_message_retry(&p)==AA_MESSAGE_E_STATE);
    CHECK(aa_message_finish(&p)==AA_MESSAGE_E_TRUNCATED);
    CHECK(aa_message_finish(&p)==AA_MESSAGE_E_TRUNCATED);
    CHECK(aa_message_push(&p,NULL,&accepted)==AA_MESSAGE_E_TRUNCATED);CHECK(accepted==0);
    CHECK(s.attempts==0);CHECK(aa_message_reset(&p)==AA_MESSAGE_OK);
    push(&p,frag(2,3,0,data,4));CHECK(s.accepted==1);
    CATEGORY("partial-message-eof-terminal-and-explicit-reset");
    setup(&p,store,4,4,&s,&e,1);
    CHECK(aa_message_finish(&p)==AA_MESSAGE_OK);CHECK(aa_message_finish(&p)==AA_MESSAGE_OK);
    CHECK(aa_message_push(&p,NULL,&accepted)==AA_MESSAGE_E_STATE);CHECK(accepted==0);
    CHECK(aa_message_retry(&p)==AA_MESSAGE_E_STATE);CHECK(s.attempts==0);
    CHECK(aa_message_reset(&p)==AA_MESSAGE_OK);push(&p,frag(2,3,0,data,4));
    CHECK(s.accepted==1);CATEGORY("finished-stream-no-new-message-until-reset");
    struct aa_message_parser untouched={0},saved=untouched;
    CHECK(aa_message_init(NULL,store,4,4,callback,&s)==AA_MESSAGE_E_ARGUMENT);
    CHECK(aa_message_init(&untouched,NULL,4,4,callback,&s)==AA_MESSAGE_E_ARGUMENT);
    CHECK(aa_message_init(&untouched,store,4,0,callback,&s)==AA_MESSAGE_E_ARGUMENT);
    CHECK(aa_message_init(&untouched,store,4,4,NULL,&s)==AA_MESSAGE_E_ARGUMENT);
    if(SIZE_MAX>UINT32_MAX)
        CHECK(aa_message_init(&untouched,store,(size_t)UINT32_MAX+1,4,callback,&s)==AA_MESSAGE_E_ARGUMENT);
    CHECK(memcmp(&untouched,&saved,sizeof(saved))==0);
    CHECK(aa_message_push(&untouched,NULL,&accepted)==AA_MESSAGE_E_ARGUMENT);CHECK(accepted==0);
    CHECK(aa_message_retry(&untouched)==AA_MESSAGE_E_ARGUMENT);
    CHECK(aa_message_finish(&untouched)==AA_MESSAGE_E_ARGUMENT);
    CHECK(aa_message_reset(&untouched)==AA_MESSAGE_E_ARGUMENT);
    setup(&p,store,4,4,&s,&e,1);
    CHECK(aa_message_push(&p,NULL,&accepted)==AA_MESSAGE_E_ARGUMENT);CHECK(accepted==0);
    struct aa_message_fragment bad=frag(2,3,0,NULL,1);
    CHECK(aa_message_push(&p,&bad,&accepted)==AA_MESSAGE_E_ARGUMENT);CHECK(accepted==0);
    CHECK(aa_message_push(&p,NULL,NULL)==AA_MESSAGE_E_ARGUMENT);
    push(&p,frag(2,3,0,data,4));CHECK(s.accepted==1);
    CATEGORY("argument-errors-not-terminal-and-init-preserves-invalid-output");
}
int main(void)
{
    literal_tests();fragmentation_tests();ownership_tests();malformed_tests();lifecycle_tests();
    printf("RESULT {\"categories\":%u,\"assertions\":%lu,\"success\":true}\n",categories,assertions);
    return 0;
}
