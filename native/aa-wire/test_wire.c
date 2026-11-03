/* SPDX-License-Identifier: GPL-3.0-or-later
 * Ordinary host C tests; no Garmin binary, CPU emulator, USB or Bluetooth.
 */
#include "wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned long checks;
static unsigned categories;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "FAIL:%s:%d:%s\n", __FILE__, __LINE__, #x); exit(2); \
} } while (0)
#define CATEGORY(name) do { ++categories; printf("PASS %s\n", name); } while (0)
struct expected {
    uint8_t channel, flags;
    uint16_t bytes;
    uint32_t total;
    const uint8_t *payload;
};
struct sink {
    const struct expected *expected;
    size_t total, accepted, attempts;
    unsigned pause_remaining;
    size_t pause_at;
    int fail_result, reenter;
    const uint8_t *paused_pointer;
    struct aa_wire_parser *parser;
};
static int on_frame(void *arg, const struct aa_wire_frame *f)
{
    struct sink *s = arg;
    const struct expected *e;
    size_t consumed = 100;
    ++s->attempts;
    CHECK(s->accepted < s->total);
    e = s->expected + s->accepted;
    CHECK(f->channel == e->channel);
    CHECK(f->flags == e->flags);
    CHECK(f->payload_bytes == e->bytes);
    CHECK(f->total_plain_bytes == e->total);
    CHECK(e->bytes == 0 || memcmp(f->payload, e->payload, e->bytes) == 0);
    if (s->reenter) {
        CHECK(aa_wire_feed(s->parser, NULL, 0, &consumed) == AA_WIRE_E_REENTRANT);
        CHECK(consumed == 0);
        CHECK(aa_wire_finish(s->parser) == AA_WIRE_E_REENTRANT);
        CHECK(aa_wire_reset(s->parser) == AA_WIRE_E_REENTRANT);
    }
    if (s->fail_result) return s->fail_result;
    if (s->pause_remaining && s->accepted == s->pause_at) {
        if (s->paused_pointer) CHECK(f->payload == s->paused_pointer);
        s->paused_pointer = f->payload;
        --s->pause_remaining;
        return AA_WIRE_PAUSED;
    }
    ++s->accepted;
    s->paused_pointer = NULL;
    return AA_WIRE_OK;
}
static void setup(struct aa_wire_parser *p, uint8_t *store, size_t cap,
                  struct sink *s, const struct expected *e, size_t count)
{
    memset(s, 0, sizeof(*s)); s->expected=e; s->total=count; s->parser=p;
    CHECK(aa_wire_init(p, store, cap, on_frame, s) == AA_WIRE_OK);
}
static void feed_all(struct aa_wire_parser *p, const uint8_t *data, size_t len)
{
    size_t consumed=100;
    CHECK(aa_wire_feed(p, data, len, &consumed) == AA_WIRE_OK);
    CHECK(consumed == len);
}
/* Independent test packet construction: parser contains no encoder. Literal
 * vectors below separately check field order/endianness and FIRST-only total.
 */
static size_t packet(uint8_t *out, const struct expected *e)
{
    size_t header = (e->flags & 3u) == 1u ? 8 : 4;
    out[0]=e->channel; out[1]=e->flags;
    out[2]=(uint8_t)(e->bytes >> 8); out[3]=(uint8_t)e->bytes;
    if (header==8) {
        out[4]=(uint8_t)(e->total >> 24); out[5]=(uint8_t)(e->total >> 16);
        out[6]=(uint8_t)(e->total >> 8); out[7]=(uint8_t)e->total;
    }
    if (e->bytes) memcpy(out+header, e->payload, e->bytes);
    return header+e->bytes;
}
static uint32_t rng(uint32_t *state)
{
    *state = *state * UINT32_C(1664525) + UINT32_C(1013904223);
    return *state;
}
static void literal_tests(void)
{
    struct aa_wire_parser p; struct sink s; uint8_t store[16];
    static const uint8_t bulk[]={0x00,0x07,0x00,0x04,0x00,0x01,0x00,0x00};
    const struct expected eb={0,7,4,0,bulk+4};
    setup(&p,store,sizeof(store),&s,&eb,1); feed_all(&p,bulk,sizeof(bulk));
    CHECK(s.accepted==1); CHECK(aa_wire_finish(&p)==AA_WIRE_OK);
    CATEGORY("literal-control-bulk");
    /* Ciphertext is 6 bytes but FIRST plaintext total is 3. Both valid wire
     * metadata: no plaintext-vs-ciphertext size comparison is permitted here. */
    static const uint8_t first[]={0x2a,0x09,0x00,0x06,0x00,0x00,0x00,0x03,
                                 0x16,0x03,0x03,0x00,0x01,0xff};
    const struct expected ef={42,9,6,3,first+8};
    setup(&p,store,sizeof(store),&s,&ef,1); feed_all(&p,first,sizeof(first));
    CHECK(s.accepted==1); CHECK(aa_wire_finish(&p)==AA_WIRE_OK);
    CATEGORY("literal-first-total-is-not-ciphertext-length");
    static const uint8_t last[]={0x01,0x02,0x00,0x00};
    const struct expected el={1,2,0,0,NULL};
    setup(&p,store,sizeof(store),&s,&el,1); feed_all(&p,last,sizeof(last));
    CHECK(s.accepted==1); CHECK(aa_wire_finish(&p)==AA_WIRE_OK);
    CATEGORY("literal-zero-length-last-no-message-assumption");
    static const uint8_t ext[]={0xff,0x0d,0x00,0x00,0xfe,0xdc,0xba,0x98};
    const struct expected ee={255,13,0,UINT32_C(0xfedcba98),NULL};
    setup(&p,NULL,0,&s,&ee,1); feed_all(&p,ext,sizeof(ext));
    CHECK(s.accepted==1); CATEGORY("literal-32-bit-total-and-zero-pool");
}
static void split_merge_tests(void)
{
    static const uint8_t stream[]={
        0x01,0x0b,0x00,0x03,0xde,0xad,0xbe,
        0x02,0x09,0x00,0x05,0x00,0x00,0x00,0x01,0x01,0x02,0x03,0x04,0x05,
        0x02,0x0a,0x00,0x00};
    const struct expected es[]={
        {1,11,3,0,stream+4},{2,9,5,1,stream+15},{2,10,0,0,NULL}};
    uint8_t store[8]; struct aa_wire_parser p; struct sink s;
    size_t cut, second;
    for (cut=0;cut<=sizeof(stream);++cut) {
        setup(&p,store,sizeof(store),&s,es,3);
        feed_all(&p,stream,cut); feed_all(&p,stream+cut,sizeof(stream)-cut);
        CHECK(s.accepted==3); CHECK(aa_wire_finish(&p)==AA_WIRE_OK);
    }
    CATEGORY("all-two-chunk-splits");
    /* Every pair of boundaries covers splits in FIRST length, FIRST total,
     * payload, zero LAST and coalesced frames, including empty chunks. */
    for (cut=0;cut<=sizeof(stream);++cut) for (second=cut;second<=sizeof(stream);++second) {
        setup(&p,store,sizeof(store),&s,es,3);
        feed_all(&p,stream,cut); feed_all(&p,stream+cut,second-cut);
        feed_all(&p,stream+second,sizeof(stream)-second);
        CHECK(s.accepted==3); CHECK(aa_wire_finish(&p)==AA_WIRE_OK);
    }
    CATEGORY("all-three-chunk-splits");
    setup(&p,store,sizeof(store),&s,es,3);
    for(cut=0;cut<sizeof(stream);++cut) feed_all(&p,stream+cut,1);
    CHECK(s.accepted==3); CHECK(s.attempts==3);
    CATEGORY("bytewise-transport-chunks");
    setup(&p,store,sizeof(store),&s,es,3); feed_all(&p,stream,sizeof(stream));
    CHECK(s.accepted==3); CHECK(s.attempts==3);
    CATEGORY("multiple-frames-in-single-feed");
}
static void random_chunk_tests(void)
{
    struct expected es[300]; uint8_t payloads[300][61], stream[22000], store[61];
    uint32_t seed=UINT32_C(0x52314771); size_t len=0,i,j,off,n;
    struct aa_wire_parser p; struct sink s;
    for(i=0;i<300;++i) {
        es[i].channel=(uint8_t)rng(&seed); es[i].flags=(uint8_t)(rng(&seed)&15u);
        es[i].bytes=(uint16_t)(rng(&seed)%62u);
        es[i].total=(es[i].flags&3u)==1u?rng(&seed):0;
        for(j=0;j<es[i].bytes;++j) payloads[i][j]=(uint8_t)rng(&seed);
        es[i].payload=payloads[i]; len+=packet(stream+len,&es[i]);
    }
    CHECK(len<=sizeof(stream)); setup(&p,store,sizeof(store),&s,es,300);
    for(off=0;off<len;off+=n) {
        n=1+(rng(&seed)%997u); if(n>len-off)n=len-off;
        feed_all(&p,stream+off,n);
    }
    CHECK(s.accepted==300); CHECK(aa_wire_finish(&p)==AA_WIRE_OK);
    CATEGORY("fixed-seed-random-chunks-and-frame-metadata");
}
static void large_tests(void)
{
    uint8_t *store=malloc(65537), *data=malloc(65543), *wire=malloc(65543);
    struct aa_wire_parser p; struct sink s; struct expected e;
    size_t i,len,off,n;
    CHECK(store && data && wire); memset(store,0xa5,65537);
    for(i=0;i<65535;++i)data[i]=(uint8_t)(i*37u+11u);
    e.channel=7;e.flags=9;e.bytes=65535;e.total=11;e.payload=data;
    len=packet(wire,&e);setup(&p,store+1,65535,&s,&e,1);
    for(off=0;off<len;off+=n){n=4096;if(n>len-off)n=len-off;feed_all(&p,wire+off,n);}
    CHECK(s.accepted==1);CHECK(store[0]==0xa5 && store[65536]==0xa5);
    CHECK(aa_wire_finish(&p)==AA_WIRE_OK);
    CATEGORY("max-65535-byte-payload-across-4096-byte-reads");
    e.bytes=10000;e.flags=3;e.total=0;len=packet(wire,&e);
    setup(&p,store+1,10000,&s,&e,1);
    feed_all(&p,wire,len-1);CHECK(s.accepted==0);feed_all(&p,wire+len-1,1);
    CHECK(s.accepted==1);CATEGORY("callback-only-after-last-payload-byte");
    free(store);free(data);free(wire);
}
static void pause_tests(void)
{
    uint8_t wire[]={1,3,0,3,10,20,30,2,2,0,0};
    const uint8_t payload[]={10,20,30};
    const struct expected es[]={{1,3,3,0,payload},{2,2,0,0,NULL}};
    uint8_t store[3]; struct aa_wire_parser p;struct sink s;size_t consumed;
    setup(&p,store,sizeof(store),&s,es,2);s.pause_remaining=2;
    CHECK(aa_wire_feed(&p,wire,sizeof(wire),&consumed)==AA_WIRE_PAUSED);
    CHECK(consumed==7);CHECK(s.accepted==0);CHECK(s.attempts==1);
    memset(wire+4,0xff,3); /* retained frame does not borrow transport input */
    CHECK(aa_wire_finish(&p)==AA_WIRE_PAUSED);CHECK(s.attempts==1);
    consumed=100;
    CHECK(aa_wire_feed(&p,wire+7,4,&consumed)==AA_WIRE_PAUSED);
    CHECK(consumed==0);CHECK(s.attempts==2);
    CHECK(aa_wire_feed(&p,NULL,0,&consumed)==AA_WIRE_OK);
    CHECK(consumed==0);CHECK(s.accepted==1);CHECK(s.attempts==3);
    feed_all(&p,wire+7,4);CHECK(s.accepted==2);CHECK(s.attempts==4);
    CHECK(aa_wire_finish(&p)==AA_WIRE_OK);
    CATEGORY("pause-retains-copied-frame-and-exact-tail-consumption");
    setup(&p,NULL,0,&s,es+1,1);s.pause_remaining=1;
    CHECK(aa_wire_feed(&p,wire+7,4,&consumed)==AA_WIRE_PAUSED);
    CHECK(consumed==4);CHECK(s.accepted==0);
    CHECK(aa_wire_feed(&p,NULL,0,&consumed)==AA_WIRE_OK);
    CHECK(consumed==0);CHECK(s.accepted==1);
    CATEGORY("zero-length-frame-backpressure");
    {
        const uint8_t merged[]={1,3,0,1,42,2,9,0,1,0,0,0,7,99,2,10,0,0};
        const struct expected three[]={{1,3,1,0,merged+4},
            {2,9,1,7,merged+13},{2,10,0,0,NULL}};
        setup(&p,store,sizeof(store),&s,three,3);s.pause_remaining=1;s.pause_at=1;
        CHECK(aa_wire_feed(&p,merged,sizeof(merged),&consumed)==AA_WIRE_PAUSED);
        CHECK(consumed==14);CHECK(s.accepted==1);CHECK(s.attempts==2);
        feed_all(&p,merged+14,4);CHECK(s.accepted==3);CHECK(s.attempts==4);
        CHECK(aa_wire_finish(&p)==AA_WIRE_OK);
        CATEGORY("backpressure-after-earlier-accepted-coalesced-frame");
    }
    setup(&p,store,sizeof(store),&s,es,2); s.reenter=1;
    wire[4]=10;wire[5]=20;wire[6]=30;
    feed_all(&p,wire,sizeof(wire));CHECK(s.accepted==2);
    CATEGORY("feed-finish-reset-reentrancy-rejected");
    setup(&p,store,sizeof(store),&s,es,2);s.fail_result=-77;
    CHECK(aa_wire_feed(&p,wire,sizeof(wire),&consumed)==AA_WIRE_E_CALLBACK);
    CHECK(consumed==7);CHECK(p.callback_status==-77);CHECK(s.accepted==0);
    CHECK(aa_wire_feed(&p,wire+7,4,&consumed)==AA_WIRE_E_CALLBACK);
    CHECK(consumed==0);CHECK(s.attempts==1);
    CATEGORY("terminal-negative-callback-and-tail-preservation");
    setup(&p,store,sizeof(store),&s,es,2);s.fail_result=2;
    CHECK(aa_wire_feed(&p,wire,sizeof(wire),&consumed)==AA_WIRE_E_CALLBACK);
    CHECK(consumed==7);CHECK(p.callback_status==2);
    CATEGORY("unrecognized-callback-result-fails-closed");
}
static void failure_tests(void)
{
    struct aa_wire_parser p;struct sink s;size_t consumed,n;
    uint8_t store[6]={0xa5,0,0,0,0,0x5a};
    const uint8_t over[]={1,9,0,5,0,0,0,1,10,20,30,40,50,2,2,0,0};
    setup(&p,store+1,4,&s,NULL,0);
    CHECK(aa_wire_feed(&p,over,sizeof(over),&consumed)==AA_WIRE_E_CAPACITY);
    CHECK(consumed==4);CHECK(s.attempts==0);CHECK(store[0]==0xa5&&store[5]==0x5a);
    CHECK(aa_wire_feed(&p,over+4,sizeof(over)-4,&consumed)==AA_WIRE_E_CAPACITY);
    CHECK(consumed==0);CHECK(aa_wire_finish(&p)==AA_WIRE_E_CAPACITY);
    CATEGORY("capacity-rejected-after-base-header-before-first-extension");
    const uint8_t flags[]={1,0x13,0,0,2,2,0,0};
    setup(&p,store+1,4,&s,NULL,0);
    CHECK(aa_wire_feed(&p,flags,sizeof(flags),&consumed)==AA_WIRE_E_FLAGS);
    CHECK(consumed==4);CHECK(s.attempts==0);
    CHECK(aa_wire_feed(&p,flags+4,4,&consumed)==AA_WIRE_E_FLAGS);
    CHECK(consumed==0);CATEGORY("reserved-flags-no-resynchronization");
    const uint8_t first[]={1,9,0,2,0,0,0,1,0xaa,0xbb};
    const struct expected e={1,9,2,1,first+8};
    for(n=1;n<sizeof(first);++n) {
        setup(&p,store+1,4,&s,&e,1);feed_all(&p,first,n);
        CHECK(s.attempts==0);CHECK(aa_wire_finish(&p)==AA_WIRE_E_TRUNCATED);
        CHECK(aa_wire_feed(&p,first+n,sizeof(first)-n,&consumed)==AA_WIRE_E_TRUNCATED);
        CHECK(consumed==0);CHECK(s.attempts==0);
    }
    CATEGORY("every-truncated-first-header-total-and-payload-prefix");
    const uint8_t bulk[]={1,3,0,2,0xaa,0xbb};
    const struct expected eb={1,3,2,0,bulk+4};
    for(n=1;n<sizeof(bulk);++n){
        setup(&p,store+1,4,&s,&eb,1);feed_all(&p,bulk,n);
        CHECK(s.attempts==0);CHECK(aa_wire_finish(&p)==AA_WIRE_E_TRUNCATED);
    }
    CATEGORY("every-truncated-short-header-and-payload-prefix");
    setup(&p,store+1,4,&s,&eb,1);feed_all(&p,bulk,3);
    CHECK(aa_wire_reset(&p)==AA_WIRE_OK);feed_all(&p,bulk,sizeof(bulk));
    CHECK(s.accepted==1);CHECK(aa_wire_finish(&p)==AA_WIRE_OK);
    CATEGORY("explicit-new-stream-reset-drops-partial-header");
    setup(&p,store+1,4,&s,&eb,1);s.pause_remaining=1;
    CHECK(aa_wire_feed(&p,bulk,sizeof(bulk),&consumed)==AA_WIRE_PAUSED);
    CHECK(aa_wire_reset(&p)==AA_WIRE_OK);
    feed_all(&p,bulk,sizeof(bulk));CHECK(s.accepted==1);
    CATEGORY("explicit-reset-drops-unaccepted-pending-frame");
    setup(&p,store+1,4,&s,&eb,1);
    CHECK(aa_wire_finish(&p)==AA_WIRE_OK);CHECK(aa_wire_finish(&p)==AA_WIRE_OK);
    CHECK(aa_wire_feed(&p,NULL,0,&consumed)==AA_WIRE_OK);CHECK(consumed==0);
    CHECK(aa_wire_feed(&p,bulk,sizeof(bulk),&consumed)==AA_WIRE_E_STATE);
    CHECK(consumed==0);CHECK(s.attempts==0);
    CHECK(aa_wire_reset(&p)==AA_WIRE_OK);feed_all(&p,bulk,sizeof(bulk));
    CHECK(s.accepted==1);CATEGORY("eof-closed-stream-rejects-future-input-until-reset");
}
static void argument_tests(void)
{
    struct aa_wire_parser p={0}, saved;struct sink s={0};size_t consumed=99;
    uint8_t store[1];
    CHECK(aa_wire_init(NULL,store,1,on_frame,&s)==AA_WIRE_E_ARGUMENT);
    saved=p;
    CHECK(aa_wire_init(&p,store,65536,on_frame,&s)==AA_WIRE_E_ARGUMENT);
    CHECK(memcmp(&p,&saved,sizeof(p))==0);
    CHECK(aa_wire_init(&p,NULL,1,on_frame,&s)==AA_WIRE_E_ARGUMENT);
    CHECK(aa_wire_init(&p,store,1,NULL,&s)==AA_WIRE_E_ARGUMENT);
    CHECK(aa_wire_feed(&p,NULL,0,&consumed)==AA_WIRE_E_ARGUMENT);CHECK(consumed==0);
    CHECK(aa_wire_finish(&p)==AA_WIRE_E_ARGUMENT);
    CHECK(aa_wire_reset(&p)==AA_WIRE_E_ARGUMENT);
    CHECK(aa_wire_feed(NULL,NULL,0,&consumed)==AA_WIRE_E_ARGUMENT);CHECK(consumed==0);
    setup(&p,store,1,&s,NULL,0);
    CHECK(aa_wire_feed(&p,NULL,1,&consumed)==AA_WIRE_E_ARGUMENT);CHECK(consumed==0);
    CHECK(aa_wire_feed(&p,NULL,0,NULL)==AA_WIRE_E_ARGUMENT);
    CHECK(aa_wire_feed(&p,NULL,0,&consumed)==AA_WIRE_OK);CHECK(consumed==0);
    CHECK(s.attempts==0);CATEGORY("argument-errors-preserve-state-and-zero-consumed");
}
int main(void)
{
    literal_tests();split_merge_tests();random_chunk_tests();large_tests();
    pause_tests();failure_tests();argument_tests();
    printf("RESULT {\"categories\":%u,\"assertions\":%lu,\"success\":true}\n",categories,checks);
    return 0;
}
