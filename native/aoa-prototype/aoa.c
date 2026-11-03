#include "aoa.h"

static int accessory(uint32_t vid, uint32_t pid)
{
    return vid == 0x18d1 && (pid == 0x2d00 || pid == 0x2d01 ||
                            pid == 0x2d04 || pid == 0x2d05);
}
/* Durations must be <2^31 ms; poll at least once in each half-wrap interval. */
static int expired(uint32_t now, uint32_t deadline)
{
    return (int32_t)(now - deadline) >= 0;
}
static int fail(struct aoa_context *c, int reason)
{
    c->state = AOA_FAILED;
    c->failure = reason;
    return reason;
}
static int utf8(const uint8_t *s, uint32_t n)
{
    uint32_t i=0, more, value, minimum, b;
    if (!s || n == 0 || n > 256 || s[n-1] != 0) return 0;
    while (i < n-1) {
        b = s[i++];
        if (b == 0) return 0;
        if (b < 0x80) continue;
        if (b >= 0xc2 && b <= 0xdf) { more=1; value=b&31; minimum=0x80; }
        else if (b >= 0xe0 && b <= 0xef) { more=2; value=b&15; minimum=0x800; }
        else if (b >= 0xf0 && b <= 0xf4) { more=3; value=b&7; minimum=0x10000; }
        else return 0;
        if (more > (n-1)-i) return 0;
        while (more--) {
            b=s[i++];
            if ((b&0xc0) != 0x80) return 0;
            value=(value<<6)|(b&63);
        }
        if (value < minimum || value > 0x10ffff ||
            (value >= 0xd800 && value <= 0xdfff)) return 0;
    }
    return 1;
}
int aoa_init(struct aoa_context *c, const struct aoa_options *o, uint32_t now)
{
    uint32_t i,j;
    (void)now;
    if (!c || !o || !o->session || !o->device_generation ||
        !o->transfer_timeout_ms || o->transfer_timeout_ms >= 0x80000000u ||
        !o->reenumeration_timeout_ms || o->reenumeration_timeout_ms >= 0x80000000u)
        return AOA_E_ARGUMENT;
    for (i=0;i<6;i++) {
        if (!utf8(o->strings[i],o->string_bytes[i])) return AOA_E_ARGUMENT;
        if ((i==0 || i==1 || i==3) && o->string_bytes[i]==1) return AOA_E_ARGUMENT;
    }
    /* options, input strings, context, and request output must not overlap.
     * init is only for fresh/quiescent context storage, never a reset API. */
    for (i=0;i<sizeof(*c);i++) ((uint8_t *)c)[i]=0;
    c->session=o->session; c->device_generation=o->device_generation;
    c->transfer_timeout_ms=o->transfer_timeout_ms;
    c->reenumeration_timeout_ms=o->reenumeration_timeout_ms;
    for (i=0;i<6;i++) {
        c->string_bytes[i]=(uint16_t)o->string_bytes[i];
        for (j=0;j<o->string_bytes[i];j++) c->strings[i][j]=o->strings[i][j];
    }
    c->state=accessory(o->initial_vid,o->initial_pid) ? AOA_ACCESSORY_IDENTIFIED : AOA_PROTOCOL;
    return AOA_IDLE;
}
int aoa_next(struct aoa_context *c, uint32_t now, struct aoa_request *r)
{
    uint32_t i, n=0;
    uint8_t *data=0;
    if (!c || !r) return AOA_E_ARGUMENT;
    if (c->state == AOA_FAILED) return c->failure;
    if (c->borrowed) {
        if (expired(now,c->deadline)) return fail(c,AOA_E_TIMEOUT);
        return AOA_BUSY;
    }
    if (c->state == AOA_ACCESSORY_IDENTIFIED) return AOA_IDLE;
    if (c->state == AOA_WAIT_REENUMERATION) {
        if (expired(now,c->deadline)) return fail(c,AOA_E_TIMEOUT);
        return AOA_IDLE;
    }
    if (c->state < AOA_PROTOCOL || c->state > AOA_START) return AOA_E_STATE;
    if (c->sequence == 0xffffffffu) return fail(c,AOA_E_SEQUENCE);
    for (i=0;i<8;i++) c->setup[i]=0;
    c->setup[0]=0x40;
    if (c->state == AOA_PROTOCOL) {
        c->setup[0]=0xc0; c->setup[1]=51;
        c->rx[0]=0; c->rx[1]=0; n=2; data=c->rx;
    } else if (c->state == AOA_STRINGS) {
        c->setup[1]=52; c->setup[4]=(uint8_t)c->string_index;
        n=c->string_bytes[c->string_index]; data=c->strings[c->string_index];
    } else c->setup[1]=53;
    c->setup[6]=(uint8_t)n; c->setup[7]=(uint8_t)(n>>8);
    c->sequence++; c->borrowed=1; c->deadline=now+c->transfer_timeout_ms;
    r->session=c->session; r->sequence=c->sequence;
    r->device_generation=c->device_generation; r->setup=c->setup;
    r->data=data; r->data_bytes=n; r->direction_in=c->state == AOA_PROTOCOL;
    return AOA_REQUEST;
}
static int token(struct aoa_context *c, uint32_t session, uint32_t sequence)
{
    return c && c->borrowed && c->session==session && c->sequence==sequence;
}
int aoa_complete(struct aoa_context *c, uint32_t session, uint32_t sequence,
                 int status, uint32_t actual, uint32_t now)
{
    uint32_t wanted;
    if (!token(c,session,sequence)) return AOA_E_STALE;
    c->borrowed=0; /* terminal completion releases the controller borrow */
    if (c->state == AOA_FAILED) return c->failure;
    if (expired(now,c->deadline)) return fail(c,AOA_E_TIMEOUT);
    if (status != 0) return fail(c,AOA_E_TRANSFER);
    wanted=(uint32_t)c->setup[6]|((uint32_t)c->setup[7]<<8);
    if (actual != wanted) return fail(c,AOA_E_TRANSFER);
    if (c->state == AOA_PROTOCOL) {
        c->protocol_version=(uint32_t)c->rx[0]|((uint32_t)c->rx[1]<<8);
        /* Only the published versions1/2 are supported by this prototype. */
        if (c->protocol_version != 1 && c->protocol_version != 2)
            return fail(c,AOA_E_PROTOCOL);
        c->state=AOA_STRINGS;
    } else if (c->state == AOA_STRINGS) {
        if (++c->string_index == 6) c->state=AOA_START;
    } else if (c->state == AOA_START) {
        c->state=AOA_WAIT_REENUMERATION;
        c->deadline=now+c->reenumeration_timeout_ms;
    } else return fail(c,AOA_E_STATE);
    return AOA_IDLE;
}
int aoa_cancel(struct aoa_context *c)
{
    if (!c) return AOA_E_ARGUMENT;
    if (c->state == AOA_FAILED) return c->failure;
    return fail(c,AOA_E_CANCELLED);
}
int aoa_cancel_ack(struct aoa_context *c, uint32_t session, uint32_t sequence)
{
    if (!token(c,session,sequence)) return AOA_E_STALE;
    if (c->state != AOA_FAILED) return AOA_E_STATE;
    c->borrowed=0;
    return AOA_IDLE;
}
int aoa_reenumerated(struct aoa_context *c, uint32_t session, uint32_t generation,
                    uint32_t vid, uint32_t pid, uint32_t now)
{
    if (!c || session != c->session) return AOA_E_STALE;
    if (c->state == AOA_FAILED) return c->failure;
    if (c->state != AOA_WAIT_REENUMERATION || c->borrowed) return AOA_E_STATE;
    if (expired(now,c->deadline)) return fail(c,AOA_E_TIMEOUT);
    if (generation <= c->device_generation) return AOA_E_STALE;
    if (!accessory(vid,pid)) return AOA_E_PROTOCOL;
    c->device_generation=generation; c->state=AOA_ACCESSORY_IDENTIFIED;
    return AOA_IDLE;
}
uint32_t aoa_context_bytes(void) { return sizeof(struct aoa_context); }
uint32_t aoa_options_bytes(void) { return sizeof(struct aoa_options); }
uint32_t aoa_request_bytes(void) { return sizeof(struct aoa_request); }
