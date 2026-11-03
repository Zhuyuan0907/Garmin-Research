#include "usb_config.h"
#include <stddef.h>

/* Freestanding support for compiler-generated aggregate initialization. */
void *memset(void *pointer,int value,size_t bytes)
{
    volatile uint8_t *p=(volatile uint8_t *)pointer;
    while (bytes--) *p++=(uint8_t)value;
    return pointer;
}

static uint32_t le16(const uint8_t *p) { return p[0]|((uint32_t)p[1]<<8); }
static int packet(uint32_t n, uint32_t speed)
{
    return speed==AOA_USB_HIGH ? n==512 : (n==8 || n==16 || n==32 || n==64);
}
int aoa_usb_parse(const uint8_t *p, uint32_t bytes, uint32_t speed, struct aoa_usb_plan *out)
{
    uint32_t at=9,n,kind,i,pairs=0,ids[8]={0},default_ids[8]={0};
    uint16_t seen_pairs[64];
    uint32_t count=0,have=0,alt=0,expected=0,endpoints=0,selected=0,candidates=0;
    uint32_t global_endpoints=0,local_endpoints=0,address,mask,mps;
    struct aoa_usb_plan result={0},current={0};
    if (!p || !out || bytes<9 || bytes>AOA_USB_MAX_CONFIGURATION ||
        (speed!=AOA_USB_FULL && speed!=AOA_USB_HIGH)) return AOA_E_ARGUMENT;
    if (p[0]!=9 || p[1]!=2 || le16(p+2)!=bytes || !p[4] || !p[5] ||
        !(p[7]&0x80) || (p[7]&0x1f)) return AOA_USB_E_DESCRIPTOR;
    result.configuration=p[5];
    while (at<bytes) {
        if (bytes-at<2) return AOA_USB_E_DESCRIPTOR;
        n=p[at];kind=p[at+1];
        if (n<2 || n>bytes-at) return AOA_USB_E_DESCRIPTOR;
        if (kind==2) return AOA_USB_E_DESCRIPTOR;
        if (kind==4) {
            if (have && endpoints!=expected) return AOA_USB_E_DESCRIPTOR;
            if (n!=9 || pairs==64) return AOA_USB_E_DESCRIPTOR;
            i=p[at+2];alt=p[at+3];
            if (i>=p[4]) return AOA_USB_E_DESCRIPTOR;
            mask=1u<<(i&31);
            if (!(ids[i>>5]&mask)) { ids[i>>5]|=mask;count++; }
            if (!alt) default_ids[i>>5]|=mask;
            for (address=0;address<pairs;address++)
                if (seen_pairs[address]==((i<<8)|alt)) return AOA_USB_E_DESCRIPTOR;
            seen_pairs[pairs++]=(uint16_t)((i<<8)|alt);
            have=1;endpoints=0;expected=p[at+4];local_endpoints=0;
            selected=!alt && p[at+5]==0xff && p[at+6]==0xff && p[at+7]==0;
            if (selected) {
                if (expected!=2) return AOA_USB_E_DESCRIPTOR;
                if (++candidates>1) return AOA_USB_E_AMBIGUOUS;
                current.configuration=p[5];current.interface_number=i;
                current.in_endpoint=0;current.out_endpoint=0;
                current.in_packet_bytes=0;current.out_packet_bytes=0;
            }
        } else if (kind==5) {
            if (!have || n<7 || ++endpoints>expected) return AOA_USB_E_DESCRIPTOR;
            address=p[at+2];
            if (!(address&15) || (address&0x70)) return AOA_USB_E_DESCRIPTOR;
            mask=1u<<((address&15)+((address&0x80)?16:0));
            if (local_endpoints&mask) return AOA_USB_E_DESCRIPTOR;
            local_endpoints|=mask;
            if (!alt) {
                if (global_endpoints&mask) return AOA_USB_E_DESCRIPTOR;
                global_endpoints|=mask;
            }
            if (selected) {
                mps=le16(p+at+4);
                if (p[at+3]!=2 || !packet(mps,speed)) return AOA_USB_E_DESCRIPTOR;
                if (address&0x80) {
                    if (current.in_endpoint) return AOA_USB_E_DESCRIPTOR;
                    current.in_endpoint=address;current.in_packet_bytes=mps;
                } else {
                    if (current.out_endpoint) return AOA_USB_E_DESCRIPTOR;
                    current.out_endpoint=address;current.out_packet_bytes=mps;
                }
                if (current.in_endpoint && current.out_endpoint) result=current;
            }
        }
        at+=n;
    }
    if (!have || endpoints!=expected || count!=p[4]) return AOA_USB_E_DESCRIPTOR;
    for (i=0;i<8;i++) if (ids[i]!=default_ids[i]) return AOA_USB_E_DESCRIPTOR;
    if (!candidates) return AOA_USB_E_NOT_FOUND;
    if (!result.in_endpoint || !result.out_endpoint) return AOA_USB_E_DESCRIPTOR;
    *out=result;
    return AOA_IDLE;
}
int aoa_usb_init(struct aoa_usb_context *c, const struct aoa_context *parent,
                 const uint8_t *config, uint32_t bytes, uint32_t speed)
{
    struct aoa_usb_plan plan;
    uint32_t i;
    int status;
    if (!c || !parent || parent->state!=AOA_ACCESSORY_IDENTIFIED || parent->borrowed ||
        !parent->session || !parent->device_generation || !parent->transfer_timeout_ms ||
        parent->transfer_timeout_ms>=0x80000000u) return AOA_E_STATE;
    status=aoa_usb_parse(config,bytes,speed,&plan);
    if (status) return status;
    /* Fresh/quiescent storage only, not a reset of a borrowed context. */
    for (i=0;i<sizeof(*c);i++) ((uint8_t *)c)[i]=0;
    c->session=parent->session;c->device_generation=parent->device_generation;
    c->sequence=parent->sequence;c->state=AOA_USB_NEEDS_CONFIGURATION;
    c->timeout_ms=parent->transfer_timeout_ms;c->plan=plan;
    return AOA_IDLE;
}
static int fail(struct aoa_usb_context *c,int reason)
{ c->state=AOA_USB_FAILED;c->failure=reason;return reason; }
static int expired(uint32_t now,uint32_t deadline)
{ return (int32_t)(now-deadline)>=0; }
int aoa_usb_next(struct aoa_usb_context *c,uint32_t now,struct aoa_request *r)
{
    if (!c || !r) return AOA_E_ARGUMENT;
    if (c->state==AOA_USB_FAILED) return c->failure;
    if (c->borrowed) {
        if (expired(now,c->deadline)) return fail(c,AOA_E_TIMEOUT);
        return AOA_BUSY;
    }
    if (c->state==AOA_USB_CONFIGURED) return AOA_IDLE;
    if (c->state!=AOA_USB_NEEDS_CONFIGURATION) return AOA_E_STATE;
    if (c->sequence==0xffffffffu) return fail(c,AOA_E_SEQUENCE);
    c->setup[0]=0;c->setup[1]=9;c->setup[2]=(uint8_t)c->plan.configuration;
    c->setup[3]=0;c->setup[4]=0;c->setup[5]=0;c->setup[6]=0;c->setup[7]=0;
    c->sequence++;c->borrowed=1;c->deadline=now+c->timeout_ms;
    r->session=c->session;r->sequence=c->sequence;r->device_generation=c->device_generation;
    r->setup=c->setup;r->data=0;r->data_bytes=0;r->direction_in=0;
    return AOA_REQUEST;
}
static int token(struct aoa_usb_context *c,uint32_t session,uint32_t sequence)
{ return c && c->borrowed && c->session==session && c->sequence==sequence; }
int aoa_usb_complete(struct aoa_usb_context *c,uint32_t session,uint32_t sequence,
                     int status,uint32_t actual,uint32_t now)
{
    if (!token(c,session,sequence)) return AOA_E_STALE;
    c->borrowed=0;
    if (c->state==AOA_USB_FAILED) return c->failure;
    if (expired(now,c->deadline)) return fail(c,AOA_E_TIMEOUT);
    if (status || actual) return fail(c,AOA_E_TRANSFER);
    if (c->state!=AOA_USB_NEEDS_CONFIGURATION) return fail(c,AOA_E_STATE);
    c->state=AOA_USB_CONFIGURED;
    return AOA_IDLE;
}
int aoa_usb_cancel(struct aoa_usb_context *c)
{
    if (!c) return AOA_E_ARGUMENT;
    if (c->state==AOA_USB_FAILED) return c->failure;
    return fail(c,AOA_E_CANCELLED);
}
int aoa_usb_cancel_ack(struct aoa_usb_context *c,uint32_t session,uint32_t sequence)
{
    if (!token(c,session,sequence)) return AOA_E_STALE;
    if (c->state!=AOA_USB_FAILED) return AOA_E_STATE;
    c->borrowed=0;return AOA_IDLE;
}
uint32_t aoa_usb_context_bytes(void) { return sizeof(struct aoa_usb_context); }
uint32_t aoa_usb_plan_bytes(void) { return sizeof(struct aoa_usb_plan); }
