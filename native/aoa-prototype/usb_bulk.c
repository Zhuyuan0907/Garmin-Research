#include "usb_bulk.h"
static int fail(struct aoa_bulk_context *c,int reason)
{ c->state=AOA_BULK_FAILED;c->failure=reason;return reason; }
static int expired(uint32_t now,uint32_t deadline)
{ return (int32_t)(now-deadline)>=0; }
int aoa_bulk_init(struct aoa_bulk_context *c,const struct aoa_usb_context *p)
{
    uint32_t i,packet;
    if (!c || !p || p->state!=AOA_USB_CONFIGURED || p->borrowed || !p->session ||
        !p->device_generation || !p->timeout_ms || p->timeout_ms>=0x80000000u)
        return AOA_E_STATE;
    if (!(p->plan.in_endpoint&0x80) || (p->plan.in_endpoint&~0x8fu) || !(p->plan.in_endpoint&15) ||
        (p->plan.out_endpoint&~15u) || !p->plan.out_endpoint) return AOA_E_ARGUMENT;
    packet=p->plan.in_packet_bytes;
    if (packet!=8 && packet!=16 && packet!=32 && packet!=64 && packet!=512) return AOA_E_ARGUMENT;
    for (i=0;i<sizeof(*c);i++) ((uint8_t *)c)[i]=0;
    c->session=p->session;c->device_generation=p->device_generation;c->sequence=p->sequence;
    c->timeout_ms=p->timeout_ms;c->state=AOA_BULK_ACTIVE;
    c->in_endpoint=p->plan.in_endpoint;c->out_endpoint=p->plan.out_endpoint;c->in_packet_bytes=packet;
    return AOA_IDLE;
}
static int active(struct aoa_bulk_context *c)
{
    if (!c) return AOA_E_ARGUMENT;
    if (c->state==AOA_BULK_ACTIVE) return AOA_IDLE;
    if (c->state==AOA_BULK_STOPPED || c->state==AOA_BULK_FAILED) return c->failure;
    return AOA_E_STATE;
}
int aoa_bulk_poll(struct aoa_bulk_context *c,uint32_t now)
{
    int status=active(c);
    if (status) return status;
    if ((c->rx.borrowed && expired(now,c->rx.deadline)) ||
        (c->tx.borrowed && expired(now,c->tx.deadline))) return fail(c,AOA_E_TIMEOUT);
    return AOA_IDLE;
}
int aoa_bulk_queue_tx(struct aoa_bulk_context *c,const uint8_t *data,uint32_t bytes)
{
    uint32_t i;int status=active(c);
    if (status) return status;
    if (!data || !bytes || bytes>AOA_BULK_BUFFER_BYTES) return AOA_E_ARGUMENT;
    if (c->tx.borrowed || c->tx.offset<c->tx.total_bytes) return AOA_BUSY;
    for (i=0;i<bytes;i++) c->tx_data[i]=data[i];
    c->tx.total_bytes=bytes;c->tx.offset=0;c->tx.actual_bytes=0;
    return AOA_IDLE;
}
static int emit(struct aoa_bulk_context *c,struct aoa_bulk_lane *lane,uint32_t direction,
                uint8_t *data,uint32_t bytes,uint32_t now,struct aoa_bulk_request *r)
{
    if (c->sequence==0xffffffffu) return fail(c,AOA_E_SEQUENCE);
    lane->sequence=++c->sequence;lane->request_bytes=bytes;
    lane->deadline=now+c->timeout_ms;lane->borrowed=1;
    r->session=c->session;r->sequence=lane->sequence;r->device_generation=c->device_generation;
    r->direction=direction;r->endpoint=direction?c->in_endpoint:c->out_endpoint;
    r->data=data;r->bytes=bytes;
    return AOA_REQUEST;
}
int aoa_bulk_next_tx(struct aoa_bulk_context *c,uint32_t now,struct aoa_bulk_request *r)
{
    int status;
    if (!r) return AOA_E_ARGUMENT;
    status=aoa_bulk_poll(c,now);if (status) return status;
    if (c->tx.borrowed) return AOA_BUSY;
    if (c->tx.offset==c->tx.total_bytes) return AOA_IDLE;
    return emit(c,&c->tx,AOA_BULK_OUT,c->tx_data+c->tx.offset,
                c->tx.total_bytes-c->tx.offset,now,r);
}
int aoa_bulk_next_rx(struct aoa_bulk_context *c,uint32_t bytes,uint32_t now,struct aoa_bulk_request *r)
{
    int status;
    if (!r) return AOA_E_ARGUMENT;
    status=aoa_bulk_poll(c,now);if (status) return status;
    if (!bytes || bytes>AOA_BULK_BUFFER_BYTES || (bytes&(c->in_packet_bytes-1))) return AOA_E_ARGUMENT;
    if (c->rx.borrowed || c->rx.offset<c->rx.actual_bytes) return AOA_BUSY;
    c->rx.actual_bytes=0;c->rx.offset=0;
    return emit(c,&c->rx,AOA_BULK_IN,c->rx_data,bytes,now,r);
}
int aoa_bulk_read_rx(struct aoa_bulk_context *c,uint8_t *out,uint32_t capacity)
{
    uint32_t count,i;int status=active(c);
    if (status) return status;
    if (!out || !capacity) return AOA_E_ARGUMENT;
    if (c->rx.borrowed) return AOA_BULK_E_PENDING;
    count=c->rx.actual_bytes-c->rx.offset;if (count>capacity) count=capacity;
    for (i=0;i<count;i++) out[i]=c->rx_data[c->rx.offset+i];
    c->rx.offset+=count;
    return (int)count;
}
int aoa_bulk_complete(struct aoa_bulk_context *c,uint32_t session,uint32_t sequence,
                      uint32_t direction,int status,uint32_t actual,uint32_t now)
{
    struct aoa_bulk_lane *lane;
    int deadline_status;
    if (!c || direction>1) return AOA_E_ARGUMENT;
    lane=direction?&c->rx:&c->tx;
    if (c->session!=session || !lane->borrowed || lane->sequence!=sequence) return AOA_E_STALE;
    lane->borrowed=0; /* terminal callback, no more controller references */
    lane->actual_bytes=actual<=lane->request_bytes?actual:0;
    if (c->state!=AOA_BULK_ACTIVE) return c->failure;
    if (expired(now,lane->deadline)) return fail(c,AOA_E_TIMEOUT);
    deadline_status=aoa_bulk_poll(c,now);
    if (deadline_status) return deadline_status;
    if (status || actual>lane->request_bytes || (!direction && !actual)) return fail(c,AOA_E_TRANSFER);
    if (direction) lane->offset=0;
    else lane->offset+=actual;
    return AOA_IDLE;
}
int aoa_bulk_stop(struct aoa_bulk_context *c,uint32_t disconnected)
{
    int status=active(c);
    if (status) return status;
    if (disconnected>1) return AOA_E_ARGUMENT;
    c->state=AOA_BULK_STOPPED;c->failure=disconnected?AOA_BULK_E_DISCONNECTED:AOA_E_CANCELLED;
    return c->failure;
}
int aoa_bulk_quiescent(const struct aoa_bulk_context *c)
{ return !c?AOA_E_ARGUMENT:(!c->rx.borrowed && !c->tx.borrowed); }
uint32_t aoa_bulk_context_bytes(void) { return sizeof(struct aoa_bulk_context); }
uint32_t aoa_bulk_request_bytes(void) { return sizeof(struct aoa_bulk_request); }
