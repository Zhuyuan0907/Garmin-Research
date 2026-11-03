/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wire.h"
#define AA_WIRE_MAGIC UINT32_C(0x57495231)
#define COLLECT 1
#define PENDING 2
#define FAILED 3
#define CLOSED 4
static uint16_t read16(const uint8_t *p)
{ return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static uint32_t read32(const uint8_t *p)
{ return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3]; }
static int valid(const struct aa_wire_parser *p)
{ return p && p->initialized == AA_WIRE_MAGIC; }
static int fail(struct aa_wire_parser *p, int error)
{ p->state = FAILED; p->error = error; return error; }
static int leave(struct aa_wire_parser *p, int result)
{ p->in_feed = 0; return result; }
static void collect_new(struct aa_wire_parser *p)
{
    p->state = COLLECT; p->header_used = 0; p->header_needed = 4;
    p->payload_used = 0; p->payload_bytes = 0;
}
int aa_wire_init(struct aa_wire_parser *p, uint8_t *storage, size_t capacity,
                 aa_wire_callback callback, void *arg)
{
    struct aa_wire_parser fresh = {0};
    if (!p || !callback || capacity > UINT16_MAX || (capacity && !storage))
        return AA_WIRE_E_ARGUMENT;
    fresh.storage = storage; fresh.capacity = capacity;
    fresh.callback = callback; fresh.callback_arg = arg;
    fresh.initialized = AA_WIRE_MAGIC;
    *p = fresh;
    collect_new(p);
    return AA_WIRE_OK;
}
int aa_wire_feed(struct aa_wire_parser *p, const uint8_t *input, size_t bytes,
                 size_t *consumed)
{
    size_t n, i;
    struct aa_wire_frame frame;
    int status;
    if (!consumed) return AA_WIRE_E_ARGUMENT;
    *consumed = 0;
    if (!valid(p) || (bytes && !input)) return AA_WIRE_E_ARGUMENT;
    if (p->in_feed) return AA_WIRE_E_REENTRANT;
    if (p->state == FAILED) return p->error;
    if (p->state == CLOSED) return bytes ? AA_WIRE_E_STATE : AA_WIRE_OK;
    if (p->state != COLLECT && p->state != PENDING) return AA_WIRE_E_STATE;
    p->in_feed = 1;
    for (;;) {
        if (p->state == PENDING) {
            frame.channel = p->header[0]; frame.flags = p->header[1];
            frame.payload_bytes = p->payload_bytes;
            frame.total_plain_bytes = (frame.flags & 3u) == AA_WIRE_FIRST
                                    ? read32(p->header + 4) : 0;
            frame.payload = p->storage;
            status = p->callback(p->callback_arg, &frame);
            p->callback_status = status;
            if (status == AA_WIRE_PAUSED) return leave(p, AA_WIRE_PAUSED);
            if (status != AA_WIRE_OK)
                return leave(p, fail(p, AA_WIRE_E_CALLBACK));
            collect_new(p);
        }
        while (p->header_used < p->header_needed && *consumed < bytes)
            p->header[p->header_used++] = input[(*consumed)++];
        if (p->header_used < p->header_needed) return leave(p, AA_WIRE_OK);
        if (p->header_needed == 4) {
            if (p->header[1] & 0xf0u)
                return leave(p, fail(p, AA_WIRE_E_FLAGS));
            p->payload_bytes = read16(p->header + 2);
            if (p->payload_bytes > p->capacity)
                return leave(p, fail(p, AA_WIRE_E_CAPACITY));
            if ((p->header[1] & 3u) == AA_WIRE_FIRST) {
                p->header_needed = 8;
                continue;
            }
        }
        n = (size_t)p->payload_bytes - p->payload_used;
        if (n > bytes - *consumed) n = bytes - *consumed;
        for (i = 0; i < n; ++i)
            p->storage[p->payload_used + i] = input[*consumed + i];
        p->payload_used += n; *consumed += n;
        if (p->payload_used < p->payload_bytes) return leave(p, AA_WIRE_OK);
        p->state = PENDING;
    }
}
int aa_wire_finish(struct aa_wire_parser *p)
{
    if (!valid(p)) return AA_WIRE_E_ARGUMENT;
    if (p->in_feed) return AA_WIRE_E_REENTRANT;
    if (p->state == FAILED) return p->error;
    if (p->state == PENDING) return AA_WIRE_PAUSED;
    if (p->state == CLOSED) return AA_WIRE_OK;
    if (p->state != COLLECT) return AA_WIRE_E_STATE;
    if (p->header_used || p->payload_used)
        return fail(p, AA_WIRE_E_TRUNCATED);
    p->state = CLOSED;
    return AA_WIRE_OK;
}
int aa_wire_reset(struct aa_wire_parser *p)
{
    if (!valid(p)) return AA_WIRE_E_ARGUMENT;
    if (p->in_feed) return AA_WIRE_E_REENTRANT;
    collect_new(p); p->error = 0; p->callback_status = 0;
    return AA_WIRE_OK;
}
