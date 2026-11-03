#include "ui_music_control.h"

static int valid(const struct umc_controller *c)
{ return c && c->magic == UMC_MAGIC; }
static uint32_t enter(struct umc_controller *c)
{ return c->adapters.metadata_enter(c->adapters.context); }
static void leave(struct umc_controller *c, uint32_t key)
{ c->adapters.metadata_leave(c->adapters.context, key); }
static int owner(struct umc_controller *c)
{ return c->adapters.current_actor(c->adapters.context) == c->config.source_tcb; }
static int admit(const struct umc_controller *c, uint32_t generation)
{
    return c->config.route == UMC_PHONE_CHANNEL8 && c->status.armed &&
        generation && generation == c->status.generation &&
        (c->status.state == UMC_ARMED || c->status.state == UMC_ACTIVE);
}
static int wake(struct umc_controller *c)
{
    int result = c->adapters.wake_source(c->adapters.context,
                                       c->config.source_tcb, UMC_SOURCE_EVENT);
    uint32_t key = enter(c);
    c->status.last_wake_error = result;
    leave(c, key);
    return result ? UMC_WAKE_FAILED : UMC_OK;
}

int umc_init(struct umc_controller *c, const struct umc_config *cfg,
             const struct umc_adapters *a)
{
    uint32_t i;
    unsigned char *raw;
    if (!c || !cfg || !a || !cfg->source_tcb || !cfg->ownership_cookie ||
        !cfg->resident_storage_confirmed ||
        (cfg->route != UMC_PHONE_CHANNEL8 && cfg->route != UMC_WAV_SOURCE9) ||
        !a->metadata_enter || !a->metadata_leave || !a->current_actor ||
        !a->wake_source || !a->prepare_start || !a->request_cancel || !a->observe_stop)
        return UMC_BAD_ARGUMENT;
    if (c->magic) return UMC_PINNED;
    /* Only first init, before publication. Never clear a live controller. */
    raw = (unsigned char *)c;
    for (i = 0; i < sizeof(*c); ++i) raw[i] = 0;
    c->config = *cfg;
    c->adapters = *a;
    c->status.state = UMC_BOOTING;
    c->status.route = cfg->route;
    c->magic = UMC_MAGIC;
    return UMC_OK;
}

int umc_runtime_ready(struct umc_controller *c)
{
    uint32_t key;
    if (!valid(c)) return UMC_BAD_ARGUMENT;
    if (!owner(c)) return UMC_WRONG_OWNER;
    key = enter(c);
    if (c->status.state != UMC_BOOTING) {
        leave(c, key); return UMC_ALREADY;
    }
    /* Caller observed full native initializer result/owner/decoder readiness.
     * This API does not create that evidence or start a native task. */
    c->status.state = UMC_IDLE;
    leave(c, key);
    return UMC_OK;
}

int umc_request_start(struct umc_controller *c, uint32_t *generation)
{
    uint32_t key;
    if (!valid(c) || !generation) return UMC_BAD_ARGUMENT;
    key = enter(c);
    *generation = c->status.generation;
    if (c->status.state == UMC_BOOTING) {
        leave(c, key); return UMC_NOT_READY;
    }
    if (c->status.state != UMC_IDLE && c->status.state != UMC_STOPPED) {
        int rejection = c->status.state == UMC_ERROR_PINNED ? UMC_PINNED : UMC_BUSY;
        leave(c, key); return rejection;
    }
    if (c->status.service_busy || c->status.media_references || c->status.callback_references) {
        leave(c, key); return UMC_BUSY;
    }
    if (c->status.generation == UINT32_MAX || c->status.admission_epoch == UINT32_MAX) {
        leave(c, key); return UMC_OVERFLOW;
    }
    c->status.generation++;
    c->status.admission_epoch++;
    c->status.armed = 0;
    c->status.state = UMC_START_QUEUED;
    c->status.cancel_issued = c->status.source_seen = c->status.source_token = c->status.cleanup_seen = 0;
    c->status.last_error = 0;
    c->pending_start = 1;
    *generation = c->status.generation;
    leave(c, key);
    return wake(c) ? UMC_WAKE_FAILED : UMC_PENDING;
}

int umc_request_stop(struct umc_controller *c, uint32_t *generation)
{
    uint32_t key;
    if (!valid(c) || !generation) return UMC_BAD_ARGUMENT;
    key = enter(c);
    *generation = c->status.generation;
    if (c->status.state == UMC_BOOTING) {
        leave(c, key); return UMC_NOT_READY;
    }
    if (c->status.state == UMC_IDLE || c->status.state == UMC_STOPPED) {
        /* No fabricated completion generation for an idle Stop. */
        leave(c, key); return UMC_ALREADY;
    }
    if (c->status.state == UMC_STOPPING) {
        leave(c, key); return UMC_ALREADY;
    }
    if (c->status.state == UMC_ERROR_PINNED) c->status.cancel_issued = 0;
    /* Close admission immediately. State/generation checks also invalidate an
     * old lease when the epoch has saturated; never wrap its identity. */
    c->status.armed = 0;
    if (c->status.admission_epoch != UINT32_MAX) c->status.admission_epoch++;
    c->status.state = UMC_STOPPING;
    c->status.stop_requested_generation = c->status.generation;
    c->pending_start = 0;
    leave(c, key);
    return wake(c) ? UMC_WAKE_FAILED : UMC_PENDING;
}

static int stop_complete(const struct umc_controller *c, const struct umc_stop_evidence *e)
{
    if (e->generation != c->status.generation || e->route != c->config.route ||
        e->ownership_cookie != c->config.ownership_cookie || !e->ownership_confirmed ||
        !e->cancel_pipeline_returned || !e->native_idle || e->node_count || e->methods_live ||
        e->provider_active || e->mixer_active || e->driver_active || e->native_calls ||
        e->reader_in_flight || e->coordinator_busy || e->coordinator_ticket ||
        e->coordinator_cancel_pending || e->anchor_live || e->owned_busy || e->owned_count ||
        e->queue_producer_busy || e->queue_consumer_busy || e->queue_pending ||
        c->status.media_references || c->status.callback_references)
        return 0;
    if (e->source_was_published || c->status.source_seen) {
        if (!e->source_was_published || !c->status.source_seen || !c->status.cleanup_seen ||
            !e->source_token || e->source_token != c->status.source_token)
            return 0;
        if (c->config.route == UMC_PHONE_CHANNEL8 &&
            (!e->node_removal_returned || !e->anchor_release_returned || !e->fifo_discard_returned))
            return 0;
        if (c->config.route == UMC_WAV_SOURCE9 && !e->queue_clear_returned) return 0;
    } else if (!e->never_published_barrier) return 0;
    return 1;
}

int umc_service(struct umc_controller *c)
{
    uint32_t key, generation, state, i;
    int result = UMC_PENDING, call_cancel = 0;
    struct umc_stop_evidence evidence;
    volatile unsigned char *zero = (volatile unsigned char *)&evidence;
    if (!valid(c)) return UMC_BAD_ARGUMENT;
    if (!owner(c)) return UMC_WRONG_OWNER;
    /* Explicit byte stores keep freestanding ARM code self-contained. Some
     * compilers lower a large automatic {0} initializer to external memset. */
    for (i = 0; i < sizeof(evidence); i++) zero[i] = 0;
    key = enter(c);
    if (c->status.service_busy) { leave(c, key); return UMC_BUSY; }
    c->status.service_busy = 1;
    generation = c->status.generation;
    state = c->status.state;
    if (state == UMC_START_QUEUED && c->pending_start) {
        c->pending_start = 0;
        c->status.state = UMC_ARMING;
    } else if (state == UMC_STOPPING && !c->status.cancel_issued) {
        c->status.cancel_issued = 1;
        call_cancel = 1;
    }
    leave(c, key);

    if (state == UMC_START_QUEUED) {
        result = c->adapters.prepare_start(c->adapters.context, c->config.route,
                                          generation, c->config.ownership_cookie);
        key = enter(c);
        /* Stop can run while prepare_start waits for an original native ACK.
         * It wins; a successful late prepare return never reopens admission. */
        if (c->status.state == UMC_ARMING && c->status.generation == generation) {
            c->status.last_error = result;
            c->status.state = result ? UMC_ERROR_PINNED :
                c->status.source_seen ? UMC_ACTIVE : UMC_ARMED;
            c->status.armed = result == 0;
        }
        state = c->status.state;
        leave(c, key);
        result = result ? UMC_ADAPTER_FAILED : UMC_OK;
    } else if (state == UMC_STOPPING) {
        if (call_cancel) {
            int accepted = c->adapters.request_cancel(c->adapters.context, c->config.route,
                                                      generation, c->config.ownership_cookie);
            if (accepted) {
                key = enter(c);
                c->status.last_error = accepted;
                c->status.state = UMC_ERROR_PINNED;
                leave(c, key);
                result = UMC_ADAPTER_FAILED;
            }
        }
        if (result != UMC_ADAPTER_FAILED) {
            int observed = c->adapters.observe_stop(c->adapters.context, c->config.route,
                                                   generation, c->config.ownership_cookie, &evidence);
            key = enter(c);
            if (!observed && c->status.state == UMC_STOPPING &&
                c->status.generation == generation && stop_complete(c, &evidence)) {
                c->status.state = UMC_STOPPED;
                c->status.stop_completed_generation = generation;
                c->status.last_error = 0;
                result = UMC_OK;
            } else {
                c->status.last_error = observed;
            }
            leave(c, key);
        }
    } else result = UMC_ALREADY;

    key = enter(c);
    c->status.service_busy = 0;
    state = c->status.state;
    call_cancel = state == UMC_STOPPING && !c->status.cancel_issued;
    leave(c, key);
    /* A Stop during synchronous prepare must be serviced without new media. */
    if (call_cancel) (void)wake(c);
    return state == UMC_STOPPING && result == UMC_OK ? UMC_PENDING : result;
}

int umc_kick(struct umc_controller *c)
{ return valid(c) ? wake(c) : UMC_BAD_ARGUMENT; }
int umc_status_read(struct umc_controller *c, struct umc_status *out)
{
    uint32_t key;
    if (!valid(c) || !out) return UMC_BAD_ARGUMENT;
    key = enter(c); *out = c->status; leave(c, key); return UMC_OK;
}
int umc_admission(struct umc_controller *c, uint32_t generation, uint32_t gate)
{
    uint32_t key;
    int allowed;
    if (!valid(c) || gate < UMC_GATE_CONFIG || gate > UMC_GATE_CONSUMER) return 0;
    key = enter(c); allowed = admit(c, generation); leave(c, key); return allowed;
}
int umc_media_acquire(struct umc_controller *c, uint32_t generation, struct umc_lease *lease)
{
    uint32_t key;
    if (!valid(c) || !lease || lease->held) return UMC_BAD_ARGUMENT;
    key = enter(c);
    if (!admit(c, generation)) { leave(c, key); return UMC_STALE; }
    if (c->status.media_references == UINT32_MAX) { leave(c, key); return UMC_OVERFLOW; }
    c->status.media_references++;
    lease->held = 1; lease->kind = 1; lease->generation = generation;
    lease->admission_epoch = c->status.admission_epoch;
    lease->ownership_cookie = c->config.ownership_cookie;
    leave(c, key); return UMC_OK;
}
int umc_media_current(struct umc_controller *c, const struct umc_lease *lease)
{
    uint32_t key;
    int current;
    if (!valid(c) || !lease) return 0;
    key = enter(c);
    current = lease->held && lease->kind == 1 && lease->ownership_cookie == c->config.ownership_cookie &&
        lease->admission_epoch == c->status.admission_epoch && admit(c, lease->generation);
    leave(c, key); return current;
}
int umc_media_release(struct umc_controller *c, struct umc_lease *lease)
{
    uint32_t key, stopping;
    if (!valid(c) || !lease) return UMC_BAD_ARGUMENT;
    key = enter(c);
    if (!lease->held || lease->kind != 1 || lease->ownership_cookie != c->config.ownership_cookie ||
        lease->generation != c->status.generation || !c->status.media_references) {
        leave(c, key); return UMC_STALE;
    }
    lease->held = 0; c->status.media_references--;
    stopping = c->status.state == UMC_STOPPING;
    leave(c, key);
    if (stopping) (void)wake(c);
    return UMC_OK;
}
int umc_callback_acquire(struct umc_controller *c, struct umc_lease *lease)
{
    uint32_t key;
    if (!valid(c) || !lease || lease->held) return UMC_BAD_ARGUMENT;
    key = enter(c);
    if (c->status.callback_references == UINT32_MAX) { leave(c, key); return UMC_OVERFLOW; }
    c->status.callback_references++;
    lease->held = 1; lease->kind = 2; lease->generation = c->status.generation;
    lease->admission_epoch = c->status.admission_epoch;
    lease->ownership_cookie = c->config.ownership_cookie;
    leave(c, key); return UMC_OK;
}
int umc_callback_release(struct umc_controller *c, struct umc_lease *lease)
{
    uint32_t key, stopping;
    if (!valid(c) || !lease) return UMC_BAD_ARGUMENT;
    key = enter(c);
    if (!lease->held || lease->kind != 2 || lease->ownership_cookie != c->config.ownership_cookie ||
        !c->status.callback_references) { leave(c, key); return UMC_STALE; }
    lease->held = 0; c->status.callback_references--;
    stopping = c->status.state == UMC_STOPPING;
    leave(c, key);
    if (stopping) (void)wake(c);
    return UMC_OK;
}
static int same_source(const struct umc_controller *c, uint32_t route,
                        uint32_t generation, uint32_t cookie)
{
    return generation && generation == c->status.generation &&
        route == c->config.route && cookie == c->config.ownership_cookie &&
        (c->status.state == UMC_ARMING || c->status.state == UMC_ARMED ||
         c->status.state == UMC_ACTIVE || c->status.state == UMC_STOPPING);
}
int umc_source_started(struct umc_controller *c, uint32_t route,
                       uint32_t generation, uint32_t cookie, uint32_t source_token)
{
    uint32_t key, stopping;
    if (!valid(c)) return UMC_BAD_ARGUMENT;
    key = enter(c);
    if (!source_token || !same_source(c, route, generation, cookie)) {
        leave(c, key); return UMC_STALE;
    }
    if (c->status.source_seen && c->status.source_token != source_token && !c->status.cleanup_seen) {
        leave(c, key); return UMC_BUSY;
    }
    if (c->status.source_token != source_token) c->status.cleanup_seen = 0;
    c->status.source_seen = 1;
    c->status.source_token = source_token;
    if (c->status.armed) c->status.state = UMC_ACTIVE;
    stopping = c->status.state == UMC_STOPPING;
    leave(c, key);
    if (stopping) (void)wake(c);
    return UMC_OK;
}
int umc_cleanup_returned(struct umc_controller *c, uint32_t route,
                         uint32_t generation, uint32_t cookie, uint32_t source_token)
{
    uint32_t key;
    if (!valid(c)) return UMC_BAD_ARGUMENT;
    key = enter(c);
    if (!same_source(c, route, generation, cookie) || !c->status.source_seen ||
        !source_token || c->status.source_token != source_token) {
        leave(c, key); return UMC_STALE;
    }
    c->status.cleanup_seen = 1;
    leave(c, key);
    return wake(c) ? UMC_WAKE_FAILED : UMC_OK;
}

const struct umc_exports ui_music_control_api
    __attribute__((used, section(".ui_music_control_api"))) = {
    UMC_ABI_VERSION, umc_init, umc_request_start, umc_request_stop,
    umc_service, umc_status_read, umc_admission, umc_source_started,
    umc_cleanup_returned
};
