/* HWID1352/SW8.00 integration prototype. Not a loader image or App proof.
 * Storage, adapter functions and all callbacks must remain resident.
 * Metadata exclusion is supplied by an adapter; this module supplies no IRQ,
 * native task, Bluetooth, audio, allocation or hardware implementation.
 */
#ifndef GARMIN_UI_MUSIC_CONTROL_PROTOTYPE_H
#define GARMIN_UI_MUSIC_CONTROL_PROTOTYPE_H
#include <stdint.h>

#define UMC_ABI_VERSION 1u
#define UMC_SOURCE_EVENT 0x80000u
#define UMC_MAGIC 0x554d4331u

enum umc_result {
    UMC_OK = 0, UMC_PENDING = 1, UMC_ALREADY = 2,
    UMC_BAD_ARGUMENT = -1, UMC_NOT_READY = -2, UMC_BUSY = -3,
    UMC_STALE = -4, UMC_WRONG_OWNER = -5, UMC_OVERFLOW = -6,
    UMC_WAKE_FAILED = -7, UMC_ADAPTER_FAILED = -8, UMC_PINNED = -9
};
enum umc_state {
    UMC_BOOTING = 0, UMC_IDLE, UMC_START_QUEUED, UMC_ARMING,
    UMC_ARMED, UMC_ACTIVE, UMC_STOPPING, UMC_STOPPED, UMC_ERROR_PINNED
};
enum umc_route { UMC_PHONE_CHANNEL8 = 8, UMC_WAV_SOURCE9 = 9 };
enum umc_gate {
    UMC_GATE_CONFIG = 1, UMC_GATE_REMOTE_START,
    UMC_GATE_EVENT17, UMC_GATE_F1, UMC_GATE_CONSUMER
};

/* Each field is evidence from a serialized native owner boundary, not a flag
 * the UI may invent. generation/cookie identify this controller's route.
 * cancel_pipeline_returned requires coordinator cancel/pump to have returned
 * zero and source cancel_requested to have cleared, not request_cancel()==0.
 * A never-published source needs the same original-owner cancellation barrier;
 * it does not need an original cleanup callback that could never occur.
 */
struct umc_stop_evidence {
    uint32_t generation, ownership_cookie, route;
    uint32_t ownership_confirmed, cancel_pipeline_returned;
    uint32_t source_was_published, source_token, never_published_barrier;
    uint32_t native_idle, node_count, methods_live;
    uint32_t provider_active, mixer_active, driver_active;
    uint32_t native_calls, reader_in_flight;
    uint32_t coordinator_busy, coordinator_ticket, coordinator_cancel_pending;
    uint32_t anchor_live, owned_busy, owned_count;
    uint32_t queue_producer_busy, queue_consumer_busy, queue_pending;
    uint32_t node_removal_returned, anchor_release_returned;
    uint32_t fifo_discard_returned, queue_clear_returned;
};

struct umc_adapters {
    void *context;
    /* Short original IRQ-save/restore section in future guest integration. */
    uint32_t (*metadata_enter)(void *);
    void (*metadata_leave)(void *, uint32_t);
    uint32_t (*current_actor)(void *);
    /* Normal-context original2FCF44, called AFTER metadata exclusion ends. */
    int (*wake_source)(void *, uint32_t source_tcb, uint32_t event);
    /* Called only on the existing source actor, never under metadata exclusion.
     * Validate native route ownership/readiness. PHONE8 arms reception; it must
     * not fake AVDTP state/remote START. WAV9 may run original synchronous start.
     * Coherent live-session resume/reset is the adapter's explicit contract.
     */
    int (*prepare_start)(void *, uint32_t route, uint32_t generation,
                         uint32_t ownership_cookie);
    /* PHONE8 maps to existing music_runtime_cancel/source_worker pipeline;
     * original coordinator alone owns36AF75/removal/release. WAV9 maps to its
     * characterized owned-source stop pipeline. Return0 ONLY accepts request.
     */
    int (*request_cancel)(void *, uint32_t route, uint32_t generation,
                          uint32_t ownership_cookie);
    /* Nonblocking owner-boundary observation. No native state repair/cleanup. */
    int (*observe_stop)(void *, uint32_t route, uint32_t generation,
                        uint32_t ownership_cookie, struct umc_stop_evidence *);
};

struct umc_config {
    uint32_t source_tcb, route, ownership_cookie;
    /* Caller must pin real module/callback/context storage before init. */
    uint32_t resident_storage_confirmed;
};
struct umc_status {
    uint32_t state, route, generation, admission_epoch, armed;
    uint32_t stop_requested_generation, stop_completed_generation;
    uint32_t cancel_issued, source_seen, source_token, cleanup_seen;
    uint32_t media_references, callback_references, service_busy;
    int32_t last_error, last_wake_error;
};
struct umc_lease {
    /* Noncopyable caller-owned token; kind1=media,kind2=whole callback. */
    uint32_t held, kind, generation, admission_epoch, ownership_cookie;
};

/* Caller supplies ZERO-initialized resident storage after the single common
 * bootstrap. Reinitialization is rejected; there is deliberately no destroy,
 * unload, reset, free, native task creation or worker-shutdown API.
 */
struct umc_controller {
    uint32_t magic;
    struct umc_config config;
    struct umc_adapters adapters;
    struct umc_status status;
    uint32_t pending_start;
};

int umc_init(struct umc_controller *, const struct umc_config *,
             const struct umc_adapters *);
int umc_runtime_ready(struct umc_controller *); /* Source owner only. */
int umc_request_start(struct umc_controller *, uint32_t *generation);
int umc_request_stop(struct umc_controller *, uint32_t *generation);
int umc_service(struct umc_controller *);       /* Source owner only. */
int umc_kick(struct umc_controller *);
int umc_status_read(struct umc_controller *, struct umc_status *);
int umc_admission(struct umc_controller *, uint32_t generation, uint32_t gate);
int umc_media_acquire(struct umc_controller *, uint32_t generation,
                      struct umc_lease *);
int umc_media_current(struct umc_controller *, const struct umc_lease *);
int umc_media_release(struct umc_controller *, struct umc_lease *);
/* Cover ENTIRE native reader/cleanup wrapper callback, including post/preempt.
 * Release wakes a STOPPING owner so an in-flight callback cannot strand Stop.
 */
int umc_callback_acquire(struct umc_controller *, struct umc_lease *);
int umc_callback_release(struct umc_controller *, struct umc_lease *);
/* Call from owned native publication/start, including a publication racing
 * Stop. Tokens must come from the tracked native anchor/node generation.
 */
int umc_source_started(struct umc_controller *, uint32_t route,
                       uint32_t generation, uint32_t ownership_cookie, uint32_t source_token);
/* Call only AFTER full original3B9DFC cleanup return. This is not STOP_DONE. */
int umc_cleanup_returned(struct umc_controller *, uint32_t route,
                         uint32_t generation, uint32_t ownership_cookie, uint32_t source_token);

struct umc_exports {
    uint32_t abi_version;
    int (*init)(struct umc_controller *, const struct umc_config *, const struct umc_adapters *);
    int (*start)(struct umc_controller *, uint32_t *);
    int (*stop)(struct umc_controller *, uint32_t *);
    int (*service)(struct umc_controller *);
    int (*status)(struct umc_controller *, struct umc_status *);
    int (*admission)(struct umc_controller *, uint32_t, uint32_t);
    int (*source_started)(struct umc_controller *, uint32_t, uint32_t, uint32_t, uint32_t);
    int (*cleanup_returned)(struct umc_controller *, uint32_t, uint32_t, uint32_t, uint32_t);
};
extern const struct umc_exports ui_music_control_api;
#endif
