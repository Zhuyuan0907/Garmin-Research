/* New REL integration candidate only; no native instruction execution claim.
 * The sole entry delegates to the common original-TTS bootstrap once. The
 * initialized .data guard must remain OUTSIDE the relinked common zero span.
 * Original loader serialization and resident no-reload are prerequisites.
 */
#include "ui_music_single.h"
extern int native_app_component_entry(void *loader);

uint32_t native_ui_music_entry_phase = UI_MUSIC_ENTRY_COLD;
struct ui_music_single native_ui_music_resident;
static const struct umcn_control_functions core = {
    umc_init, umc_runtime_ready, umc_service, umc_status_read, umc_admission,
    umc_source_started, umc_cleanup_returned, umc_callback_acquire, umc_callback_release, umc_kick
};

int native_ui_music_single_entry(void *loader)
{
    int result;
    if (native_ui_music_entry_phase != UI_MUSIC_ENTRY_COLD) return UMCN_PINNED;
    native_ui_music_entry_phase = UI_MUSIC_ENTRY_CLAIMED;
    result = native_app_component_entry(loader);
    native_ui_music_resident.bootstrap_result = result;
    native_ui_music_resident.bootstrap_done = 1;
    native_ui_music_entry_phase = (result == 6 || result == 11) ?
        UI_MUSIC_ENTRY_DONE : UI_MUSIC_ENTRY_FAILED;
    /* Preserve the original voice result; no UI/radio/task boot here. */
    return result;
}

int native_ui_music_attach_channel8(const struct umcn_bindings *bindings,
                                   uint32_t gui_owner_tcb, uint32_t cookie)
{
    struct ui_music_single *s = &native_ui_music_resident;
    int result;
    if (native_ui_music_entry_phase != UI_MUSIC_ENTRY_DONE || !s->bootstrap_done)
        return UMC_NOT_READY;
    if (s->attached || s->attach_failed_pinned || s->adapter.magic || s->control.magic)
        return UMCN_PINNED;
    if (!bindings || !gui_owner_tcb || !cookie) return UMCN_BINDING_MISSING;
    if (bindings->channel != UMC_PHONE_CHANNEL8) return UMCN_UNSUPPORTED_ROUTE;
    if (!bindings->current_task || !bindings->source || !bindings->source->tcb)
        return UMCN_BINDING_MISSING;
    if (bindings->current_task(bindings->integration_context) != bindings->source->tcb)
        return UMCN_OWNER_MISMATCH;
    result = umcn_init(&s->adapter, &s->control, bindings, &core, cookie);
    if (result) {
        if (s->adapter.magic || s->control.magic) s->attach_failed_pinned = 1;
        return result;
    }
    result = umcn_set_cleanup_bridge(&s->adapter);
    if (result) { s->attach_failed_pinned = 1; return result; }
    s->gui_owner_tcb = gui_owner_tcb;
    s->attached = 1;
    return UMCN_OK;
}

int native_ui_music_owner_ready(void)
{ return native_ui_music_resident.attached ? umcn_owner_ready(&native_ui_music_resident.adapter) : UMC_NOT_READY; }
int native_ui_music_service_owner(void)
{ return native_ui_music_resident.attached ? umcn_service_owner(&native_ui_music_resident.adapter) : UMC_NOT_READY; }
int native_ui_music_note_publication(void)
{ return native_ui_music_resident.attached ? umcn_note_owned_publication(&native_ui_music_resident.adapter) : UMC_NOT_READY; }
int native_ui_music_after_iteration(int actual_result)
{ return native_ui_music_resident.attached ? umcn_after_native_iteration(&native_ui_music_resident.adapter, actual_result) : UMC_NOT_READY; }
int native_ui_music_admission(uint32_t generation, uint32_t gate)
{ return native_ui_music_resident.attached ? umcn_admission(&native_ui_music_resident.adapter, generation, gate) : 0; }
int native_ui_music_media_begin(uint32_t generation, struct umc_lease *lease)
{ return native_ui_music_resident.attached ? umc_media_acquire(&native_ui_music_resident.control, generation, lease) : UMC_NOT_READY; }
int native_ui_music_media_current(const struct umc_lease *lease)
{ return native_ui_music_resident.attached ? umc_media_current(&native_ui_music_resident.control, lease) : 0; }
int native_ui_music_media_end(struct umc_lease *lease)
{ return native_ui_music_resident.attached ? umc_media_release(&native_ui_music_resident.control, lease) : UMC_NOT_READY; }
int native_ui_music_status(struct umc_status *status)
{ return native_ui_music_resident.attached ? umc_status_read(&native_ui_music_resident.control, status) : UMC_NOT_READY; }

int native_ui_music_gui_owner(void)
{
    struct ui_music_single *s = &native_ui_music_resident;
    if (!s->attached || !s->gui_owner_tcb) return 0;
    return s->adapter.native.current_task(s->adapter.native.integration_context) == s->gui_owner_tcb;
}

static int request(int start, uint32_t *generation)
{
    struct ui_music_single *s = &native_ui_music_resident;
    uint32_t key, token = 0;
    int result;
    if (!native_ui_music_gui_owner()) return UMC_WRONG_OWNER;
    /* Core posts only after publishing its durable command and exclusion ends.
     * No synchronous native START or cancellation occurs on the GUI stack. */
    result = start ? umc_request_start(&s->control, &token) : umc_request_stop(&s->control, &token);
    key = s->adapter.native.irq_save(s->adapter.native.integration_context);
    s->action_calls++;
    if (result < 0) s->action_rejections++;
    s->last_action_result = result;
    s->last_action_generation = token;
    s->adapter.native.irq_restore(s->adapter.native.integration_context, key);
    if (generation) *generation = token;
    return result;
}
int native_ui_music_request_start(uint32_t *generation) { return request(1, generation); }
int native_ui_music_request_stop(uint32_t *generation) { return request(0, generation); }

void native_ui_music_menu_activate(uint32_t context)
{
    struct umc_status status;
    if (context != UI_MUSIC_MENU_CONTEXT || !native_ui_music_gui_owner()) return;
    if (native_ui_music_status(&status)) return;
    if (status.state == UMC_IDLE || status.state == UMC_STOPPED)
        (void)native_ui_music_request_start(0);
    else if (status.state == UMC_START_QUEUED || status.state == UMC_ARMING ||
             status.state == UMC_ARMED || status.state == UMC_ACTIVE)
        (void)native_ui_music_request_stop(0);
    /* STOPPING is disabled for this one-icon toggle; explicit START still
     * supports the frozen core's queued restart contract. */
}

uint32_t native_ui_music_menu_appearance(uint32_t context, void *visuals,
                                        void *caption, uint32_t *word)
{
    struct umc_status status;
    (void)visuals; (void)caption; (void)word;
    if (context != UI_MUSIC_MENU_CONTEXT || !native_ui_music_gui_owner() ||
        native_ui_music_status(&status)) return 4;
    return status.state == UMC_IDLE || status.state == UMC_STOPPED ||
        status.state == UMC_START_QUEUED || status.state == UMC_ARMING ||
        status.state == UMC_ARMED || status.state == UMC_ACTIVE ? 0u : 4u;
}

const void *const native_ui_music_single_api[] __attribute__((used, section(".ui_music_single_api"))) = {
    (const void *)native_ui_music_attach_channel8, (const void *)native_ui_music_owner_ready,
    (const void *)native_ui_music_service_owner, (const void *)native_ui_music_note_publication,
    (const void *)native_ui_music_after_iteration, (const void *)native_ui_music_admission,
    (const void *)native_ui_music_media_begin, (const void *)native_ui_music_media_current,
    (const void *)native_ui_music_media_end,
    (const void *)native_ui_music_request_start, (const void *)native_ui_music_request_stop,
    (const void *)native_ui_music_status, (const void *)native_ui_music_menu_activate,
    (const void *)native_ui_music_menu_appearance
};
