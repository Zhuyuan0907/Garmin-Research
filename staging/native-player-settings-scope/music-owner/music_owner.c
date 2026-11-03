#include "music_owner.h"
extern volatile struct umcn_source_view source_worker_state;
volatile struct music_owner_trace music_owner_trace;
static int owner(void)
{
    if (!source_worker_state.tcb || music_owner_current()!=source_worker_state.tcb) {
        music_owner_trace.owner_rejections++; return 0;
    }
    return 1;
}
int music_owner_initialized(int actual_result)
{
    if (!owner()) return UMC_WRONG_OWNER;
    music_owner_trace.initializer_returns++;
    if (actual_result) return actual_result;
    /* Original coordinator/runtime wrapper produced readiness. This call
     * neither attaches nor invents reservation, AV session or IRQ state. */
    if (!native_ui_music_resident.attached) return UMCN_BINDING_MISSING;
    music_owner_trace.last_ready=native_ui_music_owner_ready();
    return music_owner_trace.last_ready;
}
int music_owner_control_boundary(uint32_t pending)
{
    if (!owner()) return UMC_WRONG_OWNER;
    if (pending & UMC_SOURCE_EVENT) music_owner_trace.control_events++;
    if (pending & ~UMC_SOURCE_EVENT) music_owner_trace.ordinary_events++;
    if (!native_ui_music_resident.attached) return UMCN_BINDING_MISSING;
    music_owner_trace.last_ready=native_ui_music_owner_ready();
    if (music_owner_trace.last_ready!=UMC_OK && music_owner_trace.last_ready!=UMC_ALREADY)
        return music_owner_trace.last_ready;
    if (!(pending & UMC_SOURCE_EVENT)) return UMC_OK;
    music_owner_trace.service_calls++;
    music_owner_trace.last_service=native_ui_music_service_owner();
    return music_owner_trace.last_service;
}
int music_owner_after_boundary(int actual_result)
{
    if (!owner()) return UMC_WRONG_OWNER;
    music_owner_trace.iteration_returns++;
    if (!source_worker_state.cancel_requested)
        music_owner_trace.cancel_flag_cleared_observations++;
    if (!native_ui_music_resident.attached) return UMCN_BINDING_MISSING;
    /* Only this persistent source actor observes actual registration after
     * complete coordinator return. The adapter independently validates node,
     * token/anchor/native_calls and native ownership witness before STARTED. */
    music_owner_trace.publication_observations++;
    music_owner_trace.last_publication=native_ui_music_note_publication();
    music_owner_trace.last_iteration=native_ui_music_after_iteration(actual_result);
    return music_owner_trace.last_iteration;
}
int music_owner_bind_on_source(struct umcn_bindings *bindings,uint32_t gui,uint32_t cookie)
{
    int result;
    if (!owner()) return UMC_WRONG_OWNER;
    if (!bindings) return UMCN_BINDING_MISSING;
    if (bindings->channel && bindings->channel!=8u) return UMCN_UNSUPPORTED_ROUTE;
    result=native_ui_music_linked_bindings(bindings);
    if (result!=UMCN_BINDING_MISSING && result!=UMCN_OK) return result;
    if (!bindings->resident_storage_confirmed || !bindings->ownership_snapshot ||
        !bindings->prepare_session || !bindings->integration_context) return UMCN_BINDING_MISSING;
    if (bindings->channel!=8u) return UMCN_UNSUPPORTED_ROUTE;
    return native_ui_music_attach_channel8(bindings,gui,cookie);
}
const void *const music_owner_api[] __attribute__((used,section(".music_owner_api")))={
    (const void *)music_owner_initialized,(const void *)music_owner_control_boundary,
    (const void *)music_owner_after_boundary,(const void *)music_owner_bind_on_source
};
