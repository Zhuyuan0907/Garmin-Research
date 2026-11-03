/* NEW owning TU, replacing the old memory-output owning object in a FUTURE
 * image. Include frozen bytes exactly once; same static anchor survives.
 * Private original API array must NOT be retained/exported by the new linker. */
#include "music_session_guard.h"
#define memory_output_register mcs_original_output_register
#define memory_output_read mcs_original_output_read
#define memory_output_after_selection mcs_original_output_after_selection
#define memory_output_release mcs_original_output_release
#define memory_output_api mcs_unleased_output_api
#include "../../native-player-settings-scope/music-owner/memory_output_owner.c"
#undef memory_output_register
#undef memory_output_read
#undef memory_output_after_selection
#undef memory_output_release
#undef memory_output_api
int memory_output_register(uint32_t ticket)
{
    int r=mcs_register_begin(mcs_bridge_context,ticket);
    if(r)return r;
    r=mcs_original_output_register(ticket);
    return mcs_register_end(mcs_bridge_context,r);
}
uint32_t memory_output_read(uint32_t instance,uint8_t *output,uint32_t capacity)
{
    /* No current-pool-only fallback: an index lacks generation. Navigation
     * uses its unchanged methods; this reader is installed only on our anchor. */
    if(!mcs_reader_admit(mcs_bridge_context,instance))return 0;
    return mcs_original_output_read(instance,output,capacity);
}
int memory_output_after_selection(uint32_t ticket)
{
    struct mcs_guard *g=mcs_bridge_context;uint32_t f;int r=MCS_REJECTED;
    if(!g || g->magic!=MCS_MAGIC)return MCS_REJECTED;
    f=lock();
    /* Re-selection rebuilds the complete method array. Validate native
     * provider/anchor again; do not clear original installed metadata to make
     * the old one-shot attach pretend it is a first install. */
    if(!memory_output_control.native_calls && !memory_output_control.reader_in_flight &&
       !g->borrow && ticket && ticket==memory_output_control.active_ticket &&
       (word(record(),0x108u)==STOCK_READ ||
        word(record(),0x108u)==(uint32_t)(uintptr_t)mcs_original_output_read ||
        word(record(),0x108u)==(uint32_t)(uintptr_t)memory_output_read)){
        r=mcs_capture_selected(g,ticket);
        if(!r){
            *(volatile uint32_t *)(record()+0x108u)=(uint32_t)(uintptr_t)memory_output_read;
            continuous_anchor_instance=g->selected_instance;
            memory_output_control.installed=1;
        }
    }
    unlock(f);return r;
}
int memory_output_release(uint32_t ticket)
{
    struct mcs_guard *g=mcs_bridge_context;uint32_t f;int busy;
    if(!g || g->magic!=MCS_MAGIC)return MCS_REJECTED;
    f=lock();busy=g->borrow!=0;unlock(f);
    if(busy)return UMC_PENDING;
    /* Caller must hold mcs_mutation via NEW coordinator cancel wrapper.
     * The original release itself is never replaced by a synthetic done. */
    if(!g->native_mutation)return MCS_REJECTED;
    return mcs_original_output_release(ticket);
}
const void *const mcs_output_api[] __attribute__((used,section(".mcs_output_api")))={
    (const void *)memory_output_register,(const void *)memory_output_after_selection,
    (const void *)memory_output_read,(const void *)memory_output_release,
    (const void *)native_ui_music_owned_anchor_address
};
