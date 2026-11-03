/* NEW owning TU includes frozen FIFO/anchor bytes exactly once. The old
 * unleased APIs are private and garbage collected. The registration seed
 * remains a legacy source token; native binding/release use a distinct scoped
 * session. No frozen file, native MAIN code or original return is changed. */
#include "music_session_guard_v4.h"
#define memory_output_register mcs_original_output_register
#define memory_output_read mcs_original_output_read
#define memory_output_after_selection mcs_original_output_after_selection
#define memory_output_release mcs_original_output_release
#define memory_output_api mcs_unleased_output_api
#include "/root/garmin/staging/native-player-settings-scope/music-owner/memory_output_owner.c"
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
    if(!mcs_reader_admit(mcs_bridge_context,instance))return 0;
    /* Frozen reader consumes current FIFO tickets, validates each generation
     * and retains slot.in_flight until its unlocked copy has finished. Its
     * active_ticket test is a legacy source-live boolean, not a slot lookup. */
    return mcs_original_output_read(instance,output,capacity);
}
int memory_output_bind_selected_session(uint32_t session)
{
    struct mcs_guard *g=mcs_bridge_context;uint32_t f;int r=MCS_REJECTED;
    if(!g || g->magic!=MCS_MAGIC)return MCS_REJECTED;
    f=lock();
    if(!memory_output_control.native_calls && !memory_output_control.reader_in_flight &&
       !g->borrow && !g->native_mutation && session==g->epoch &&
       (word(record(),0x108u)==STOCK_READ ||
        word(record(),0x108u)==(uint32_t)(uintptr_t)mcs_original_output_read ||
        word(record(),0x108u)==(uint32_t)(uintptr_t)memory_output_read)){
        r=mcs_capture_selected(g,session);
        if(!r){
            *(volatile uint32_t *)(record()+0x108u)=(uint32_t)(uintptr_t)memory_output_read;
            continuous_anchor_instance=g->selected_instance;
            memory_output_control.installed=1;
        }
    }
    unlock(f);return r;
}
/* Explicitly reject the old ticket-shaped selection/release APIs. A caller
 * must use the scoped session APIs above/below, never its current FIFO head. */
int memory_output_after_selection(uint32_t ticket)
{(void)ticket;return MCS_REJECTED;}
int memory_output_release(uint32_t ticket)
{(void)ticket;return MCS_REJECTED;}
int memory_output_release_session(uint32_t session)
{
    struct mcs_guard *g=mcs_bridge_context;uint32_t f,seed;int r;
    if(!g || g->magic!=MCS_MAGIC)return MCS_REJECTED;
    f=lock();
    if(g->borrow || memory_output_control.reader_in_flight){unlock(f);return UMC_PENDING;}
    if(!session || session!=g->epoch || session!=g->selected_session ||
       !g->held || !g->native_mutation || !g->registration_ticket){
        unlock(f);return MCS_REJECTED;
    }
    seed=g->registration_ticket;unlock(f);
    /* Original release requires the native stop/cleanup/list removal boundary
     * plus idle methods/provider/mixer. Empty FIFO does not release anchor. */
    r=mcs_original_output_release(seed);
    if(!r){f=lock();g->selected_session=0;g->selected_instance=UINT32_MAX;
        g->registration_ticket=0;unlock(f);}
    return r;
}

uint32_t resident_pcm_address(uint32_t index)
{ return index<4u?(uint32_t)(uintptr_t)buffers[index]:0u; }
