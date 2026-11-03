/* Explicit single-actor offline driver for one original selector/full pull.
 * This caller is NOT the native mixer actor2FA572, which still BLs MAIN.
 * Storage remains resident; no cancellation completion/unload is invented. */
#include "music_session_guard_v2.h"
#include "memory_output.h"
extern int mcs_native_normal_context(void *);
extern uint32_t native_ui_music_owned_anchor_address(void);
extern int aas_pcm_initialize(uint32_t);
extern void aas_pcm_status(uint32_t *);

struct umc_controller aas_control;
struct mcs_guard aas_guard;
uint32_t aas_generation,aas_wakes;
static uint32_t irq_enter(void *p)
{(void)p;return ((uint32_t (*)(void))0x21b6ccu)();}
static void irq_leave(void *p,uint32_t flags)
{(void)p;((void (*)(uint32_t))0x21b6dcu)(flags);}
static uint32_t current_actor(void *p)
{(void)p;return ((uint32_t (*)(void))0x358d25u)();}
static int wake_fixture(void *p,uint32_t actor,uint32_t bits)
{(void)p;if(actor!=aas_guard.owner || bits!=UMC_SOURCE_EVENT)return -1;
 aas_wakes++;return 0;}
static int prepare_scoped(void *p,uint32_t route,uint32_t generation,uint32_t cookie)
{(void)p;if(route!=8 || cookie!=0x1352)return -1;
 return mcs_reserve_scoped(&aas_guard,generation);}
static int unavailable_cancel(void *p,uint32_t route,uint32_t gen,uint32_t cookie)
{(void)p;(void)route;(void)gen;(void)cookie;return -200;}
static int unavailable_stop(void *p,uint32_t route,uint32_t gen,uint32_t cookie,
                            struct umc_stop_evidence *e)
{(void)p;(void)route;(void)gen;(void)cookie;(void)e;return -200;}
int aas_initialize(uint32_t record,uint32_t pool)
{
    struct umc_config cfg={current_actor(0),8,0x1352,1};
    struct umc_adapters ops={0,irq_enter,irq_leave,current_actor,wake_fixture,
                            prepare_scoped,unavailable_cancel,unavailable_stop};
    _Static_assert(sizeof(struct output_control)==sizeof(struct umcn_output_view),"output ABI");
    _Static_assert(sizeof(struct owned_slot)==sizeof(struct umcn_slot_view),"slot ABI");
    int result=aas_pcm_initialize(8);
    if(result)return result;
    result=umc_init(&aas_control,&cfg,&ops);if(result)return result;
    result=mcs_init(&aas_guard,&aas_control,
        (volatile struct umcn_output_view *)&memory_output_control,
        (volatile struct umcn_slot_view *)memory_output_slots,
        (uint8_t *)record,(uint8_t *)pool,native_ui_music_owned_anchor_address(),
        mcs_native_normal_context,0);
    if(result)return result;
    mcs_bridge_context=&aas_guard;
    result=umc_runtime_ready(&aas_control);if(result)return result;
    result=umc_request_start(&aas_control,&aas_generation);
    if(result!=UMC_PENDING)return result;
    result=umc_service(&aas_control);if(result)return result;
    return mcs_install_queue_callback(&aas_guard);
}
int aas_register(uint32_t ticket){return memory_output_register(ticket);}
int aas_select(uint32_t ticket)
{
    int result=memory_output_selection_guard(ticket);if(result)return result;
    volatile uint8_t *r=aas_guard.source_record;
    result=((int (*)(volatile void *))0x277537u)(r+0x1a8u);
    if(result)return result;
    /* Index/default/factory preparation and busy flag come from original code. */
    (void)((int (*)(uint32_t,uint32_t))0x2f9f2fu)(8,0);
    return memory_output_after_selection(ticket);
}
int aas_stop(void){return umc_request_stop(&aas_control,&aas_generation);}
void aas_status(uint32_t *p)
{
    p[0]=aas_guard.selected_ticket;p[1]=aas_guard.selected_instance;
    p[2]=aas_guard.borrow!=0;p[3]=aas_guard.pulls;
    p[4]=aas_guard.full_returns;p[5]=aas_guard.pull_rejections;
    p[6]=aas_control.status.media_references;p[7]=aas_control.status.callback_references;
    p[8]=aas_control.status.stop_completed_generation;p[9]=aas_control.status.armed;
    p[10]=memory_output_control.active_ticket;p[11]=memory_output_control.installed;
    p[12]=memory_output_control.reader_in_flight;p[13]=memory_output_control.reads;
    p[14]=memory_output_control.bytes_read;p[15]=memory_output_slots[0].state;
    p[16]=memory_output_slots[0].ticket;p[17]=aas_wakes;
    aas_pcm_status(p+18);
}
/* Read-only in-flight snapshot used by CODE observers, never host-seeded. */
const uint32_t aas_offsets[] __attribute__((used,section(".aas_offsets")))={
    offsetof(struct mcs_guard,borrow),offsetof(struct mcs_guard,selected_ticket),
    offsetof(struct mcs_guard,selected_instance),
    offsetof(struct umc_controller,status)+offsetof(struct umc_status,media_references),
    offsetof(struct umc_controller,status)+offsetof(struct umc_status,callback_references)
};
