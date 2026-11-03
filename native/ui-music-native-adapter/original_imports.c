#include "native_adapter.h"
#include "exact_continuous_bindings.h"

/* The host suite never invokes these original address imports. */
static uint32_t original_save(void *ignored)
{
    uint32_t flags;
    (void)ignored;
    flags=((uint32_t (*)(void))(uintptr_t)0x21b6ccu)();
    __asm__ volatile ("" ::: "memory"); return flags;
}
static void original_restore(void *ignored,uint32_t flags)
{
    (void)ignored; __asm__ volatile ("" ::: "memory");
    ((void (*)(uint32_t))(uintptr_t)0x21b6dcu)(flags);
}
static uint32_t original_current(void *ignored)
{ (void)ignored; return ((uint32_t (*)(void))(uintptr_t)0x358d25u)(); }
static void original_post(void *ignored,uint32_t tcb,uint32_t event)
{ (void)ignored; ((void (*)(uint32_t,uint32_t))(uintptr_t)0x2fcf44u)(tcb,event); }
static int exact_runtime_cancel(void *ignored)
{ (void)ignored; return ((int (*)(void))(uintptr_t)UMCN_RUNTIME_CANCEL)(); }
static void exact_source_completed(void *ignored,const volatile void *record)
{ (void)ignored; ((void (*)(const volatile void *))(uintptr_t)UMCN_SOURCE_COMPLETED)(record); }
int umcn_fill_exact_continuous_bindings(struct umcn_bindings *b)
{
    if(!b) return UMCN_BINDING_MISSING;
    b->irq_save=original_save; b->irq_restore=original_restore;
    b->current_task=original_current; b->native_post=original_post;
    b->runtime_cancel=exact_runtime_cancel; b->original_source_completed=exact_source_completed;
    b->runtime=(volatile struct umcn_runtime_view *)(uintptr_t)UMCN_RUNTIME_STATE;
    b->source=(volatile struct umcn_source_view *)(uintptr_t)UMCN_SOURCE_STATE;
    b->coordinator=(volatile struct umcn_coordinator_view *)(uintptr_t)UMCN_COORDINATOR_STATE;
    b->output=(volatile struct umcn_output_view *)(uintptr_t)UMCN_OUTPUT_STATE;
    b->owned=(volatile struct umcn_owned_view *)(uintptr_t)UMCN_OWNED_STATE;
    b->queue=(volatile struct umcn_queue_view *)(uintptr_t)UMCN_QUEUE_STATE;
    b->decoder=(volatile struct umcn_worker_view *)(uintptr_t)UMCN_DECODER_STATE;
    b->slots=(volatile struct umcn_slot_view *)(uintptr_t)UMCN_OUTPUT_SLOTS;
    b->source_record=(volatile uint8_t *)(uintptr_t)UMCN_SOURCE_RECORD;
    b->mixer_record=(volatile uint8_t *)(uintptr_t)UMCN_MIXER_RECORD;
    b->driver_record=(volatile uint8_t *)(uintptr_t)UMCN_DRIVER_RECORD;
    b->source_state=(volatile uint8_t *)(uintptr_t)UMCN_NATIVE_SOURCE_STATE;
    b->provider_pool=(volatile uint8_t *)(uintptr_t)UMCN_PROVIDER_POOL;
    b->anchor_address=UMCN_ANCHOR_ZERO; b->channel=8;
    /* Missing ownership/session/core/call-site bindings are left missing.
     * This helper does not initialize controller or certify residency. */
    return UMCN_BINDING_MISSING;
}
