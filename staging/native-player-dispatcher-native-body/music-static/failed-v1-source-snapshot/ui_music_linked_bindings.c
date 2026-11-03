/* These relocations must bind to symbols from the same future single image.
 * The immutable old continuous absolute-address map is deliberately unused.
 * This file does not call boot/start, install a hook, or claim ownership. */
#include "ui_music_single.h"
extern int music_runtime_cancel(void);
extern void source_worker_completed(const volatile void *record);
extern volatile struct umcn_runtime_view music_runtime_state;
extern volatile struct umcn_source_view source_worker_state;
extern volatile struct umcn_coordinator_view coordinator_state;
extern volatile struct umcn_output_view memory_output_control;
extern volatile struct umcn_owned_view owned_media_control;
extern volatile struct umcn_queue_view media_queue_control;
extern volatile struct umcn_worker_view media_worker_state;
extern volatile struct umcn_slot_view memory_output_slots[4];
extern uint8_t anchor_zero;
static uint32_t save(void *ignored)
{ (void)ignored; return ((uint32_t (*)(void))(uintptr_t)0x21b6ccu)(); }
static void restore(void *ignored, uint32_t flags)
{ (void)ignored; ((void (*)(uint32_t))(uintptr_t)0x21b6dcu)(flags); }
static uint32_t current(void *ignored)
{ (void)ignored; return ((uint32_t (*)(void))(uintptr_t)0x358d25u)(); }
static void post(void *ignored, uint32_t tcb, uint32_t event)
{ (void)ignored; ((void (*)(uint32_t,uint32_t))(uintptr_t)0x2fcf44u)(tcb,event); }
static int cancel(void *ignored) { (void)ignored; return music_runtime_cancel(); }
static void completed(void *ignored, const volatile void *record)
{ (void)ignored; source_worker_completed(record); }
int native_ui_music_linked_bindings(struct umcn_bindings *b)
{
    if (!b) return UMCN_BINDING_MISSING;
    b->irq_save=save; b->irq_restore=restore; b->current_task=current; b->native_post=post;
    b->runtime_cancel=cancel; b->original_source_completed=completed;
    b->runtime=&music_runtime_state; b->source=&source_worker_state;
    b->coordinator=&coordinator_state; b->output=&memory_output_control;
    b->owned=&owned_media_control; b->queue=&media_queue_control;
    b->decoder=&media_worker_state; b->slots=memory_output_slots;
    b->source_record=(volatile uint8_t *)(uintptr_t)(0x034e6f08u+8u*520u);
    b->mixer_record=(volatile uint8_t *)(uintptr_t)(0x034e5378u+8u*304u);
    b->driver_record=(volatile uint8_t *)(uintptr_t)(0x034e32bcu+8u*84u);
    b->source_state=(volatile uint8_t *)(uintptr_t)(0x034e9398u+8u);
    b->provider_pool=(volatile uint8_t *)(uintptr_t)0x034e3cf4u;
    b->anchor_address=(uint32_t)(uintptr_t)&anchor_zero; b->channel=8;
    /* Inputs integration_context, ownership_snapshot, prepare_session and
     * resident_storage_confirmed must be explicitly supplied, never seeded. */
    return UMCN_BINDING_MISSING;
}
