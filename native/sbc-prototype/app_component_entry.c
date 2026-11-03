/* Emulator-only complete prototype appended to the stock TTS reservation.
 * Original exports remain owned by the original bootstrap. No task/hook/SEP
 * is activated automatically; voice reload/unload safety is unestablished.
 */
#include <stdint.h>
#include <string.h>
#include "decoder.h"
extern uint8_t __app_zero_start[],__app_zero_end[];
extern int original_tts_entry(void *);
struct app_component_state { uint32_t entered;int32_t original_result,decoder_result; };
volatile struct app_component_state app_component_state;
int native_app_component_entry(void *loader)
{
    /* Linker boundaries are word-aligned. Clear by words, as stock startup
     * does; the freestanding byte memset needlessly extends startup time. */
    volatile uint32_t *at=(volatile uint32_t *)__app_zero_start;
    volatile uint32_t *end=(volatile uint32_t *)__app_zero_end;
    while (at<end) *at++=0;
    app_component_state.entered=1;
    int result=original_tts_entry(loader);
    app_component_state.original_result=result;
    if (result==11 || result==6) app_component_state.decoder_result=garmin_sbc_reset();
    else app_component_state.decoder_result=-22;
    return result;
}
extern int owned_media_init(uint32_t),media_queue_begin(void);
extern uint32_t media_worker_boot(uint32_t),source_worker_boot(uint32_t);
extern int source_worker_shutdown(void),media_worker_shutdown(void);
extern int media_worker_callback(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
extern void source_publication_hook(void),source_completion_hook(void),playback_callback_hook(void);
const void *const app_component_api[] __attribute__((used,section(".app_component_api")))={
    (const void *)owned_media_init,(const void *)media_queue_begin,
    (const void *)media_worker_boot,(const void *)source_worker_boot,
    (const void *)source_worker_shutdown,(const void *)media_worker_shutdown,
    (const void *)media_worker_callback,(const void *)garmin_sbc_reset,
    (const void *)garmin_sbc_decode_frame,(const void *)source_publication_hook,
    (const void *)source_completion_hook,(const void *)playback_callback_hook
};
