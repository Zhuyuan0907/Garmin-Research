/* HWID1352/8.00 OFFLINE EXPERIMENT ONLY.
 * MAIN write permission/cache synchronization/exclusive startup/loader pinning
 * are explicit emulator prerequisites, not established device APIs. No unload,
 * real-time worker integration, playback or menu is provided by this stage.
 */
#include <stdint.h>
#include "../music-endpoint/endpoint.h"
#include "../avdtp-gate/gate.h"
#include "../avdtp-policy/policy.h"
#include "music_patch_imports.h"

extern int native_app_component_entry(void *);
extern int music_reply_dispatch(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);

struct music_component_state {
    uint32_t entered,patches_installed,local_seid,published,callbacks,media_dropped;
    int32_t bootstrap_result;
    uint32_t last_event,last_status,last_length;
};
volatile struct music_component_state music_component_state;

/* Native callback executes in the loaded reservation. Capture evidence, but
 * deliberately refuse media until session/MTU guards and workers are wired.
 * Stock dispatch ignores the return value: it is never proof of playback.
 */
int native_music_callback(uint32_t event,uint32_t status,const void *handle,
                          const uint8_t *payload,uint32_t length)
{
    (void)handle;(void)payload;
    music_component_state.callbacks++;
    music_component_state.last_event=event;
    music_component_state.last_status=status;
    music_component_state.last_length=length;
    if (event==0xf1) { music_component_state.media_dropped++;return -55; }
    return 0;
}

static int dispatch_install(void)
{
    /* Validate ALL eight sites before writing any. Expected bytes were read
     * from the exact checked MAIN. Caller must serialize/pin this experiment.
     */
    for (uint32_t i=0;i<MUSIC_PATCH_COUNT;i++) {
        const struct music_patch *p=&music_patches[i];
        const volatile uint8_t *dst=(const volatile uint8_t *)p->address;
        for (uint32_t j=0;j<p->length;j++)
            if (dst[j]!=p->before[j]) return -46;
    }
    for (uint32_t i=0;i<MUSIC_PATCH_COUNT;i++) {
        const struct music_patch *p=&music_patches[i];
        volatile uint8_t *dst=(volatile uint8_t *)p->address;
        for (uint32_t j=0;j<p->length;j++) dst[j]=p->after[j];
    }
    /* Original wrapper routes to privileged cache maintenance. The emulator
     * models invalidation; actual MMU/cache and concurrency remain untested.
     */
    ((void (*)(void))0x221d2du)();
    music_component_state.patches_installed=1;
    return 0;
}

int native_music_start(void)
{
    if (music_component_state.patches_installed || music_component_state.local_seid)
        return -48;
    /* Original SDP initialization must precede the new loader entry. These
     * checks establish only necessary readiness, not complete radio health.
     */
    if (*(const volatile uint32_t *)(0x3a7c108u+7u*12u)!=0x90007u ||
        *(const volatile uint8_t *)0xf42e3cu!=14u)
        return -47;
    int result=dispatch_install();
    if (result) return result;
    int seid=music_endpoint_prepare((uint32_t)native_music_callback,672u);
    if (seid<0) return seid; /* Dispatch ownership retained; never unload. */
    music_component_state.local_seid=(uint32_t)seid;
    result=music_endpoint_publish((uint32_t)seid,(uint32_t)native_music_callback);
    music_component_state.published=music_endpoint_publication_state();
    return result;
}

int native_music_component_entry(void *loader)
{
    /* Existing verified entry clears ALL relinked BSS/workspaces, calls the
     * original TTS bootstrap and resets SBC. Its40 exports stay unchanged.
     * Voice reload while dispatch/callbacks are active is NOT supported.
     */
    int result=native_app_component_entry(loader);
    music_component_state.entered=1;
    music_component_state.bootstrap_result=(result==11 || result==6)?native_music_start():-22;
    return result;
}

const void *const music_component_api[] __attribute__((used,section(".music_component_api")))={
    (const void *)native_music_start,(const void *)native_music_callback,
    (const void *)music_endpoint_prepare,(const void *)music_endpoint_publish,
    (const void *)music_endpoint_capabilities,(const void *)music_configuration_gate,
    (const void *)music_reply_dispatch,(const void *)music_validate_configuration,
    (const void *)music_guard_bind,(const void *)music_guard_unbind,
    (const void *)music_guard_packet,(const void *)music_guard_frame
};
