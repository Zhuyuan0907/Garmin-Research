/* HWID1352/SW8.00 loader-to-private-menu experiment. EMULATION ONLY.
 * Registering during the TTS entry is a deliberate fixture experiment;
 * production UI-thread ownership/timing is unverified. Module/callback/resource
 * memory must remain pinned. No hot reload or safe unregister is provided.
 */
#include <stdint.h>

extern int native_app_component_entry(void *loader);
extern uint32_t native_player_menu_install(void *,uint32_t,uint32_t,const uint16_t *);
extern void native_player_menu_activate(uint32_t);

struct player_component_state {
    uint32_t entered;
    int32_t original_result;
    uint32_t registry, icon_id;
    int32_t registration_result;
};
volatile struct player_component_state player_component_state;
static const uint16_t caption[] = {'P','i',' ',0x64ad,0x653e,0x5668,0};

int native_player_component_entry(void *loader)
{
    int result=native_app_component_entry(loader);
    player_component_state.entered=1;
    player_component_state.original_result=result;
    player_component_state.icon_id=0x7f135201u;
    player_component_state.registration_result=-22;
    if (result==11 || result==6) {
        void *registry=((void *(*)(void))(uintptr_t)0x31590b)();
        player_component_state.registry=(uint32_t)registry;
        player_component_state.registration_result=(int32_t)native_player_menu_install(
            registry,player_component_state.icon_id,0x13528000u,caption);
    }
    /* Preserve original voice return semantics even if our menu was rejected.
     * This is not a rollback/unload guarantee for a registered callback.
     */
    return result;
}

const void *const player_component_api[] __attribute__((used,section(".player_component_api")))={
    (const void *)native_player_menu_install,(const void *)native_player_menu_activate
};
