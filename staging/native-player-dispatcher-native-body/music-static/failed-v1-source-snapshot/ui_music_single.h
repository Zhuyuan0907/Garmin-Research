#ifndef GARMIN_NEW_UI_MUSIC_SINGLE_H
#define GARMIN_NEW_UI_MUSIC_SINGLE_H
#include <stdint.h>
#include "../../../native/ui-music-native-adapter/native_adapter.h"

#define UI_MUSIC_ICON_ID 0x7f135201u
#define UI_MUSIC_MENU_CONTEXT 0x13528000u
#define UI_MUSIC_ENTRY_COLD 0x55495331u
#define UI_MUSIC_ENTRY_CLAIMED 0x55495332u
#define UI_MUSIC_ENTRY_DONE 0x55495333u
#define UI_MUSIC_ENTRY_FAILED 0x55495334u

/* A fresh single image is initialized once by the common BSS initializer.
 * None of these interfaces resets, exits, frees or unloads resident storage.
 * GUI owner identity is an integration input, not an ownership proof.
 */
struct ui_music_single {
    struct umc_controller control;
    struct umcn_context adapter;
    uint32_t bootstrap_done, attached, attach_failed_pinned, gui_owner_tcb;
    int32_t bootstrap_result, last_action_result;
    uint32_t last_action_generation, action_calls, action_rejections;
    uint32_t menu_attempts, menu_delivered;
};
extern struct ui_music_single native_ui_music_resident;
extern uint32_t native_ui_music_entry_phase;

int native_ui_music_single_entry(void *loader);
int native_ui_music_attach_channel8(const struct umcn_bindings *, uint32_t gui_owner_tcb, uint32_t cookie);
int native_ui_music_owner_ready(void);
int native_ui_music_service_owner(void);
int native_ui_music_note_publication(void);
int native_ui_music_after_iteration(int actual_result);
int native_ui_music_admission(uint32_t generation, uint32_t gate);
int native_ui_music_media_begin(uint32_t generation, struct umc_lease *);
int native_ui_music_media_current(const struct umc_lease *);
int native_ui_music_media_end(struct umc_lease *);
int native_ui_music_request_start(uint32_t *generation);
int native_ui_music_request_stop(uint32_t *generation);
int native_ui_music_status(struct umc_status *);
int native_ui_music_gui_owner(void);
void native_ui_music_menu_activate(uint32_t context);
uint32_t native_ui_music_menu_appearance(uint32_t context, void *visuals, void *caption, uint32_t *word);
int native_ui_music_menu_install(void *registry, const uint16_t *caption);

/* Addresses are ELF symbols, not immutable old continuous addresses. This
 * fills original kernel/state callbacks but returns BINDING_MISSING until the
 * caller supplies native reservation/session/residency interfaces. */
int native_ui_music_linked_bindings(struct umcn_bindings *);
#endif
