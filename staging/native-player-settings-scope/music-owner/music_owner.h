#ifndef GARMIN_NEW_MUSIC_OWNER_H
#define GARMIN_NEW_MUSIC_OWNER_H
#include <stdint.h>
#include "../../../staging/native-player-dispatcher-native-body/music-static/ui_music_single.h"
struct music_owner_trace {
    uint32_t initializer_returns, control_events, ordinary_events, owner_rejections;
    uint32_t service_calls, publication_observations, iteration_returns;
    uint32_t cancel_flag_cleared_observations;
    int32_t last_ready,last_service,last_publication,last_iteration;
};
extern volatile struct music_owner_trace music_owner_trace;
uint32_t music_owner_irq_save(void);
void music_owner_irq_restore(uint32_t);
uint32_t music_owner_current(void);
void music_owner_post(uint32_t,uint32_t);
uint32_t music_owner_wait(void);
uint32_t music_owner_construct(uint32_t *);
void music_owner_registry(uint32_t *);
int music_owner_initialized(int);
int music_owner_control_boundary(uint32_t);
int music_owner_after_boundary(int);
/* Caller must supply actual resident native reservation/session callbacks.
 * No default success or synthetic ownership witness exists in this image. */
int music_owner_bind_on_source(struct umcn_bindings *,uint32_t,uint32_t);
#endif
