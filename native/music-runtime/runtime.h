#ifndef GARMIN_MUSIC_RUNTIME_H
#define GARMIN_MUSIC_RUNTIME_H
#include <stdint.h>
int music_runtime_boot(uint32_t channel,uint32_t decoder_priority,uint32_t source_priority);
int music_runtime_cancel(void);
int music_runtime_shutdown(void);
int music_runtime_ready(void);
int music_runtime_source_busy(void);
int music_runtime_actor_present(void);
int music_runtime_start_gate(uint32_t,uint32_t,uint32_t,const uint8_t *,uint32_t);
void source_worker_published(int);
#endif
