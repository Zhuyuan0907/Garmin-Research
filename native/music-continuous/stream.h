#ifndef GARMIN_MUSIC_STREAM_H
#define GARMIN_MUSIC_STREAM_H
#include <stdint.h>
int music_stream_output_prepare(uint32_t channel);
int music_stream_configuration_gate(uint32_t,uint32_t,uint32_t,const uint8_t *,uint32_t);
int music_stream_callback(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
int music_stream_consume(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
int music_stream_retire_private(uint32_t);
#endif
