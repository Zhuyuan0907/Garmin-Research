/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef AA_RGB565_H
#define AA_RGB565_H
#include <stdint.h>
#include <stddef.h>
#include "h264.h"
enum { AA_RGB565_OK=0,AA_RGB565_E_ARGUMENT=-1,AA_RGB565_E_CAPACITY=-2 };
enum { AA_RGB565_BT601=1,AA_RGB565_BT709=2 };
enum { AA_RGB565_LIMITED=0,AA_RGB565_FULL=1 };
/* Caller explicitly chooses matrix/range, not inferred from arbitrary phone
 * content. Nearest-neighbor scaling and fixed-point conversion to LE RGB565.
 * Complete readable plane capacities, valid accessible disjoint buffers and
 * retained copied decoder frame required. Output pitch>=width*2, preserves
 * row padding. Software surface only; no native framebuffer/display ABI. */
int aa_rgb565_render(const aa_h264_frame *,const size_t plane_bytes[3],
                    uint8_t *out,size_t capacity,uint32_t width,uint32_t height,
                    size_t pitch,int matrix,int range);
#endif
