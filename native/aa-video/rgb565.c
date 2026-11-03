/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "rgb565.h"
static int floor256(int x){return x>=0?x/256:-((-x+255)/256);}
static int clamp(int x){return x<0?0:x>255?255:x;}
int aa_rgb565_render(const aa_h264_frame *f,const size_t sizes[3],
                    uint8_t *out,size_t cap,uint32_t w,uint32_t h,size_t pitch,
                    int matrix,int range){
    uint32_t x,y,sx,sy,pw,ph;size_t i,need;int c,d,e,r,g,b,yc,rc,gdc,gec,bc;
    uint16_t pixel;
    if(!f||!sizes||!out||!w||!h||w>4096||h>4096||!f->width||!f->height||
       f->width>4096||f->height>4096||(f->width&1)||(f->height&1)||
       pitch<(size_t)w*2||(matrix!=AA_RGB565_BT601&&matrix!=AA_RGB565_BT709)||
       (range!=AA_RGB565_LIMITED&&range!=AA_RGB565_FULL))return AA_RGB565_E_ARGUMENT;
    for(i=0;i<3;i++){
        pw=i?f->width/2:f->width;ph=i?f->height/2:f->height;
        if(!f->planes[i]||f->strides[i]<pw)return AA_RGB565_E_ARGUMENT;
        if(f->strides[i]>(SIZE_MAX-pw)/(ph-1?ph-1:1))return AA_RGB565_E_CAPACITY;
        need=(size_t)(ph-1)*f->strides[i]+pw;
        if(sizes[i]<need)return AA_RGB565_E_CAPACITY;
    }
    if(pitch>(SIZE_MAX-(size_t)w*2)/(h-1?h-1:1))return AA_RGB565_E_CAPACITY;
    need=(size_t)(h-1)*pitch+(size_t)w*2;if(cap<need)return AA_RGB565_E_CAPACITY;
    yc=range==AA_RGB565_FULL?256:298;
    if(matrix==AA_RGB565_BT601){
        rc=range==AA_RGB565_FULL?359:409;gdc=range==AA_RGB565_FULL?88:100;
        gec=range==AA_RGB565_FULL?183:208;bc=range==AA_RGB565_FULL?454:516;
    }else{
        rc=range==AA_RGB565_FULL?403:459;gdc=range==AA_RGB565_FULL?48:55;
        gec=range==AA_RGB565_FULL?120:136;bc=range==AA_RGB565_FULL?475:541;
    }
    for(y=0;y<h;y++){
        sy=(uint32_t)(((uint64_t)y*f->height)/h);
        for(x=0;x<w;x++){
            sx=(uint32_t)(((uint64_t)x*f->width)/w);
            c=f->planes[0][(size_t)sy*f->strides[0]+sx]-(range==AA_RGB565_FULL?0:16);
            d=f->planes[1][(size_t)(sy/2)*f->strides[1]+sx/2]-128;
            e=f->planes[2][(size_t)(sy/2)*f->strides[2]+sx/2]-128;
            r=clamp(floor256(yc*c+rc*e+128));g=clamp(floor256(yc*c-gdc*d-gec*e+128));
            b=clamp(floor256(yc*c+bc*d+128));pixel=(uint16_t)(((r>>3)<<11)|((g>>2)<<5)|(b>>3));
            out[(size_t)y*pitch+x*2]=(uint8_t)pixel;out[(size_t)y*pitch+x*2+1]=(uint8_t)(pixel>>8);
        }
    }
    return 0;
}
