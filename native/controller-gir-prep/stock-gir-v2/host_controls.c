/* Logic controls with stub imports. These never execute Garmin/ARM code. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "controller_gir_prep.h"
#include "exact_abi.h"
#include "stock_gir_input.h"

struct word { uint32_t p,v; } words[64];
static unsigned used, calls, log_calls[32], writes;
static uint32_t mock_sp=0x09503e00,mock_cpsr=31;
static int scenario;
static void put(uint32_t p,uint32_t v) {
    for(unsigned i=0;i<used;++i) if(words[i].p==p) { words[i].v=v;return; }
    if(used==64) abort();
    words[used++]=(struct word){p,v};
}
uint32_t cg_read32(uint32_t p) {
    for(unsigned i=0;i<used;++i) if(words[i].p==p) return words[i].v;
    fprintf(stderr,"Unexpected read32 %08x\n",p);abort();
}
uint8_t cg_read8(uint32_t p) { return (uint8_t)(cg_read32(p&~3u)>>((p&3)*8)); }
void cg_write32(uint32_t p,uint32_t v) { ++writes;put(p,v); }
void cg_write8(uint32_t p,uint8_t v) {
    uint32_t shift=(p&3)*8,old=cg_read32(p&~3u);++writes;
    put(p&~3u,(old&~(255u<<shift))|((uint32_t)v<<shift));
}
uint32_t cg_current_sp(void) { return mock_sp; }
uint32_t cg_current_cpsr(void) { return mock_cpsr; }
static void mark(unsigned phase) {
    if(calls==32) abort();
    log_calls[calls++]=phase;
    if(scenario==14 && phase==CG_WIDGET_REGISTRY) put(0xf09090,0x09508f90);
    if(scenario==15 && phase==CG_DISPLAY_LIST) mock_sp-=8;
    if(scenario==21 && phase==CG_MENU_SIGNALS) mock_cpsr=0x12;
}
uint32_t cg_settings_set(uint32_t key,const void *p,uint32_t n,uint32_t cache) {
    if(key!=0x19b || n!=4 || cache || *(const uint32_t *)p!=1) abort();
    mark(CG_SETTING_WRITE);return scenario==5?1:0;
}
uint32_t cg_settings_read(uint32_t key,uint32_t *p) {
    if(key!=0x19b) abort();
    mark(CG_SETTING_READ);*p=0x18001020;
    return scenario==6?2:4;
}
void cg_widget_init(void) { mark(CG_WIDGET_REGISTRY); }
void cg_display_init(void) { mark(CG_DISPLAY_LIST); }
uint32_t cg_platform_hash(void) { mark(CG_PLATFORM);return scenario==8?0:CG_STOCK_PLATFORM; }
uint32_t cg_gir_register(uint32_t p,uint8_t *kind) {
    if(p!=0x0b800000) abort();
    mark(CG_GIR_REGISTER);*kind=0;return scenario==9?0:1;
}
uint32_t cg_gir_catalog(void) { mark(CG_GIR_CATALOG);return scenario==22?0x034f7740:0x034f7730; }
void cg_static_fonts_init(void) { mark(CG_STATIC_FONTS); }
uint32_t cg_external_fonts_init(uint32_t m) {
    if(m!=1) abort();
    mark(CG_EXTERNAL_FONTS);return scenario==12?3:0;
}
void cg_menu_signals_init(void) { mark(CG_MENU_SIGNALS); }
void cg_db_set_cell(uint32_t menu,uint32_t icon,uint32_t cell,uint32_t size) {
    if(menu!=0x08801000 || icon!=0x7f135201 || cell!=12 || size ||
       cg_read32(menu+24)!=0x084c0000 || cg_read8(menu+28)!=1 || cg_read32(0x084c0000)!=0) abort();
    mark(CG_DB_SELECT);
}
static void check(int v,const char *message) { if(!v) { fprintf(stderr,"case%d: %s\n",scenario,message);exit(1); } }

int main(int argc,char **argv) {
    if(argc!=2) return 2;
    scenario=atoi(argv[1]);
    struct cg_config c={CG_CONFIG_MAGIC,sizeof(c),CG_EXPLICIT_INPUT_FLAGS,
        0x09503f90,0x09500040,0x09503f90,CG_STOCK_RUNTIME,CG_STOCK_BYTES,CG_STOCK_DIRECTORY,
        CG_STOCK_RUNTIME,CG_STOCK_RUNTIME+CG_STOCK_BYTES,
        0x08800000,0x08810000,0x18001000,0x18009000,0x084c0000,0x7f135201,12,0};
    struct cg_result r;memset(&r,0xa5,sizeof(r));
    put(0xf09090,c.controller_tcb);put(0xf09094,0);put(0xf06ef4,0x01000000);
    put(c.stock_gir+12,CG_STOCK_PLATFORM);put(c.stock_gir+20,CG_STOCK_BYTES);put(c.stock_gir+28,CG_STOCK_DIRECTORY);
    put(0x18001020,1);put(0x034f7730,0x08802000);put(0x034f7734,0x08802018);put(0x034f7738,0x08802020);
    put(0x08802000,0x0100);put(0x0880200c,c.stock_gir);put(0x08802010,CG_STOCK_DIRECTORY);
    put(0xf11e0c,0x08801000);put(0x08801018,0);put(0x0880101c,0);put(0x084c0000,0xdeadbeef);
    static const int expected[]={1,-2,-3,-1,-4,-5,-6,-6,-7,-8,-9,-9,-10,-11,-2,-3,1,-9,-1,-2,-2,-2,-9,-1,-1,-1,-1,-1,-9};
    if(scenario<0 || scenario>28) return 2;
    if(scenario==1) put(0xf09090,0x09508f90);
    if(scenario==2) mock_sp=0x09500020;
    if(scenario==3) c.flags=7;
    if(scenario==4) put(0xf06ef4,0);
    if(scenario==7) put(0x18001020,2);
    if(scenario==10) put(0x034f7734,0x08802014);
    if(scenario==11) put(0x08802000,0x0101);
    if(scenario==13) put(0xf11e0c,0);
    if(scenario==17) c.catalog_record_high=0x08802018;
    if(scenario==18) c.stock_gir=0xfffffff0;
    if(scenario==19) mock_cpsr=0x10;
    if(scenario==20) put(0xf09094,1);
    if(scenario==23) c.gir_input_high-=1;
    if(scenario==24) c.gir_input_low+=1;
    if(scenario==25) c.stock_gir_directory_bytes-=1;
    if(scenario==26) c.stock_gir_bytes=0x02000001;
    if(scenario==27) c.gir_input_high=c.gir_input_low-1;
    if(scenario==28) c.catalog_record_low=0x08802001;
    int result=cg_controller_prepare(&c,&r);
    check(result==expected[scenario],"unexpected status");
    const unsigned order[]={2,3,4,5,6,7,8,9,10,11,13};
    check(calls<=11,"unexpected extra call");
    for(unsigned i=0;i<calls;++i) check(log_calls[i]==order[i],"native call order differs");
    if(result==1) {
        check(calls==11 && writes==3,"missing calls or provider writes");
        check(r.phase==CG_NATIVE_SEQUENCE_RETURNED && r.db_setter_returned==1 && !r.db_row_or_closed_SQL_verified,
              "native return incorrectly claims verified SQL");
        if(scenario==16) check(cg_controller_prepare(&c,&r)==CG_ALREADY_STARTED,"second native preparation permitted");
    } else {
        check(writes==0,"failure entered SQL provider mutation");
        if(scenario!=3 && scenario!=18 && scenario!=23 && scenario!=24 && scenario!=26 && scenario!=27)
            check(cg_controller_prepare(&c,&r)==CG_ALREADY_STARTED,"partial failed preparation retry permitted");
    }
    printf("{\"case\":%d,\"passed\":true,\"status\":%d,\"stub_native_calls\":%u}\n",scenario,result,calls);
    return 0;
}
