/* Passive loader bootstrap. No global audio reset, task, Bluetooth publication
 * or MAIN patch is performed here. Activation requires a separate warm owner.
 * The fixed stock DLL buffer can be overwritten by later voice loads; this
 * bootstrap does not claim a loader pin or an unload protocol.
 */
#include <stdint.h>
#include <string.h>
extern uint8_t __resident_bss_start[], __resident_bss_end[];
extern uint8_t __resident_file_end[], __resident_end[];
extern int original_tts_entry(void *);
extern uint32_t mh_boot_source(void);
extern int aas_media_ingress(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
extern int mh_request_command(uint32_t);
extern int nsg_native_callback(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
extern uint32_t resident_pcm_address(uint32_t);
extern int nr_configuration_gate(uint32_t,uint32_t,uint32_t,const uint8_t *,uint32_t);
extern int nr_start_suspend_gate(uint32_t,uint32_t,uint32_t,const uint8_t *,uint32_t);
extern int nr_reply_dispatch(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);

/* Initialized data is outside the zero range. The stock reader reloads this
 * word on every new file load, so it cannot protect against voice replacement.
 */
static uint32_t resident_entry_phase = 0x52534931u;
volatile uint32_t resident_entry_count, resident_loader_status;
volatile uint32_t resident_passive_ready;

struct resident_api {
 uint32_t tag,version,bytes;
 const void *module_base,*file_end,*ram_end;
 uint32_t (*source_boot)(void);
 int (*ingress)(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
 int (*command)(uint32_t);
 int (*native_callback)(uint32_t,uint32_t,const void *,const uint8_t *,uint32_t);
 uint32_t (*pcm_address)(uint32_t);
 const void *configure,*start_suspend,*reply;
};
const struct resident_api resident_player_api
 __attribute__((used,section(".resident_api"))) = {
 0x52504c31u,1u,sizeof(struct resident_api),(void *)0x02d4bb74u,
 __resident_file_end,__resident_end,mh_boot_source,aas_media_ingress,
 mh_request_command,nsg_native_callback,resident_pcm_address,
 nr_configuration_gate,nr_start_suspend_gate,nr_reply_dispatch
};

int resident_music_entry(void *loader)
{
 if(resident_entry_phase==0x52534931u){
  memset(__resident_bss_start,0,
         (uintptr_t)__resident_bss_end-(uintptr_t)__resident_bss_start);
  resident_entry_phase=0x52534932u;
 }
 int status=original_tts_entry(loader);
 resident_entry_count++;
 resident_loader_status=(uint32_t)status;
 resident_passive_ready=(status==11 || status==6);
 /* Retain all forty original voice exports and the original raw return. */
 return status;
}
