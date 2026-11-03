/* Exact1352/SW8 reader ABI. Boot-scoped reservation, not an unload protocol.
 * Copy the52-byte descriptor onto THIS caller's stack so another INIT cannot
 * raise this reader's file/RAM capacity through the shared descriptor. The
 * private limit protects this module's code and its full-return frame. Earlier
 * voice-selection concurrency, live installation and warm ownership are not
 * established. All original reader errors and file callbacks are retained.
 */
#include <stdint.h>
extern uint8_t __resident_tail_start[];
extern int stock_reader_tail_relocated(void *,const void *);
int resident_loader_read_gate(void *descriptor,const void *callbacks)
{
 const volatile uint32_t *d=descriptor;
 uint32_t local[13];
 if(!d || !callbacks)return 4;
 for(uint32_t i=0;i<13u;i++)local[i]=d[i];
 if(local[6]!=0x02d4bb74u || local[7]!=0x300000u)return 4;
 local[7]=(uintptr_t)__resident_tail_start-0x02d4bb74u;
 return stock_reader_tail_relocated(local,callbacks);
}
