/* Exact 1352/SW8.00 stock reader ABI. Permanent boot-scoped tail reservation.
 * The loader initializes its capacity to3MiB on every INIT; this wrapper lowers
 * it BEFORE both file-copy and header-RAM checks. It neither enables playback
 * nor certifies warm ownership. Installation/MMU/cache remain unimplemented.
 * Tail call is required: there must be no return frame inside replaceable data.
 */
#include <stdint.h>
extern uint8_t __resident_tail_start[];
extern int stock_reader_tail_relocated(void *,const void *);
int resident_loader_read_gate(void *descriptor,const void *callbacks)
{
 volatile uint32_t *d=descriptor;
 if(!d || !callbacks || d[6]!=0x02d4bb74u || d[7]!=0x300000u)
  return 4;
 d[7]=(uintptr_t)__resident_tail_start-0x02d4bb74u;
 return stock_reader_tail_relocated(descriptor,callbacks);
}
