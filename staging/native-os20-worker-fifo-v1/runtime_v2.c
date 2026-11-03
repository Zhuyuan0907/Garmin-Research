/* Minimal freestanding byte copies and explicit division-failure boundary.
 * libgcc division-zero trap never calls a Linux signal/runtime service. */
#include <stddef.h>
#include "worker_fifo_v1.h"
void *memcpy(void *d,const void *s,size_t n){unsigned char *a=d;const unsigned char *b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int v,size_t n){unsigned char *a=d;while(n--)*a++=(unsigned char)v;return d;}
int __aeabi_idiv0(int value){(void)value;fifo_failure_v1();return 0;}
long long __aeabi_ldiv0(long long value){(void)value;fifo_failure_v1();return 0;}
