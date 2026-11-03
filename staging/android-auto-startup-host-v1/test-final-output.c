/* Host-only API output control, not a real TLS flight. */
#include "tls.h"
#include <string.h>
static int armed;
static size_t offset=7;
static const unsigned char synthetic[7]={22,3,3,0,2,0xa5,0x5a};
int __real_aa_tls_handshake(void *,uint32_t,uint32_t);
int __real_aa_tls_take_out(void *,uint32_t,void *,uint32_t);
int __wrap_aa_tls_handshake(void *p,uint32_t s,uint32_t n){
    int r=__real_aa_tls_handshake(p,s,n);
    if(r==1 && armed){armed=0;offset=0;}return r;
}
int __wrap_aa_tls_take_out(void *p,uint32_t s,void *out,uint32_t cap){
    int r=__real_aa_tls_take_out(p,s,out,cap);
    size_t n;
    if(r || offset==sizeof(synthetic))return r;
    n=sizeof(synthetic)-offset;if(n>cap)n=cap;
    memcpy(out,synthetic+offset,n);offset+=n;return (int)n;
}
void aa_test_inject_final_output(int n){armed=n;offset=sizeof(synthetic);}
