/* Test-only controls; includes exact production source. */
#include "tls.c"
static int inject, injected_result;
static unsigned char last[16384];
static size_t last_n;
static uintptr_t last_pointer;
int __real_mbedtls_ssl_write(mbedtls_ssl_context *, const unsigned char *, size_t);
int __wrap_mbedtls_ssl_write(mbedtls_ssl_context *s,const unsigned char *b,size_t n){
    if(!inject)return __real_mbedtls_ssl_write(s,b,n);
    inject=0;last_n=n;last_pointer=(uintptr_t)b;
    if(n<=sizeof(last))memcpy(last,b,n);
    return injected_result;
}
void aa_test_next_write(int n){inject=1;injected_result=n;}
size_t aa_test_last_write(void *p){memcpy(p,last,last_n);return last_n;}
uintptr_t aa_test_last_pointer(void){return last_pointer;}
int aa_test_reseed(void *p){struct context *c=p;return mbedtls_ctr_drbg_reseed(&c->rng,NULL,0);}
int aa_test_want_read(void){return MBEDTLS_ERR_SSL_WANT_READ;}
int aa_test_want_write(void){return MBEDTLS_ERR_SSL_WANT_WRITE;}
