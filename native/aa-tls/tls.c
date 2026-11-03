/* SPDX-License-Identifier: Apache-2.0 */
#include "tls.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include <string.h>
#define QUEUE_BYTES 32768u
#define MAGIC 0x4141544cu
struct context {
    uint32_t magic,session,state,deadline,pending_bytes,pending_offset;
    int error;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca,cert;
    mbedtls_pk_context key;
    mbedtls_ctr_drbg_context rng;
    aa_tls_entropy_fn entropy;
    void *entropy_context;
    uint32_t rx_bytes,tx_bytes;
    unsigned char rx[QUEUE_BYTES],tx[QUEUE_BYTES],pending[16384];
};
static uint32_t runtime_ready;
static mbedtls_time_t runtime_time;
int64_t aa_tls_clock_read(int64_t*t){if(t)*t=runtime_time;return runtime_time;}
uint32_t aa_tls_context_bytes(void){return sizeof(struct context);}
uint32_t aa_tls_params_bytes(void){return sizeof(struct aa_tls_params);}
static int range(const void*p,uint32_t n){return p&&n&&(uintptr_t)p<=UINTPTR_MAX-n;}
int aa_tls_runtime_init(void *heap,uint32_t n,uint32_t seconds){
    if(runtime_ready)return AA_TLS_BAD_STATE;
    if(!range(heap,n)||((uintptr_t)heap&7)||n<4096||seconds<1577836800u||seconds>4102444799u)return AA_TLS_BAD_ARGUMENT;
    runtime_time=seconds;
    mbedtls_memory_buffer_alloc_init(heap,n);runtime_ready=1;return 0;
}
int aa_tls_runtime_set_time(uint32_t seconds){
    if(!runtime_ready)return AA_TLS_BAD_STATE;
    if(seconds<1577836800u||seconds>4102444799u||seconds<(uint64_t)runtime_time)return AA_TLS_BAD_ARGUMENT;
    runtime_time=seconds;return 0;
}
static int entropy(void *p,unsigned char*out,size_t n){
    struct context*c=p;
    if(!c->entropy||c->entropy(c->entropy_context,out,n)){
        mbedtls_platform_zeroize(out,n);return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
    return 0;
}
static int send_bytes(void*p,const unsigned char*buf,size_t n){
    struct context*c=p;size_t space=QUEUE_BYTES-c->tx_bytes;if(!space)return MBEDTLS_ERR_SSL_WANT_WRITE;
    if(n>space)n=space;memcpy(c->tx+c->tx_bytes,buf,n);c->tx_bytes+=n;return (int)n;
}
static int receive_bytes(void*p,unsigned char*buf,size_t n){
    struct context*c=p;if(!c->rx_bytes)return MBEDTLS_ERR_SSL_WANT_READ;
    if(n>c->rx_bytes)n=c->rx_bytes;memcpy(buf,c->rx,n);c->rx_bytes-=n;memmove(c->rx,c->rx+n,c->rx_bytes);return (int)n;
}
static void release(struct context*c){
    mbedtls_ssl_free(&c->ssl);mbedtls_ssl_config_free(&c->conf);mbedtls_x509_crt_free(&c->ca);
    mbedtls_x509_crt_free(&c->cert);mbedtls_pk_free(&c->key);mbedtls_ctr_drbg_free(&c->rng);
}
static int valid(struct context*c,uint32_t session){
    if(!c||c->magic!=MAGIC)return AA_TLS_BAD_STATE;
    if(!session||c->session!=session)return AA_TLS_BAD_SESSION;return 0;
}
static int result(struct context*c,int r){
    if(r==MBEDTLS_ERR_SSL_WANT_READ||r==MBEDTLS_ERR_SSL_WANT_WRITE)return r;
    if(r<0){c->state=4;c->error=r;mbedtls_platform_zeroize(c->pending,sizeof(c->pending));c->pending_bytes=0;c->pending_offset=0;}return r;
}
int aa_tls_init(void *v,const struct aa_tls_params*p){
    struct context*c=v;
    if(!runtime_ready||!c||((uintptr_t)c&7)||!p||!p->session||!p->timeout_ms||p->timeout_ms>0x7fffffffu||
       !p->entropy||
       !range(p->hostname,p->hostname_bytes)||p->hostname_bytes>128||
       !range(p->ca,p->ca_bytes)||p->ca_bytes>32768||
       !range(p->cert,p->cert_bytes)||p->cert_bytes>32768||
       !range(p->key,p->key_bytes)||p->key_bytes>32768)return AA_TLS_BAD_ARGUMENT;
    const char*hostname=p->hostname;
    if(hostname[p->hostname_bytes-1]||strlen(hostname)!=p->hostname_bytes-1)return AA_TLS_BAD_ARGUMENT;
    /* Fresh, caller-owned zeroed context required; live context cannot reset. */
    if(c->magic)return AA_TLS_BAD_STATE;
    memset(c,0,sizeof(*c));c->magic=MAGIC;c->session=p->session;c->deadline=p->now_ms+p->timeout_ms;
    mbedtls_ssl_init(&c->ssl);mbedtls_ssl_config_init(&c->conf);mbedtls_x509_crt_init(&c->ca);
    mbedtls_x509_crt_init(&c->cert);mbedtls_pk_init(&c->key);mbedtls_ctr_drbg_init(&c->rng);
    c->entropy=p->entropy;c->entropy_context=p->entropy_context;
    int r=mbedtls_ctr_drbg_seed(&c->rng,entropy,c,(const unsigned char*)"native-aa-tls",13);
    if(r==0)r=mbedtls_x509_crt_parse(&c->ca,p->ca,p->ca_bytes);
    if(r==0)r=mbedtls_x509_crt_parse(&c->cert,p->cert,p->cert_bytes);
    if(r==0)r=mbedtls_pk_parse_key(&c->key,p->key,p->key_bytes,NULL,0,mbedtls_ctr_drbg_random,&c->rng);
    if(r==0)r=mbedtls_ssl_config_defaults(&c->conf,MBEDTLS_SSL_IS_CLIENT,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT);
    if(r==0){
        mbedtls_ssl_conf_min_tls_version(&c->conf,MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&c->conf,MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_authmode(&c->conf,MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&c->conf,&c->ca,NULL);
        mbedtls_ssl_conf_rng(&c->conf,mbedtls_ctr_drbg_random,&c->rng);
        r=mbedtls_ssl_conf_own_cert(&c->conf,&c->cert,&c->key);
    }
    if(r==0)r=mbedtls_ssl_setup(&c->ssl,&c->conf);
    if(r==0)r=mbedtls_ssl_set_hostname(&c->ssl,hostname);
    if(r){c->state=4;c->error=r;release(c);return r;}
    mbedtls_ssl_set_bio(&c->ssl,c,send_bytes,receive_bytes,NULL);return 0;
}
int aa_tls_feed(void*v,uint32_t session,const void*data,uint32_t n){
    struct context*c=v;int r=valid(c,session);if(r)return r;
    if(c->state>2)return AA_TLS_BAD_STATE;
    if(!n)return 0;if(!range(data,n))return AA_TLS_BAD_ARGUMENT;
    if(n>QUEUE_BYTES-c->rx_bytes)return AA_TLS_CAPACITY;
    memcpy(c->rx+c->rx_bytes,data,n);c->rx_bytes+=n;return (int)n;
}
int aa_tls_take_out(void*v,uint32_t session,void*out,uint32_t n){
    struct context*c=v;int r=valid(c,session);if(r)return r;
    if(!range(out,n))return AA_TLS_BAD_ARGUMENT;if(n>c->tx_bytes)n=c->tx_bytes;
    memcpy(out,c->tx,n);c->tx_bytes-=n;memmove(c->tx,c->tx+n,c->tx_bytes);return (int)n;
}
int aa_tls_handshake(void*v,uint32_t session,uint32_t now){
    struct context*c=v;int r=valid(c,session);if(r)return r;
    if(c->state==1)return 1;if(c->state)return c->error?c->error:AA_TLS_BAD_STATE;
    if((int32_t)(now-c->deadline)>=0)return result(c,AA_TLS_TIMED_OUT);
    r=mbedtls_ssl_handshake(&c->ssl);if(r==0){c->state=1;return 1;}return result(c,r);
}
int aa_tls_write(void*v,uint32_t session,const void*data,uint32_t n){
    struct context*c=v;int r=valid(c,session);if(r)return r;
    if(c->state!=1)return AA_TLS_BAD_STATE;if(c->pending_bytes)return AA_TLS_BUSY;
    if(!range(data,n)||n>sizeof(c->pending))return AA_TLS_BAD_ARGUMENT;
    memcpy(c->pending,data,n);c->pending_bytes=n;c->pending_offset=0;return aa_tls_retry_write(c,session);
}
int aa_tls_retry_write(void*v,uint32_t session){
    struct context*c=v;int r=valid(c,session);if(r)return r;
    if(c->state!=1||!c->pending_bytes)return AA_TLS_BAD_STATE;
    uint32_t remaining=c->pending_bytes-c->pending_offset;
    r=mbedtls_ssl_write(&c->ssl,c->pending+c->pending_offset,remaining);
    if(r>0){
        if((uint32_t)r>remaining)return result(c,AA_TLS_BAD_STATE);
        c->pending_offset+=(uint32_t)r;
        if(c->pending_offset==c->pending_bytes){
            mbedtls_platform_zeroize(c->pending,sizeof(c->pending));c->pending_bytes=0;c->pending_offset=0;
        }
    }
    return result(c,r);
}
int aa_tls_pending_bytes(void*v,uint32_t session){struct context*c=v;int r=valid(c,session);return r?r:(int)(c->pending_bytes-c->pending_offset);}
int aa_tls_read(void*v,uint32_t session,void*out,uint32_t n){
    struct context*c=v;int r=valid(c,session);if(r)return r;
    if(c->state!=1)return AA_TLS_BAD_STATE;if(!range(out,n)||n>16384)return AA_TLS_BAD_ARGUMENT;
    r=mbedtls_ssl_read(&c->ssl,out,n);
    if(r==MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY){c->state=3;return r;}return result(c,r);
}
int aa_tls_close(void*v,uint32_t session){
    struct context*c=v;int r=valid(c,session);if(r)return r;
    if(c->pending_bytes)return AA_TLS_BUSY;if(c->state!=1&&c->state!=2)return AA_TLS_BAD_STATE;
    c->state=2;r=mbedtls_ssl_close_notify(&c->ssl);if(r==0)c->state=3;return result(c,r);
}
int aa_tls_status(void*v,uint32_t session){struct context*c=v;int r=valid(c,session);return r?r:c->state==4?c->error:(int)c->state;}
uint32_t aa_tls_verify_flags(void*v,uint32_t session){struct context*c=v;return valid(c,session)?UINT32_MAX:mbedtls_ssl_get_verify_result(&c->ssl);}
int aa_tls_free(void*v,uint32_t session){struct context*c=v;int r=valid(c,session);if(r)return r;release(c);mbedtls_platform_zeroize(c,sizeof(*c));return 0;}
uint32_t aa_tls_heap_used(void){size_t used,blocks;mbedtls_memory_buffer_alloc_cur_get(&used,&blocks);return used;}
uint32_t aa_tls_heap_max(void){size_t used,blocks;mbedtls_memory_buffer_alloc_max_get(&used,&blocks);return used;}
int aa_tls_heap_verify(void){return mbedtls_memory_buffer_alloc_verify();}
