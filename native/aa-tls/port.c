/* SPDX-License-Identifier: Apache-2.0 */
#include "mbedtls/platform_util.h"
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#ifndef AA_TLS_HOST
void *memcpy(void *d,const void *s,size_t n){unsigned char *a=d;const unsigned char*b=s;while(n--)*a++=*b++;return d;}
void *memset(void *d,int v,size_t n){unsigned char*a=d;while(n--)*a++=(unsigned char)v;return d;}
void *memmove(void*d,const void*s,size_t n){unsigned char*a=d;const unsigned char*b=s;if(a<b){while(n--)*a++=*b++;}else{a+=n;b+=n;while(n--)*--a=*--b;}return d;}
int memcmp(const void*a,const void*b,size_t n){const unsigned char*x=a,*y=b;while(n--){if(*x!=*y)return *x-*y;x++;y++;}return 0;}
size_t strlen(const char*s){const char*p=s;while(*p)p++;return (size_t)(p-s);}
int strcmp(const char*a,const char*b){while(*a&&*a==*b){a++;b++;}return (unsigned char)*a-(unsigned char)*b;}
int strncmp(const char*a,const char*b,size_t n){while(n--){if(*a!=*b||!*a)return (unsigned char)*a-(unsigned char)*b;a++;b++;}return 0;}
char *strchr(const char*s,int c){do{if(*s==(char)c)return (char*)s;}while(*s++);return NULL;}
char *strstr(const char*s,const char*q){size_t n=strlen(q);if(!n)return (char*)s;while(*s){if(*s==*q&&strncmp(s,q,n)==0)return (char*)s;s++;}return NULL;}
#else
#include <string.h>
#endif
int aa_tls_ignore_fprintf(void *stream,const char*format,...){(void)stream;(void)format;return 0;}
void aa_tls_allocator_fatal(int status){(void)status;__builtin_trap();}
#ifndef AA_TLS_HOST
int __aeabi_idiv0(int v){aa_tls_allocator_fatal(v);return v;}
long long __aeabi_ldiv0(long long v){aa_tls_allocator_fatal((int)v);return v;}
#endif
static int leap(int y){return y%4==0&&(y%100!=0||y%400==0);}
struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *t,struct tm *o){
    static const int days[12]={31,28,31,30,31,30,31,31,30,31,30,31};
    if(!t||!o||*t<0||*t>4102444799LL)return NULL;
    uint32_t seconds=(uint32_t)*t,day=seconds/86400,rest=seconds%86400;
    memset(o,0,sizeof(*o));o->tm_sec=rest%60;o->tm_min=rest/60%60;o->tm_hour=rest/3600;
    o->tm_wday=(day+4)%7;int year=1970;
    while(day>=(uint32_t)(365+leap(year))){day-=365+leap(year);year++;}
    o->tm_year=year-1900;o->tm_yday=day;int month=0;
    while(day>=(uint32_t)(days[month]+(month==1&&leap(year)))){day-=days[month]+(month==1&&leap(year));month++;}
    o->tm_mon=month;o->tm_mday=day+1;return o;
}
