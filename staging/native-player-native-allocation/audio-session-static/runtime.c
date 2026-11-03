/* Freestanding component memcpy/memset; no Linux/libc runtime imports. */
void *memcpy(void *destination,const void *source,unsigned count)
{unsigned char *d=destination;const unsigned char *s=source;
 for(unsigned i=0;i<count;i++){d[i]=s[i];}
 return destination;}
void *memset(void *destination,int value,unsigned count)
{unsigned char *d=destination;for(unsigned i=0;i<count;i++)d[i]=(unsigned char)value;
 return destination;}
void *__aeabi_memcpy(void *d,const void *s,unsigned n){return memcpy(d,s,n);}
void *__aeabi_memcpy4(void *d,const void *s,unsigned n){return memcpy(d,s,n);}
void *__aeabi_memset(void *d,unsigned n,int c){return memset(d,c,n);}
void *__aeabi_memclr(void *d,unsigned n){return memset(d,0,n);}
