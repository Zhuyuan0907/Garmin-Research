/* Freestanding policy prototype for the exact incoming raw-SBC music path.
 * This deliberately supports only MediaTransport + audio/SBC, 44.1/48 kHz,
 * and bitpool2..53. Unsupported services/formats are rejected, not silently
 * stripped or accepted as capabilities. No firmware hook or real endpoint.
 */
#include "policy.h"
_Static_assert(sizeof(uintptr_t)==4,"Requires32-bit native ABI");
_Static_assert(sizeof(struct music_config)==36,"Configuration ABI");
_Static_assert(sizeof(struct music_guard)==20,"Guard ABI");
_Static_assert(sizeof(struct music_native_view)==48,"Native snapshot ABI");
uint32_t music_config_bytes(void){return sizeof(struct music_config);}
uint32_t music_guard_bytes(void){return sizeof(struct music_guard);}
uint32_t music_view_bytes(void){return sizeof(struct music_native_view);}
static int range(const void *p,uint32_t n,uint32_t align)
{
    uintptr_t a=(uintptr_t)p;
    return a && !(a&(align-1u)) && n && a<=UINT32_MAX-n;
}
static int overlap(const void *a,uint32_t an,const void *b,uint32_t bn)
{return (uintptr_t)a<(uintptr_t)b+bn && (uintptr_t)b<(uintptr_t)a+an;}
static int single(uint32_t x){return x && !(x&(x-1u));}
static int codec(uint32_t word,struct music_config *c)
{
    uint32_t b0=word&255u,b1=(word>>8)&255u,minimum=(word>>16)&255u,maximum=word>>24;
    uint32_t rate=b0&0xf0u,mode=b0&15u,blocks=b1&0xf0u,bands=b1&12u,allocation=b1&3u;
    if (!single(rate) || !(rate&0x30u) || !single(mode) || !single(blocks) ||
        !single(bands) || !single(allocation) || minimum<2u || maximum>53u || minimum>maximum)
        return MUSIC_BAD_CODEC;
    c->codec_word=word;c->rate=rate==0x20u?44100u:48000u;
    c->mode=mode==8u?0u:mode==4u?1u:mode==2u?2u:3u;
    c->channels=c->mode==0u?1u:2u;c->subbands=bands==8u?4u:8u;
    c->blocks=blocks==0x80u?4u:blocks==0x40u?8u:blocks==0x20u?12u:16u;
    c->allocation=allocation==2u?1u:0u;
    return 0;
}
static void config_copy(struct music_config *d,const struct music_config *s)
{
    d->local_seid=s->local_seid;d->remote_seid=s->remote_seid;d->codec_word=s->codec_word;
    d->rate=s->rate;d->channels=s->channels;d->blocks=s->blocks;
    d->subbands=s->subbands;d->allocation=s->allocation;d->mode=s->mode;
}
int music_validate_configuration(const uint8_t *p,uint32_t n,uint32_t local,struct music_config *out)
{
    struct music_config selected;
    if (n<2u || n>128u || !range(p,n,1) || !range(out,sizeof(*out),4) ||
        overlap(p,n,out,sizeof(*out))) return MUSIC_BAD_ARGUMENT;
    if (local<1u || local>3u || (p[0]&3u) || (p[1]&3u) || p[0]>>2!=local ||
        p[1]>>2<1u || p[1]>>2>62u) return MUSIC_BAD_SEID;
    uint32_t seen=0,position=2,word=0;
    while(position<n) {
        if(n-position<2u)return MUSIC_BAD_SERVICE;
        uint32_t category=p[position++],length=p[position++];
        if(length>n-position)return MUSIC_BAD_SERVICE;
        if(category==1u) {
            if(length || (seen&1u))return MUSIC_BAD_SERVICE;
            seen|=1u;
        } else if(category==7u) {
            if(length!=6u || (seen&2u))return MUSIC_BAD_SERVICE;
            if(p[position] || p[position+1])return MUSIC_BAD_CODEC;
            word=(uint32_t)p[position+2] | (uint32_t)p[position+3]<<8 |
                (uint32_t)p[position+4]<<16 | (uint32_t)p[position+5]<<24;
            seen|=2u;
        } else return MUSIC_UNSUPPORTED_SERVICE;
        position+=length;
    }
    if(seen!=3u)return MUSIC_BAD_SERVICE;
    int result=codec(word,&selected);if(result)return result;
    selected.local_seid=local;selected.remote_seid=p[1]>>2;
    config_copy(out,&selected);return 0;
}
int music_guard_bind(struct music_guard *g,uint32_t session,const struct music_config *c)
{
    struct music_config v;
    if(!range(g,sizeof(*g),4) || !range(c,sizeof(*c),4) ||
        overlap(g,sizeof(*g),c,sizeof(*c)))return MUSIC_BAD_ARGUMENT;
    if(g->active)return MUSIC_BUSY;
    if(!session || session<=g->session)return MUSIC_BAD_SESSION;
    if(c->local_seid<1u || c->local_seid>3u || c->remote_seid<1u || c->remote_seid>62u)
        return MUSIC_BAD_SEID;
    int result=codec(c->codec_word,&v);if(result)return result;
    if(v.rate!=c->rate || v.channels!=c->channels || v.blocks!=c->blocks ||
        v.subbands!=c->subbands || v.allocation!=c->allocation || v.mode!=c->mode)
        return MUSIC_BAD_CODEC;
    g->session=session;g->local_seid=c->local_seid;g->remote_seid=c->remote_seid;
    g->codec_word=c->codec_word;g->active=1;return 0;
}
int music_guard_unbind(struct music_guard *g,uint32_t session)
{
    if(!range(g,sizeof(*g),4))return MUSIC_BAD_ARGUMENT;
    if(!g->active || !session || session!=g->session)return MUSIC_BAD_SESSION;
    g->active=0;return 0; /* Keep high-water session; do not permit wrap/reuse. */
}
int music_guard_packet(const struct music_guard *g,uint32_t session,const struct music_native_view *v,uint32_t bytes)
{
    if(!range(g,sizeof(*g),4) || !range(v,sizeof(*v),4) ||
        overlap(g,sizeof(*g),v,sizeof(*v)))return MUSIC_BAD_ARGUMENT;
    if(g->active!=1u || !session || session!=g->session)return MUSIC_BAD_SESSION;
    if(v->state!=8u || v->pending || v->codec_word!=g->codec_word ||
        v->local_seid!=g->local_seid || v->remote_seid!=g->remote_seid)return MUSIC_BAD_STATE;
    if(v->channel_index>=12u || v->sep_channel_index!=v->channel_index || v->lcid<0x40u ||
        v->lcid>0xffffu || v->type!=255u || v->owner_sep+1u!=g->local_seid || v->flags!=0x10u)
        return MUSIC_BAD_CHANNEL;
    if(v->local_receive_mtu<1u || v->local_receive_mtu>4096u || !bytes || bytes>v->local_receive_mtu)return MUSIC_BAD_PACKET_SIZE;
    return 0;
}
int music_guard_frame(const struct music_guard *g,uint32_t session,const uint8_t *p,uint32_t n)
{
    struct music_config c;
    if(!range(g,sizeof(*g),4) || n<4u || n>4096u || !range(p,n,1) ||
        overlap(g,sizeof(*g),p,n))return MUSIC_BAD_ARGUMENT;
    if(g->active!=1u || !session || session!=g->session)return MUSIC_BAD_SESSION;
    int result=codec(g->codec_word,&c);if(result)return result;
    uint32_t expected=(c.rate==44100u?2u:3u)<<6 | (c.blocks/4u-1u)<<4 |
        c.mode<<2 | c.allocation<<1 | (c.subbands==8u);
    uint32_t bitpool=p[2],minimum=(g->codec_word>>16)&255u,maximum=g->codec_word>>24;
    if(p[0]!=0x9cu || p[1]!=expected || bitpool<minimum || bitpool>maximum)return MUSIC_BAD_CODEC;
    uint32_t bits=c.blocks*bitpool;
    if(c.mode<=1u)bits*=c.channels;
    if(c.mode==3u)bits+=c.subbands;
    uint32_t length=4u+c.subbands*c.channels/2u+(bits+7u)/8u;
    if(length>n)return MUSIC_BAD_PACKET_SIZE;
    return (int)length;
}
