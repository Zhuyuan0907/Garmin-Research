/* New copy of the identified Grid record/helper boundary only. ARM compile
 * is not actual GUI construction, foreground, input or ownership evidence.
 * It reuses the one known home ID/context; no new Page/widget ABI is guessed.
 */
#include <stddef.h>
#include "ui_music_single.h"
typedef struct { uint32_t words[4]; } NativeString;
typedef struct { NativeString text; uint32_t auxiliary; } GridCaption;
typedef struct { uint32_t hash; char *owned_name; } ResourceRef;
typedef struct {
    uint32_t id; uint8_t flag, pad0[3]; GridCaption label;
    ResourceRef visual[7]; void (*launch)(uint32_t); uint32_t context;
    uint8_t type, pad1[3];
    uint32_t (*appearance)(uint32_t, void *, void *, uint32_t *);
} GridIconType;
_Static_assert(sizeof(NativeString)==16, "original string size");
_Static_assert(sizeof(GridCaption)==20, "original caption size");
_Static_assert(sizeof(ResourceRef)==8, "original resource reference");
_Static_assert(sizeof(GridIconType)==100, "original Grid record size");
_Static_assert(offsetof(GridIconType,launch)==84, "original launch offset");
_Static_assert(offsetof(GridIconType,context)==88, "original context offset");
_Static_assert(offsetof(GridIconType,appearance)==96, "original appearance offset");
static int extent(uintptr_t begin, uintptr_t end)
{
    uint32_t count=0;
    if (end < begin) return 0;
    while (begin != end) {
        if (end-begin < 100u || ++count > 4096u) return 0;
        begin += 100u;
    }
    return 1;
}
int native_ui_music_menu_install(void *registry, const uint16_t *caption)
{
    typedef NativeString *(*StringCtor)(NativeString *,const uint16_t *,uint32_t);
    typedef void (*StringDtor)(NativeString *);
    typedef GridIconType *(*GridCtor)(GridIconType *,uint32_t,uint32_t,const GridCaption *,
        const ResourceRef *,const ResourceRef *,const ResourceRef *,const ResourceRef *,const ResourceRef *,
        void (*)(uint32_t),uint32_t,uint32_t,const ResourceRef *,const ResourceRef *,
        uint32_t (*)(uint32_t,void *,void *,uint32_t *));
    typedef void (*GridDtor)(GridIconType *);
    typedef void (*Append)(void *,const GridIconType *);
    uintptr_t begin,end,capacity,cursor;
    uint32_t n;
    GridCaption label;
    GridIconType record;
    ResourceRef visual={0x08a56eacu,0};
    if (!native_ui_music_gui_owner()) return UMC_WRONG_OWNER;
    native_ui_music_resident.menu_attempts++;
    if (!registry || ((uintptr_t)registry&3u) || !caption || ((uintptr_t)caption&1u)) return 1;
    for (n=0;n<64u && caption[n];n++) {}
    if (!n || n==64u) return 1;
    begin=((uint32_t *)registry)[3]; end=((uint32_t *)registry)[4]; capacity=((uint32_t *)registry)[5];
    if ((begin|end|capacity)&3u || capacity<end || (!begin && (end||capacity)) ||
        !extent(begin,end) || !extent(begin,capacity)) return 1;
    for (cursor=begin;cursor<end;cursor+=100u)
        if (((const GridIconType *)cursor)->id==UI_MUSIC_ICON_ID) return 2;
    label.auxiliary=0;
    ((StringCtor)(uintptr_t)0x39274fu)(&label.text,caption,0xffffffffu);
    ((GridCtor)(uintptr_t)0x498fc4u)(&record,UI_MUSIC_ICON_ID,0,&label,
        &visual,&visual,&visual,&visual,&visual,native_ui_music_menu_activate,
        UI_MUSIC_MENU_CONTEXT,0,&visual,&visual,native_ui_music_menu_appearance);
    ((Append)(uintptr_t)0x31592bu)(registry,&record);
    ((GridDtor)(uintptr_t)0x399088u)(&record);
    ((StringDtor)(uintptr_t)0x392773u)(&label.text);
    native_ui_music_resident.menu_delivered++;
    /* Wrapper delivery only; verify actual copied callbacks/registry/frame
     * in a future original GUI actor run. No native rendering claim. */
    return 0;
}
