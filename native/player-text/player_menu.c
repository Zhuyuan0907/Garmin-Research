/* Exact HWID 1352 / SW 8.00 private ABI experiment. EMULATION ONLY.
 * This is neither a firmware installer nor a supported Garmin App API.
 * The module, callback, caption and resource storage must stay resident.
 */
#include <stdint.h>
#include <stddef.h>

/* The stock string ctor/copy initializes16 bytes. Grid captions include
 * an additional borrowed/auxiliary word which stock copies separately. */
typedef struct { uint32_t words[4]; } NativeString;
typedef struct { NativeString text; uint32_t auxiliary; } GridCaption;
_Static_assert(sizeof(NativeString)==16, "Stock string object");
_Static_assert(sizeof(GridCaption)==20, "Grid caption including auxiliary word");
typedef struct { const char *constant; char *owned; } CString;
typedef struct {
    uint32_t id;
    uint8_t flag, pad0[3];
    GridCaption label;
    CString visual[7];
    void (*launch)(uint32_t);
    uint32_t context;
    uint8_t type, pad1[3];
    uint32_t (*appearance)(uint32_t, void *, NativeString *, uint32_t *);
} GridIconType;

_Static_assert(sizeof(GridIconType) == 100, "Exact original record size");
_Static_assert(offsetof(GridIconType, launch) == 84, "Launch ABI");
_Static_assert(offsetof(GridIconType, context) == 88, "Context ABI");
_Static_assert(offsetof(GridIconType, appearance) == 96, "Appearance ABI");

typedef struct {
    uint32_t attempts, accepted, activations, last_context;
    uint32_t audio_register_requests, audio_start_requests;
} MenuState;
MenuState native_player_menu_state;

/* Constant record-size divisions cannot reach these freestanding EABI
 * traps. Keep libgcc from pulling its Linux signal handler into this image.
 */
int __aeabi_idiv0(int value) { (void)value; for (;;) {} }
long long __aeabi_ldiv0(long long value) { (void)value; for (;;) {} }

static const uint16_t wav_path[] = {
    '0', ':', '/', 'G', 'a', 'r', 'm', 'i', 'n', '/',
    't', 'e', 's', 't', '.', 'w', 'a', 'v', 0
};
static const char empty_visual[] = "";

/* Recovered stock normal-Grid updater54A2FA calls record+0x14 with
 * context, seven default shared_ptr pairs, a default NativeString and one
 * default word. The returned value is passed to Widget virtual39 (state).
 * This prototype requests state0 only for its resident player context.
 * It leaves all stock-constructed outputs unchanged and borrows no pointer.
 */
typedef struct {
    uint32_t calls, rejected, last_context, last_visuals, last_caption, last_word;
} AppearanceState;
AppearanceState native_player_appearance_state;

uint32_t native_player_menu_appearance(uint32_t context, void *visuals,
                                      NativeString *caption, uint32_t *word)
{
    native_player_appearance_state.calls++;
    native_player_appearance_state.last_context = context;
    native_player_appearance_state.last_visuals = (uint32_t)(uintptr_t)visuals;
    native_player_appearance_state.last_caption = (uint32_t)(uintptr_t)caption;
    native_player_appearance_state.last_word = (uint32_t)(uintptr_t)word;
    if (context != 0x13528000) {
        native_player_appearance_state.rejected++;
        return 4;  /* Same stock disabled state seen after normal factory. */
    }
    return 0;
}


void native_player_menu_activate(uint32_t context)
{
    /* Match the stock diagnostic WAV handler's request and start sequence.
     * Its registration result is not interpreted as an invented success flag.
     * The VM records these two API boundaries; it does not model the speaker.
     */
    typedef uint32_t (*RegisterAudio)(uint32_t, uint32_t, uint32_t,
                                      const uint16_t *, uint32_t, uint32_t, uint32_t);
    typedef uint32_t (*StartAudio)(uint32_t, uint32_t);
    native_player_menu_state.activations++;
    native_player_menu_state.last_context = context;
    native_player_menu_state.audio_register_requests++;
    ((RegisterAudio)(uintptr_t)0x525f14)(9, 22, 11, wav_path, 38, 0, 0);
    native_player_menu_state.audio_start_requests++;
    ((StartAudio)(uintptr_t)0x36b721)(9, 0);
}

/* Return values belong to this wrapper, not to the private stock API:
 * 0 appended; 1 bad input/catalog; 2 ID already registered.
 * Valid mapped pointers, UI-thread ownership and successful allocations are
 * prerequisites. It is not an arbitrary-pointer validator or thread lock.
 */
uint32_t native_player_menu_install(void *registry, uint32_t id,
                                   uint32_t context, const uint16_t *caption)
{
    typedef NativeString *(*StringCtor)(NativeString *, const uint16_t *, uint32_t);
    typedef void (*StringDtor)(NativeString *);
    typedef GridIconType *(*GridCtor)(GridIconType *, uint32_t, uint32_t,
        const GridCaption *, const CString *, const CString *, const CString *,
        const CString *, const CString *, void (*)(uint32_t), uint32_t, uint32_t,
        const CString *, const CString *, uint32_t (*)(uint32_t, void *, NativeString *, uint32_t *));
    typedef void (*GridDtor)(GridIconType *);
    typedef void (*Append)(void *, const GridIconType *);
    uintptr_t begin, end, capacity;
    uint32_t length, i;
    GridCaption label;
    GridIconType record;
    CString visual = { empty_visual, 0 };

    native_player_menu_state.attempts++;
    if (!registry || ((uintptr_t)registry & 3) || !caption ||
        ((uintptr_t)caption & 1) || !id || id > 0x7fffffff)
        return 1;
    for (length = 0; length < 64 && caption[length]; length++) {}
    if (!length || length == 64) return 1;
    begin = ((uint32_t *)registry)[3];
    end = ((uint32_t *)registry)[4];
    capacity = ((uint32_t *)registry)[5];
    if ((begin | end | capacity) & 3 || end < begin || capacity < end ||
        (end - begin) % sizeof(GridIconType) ||
        (capacity - begin) % sizeof(GridIconType) ||
        (capacity - begin) / sizeof(GridIconType) > 4096 ||
        (!begin && (end || capacity)))
        return 1;
    for (i = 0; i < (end - begin) / sizeof(GridIconType); i++)
        if (((const GridIconType *)begin)[i].id == id) return 2;

    /* Do not let the separately-copied caption word inherit stack bytes. */
    label.auxiliary = 0;
    ((StringCtor)(uintptr_t)0x39274f)(&label.text, caption, 0xffffffff);
    ((GridCtor)(uintptr_t)0x498fc4)(&record, id, 0, &label,
        &visual, &visual, &visual, &visual, &visual,
        native_player_menu_activate, context, 0, &visual, &visual, native_player_menu_appearance);
    ((Append)(uintptr_t)0x31592b)(registry, &record);
    ((GridDtor)(uintptr_t)0x399088)(&record);
    ((StringDtor)(uintptr_t)0x392773)(&label.text);
    native_player_menu_state.accepted++;
    return 0;
}
