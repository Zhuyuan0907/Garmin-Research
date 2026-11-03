/* NEW owning translation unit: the original C and its static anchor occur
 * exactly once. No frozen source or object's linkage is changed. */
#include "../../../native/music-continuous/memory_output.c"
_Static_assert(sizeof(anchor_zero) == 2, "original owned anchor ABI");
_Static_assert(sizeof(uintptr_t) == 4, "native 32-bit address ABI");
uint32_t native_ui_music_owned_anchor_address(void)
{
    return (uint32_t)(uintptr_t)&anchor_zero;
}
