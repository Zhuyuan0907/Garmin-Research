/* EMULATION-ONLY bounded pending/mailbox publisher for the exact frozen image.
 * This API supplies no source/session/audio ownership or GUI control binding.
 * The real persistent source loop consumes these bits via original post/wait.
 */
#include <stdint.h>
#include "../../../native/ui-music-native-adapter/native_adapter.h"
extern volatile struct umcn_source_view source_worker_state;
extern uint32_t music_owner_irq_save(void);
extern void music_owner_irq_restore(uint32_t);
extern void music_owner_post(uint32_t,uint32_t);
int music_native_publish(uint32_t events)
{
    uint32_t key;
    if (!events || (events & ~0x000f0000u)) return -20;
    key=music_owner_irq_save();
    if (!source_worker_state.tcb || source_worker_state.finished_on_stack ||
        source_worker_state.quit_requested) {
        music_owner_irq_restore(key); return -22;
    }
    source_worker_state.pending|=events;
    uint32_t tcb=source_worker_state.tcb;
    music_owner_irq_restore(key);
    music_owner_post(tcb,events);
    return 0;
}
