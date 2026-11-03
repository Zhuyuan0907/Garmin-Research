/* Original coordinator executes unchanged inside a scoped whole-return
 * mutation guard; pending1 means no original call was admitted. */
#include "music_session_guard_v2.h"
#define media_coordinator_cancel mcs_original_coordinator_cancel
#define media_coordinator_pump mcs_original_coordinator_pump
#define coordinator_api mcs_unleased_coordinator_api
#include "../../../native/music-continuous/media_coordinator.c"
#undef media_coordinator_cancel
#undef media_coordinator_pump
#undef coordinator_api
int media_coordinator_cancel(void)
{
    int result=mcs_mutation_begin(mcs_bridge_context);
    if(result)return result;
    result=mcs_original_coordinator_cancel();
    mcs_mutation_end(mcs_bridge_context);
    return result;
}
int media_coordinator_pump(void)
{
    int result=mcs_mutation_begin(mcs_bridge_context);
    if(result)return result;
    result=mcs_original_coordinator_pump();
    mcs_mutation_end(mcs_bridge_context);
    return result;
}
const void *const mcs_coordinator_api[] __attribute__((used,section(".mcs_coordinator_api")))={
    (const void *)media_coordinator_pump,(const void *)media_coordinator_cancel
};
