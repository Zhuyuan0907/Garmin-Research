#include "recovered_abi.h"
/* Compile-time layout check only; no exported task entry or device call. */
_Static_assert(offsetof(struct os20_research_record,user_entry_word)==12,"callback");
_Static_assert(offsetof(struct os20_research_record,user_argument_word)==16,"argument");
