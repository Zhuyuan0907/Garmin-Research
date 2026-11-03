#ifndef UMCN_CLEANUP_BRIDGE_CONTRACT_H
#define UMCN_CLEANUP_BRIDGE_CONTRACT_H
#define UMCN_CLEANUP_FRAME_BYTES 64
#define UMCN_ORIGINAL_CLEANUP_ENTRY 0x003b9dfc
#define UMCN_ORIGINAL_CLEANUP_RESUME_THUMB 0x003b9e07
/* Exact MAIN bytes at entry before any hook:
 * f0 b5 05 00 00 20 2e 00 87 b0
 * push{r4-r7,lr};movs r5,r0;movs r0,#0;movs r6,r5;sub sp,#28
 */
#endif
