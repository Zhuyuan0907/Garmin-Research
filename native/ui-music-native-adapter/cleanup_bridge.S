/* Compiled only; not installed or executed by this prototype. Exact immutable
 * source_event_hooks.S prologue/continuation ABI, with an explicit64-byte frame
 * and whole-callback reference. Caller r0/result/LR and callee registers retained.
 */
.syntax unified
.cpu arm1176jzf-s
.arm
#include "cleanup_bridge_contract.h"
.section .text.umcn_cleanup_bridge,"ax",%progbits
.global umcn_cleanup_bridge
.type umcn_cleanup_bridge,%function
umcn_cleanup_bridge:
    push {r4,r5,r6,r7,r8,lr}
    mov r4,sp
    mov r6,r0
    mov r8,lr
    sub sp,sp,#UMCN_CLEANUP_FRAME_BYTES
    bic sp,sp,#7
    ldr r0,=umcn_cleanup_bridge_context
    ldr r0,[r0]
    mov r1,r6
    mov r2,sp
    mov r3,r8
    bl umcn_cleanup_begin
    mov r0,r6
    bl umcn_original_cleanup_continuation
.global umcn_cleanup_original_full_return
umcn_cleanup_original_full_return:
    mov r7,r0
    ldr r0,=umcn_cleanup_bridge_context
    ldr r0,[r0]
    mov r1,sp
    mov r2,r6
    mov r3,r7
    bl umcn_cleanup_after_original
    mov r0,r7
    mov sp,r4
    pop {r4,r5,r6,r7,r8,lr}
    bx lr
.size umcn_cleanup_bridge,.-umcn_cleanup_bridge
.global umcn_original_cleanup_continuation
.type umcn_original_cleanup_continuation,%function
umcn_original_cleanup_continuation:
    push {r4,r5,r6,r7,lr}
    movs r5,r0
    movs r0,#0
    movs r6,r5
    sub sp,sp,#28
    ldr r12,=UMCN_ORIGINAL_CLEANUP_RESUME_THUMB
    bx r12
.size umcn_original_cleanup_continuation,.-umcn_original_cleanup_continuation
.ltorg
.section .note.GNU-stack,"",%progbits
