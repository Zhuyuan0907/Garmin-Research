/* Offline only: exact original prologues verified by builder. Publication
 * forwards the fifth stack argument, keeps the original result, then posts.
 * Completion posts only after the entire original cleanup function returns.
 */
.syntax unified
.cpu arm1176jzf-s
.arm
#include "source_worker_imports.h"
.section .text.source_hooks,"ax",%progbits
.global source_publication_hook
.type source_publication_hook,%function
source_publication_hook:
    push {r4,r5,r6,lr}
    mov r4,sp
    ldr r12,[r4,#16]
    sub sp,sp,#8
    bic sp,sp,#7
    str r12,[sp]
    bl source_publication_original
.global source_publication_after_original
source_publication_after_original:
    mov r5,r0
    bl source_worker_published
    mov r0,r5
    mov sp,r4
    pop {r4,r5,r6,lr}
    bx lr
.size source_publication_hook,.-source_publication_hook
.global source_publication_original
.type source_publication_original,%function
source_publication_original:
    push {r0,r1,r4,r5,r6,r7,r8,r9,r10,lr}
    mov r5,r0
    ldr r12,=OWNED_CONSUME_RESUME
    bx r12
.size source_publication_original,.-source_publication_original
.global source_completion_hook
.type source_completion_hook,%function
source_completion_hook:
    push {r4,r5,r6,lr}
    mov r4,sp
    mov r6,r0
    bl source_completion_original
.global source_completion_after_original
source_completion_after_original:
    mov r5,r0
    mov r0,r6
    bic sp,sp,#7
    bl source_worker_completed
    mov r0,r5
    mov sp,r4
    pop {r4,r5,r6,lr}
    bx lr
.size source_completion_hook,.-source_completion_hook
.global source_completion_original
.type source_completion_original,%function
source_completion_original:
    push {r4,r5,r6,r7,lr}
    movs r5,r0
    movs r0,#0
    movs r6,r5
    sub sp,sp,#28
    ldr r12,=0x3b9e07
    bx r12
.size source_completion_original,.-source_completion_original
.section .note.GNU-stack,"",%progbits
