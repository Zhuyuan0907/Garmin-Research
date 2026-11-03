/* Offline Thumb entry patch targets this ARM shim. Original callback's stack
 * alignment is preserved for its body; only the new C call is EABI-aligned.
 * Displaced instructions are exact2F998E..2F9996, validated by the builder.
 */
.syntax unified
.cpu arm1176jzf-s
.arm
.section .text.playback_hook,"ax",%progbits
.global playback_callback_hook
.type playback_callback_hook,%function
playback_callback_hook:
    push {r0-r6,lr}
    mov r4,sp
    bic sp,sp,#7
    bl playback_before_start
    cmp r0,#0
    bne 1f
    mov sp,r4
    pop {r0-r6,lr}
    b playback_callback_original
1:
    mov r12,r0
    mov sp,r4
    pop {r0-r6,lr}
    mov r0,r12
    bx lr
.size playback_callback_hook,.-playback_callback_hook

.global playback_callback_original
.type playback_callback_original,%function
playback_callback_original:
    push {r4,r5,lr}
    movs r2,r0
    movs r5,#0
    ldrsb r0,[r2,r5]
    movs r1,#255
    ldr r12,=0x2f9999
    bx r12
.size playback_callback_original,.-playback_callback_original
.section .note.GNU-stack,"",%progbits
