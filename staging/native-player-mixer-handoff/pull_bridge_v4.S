/* NEW ARM full-return wrapper. NOT installed anywhere by this REL artifact.
 * Original2F9CCA prologue is Thumb f1b5 8ab0, total native frame64bytes.
 * This wrapper's frame is separate and remains live through originalreturn. */
 .syntax unified
 .cpu arm1176jzf-s
 .arm
 .text
 .align 2
 .global mcs_pull_bridge
 .type mcs_pull_bridge,%function
mcs_pull_bridge:
 stmdb sp!,{r0-r3,r4-r8,lr}
 mov r8,sp
 bic sp,sp,#7
 sub sp,sp,#80
 mov r1,sp
 mov r2,#0
 mov r3,#18
1: str r2,[r1],#4
 subs r3,r3,#1
 bne 1b
 ldr r0,[r8]
 mov r1,sp
 ldr r2,[r8,#36] /* Original mixer BL return LR, not wrapper internal LR. */
 bl mcs_pull_begin
 cmp r0,#0
 bne 2f
 ldmia r8,{r0-r3}
 bl mcs_original_pull_thunk
 str r0,[sp,#72]
 mov r1,r0
 mov r0,sp
 bl mcs_pull_end
 ldr r0,[sp,#72]
 b 3f
2: mov r0,#0
3: str r0,[r8]
 mov sp,r8
 ldmia sp!,{r0-r3,r4-r8,lr}
 bx lr
 .size mcs_pull_bridge,.-mcs_pull_bridge
 .thumb
 .align 2
 .thumb_func
 .type mcs_original_pull_thunk,%function
mcs_original_pull_thunk:
 .hword 0xb5f1
 .hword 0xb08a
 ldr r3,4f
 bx r3
 .align 2
4: .word 0x002f9ccf
 .size mcs_original_pull_thunk,.-mcs_original_pull_thunk
 .section .note.GNU-stack,"",%progbits
