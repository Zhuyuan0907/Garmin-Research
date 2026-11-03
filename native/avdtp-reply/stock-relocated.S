.syntax unified
.cpu arm1176jzf-s
.thumb
.section .text.stock_reply_relocated,"ax",%progbits
.balign 4
.global stock_reply_relocated
.type stock_reply_relocated,%function
.thumb_func
stock_reply_relocated:
    /* Exact eight displaced instructions at 5756AC..5756BC. */
    push {r4,r5,lr}
    sub sp,#12
    ldr r4,[sp,#24]
    movs r5,r3
    movs r3,#2
    cmp r4,#0
    beq 2f
    movs r3,#3
2:
    /* Keep r0..r3 and all callee-saved registers intact at continuation. */
    push {r0}
    ldr r0,1f
    mov ip,r0
    pop {r0}
    bx ip
    .balign 4
1:  .word 0x005756bd
.size stock_reply_relocated,.-stock_reply_relocated
