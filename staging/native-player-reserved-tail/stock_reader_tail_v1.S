.syntax unified
.cpu arm1176jzf-s
.thumb
.section .text.stock_reader_tail_relocated,"ax",%progbits
.balign 4
.global stock_reader_tail_relocated
.type stock_reader_tail_relocated,%function
.thumb_func
stock_reader_tail_relocated:
    /* Exact first8 bytes of original3B3294..3B329C. */
    push {r4,r5,r6,r7,lr}
    movs r4,r1
    ldr r2,[r1,#4]
    movs r5,r0
    push {r3}
    ldr r3,1f
    mov ip,r3
    pop {r3}
    bx ip
    .balign 4
1:  .word 0x003b329d
.size stock_reader_tail_relocated,.-stock_reader_tail_relocated
