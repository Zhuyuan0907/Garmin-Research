.syntax unified
.cpu arm1176jzf-s
.macro shim name
.section .text.al_\name\()_entry,"ax",%progbits
.arm
.global al_\name\()_entry
.type al_\name\()_entry,%function
al_\name\()_entry:
ldr r3,[sp],#4
b al_\name\()_gate
.endm
.macro jump dest
push {r3}
ldr r3,1f
mov ip,r3
pop {r3}
bx ip
.align 2
1: .word \dest
.endm
shim config
shim stop
shim start
shim seek
.section .text.al_stock_config,"ax",%progbits
.thumb
.align 2
.global al_stock_config
.type al_stock_config,%function
.thumb_func
al_stock_config:
push {r4,r5,r6,lr}
movs r5,r2
adds r4,r0,#7
movs r2,#0
adds r4,#255
mvns r2,r2
jump 0x4cae25
.section .text.al_stock_stop,"ax",%progbits
.thumb
.align 2
.global al_stock_stop
.type al_stock_stop,%function
.thumb_func
al_stock_stop:
movs r2,#0
mvns r2,r2
push {r4,lr}
cmp r0,#0
beq 2f
adds r4,r0,#7
jump 0x4cae51
2:
jump 0x4cae69
.section .text.al_stock_start,"ax",%progbits
.thumb
.align 2
.global al_stock_start
.type al_stock_start,%function
.thumb_func
al_stock_start:
push {r4,r5,r6,lr}
movs r5,#0
cmp r0,#0
beq 2f
movs r4,#0x43
lsls r4,r4,#3
jump 0x4cae79
2:
jump 0x4cae87
.section .text.al_stock_seek,"ax",%progbits
.thumb
.align 2
.global al_stock_seek
.type al_stock_seek,%function
.thumb_func
al_stock_seek:
cmp r0,#0
bne 2f
subs r0,r0,#1
bx lr
2:
push {r4,r5,lr}
jump 0x4caf39
.section .text.al_stock_clear,"ax",%progbits
.thumb
.align 2
.global al_stock_clear
.type al_stock_clear,%function
.thumb_func
al_stock_clear:
.byte 0x00,0x21,0x01,0x73,0x08,0x00,0x70,0x47
.size al_stock_clear,.-al_stock_clear
/* Low16 == Thumb BX r3 instruction. Native LDR literal overlaps that BX.
 * This fixed ARM entry stays inside the same original loaded DLL image. */
.section .ali_clear_fixed,"ax",%progbits
.arm
.global al_clear_fixed_entry
.type al_clear_fixed_entry,%function
al_clear_fixed_entry:
b al_clear_gate
.size al_clear_fixed_entry,.-al_clear_fixed_entry
