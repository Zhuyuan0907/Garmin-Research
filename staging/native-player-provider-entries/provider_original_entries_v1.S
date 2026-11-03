.syntax unified
.cpu arm1176jzf-s
.thumb
.macro jump destination
push {r3}
ldr r3,1f
mov ip,r3
pop {r3}
bx ip
.align 2
1: .word \destination
.endm
.section .text.pg_stock_start,"ax",%progbits
.thumb
.align 2
.global pg_stock_start
.type pg_stock_start,%function
.thumb_func
pg_stock_start:
lsls r3,r0,#3
adds r0,r3,r0
ldr r3,2f
lsls r0,r0,#6
jump 0x48ee01
2: .word 0x034e3cf4
.section .text.pg_stock_stop,"ax",%progbits
.thumb
.align 2
.global pg_stock_stop
.type pg_stock_stop,%function
.thumb_func
pg_stock_stop:
lsls r3,r0,#3
ldr r1,2f
adds r0,r3,r0
lsls r0,r0,#6
push {r4,lr}
jump 0x48ee1d
2: .word 0x034e3cf4
.section .text.pg_stock_free,"ax",%progbits
.thumb
.align 2
.global pg_stock_free
.type pg_stock_free,%function
.thumb_func
pg_stock_free:
lsls r3,r0,#3
ldr r2,2f
adds r0,r3,r0
movs r1,#0
jump 0x48ee61
2: .word 0x034e3cf4
.section .text.pg_stock_config,"ax",%progbits
.thumb
.align 2
.global pg_stock_config
.type pg_stock_config,%function
.thumb_func
pg_stock_config:
push {r4,r5,r6,lr}
lsls r3,r0,#3
adds r0,r3,r0
ldr r3,2f
jump 0x48eead
2: .word 0x034e3cf4
.section .text.pg_stock_reset,"ax",%progbits
.thumb
.align 2
.global pg_stock_reset
.type pg_stock_reset,%function
.thumb_func
pg_stock_reset:
/* Whole original loop relocated: entry patch covers old +6 loop header. */
ldr r2,2f
movs r0,#0
movs r1,r0
3:
lsls r3,r0,#3
adds r3,r3,r0
lsls r3,r3,#6
adds r3,r3,r2
adds r0,r0,#1
cmp r0,#5
strb r1,[r3,#12]
blt 3b
bx lr
.align 2
2: .word 0x034e3cf4
.section .text.pg_stock_seek,"ax",%progbits
.thumb
.align 2
.global pg_stock_seek
.type pg_stock_seek,%function
.thumb_func
pg_stock_seek:
lsls r3,r0,#3
ldr r2,2f
adds r0,r3,r0
lsls r0,r0,#6
jump 0x48eef1
2: .word 0x034e3cf4
