.syntax unified
.cpu arm1176jzf-s
.macro shim name
.section .text.lw_\name\()_entry,"ax",%progbits
.arm
.global lw_\name\()_entry
.type lw_\name\()_entry,%function
lw_\name\()_entry:
ldr r3,[sp],#4
b lw_\name\()_gate
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
shim write_alias
shim seek_alias
shim setup
shim read
shim write
shim seek
.section .text.lw_stock_write_alias,"ax",%progbits
.thumb
.align 2
.global lw_stock_write_alias
.type lw_stock_write_alias,%function
.thumb_func
lw_stock_write_alias:
push {r4,r5,r6,lr}
movs r5,#0
cmp r0,#0
beq 2f
movs r4,#0x87
lsls r4,r4,#2
jump 0x4cae97
2:
jump 0x4caea5
.section .text.lw_stock_seek_alias,"ax",%progbits
.thumb
.align 2
.global lw_stock_seek_alias
.type lw_stock_seek_alias,%function
.thumb_func
lw_stock_seek_alias:
push {r4,r5,r6,lr}
movs r5,#0
mvns r5,r5
cmp r0,#0
beq 2f
adds r3,r0,#7
jump 0x4caeb5
2:
jump 0x4caec9
.section .text.lw_stock_setup,"ax",%progbits
.thumb
.align 2
.global lw_stock_setup
.type lw_stock_setup,%function
.thumb_func
lw_stock_setup:
.byte 0x0a,0x68,0x02,0x60,0x49,0x68,0x41,0x60,0x01,0x21
jump 0x5e75a9
.section .text.lw_stock_read,"ax",%progbits
.thumb
.align 2
.global lw_stock_read
.type lw_stock_read,%function
.thumb_func
lw_stock_read:
.byte 0x70,0xb5,0x04,0x00,0x08,0x00,0x21,0x7b,0x00,0x25
jump 0x5e75c5
.section .text.lw_stock_write,"ax",%progbits
.thumb
.align 2
.global lw_stock_write
.type lw_stock_write,%function
.thumb_func
lw_stock_write:
push {r4,r5,r6,lr}
movs r4,r0
ldrb r0,[r0,#12]
movs r5,#0
cmp r0,#0
beq 2f
jump 0x5e75fd
2:
jump 0x5e761f
.section .text.lw_stock_seek,"ax",%progbits
.thumb
.align 2
.global lw_stock_seek
.type lw_stock_seek,%function
.thumb_func
lw_stock_seek:
movs r3,#0
mvns r3,r3
cmp r2,#0
beq 2f
cmp r2,#1
jump 0x5e762d
2:
jump 0x5e7643
