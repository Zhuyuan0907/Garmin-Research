.syntax unified
.cpu arm1176jzf-s
.section .text.rg_profile_entry,"ax",%progbits
.arm
.global rg_profile_entry
.type rg_profile_entry,%function
rg_profile_entry:
ldr r3, [sp], #4
b rg_profile_gate
.section .text.rg_stock_profile,"ax",%progbits
.thumb
.align 2
.global rg_stock_profile
.type rg_stock_profile,%function
.thumb_func
rg_stock_profile:
.byte 0xf7,0xb5,0x0,0x20,0xf,0x0,0x84,0xb0,0x0,0x2a
push {r3}
ldr r3,1f
mov ip,r3
pop {r3}
bx ip
.align 2
1: .word 0x277d31
.section .text.rg_queue_entry,"ax",%progbits
.arm
.global rg_queue_entry
.type rg_queue_entry,%function
rg_queue_entry:
ldr r3, [sp], #4
b rg_queue_gate
.section .text.rg_stock_queue,"ax",%progbits
.thumb
.align 2
.global rg_stock_queue
.type rg_stock_queue,%function
.thumb_func
rg_stock_queue:
.byte 0xff,0xb5,0x5,0x0,0x0,0x20,0x83,0xb0,0x1,0x90
push {r3}
ldr r3,1f
mov ip,r3
pop {r3}
bx ip
.align 2
1: .word 0x277c75
.section .text.rg_selector_entry,"ax",%progbits
.arm
.global rg_selector_entry
.type rg_selector_entry,%function
rg_selector_entry:
ldr r3, [sp], #4
b rg_selector_gate
.section .text.rg_stock_selector,"ax",%progbits
.thumb
.align 2
.global rg_stock_selector
.type rg_stock_selector,%function
.thumb_func
rg_stock_selector:
.byte 0xf3,0xb5,0x95,0xb0,0x15,0x98,0xd,0x0,0x83,0x1
push {r3}
ldr r3,1f
mov ip,r3
pop {r3}
bx ip
.align 2
1: .word 0x2f9f39
.section .text.rg_prepare_entry,"ax",%progbits
.arm
.global rg_prepare_entry
.type rg_prepare_entry,%function
rg_prepare_entry:
ldr r3, [sp], #4
b rg_prepare_gate
.section .text.rg_stock_prepare,"ax",%progbits
.thumb
.align 2
.global rg_stock_prepare
.type rg_stock_prepare,%function
.thumb_func
rg_stock_prepare:
push {r0,r1,r2,r3,r4,r5,r6,r7,lr}
movs r5,r0
movs r1,r3
adds r0,#0xf4
sub sp,#4
push {r3}
ldr r3,3f
mov ip,r3
pop {r3}
blx ip
movs r4,r5
push {r3}
ldr r3,1f
mov ip,r3
pop {r3}
bx ip
.align 2
1: .word 0x4379e5
3: .word 0x437765
.section .text.rg_allocate_entry,"ax",%progbits
.arm
.global rg_allocate_entry
.type rg_allocate_entry,%function
rg_allocate_entry:
b rg_allocate_gate
.section .text.rg_stock_allocate,"ax",%progbits
.thumb
.align 2
.global rg_stock_allocate
.type rg_stock_allocate,%function
.thumb_func
rg_stock_allocate:
push {r4,r5}
movs r4,r0
ldr r0,3f
ldr r2,4f
push {r3}
ldr r3,1f
mov ip,r3
pop {r3}
bx ip
.align 2
1: .word 0x48ee71
3: .word 0xffff
4: .word 0x034e3cf4
