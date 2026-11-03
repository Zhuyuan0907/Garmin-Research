.syntax unified
.cpu arm1176jzf-s
.arm
.text
.global _start
_start:
push {r0,r1,r2,r3,r12,lr}
ldr r0, controller
mov r1,#1
ldr r12, post
blx r12
pop {r0,r1,r2,r3,r12,lr}
ldr pc, resume
.align 2
controller: .word 0x9503f90
post: .word 0x2fcf44
resume: .word 0x2f830ec
