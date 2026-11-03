.syntax unified
.cpu arm1176jzf-s
.arm
.section .text.ms_initializer_sync_bridge,"ax",%progbits
.global ms_initializer_sync_bridge
.type ms_initializer_sync_bridge,%function
ms_initializer_sync_bridge:
    /* Preserve original argument registers and original3B9C59 LR. The
     * admission call ends its IRQ exclusion before native code may wait. */
    push {r0-r3,r4,lr}
    mov r3,lr
    bl ms_before_original_sync
    pop {r0-r3,r4,lr}
    ldr ip,=0x46cc7b
    bx ip
.size ms_initializer_sync_bridge,.-ms_initializer_sync_bridge
