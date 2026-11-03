/* New RX veneers preserve only the three sealed endpoint entry addresses.
 * No original firmware bytes are patched. These are not installable hooks. */
.syntax unified
.thumb
.section .legacy.worker,"ax",%progbits
.global resident_music_worker_v1
.thumb_func
resident_music_worker_v1:
    ldr r3,1f
    bx r3
    .align 2
1:  .word fifo_worker_core_v1
.section .legacy.controller,"ax",%progbits
.global resident_controller_v1
.thumb_func
resident_controller_v1:
    ldr r3,2f
    bx r3
    .align 2
2:  .word fifo_controller_core_v1
.section .legacy.idle,"ax",%progbits
.global resident_idle_v1
.thumb_func
resident_idle_v1:
    ldr r3,3f
    bx r3
    .align 2
3:  .word fifo_idle_core_v1
.section .note.GNU-stack,"",%progbits
