/* Reverse-engineered loader experiment only; not a device install candidate. */
.syntax unified
.cpu arm1176jzf-s
.arm
.section .component_header,"ax",%progbits
.global garmin_component_start
.type garmin_component_start,%function
garmin_component_start:
    b garmin_component_entry
    .word __component_ram_bytes
.size garmin_component_start, .-garmin_component_start
.section .note.GNU-stack,"",%progbits
