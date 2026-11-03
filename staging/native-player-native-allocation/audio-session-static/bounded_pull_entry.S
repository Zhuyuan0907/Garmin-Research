/* Explicit bounded caller, not a native MAIN2FA572 call-site patch. */
.syntax unified
.cpu arm1176jzf-s
.arm
.section .text.aas_pull,"ax",%progbits
.global aas_pull
.type aas_pull,%function
aas_pull:
 b mcs_pull_bridge
.size aas_pull,.-aas_pull
.section .note.GNU-stack,"",%progbits
