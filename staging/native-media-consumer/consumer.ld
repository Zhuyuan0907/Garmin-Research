/* Emulator-only companion, not a DLLIMG or VPM. */
ENTRY(media_worker_init)
PHDRS { code PT_LOAD FLAGS(5); state PT_LOAD FLAGS(6); payload PT_LOAD FLAGS(6); stack PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x08300000;
 .text : { *(.text*) } :code
 .rodata : { KEEP(*(.queue_api)) KEEP(*(.worker_api)) KEEP(*(.consumer_api)) *(.rodata*) } :code
 __queue_code_end = .;
 . = ALIGN(4096);
 __queue_state_start = .;
 .data : { *(.data*) } :state
 .bss (NOLOAD) : { *(.bss*) *(COMMON) } :state
 __queue_state_end = .;
 . = ALIGN(4096)+4096;
 .queue_payload (NOLOAD) : { __queue_payload_start = .; *(.queue_payload) } :payload
 __queue_payload_end = .;
 . = ALIGN(4096)+4096;
 .worker_stack (NOLOAD) : { __worker_stack_start = .; *(.worker_stack) } :stack
 __worker_stack_end = .;
 ASSERT(__queue_payload_end-__queue_payload_start == 16384, "Payload size differs")
 ASSERT(__worker_stack_end-__worker_stack_start == 16384, "Stack size differs")
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
