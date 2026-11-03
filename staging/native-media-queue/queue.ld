/* Emulator-only standalone companion, not a DLLIMG. */
ENTRY(media_queue_init)
PHDRS { code PT_LOAD FLAGS(5); state PT_LOAD FLAGS(6); payload PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x08300000;
 .text : { *(.text*) } :code
 .rodata : { KEEP(*(.queue_api)) *(.rodata*) } :code
 __queue_code_end = .;
 . = ALIGN(4096);
 __queue_state_start = .;
 .data : { *(.data*) } :state
 .bss (NOLOAD) : { *(.bss*) *(COMMON) } :state
 __queue_state_end = .;
 . = ALIGN(4096)+4096;
 .queue_payload (NOLOAD) : { __queue_payload_start = .; *(.queue_payload) } :payload
 __queue_payload_end = .;
 ASSERT(__queue_payload_end-__queue_payload_start == 16384, "Queue payload size differs")
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
