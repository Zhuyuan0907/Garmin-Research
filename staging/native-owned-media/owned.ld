ENTRY(owned_media_init)
SECTIONS {
 . = 0x08800000;
 .text : { KEEP(*(.owned_api)) KEEP(*(.output_api)) KEEP(*(.queue_api)) KEEP(*(.worker_api))
           KEEP(*(.extension_exports)) *(.text .text.*) *(.rodata .rodata.*) }
 __output_code_end = .;
 ASSERT(. <= 0x08840000, "owned code exceeds limit")
 . = 0x08840000; __output_state_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
 __output_state_end = .;
 ASSERT(. <= 0x08846000, "owned state exceeds limit")
 . = 0x08848000; .pcm0 (NOLOAD) : { *(.pcm0) }
 . = 0x0884a000; .pcm1 (NOLOAD) : { *(.pcm1) }
 . = 0x0884c000; .pcm2 (NOLOAD) : { *(.pcm2) }
 . = 0x0884e000; .pcm3 (NOLOAD) : { *(.pcm3) }
 . = 0x08850000; .gather (NOLOAD) : { *(.gather) }
 . = 0x08860000;
 .queue_payload (NOLOAD) : { __queue_payload_start = .; *(.queue_payload) __queue_payload_end = .; }
 . = 0x08870000;
 .worker_stack (NOLOAD) : { __worker_stack_start = .; *(.worker_stack) __worker_stack_end = .; }
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
