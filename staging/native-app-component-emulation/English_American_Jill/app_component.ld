ENTRY(native_app_component_entry)
original_tts_entry = 0x2d677b4;
SECTIONS {
 . = 0x2f13000;
 .text : { KEEP(*(.text.native_app_component_entry))
   KEEP(*(.app_component_api)) KEEP(*(.owned_api)) KEEP(*(.output_api))
   KEEP(*(.queue_api)) KEEP(*(.worker_api)) KEEP(*(.playback_api))
   KEEP(*(.coordinator_api)) KEEP(*(.source_worker_api)) KEEP(*(.extension_exports))
   *(.text .text.*) *(.rodata .rodata.*) }
 __app_code_end = .;
 ASSERT(. <= 0x2f23000, "combined code exceeds64KiB")
 . = 0x2f23000; __app_zero_start = .;
 .bss (NOLOAD) : { __app_bss_start = .; *(.bss .bss.*) *(COMMON) __app_bss_end = .; }
 ASSERT(. <= 0x2f28000, "combined BSS exceeds20KiB")
 . = 0x2f29000; .pcm0 (NOLOAD) : { *(.pcm0) }
 . = 0x2f2a000; .pcm1 (NOLOAD) : { *(.pcm1) }
 . = 0x2f2b000; .pcm2 (NOLOAD) : { *(.pcm2) }
 . = 0x2f2c000; .pcm3 (NOLOAD) : { *(.pcm3) }
 . = 0x2f2d000; .gather (NOLOAD) : { *(.gather) }
 . = 0x2f2e000; .queue_payload (NOLOAD) : {
   __queue_payload_start = .; *(.queue_payload) __queue_payload_end = .; }
 . = 0x2f33000; .worker_stack (NOLOAD) : {
   __worker_stack_start = .; *(.worker_stack) __worker_stack_end = .; }
 . = 0x2f37000; .source_stack (NOLOAD) : {
   __source_stack_start = .; *(.source_stack) __source_stack_end = .; }
 __app_zero_end = .; __app_end = .;
 __combined_ram_bytes = ABSOLUTE(. - 0x2d4bb74);
 ASSERT(__combined_ram_bytes <= 0x300000, "exceeds original DLL reservation")
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
