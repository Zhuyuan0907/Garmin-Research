ENTRY(native_music_component_entry)
PHDRS { code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
original_tts_entry = 0x2d5a938;
SECTIONS {
 . = 0x2f7d000;
 .text : { KEEP(*(.text.native_music_component_entry)) KEEP(*(.text.native_app_component_entry)) KEEP(*(.music_component_api))
   KEEP(*(.app_component_api)) KEEP(*(.owned_api)) KEEP(*(.output_api))
   KEEP(*(.queue_api)) KEEP(*(.worker_api)) KEEP(*(.playback_api))
   KEEP(*(.coordinator_api)) KEEP(*(.source_worker_api)) KEEP(*(.extension_exports))
   *(.text .text.*) *(.rodata .rodata.*) } :code
 __app_code_end = .;
 ASSERT(. <= 0x2f8d000, "combined code exceeds64KiB")
 . = 0x2f8d000; __app_zero_start = .;
 .bss (NOLOAD) : { __app_bss_start = .; *(.bss .bss.*) *(COMMON) __app_bss_end = .; } :data
 ASSERT(. <= 0x2f92000, "combined BSS exceeds20KiB")
 . = 0x2f93000; .pcm0 (NOLOAD) : { *(.pcm0) } :data
 . = 0x2f94000; .pcm1 (NOLOAD) : { *(.pcm1) } :data
 . = 0x2f95000; .pcm2 (NOLOAD) : { *(.pcm2) } :data
 . = 0x2f96000; .pcm3 (NOLOAD) : { *(.pcm3) } :data
 . = 0x2f97000; .gather (NOLOAD) : { *(.gather) } :data
 . = 0x2f98000; .queue_payload (NOLOAD) : {
   __queue_payload_start = .; *(.queue_payload) __queue_payload_end = .; } :data
 . = 0x2f9d000; .worker_stack (NOLOAD) : {
   __worker_stack_start = .; *(.worker_stack) __worker_stack_end = .; } :data
 . = 0x2fa1000; .source_stack (NOLOAD) : {
   __source_stack_start = .; *(.source_stack) __source_stack_end = .; } :data
 __app_zero_end = .; __app_end = .;
 __combined_ram_bytes = ABSOLUTE(. - 0x2d4bb74);
 ASSERT(__combined_ram_bytes <= 0x300000, "exceeds original DLL reservation")
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
