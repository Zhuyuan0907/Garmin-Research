ENTRY(native_app_component_entry)
original_tts_entry = 0x2d5a930;
SECTIONS {
 . = 0x2f96000;
 .text : { KEEP(*(.text.native_app_component_entry))
   KEEP(*(.app_component_api)) KEEP(*(.owned_api)) KEEP(*(.output_api))
   KEEP(*(.queue_api)) KEEP(*(.worker_api)) KEEP(*(.playback_api))
   KEEP(*(.coordinator_api)) KEEP(*(.source_worker_api)) KEEP(*(.extension_exports))
   *(.text .text.*) *(.rodata .rodata.*) }
 __app_code_end = .;
 ASSERT(. <= 0x2fa6000, "combined code exceeds64KiB")
 . = 0x2fa6000; __app_zero_start = .;
 .bss (NOLOAD) : { __app_bss_start = .; *(.bss .bss.*) *(COMMON) __app_bss_end = .; }
 ASSERT(. <= 0x2fab000, "combined BSS exceeds20KiB")
 . = 0x2fac000; .pcm0 (NOLOAD) : { *(.pcm0) }
 . = 0x2fad000; .pcm1 (NOLOAD) : { *(.pcm1) }
 . = 0x2fae000; .pcm2 (NOLOAD) : { *(.pcm2) }
 . = 0x2faf000; .pcm3 (NOLOAD) : { *(.pcm3) }
 . = 0x2fb0000; .gather (NOLOAD) : { *(.gather) }
 . = 0x2fb1000; .queue_payload (NOLOAD) : {
   __queue_payload_start = .; *(.queue_payload) __queue_payload_end = .; }
 . = 0x2fb6000; .worker_stack (NOLOAD) : {
   __worker_stack_start = .; *(.worker_stack) __worker_stack_end = .; }
 . = 0x2fba000; .source_stack (NOLOAD) : {
   __source_stack_start = .; *(.source_stack) __source_stack_end = .; }
 __app_zero_end = .; __app_end = .;
 __combined_ram_bytes = ABSOLUTE(. - 0x2d4bb74);
 ASSERT(__combined_ram_bytes <= 0x300000, "exceeds original DLL reservation")
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
