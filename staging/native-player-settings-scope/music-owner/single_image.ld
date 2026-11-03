ENTRY(native_ui_music_single_entry)
PHDRS { code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
original_tts_entry = 0x2d5a938;
/* One cleanup implementation/address, including preserved private APIs. */
source_completion_hook = umcn_cleanup_bridge;
SECTIONS {
 . = 0x2f7d000;
 .text : {
   KEEP(*(.text.native_ui_music_single_entry))
   KEEP(*(.text.native_app_component_entry))
   KEEP(*(.ui_music_single_api)) KEEP(*(.ui_music_control_api))
   KEEP(*(.text.native_ui_music_menu_install))
   KEEP(*(.text.native_ui_music_linked_bindings))
   KEEP(*(.text.umcn_cleanup_bridge))
   KEEP(*(.music_owner_api)) KEEP(*(.music_component_api)) KEEP(*(.music_stream_api)) KEEP(*(.music_runtime_api))
   KEEP(*(.app_component_api)) KEEP(*(.owned_api)) KEEP(*(.output_api))
   KEEP(*(.queue_api)) KEEP(*(.worker_api)) KEEP(*(.playback_api))
   KEEP(*(.coordinator_api)) KEEP(*(.source_worker_api)) KEEP(*(.extension_exports))
   *(.text .text.*) *(.rodata .rodata.*)
 } :code
 __app_code_end = .;
 ASSERT(. <= 0x2f9d000, "combined code exceeds128KiB")
 . = 0x2f9d000; __app_data_start = .;
 .data : { *(.data .data.*) } :data
 __app_data_end = .; __app_file_end = .;
 ASSERT(. <= 0x2f9e000, "initialized data exceeds one RW page")
 . = 0x2f9e000; __app_zero_start = .;
 .bss (NOLOAD) : { __app_bss_start = .; *(.bss .bss.*) *(COMMON) __app_bss_end = .; } :data
 ASSERT(. <= 0x2fa3000, "combined BSS exceeds20KiB")
 . = 0x2fa4000; .pcm0 (NOLOAD) : { *(.pcm0) } :data
 . = 0x2fa5000; .pcm1 (NOLOAD) : { *(.pcm1) } :data
 . = 0x2fa6000; .pcm2 (NOLOAD) : { *(.pcm2) } :data
 . = 0x2fa7000; .pcm3 (NOLOAD) : { *(.pcm3) } :data
 . = 0x2fa8000; .gather (NOLOAD) : { *(.gather) } :data
 . = 0x2fa9000; .queue_payload (NOLOAD) : {
   __queue_payload_start = .; *(.queue_payload) __queue_payload_end = .;
 } :data
 ASSERT(. <= 0x2fad000, "queue payload exceeds four pages")
 . = 0x2fae000; .worker_stack (NOLOAD) : {
   __worker_stack_start = .; *(.worker_stack) __worker_stack_end = .;
 } :data
 ASSERT(. <= 0x2fb2000, "decoder stack exceeds16KiB")
 . = 0x2fb2000; .source_stack (NOLOAD) : {
   __source_stack_start = .; *(.source_stack) __source_stack_end = .;
 } :data
 ASSERT(. <= 0x2fb6000, "source stack exceeds16KiB")
 __app_zero_end = .; __app_end = .;
 __combined_ram_bytes = ABSOLUTE(. - 0x2d4bb74);
 ASSERT((__app_zero_start & 3) == 0 && (__app_zero_end & 3) == 0, "zero span alignment")
 ASSERT(__app_data_end <= __app_zero_start, "initialized data must survive bootstrap zero")
 ASSERT(__combined_ram_bytes <= 0x300000, "exceeds original DLL reservation")
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
