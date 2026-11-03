ENTRY(resident_music_entry)
PHDRS { code PT_LOAD FLAGS(5); state PT_LOAD FLAGS(6); }
original_tts_entry = 0x2d5a938;
SECTIONS {
 .stock_tts 0x2d4bb74 : { KEEP(*(.stock_tts)) } :code
 . = 0x2f96000; __resident_tail_start = .;
 .text : { KEEP(*(.text.resident_music_entry)) KEEP(*(.text.rg_*)) KEEP(*(.text.ns_*)) KEEP(*(.text.pg_*)) KEEP(*(.text.resident_loader_read_gate)) KEEP(*(.text.stock_reader_tail_relocated)) KEEP(*(.text.sbi_*)) KEEP(*(.text.ms_*)) KEEP(*(.text.mh_*))
  KEEP(*(.text.aas_*)) KEEP(*(.text.music_endpoint_*)) KEEP(*(.text.memory_output_release_session))
  KEEP(*(.text.mcs_pull_bridge)) KEEP(*(.text.mcs_native_ownership_snapshot))
  *(.text*) *(.rodata*) KEEP(*(.mh_offsets)) KEEP(*(.aas_offsets))
  KEEP(*(.resident_api)) } :code
 __resident_code_end = .;
 . = ALIGN(4096);
 .data : { *(.data*) } :state
 __resident_file_end = .;
 . = ALIGN(4096); __resident_bss_start = .;
 .bss (NOLOAD) : { *(.bss*) *(COMMON) } :state
 . = ALIGN(4096);
 .pcm0 (NOLOAD) : { *(.pcm0) } :state
 .pcm1 (NOLOAD) : { *(.pcm1) } :state
 .pcm2 (NOLOAD) : { *(.pcm2) } :state
 .pcm3 (NOLOAD) : { *(.pcm3) } :state
 .mh_source_stack (NOLOAD) : { *(.mh_source_stack) } :state
 .gather (NOLOAD) : { *(.gather) } :state
 .queue_payload (NOLOAD) : { *(.queue_payload) } :state
 __resident_bss_end = .; __resident_end = .;
 ASSERT(__resident_end-0x2d4bb74 <= 0x300000,"Stock DLL capacity exceeded")
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*)
  *(.output_api) *(.owned_api) *(.queue_api) *(.worker_api) *(.mcs_output_api) }
}
