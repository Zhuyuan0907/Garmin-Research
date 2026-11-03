ENTRY(cache_marker_entry)
original_tts_entry = 0x2d5a938;
SECTIONS { . = 0x2f7c634; .entry : { KEEP(*(.text.cache_marker_entry)) }
 .text : { *(.text*) } .rodata : { *(.rodata*) } . = ALIGN(32);
 .data : { *(.data*) } . = ALIGN(32); .bss (NOLOAD) : {
 __marker_bss_start = .; *(.bss*) *(COMMON) __marker_bss_end = .; }
 __combined_ram_bytes = . - 0x2d4bb74;
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) } }
