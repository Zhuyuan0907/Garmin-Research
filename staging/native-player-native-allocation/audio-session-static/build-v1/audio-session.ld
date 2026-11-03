ENTRY(aas_initialize)
SECTIONS {
 . = 0x07000000;
 .text : { KEEP(*(.text.aas_*)) KEEP(*(.text.mcs_pull_bridge)) KEEP(*(.text.mcs_native_ownership_snapshot)) KEEP(*(.aas_offsets)) *(.text*) *(.rodata*) }
 . = ALIGN(4096);
 .data : { *(.data*) }
 . = ALIGN(4096);
 .bss (NOLOAD) : { *(.bss*) *(COMMON) }
 .pcm0 0x07700000 (NOLOAD) : { *(.pcm0) }
 .pcm1 0x07701000 (NOLOAD) : { *(.pcm1) }
 .pcm2 0x07702000 (NOLOAD) : { *(.pcm2) }
 .pcm3 0x07703000 (NOLOAD) : { *(.pcm3) }
 .ARM.attributes 0 : { *(.ARM.attributes) }
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) *(.output_api) *(.owned_api) *(.queue_api) *(.worker_api) *(.mcs_output_api) }
}
