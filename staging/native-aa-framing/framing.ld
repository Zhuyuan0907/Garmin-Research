ENTRY(aa_frame_init)
SECTIONS { . = 0x8900000; .text : { *(.text .text.*) *(.rodata .rodata.*) }
__code_end = .; .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
/DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) } }
