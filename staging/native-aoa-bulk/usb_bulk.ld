ENTRY(aoa_bulk_init)
SECTIONS { . = 0x8800000; .text : { *(.text .text.*) *(.rodata .rodata.*) }
__code_end = .; .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
/DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) } }
