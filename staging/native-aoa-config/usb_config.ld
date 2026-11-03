ENTRY(aoa_usb_parse)
SECTIONS { . = 0x8700000; .text : { *(.text .text.*) *(.rodata .rodata.*) }
__code_end = .; .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
/DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) } }
