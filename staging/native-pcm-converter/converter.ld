ENTRY(pcm_converter_clear)
PHDRS { code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x08000000;
 .text : { *(.text*) } :code
 .rodata : { *(.rodata*) } :code
 . = ALIGN(4096);
 .data : { *(.data*) } :data
 .bss (NOLOAD) : { *(.bss*) *(COMMON) } :data
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
