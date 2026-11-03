ENTRY(nr_configuration_gate)
PHDRS { code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x08e00000;
 .text : { *(.text .text.*) *(.rodata .rodata.*) } :code
 __code_end = .;
 . = ALIGN(4096); __bss_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } :data
 __bss_end = .;
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
