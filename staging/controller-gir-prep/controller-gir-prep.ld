/* Offline fixture only, not a Garmin loader map. */
ENTRY(cg_controller_prepare)
PHDRS { code PT_LOAD FLAGS(5); state PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x0ea00000;
 .text : { *(.text*) } :code
 .rodata : { *(.rodata*) } :code
 . = ALIGN(4096);
 .data : { *(.data*) } :state
 .bss (NOLOAD) : { *(.bss*) *(COMMON) } :state
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
