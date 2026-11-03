ENTRY(music_validate_configuration)
SECTIONS {
 . = 0x8b00000;
 .text : { *(.text .text.*) *(.rodata .rodata.*) }
 __code_end = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
