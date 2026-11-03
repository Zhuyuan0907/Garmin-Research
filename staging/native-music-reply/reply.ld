ENTRY(music_reply_dispatch)
PHDRS { code PT_LOAD FLAGS(5); }
SECTIONS {
 . = 0x8a00000;
 .text : { *(.text.music_reply_dispatch) *(.text .text.*) *(.rodata .rodata.*) } :code
 __code_end = .;
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
