ENTRY(scheduled_decode_entry_v1)
PHDRS { text PT_LOAD FLAGS(5); }
SECTIONS {
    . = 0x09050000;
    .text : { *(.text*) *(.rodata*) } :text
    /DISCARD/ : { *(.comment*) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
