ENTRY(resident_music_worker_v1)
PHDRS { text PT_LOAD FLAGS(5); }
SECTIONS {
    . = 0x09050000;
    .text : { KEEP(*(.text.resident_music_worker_v1)) *(.text*) *(.rodata*) } :text
    /DISCARD/ : { *(.comment*) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
