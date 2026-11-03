/* Emulator-only, no device installation. */
ENTRY(voice_convert_entry)
PHDRS { code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
original_tts_entry = 0x2d677b4;
SECTIONS {
    . = 0x2f123d4;
    .entry : { KEEP(*(.text.voice_convert_entry)) } :code
    .text : { *(.text*) } :code
    .rodata : { KEEP(*(.extension_exports)) *(.rodata*) } :code
    . = ALIGN(32);
    .data : { *(.data*) } :data
    . = ALIGN(32);
    .bss (NOLOAD) : {
        __extension_bss_start = .;
        *(.bss*) *(COMMON)
        __extension_bss_end = .;
    } :data
    __extension_end = .;
    __combined_ram_bytes = . - 0x2d4bb74;
    ASSERT(__combined_ram_bytes <= 0x300000, "Exceeds original loader capacity")
    /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
