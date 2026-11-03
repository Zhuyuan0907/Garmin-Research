/* Stock loader addresses are used only in the emulator. These RAM addresses
 * have not been validated for installing a replacement component on-device.
 */
ENTRY(garmin_component_start)
PHDRS {
    code PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}
SECTIONS {
    . = 0x02D4BB74;
    __component_image_start = .;
    .component_header : { KEEP(*(.component_header)) } :code
    .text : { *(.text*) } :code
    .rodata : { *(.rodata*) } :code
    . = ALIGN(32);
    .data : { *(.data*) } :data
    . = ALIGN(32);
    .bss (NOLOAD) : {
        __component_bss_start = .;
        *(.bss*) *(COMMON)
        __component_bss_end = .;
    } :data
    __component_image_end = .;
    __component_ram_bytes = __component_image_end - __component_image_start;
    ASSERT(__component_ram_bytes <= 0x300000, "Exceeds observed loader capacity")
    /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
