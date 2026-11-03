ENTRY(allocator_supply_then_mixer_v1)
PHDRS { code PT_LOAD FLAGS(5); state PT_LOAD FLAGS(6); }
SECTIONS {
 .text 0x0c000000 : { *(.text*) *(.rodata*) } :code
 .bss 0x0c010000 (NOLOAD) : { *(.bss*) *(COMMON) } :state
 /DISCARD/ : { *(.comment*) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
