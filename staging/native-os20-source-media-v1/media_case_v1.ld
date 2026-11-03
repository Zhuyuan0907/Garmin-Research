ENTRY(media_case_bootstrap_v1)
PHDRS { code PT_LOAD FLAGS(5); state PT_LOAD FLAGS(6); stack PT_LOAD FLAGS(6); }
SECTIONS {
 .text 0x0b000000 : { *(.text*) *(.rodata*) } :code
 .bss 0x0b010000 (NOLOAD) : { *(.bss*) *(COMMON) } :state
 .producer_stack 0x0b020000 (NOLOAD) : { *(.producer_stack) } :stack
 /DISCARD/ : { *(.comment*) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
