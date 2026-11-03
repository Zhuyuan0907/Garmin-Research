ENTRY(qcs_initialize)
SECTIONS {
 . = 0x07000000;
 .text : { *(.text.qcs_*) KEEP(*(.text.mcs_native_ownership_snapshot)) *(.text*) *(.rodata*) }
 . = ALIGN(4096);
 .data : { *(.data*) }
 . = ALIGN(4096);
 .bss (NOLOAD) : { *(.bss*) *(COMMON) }
 .ARM.attributes 0 : { *(.ARM.attributes) }
 /DISCARD/ : { *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }
}
