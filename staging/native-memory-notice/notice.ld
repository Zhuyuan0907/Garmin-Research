ENTRY(memory_notice_dispatch)
SECTIONS {
 . = 0x08500000;
 .text : { KEEP(*(.notice_api)) *(.text .text.*) *(.rodata .rodata.*) }
 __notice_code_end = .;
 ASSERT(__notice_code_end <= 0x08501000, "observer code exceeds page")
 . = 0x08501000;
 __notice_state_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
 __notice_state_end = .;
 ASSERT(__notice_state_end <= 0x08501fc0, "observer state exceeds guarded page")
 /DISCARD/ : { *(.comment) *(.note*) }
}
