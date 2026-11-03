ENTRY(memory_output_submit)
SECTIONS {
 . = 0x08600000;
 .text : { KEEP(*(.output_api)) *(.text .text.*) *(.rodata .rodata.*) }
 __output_code_end = .;
 ASSERT(__output_code_end <= 0x08602000, "output code exceeds two pages")
 . = 0x08602000;
 __output_state_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
 __output_state_end = .;
 ASSERT(__output_state_end <= 0x08602fc0, "output state exceeds guarded page")
 . = 0x08604000; .pcm0 (NOLOAD) : { *(.pcm0) }
 . = 0x08606000; .pcm1 (NOLOAD) : { *(.pcm1) }
 . = 0x08608000; .pcm2 (NOLOAD) : { *(.pcm2) }
 . = 0x0860a000; .pcm3 (NOLOAD) : { *(.pcm3) }
 /DISCARD/ : { *(.comment) *(.note*) }
}
