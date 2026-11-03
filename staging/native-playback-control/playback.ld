ENTRY(playback_callback_hook)
PROVIDE(memory_output_control = 0x8844180);
PROVIDE(memory_output_slots = 0x8844120);
PROVIDE(memory_output_after_selection = 0x8802cfc);
SECTIONS {
 . = 0x08a00000;
 .text : { KEEP(*(.playback_api)) *(.text .text.*) *(.rodata .rodata.*) }
 __playback_code_end = .;
 ASSERT(__playback_code_end <= 0x08a02000, "playback code exceeds two pages")
 . = 0x08a02000;
 __playback_state_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
 __playback_state_end = .;
 ASSERT(__playback_state_end <= 0x08a02fc0, "playback state exceeds guarded page")
 /DISCARD/ : { *(.comment) *(.note*) }
}
