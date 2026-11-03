ENTRY(media_coordinator_init)
PROVIDE(memory_output_control = 0x8844180);
PROVIDE(memory_output_slots = 0x8844120);
PROVIDE(memory_output_register = 0x8802fec);
PROVIDE(memory_output_selection_guard = 0x8802b70);
PROVIDE(owned_media_control = 0x88444c0);
PROVIDE(owned_media_next = 0x8803398);
PROVIDE(owned_media_release = 0x88035d0);
PROVIDE(media_queue_stop = 0x880392c);
SECTIONS {
 . = 0x08b00000;
 .text : { KEEP(*(.coordinator_api)) *(.text .text.*) *(.rodata .rodata.*) }
 __coordinator_code_end = .;
 ASSERT(__coordinator_code_end <= 0x08b02000, "coordinator code exceeds two pages")
 . = 0x08b02000;
 __coordinator_state_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
 __coordinator_state_end = .;
 ASSERT(__coordinator_state_end <= 0x08b02fc0, "coordinator state exceeds guarded page")
 /DISCARD/ : { *(.comment) *(.note*) }
}
