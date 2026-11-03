ENTRY(source_worker_boot)
PROVIDE(media_coordinator_init = 0x8b00144);
PROVIDE(media_coordinator_pump = 0x8b004d4);
PROVIDE(media_coordinator_cancel = 0x8b00480);
PROVIDE(coordinator_state = 0x8b02000);
PROVIDE(owned_media_control = 0x88444c0);
PROVIDE(memory_output_control = 0x8844180);
SECTIONS {
 . = 0x08c00000;
 .text : { KEEP(*(.source_worker_api)) *(.text .text.*) *(.rodata .rodata.*) }
 __source_code_end = .;
 ASSERT(__source_code_end <= 0x08c02000, "source code exceeds two pages")
 . = 0x08c02000;
 __source_state_start = .;
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) }
 __source_state_end = .;
 ASSERT(__source_state_end <= 0x08c02fc0, "source state exceeds guarded page")
 . = 0x08c04000;
 __source_stack_start = .;
 .source_stack (NOLOAD) : { *(.source_stack) }
 __source_stack_end = .;
 ASSERT(__source_stack_end == 0x08c08000, "source stack extent differs")
 /DISCARD/ : { *(.comment) *(.note*) }
}
