ENTRY(music_native_publish)
source_worker_state = 0x2fa279c;
music_owner_irq_save = 0x2f87490;
music_owner_irq_restore = 0x2f8749c;
music_owner_post = 0x2f874b4;
SECTIONS { . = 0x09600000; .text : { KEEP(*(.text.music_native_publish)) *(.text*) *(.rodata*) } /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment) *(.note*) } }
