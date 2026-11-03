ENTRY(resident_music_worker_v1)
PHDRS { legacy PT_LOAD FLAGS(5); text PT_LOAD FLAGS(5); state PT_LOAD FLAGS(6);
        queue PT_LOAD FLAGS(6); gather PT_LOAD FLAGS(6); pcm PT_LOAD FLAGS(6); }
SECTIONS {
    .legacy_worker 0x09050000 : { KEEP(*(.legacy.worker)) } :legacy
    .legacy_controller 0x090501e4 : { KEEP(*(.legacy.controller)) } :legacy
    .legacy_idle 0x090502f8 : { KEEP(*(.legacy.idle)) } :legacy
    .text 0x09100000 : { *(.text*) *(.rodata*) } :text
    .bss 0x09110000 (NOLOAD) : { *(.bss*) *(COMMON) } :state
    .queue_payload 0x09120000 (NOLOAD) : { *(.queue_payload) } :queue
    .gather 0x09130000 (NOLOAD) : { *(.gather) } :gather
    .pcm0 0x09140000 (NOLOAD) : { *(.pcm0) } :pcm
    .pcm1 0x09141000 (NOLOAD) : { *(.pcm1) } :pcm
    .pcm2 0x09142000 (NOLOAD) : { *(.pcm2) } :pcm
    .pcm3 0x09143000 (NOLOAD) : { *(.pcm3) } :pcm
    /DISCARD/ : { *(.comment*) *(.note*) *(.ARM.exidx*) *(.ARM.extab*)
                 *(.output_api) *(.owned_api) *(.queue_api) *(.worker_api)
                 *(.extension_exports) *(.worker_stack) }
}
