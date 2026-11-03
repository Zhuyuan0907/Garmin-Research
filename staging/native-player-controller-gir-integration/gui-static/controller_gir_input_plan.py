"""Pure input layout/config helper. No Unicorn import or native API execution."""
import struct

TEXT_BASE = 0x0ea10000
BSS_BASE = 0x0ea11000
INPUT_PAGE = 0x18320000
CONFIG = INPUT_PAGE + 64
RESULT = INPUT_PAGE + 320
ENTRY = TEXT_BASE + 0x4c
CATALOG_DOMAIN = (0x08800000, 0x08c00000)
RAW_GIR_CALLS = {
    (0x3009a0, 0x11c510): dict(pointer=0x034f773c, tag=0x41b544,
        containing_function='0x41cc46', scope='exact stock GIR current-controller RAII'),
    (0x3008b0, 0x41ccd2): dict(pointer=0x034f773c, tag=0x41b544,
        containing_function='0x41cc46', scope='exact stock GIR current-controller RAII'),
}

def make_config(controller=0x09503f90):
    if controller != 0x09503f90:
        raise ValueError('This config is limited to the existing declared controller fixture')
    return struct.pack('<19I', 0x13520800,76,15,controller,0x09500040,controller,
        0x0b800000,29146504,731912,0x0b800000,0x0d3cbd88,*CATALOG_DOMAIN,
        0x18001000,0x18009000,0x084c0000,0x7f135201,12,0)

def normalized_regions(rows):
    return [(int(r['low'],16),int(r['high'],16)+1,r['permissions']) for r in rows]

def overlap(a,b,c,d):
    return a<d and c<b

def input_layout(regions,live_allocations=()):
    """Return declarations only. Root must apply them to a fresh checked VM."""
    for lo,hi,_ in regions:
        if overlap(INPUT_PAGE,INPUT_PAGE+4096,lo,hi):
            raise ValueError('New config/result page is already mapped')
    for start,end in live_allocations:
        if overlap(TEXT_BASE,BSS_BASE+4096,start,end):
            raise ValueError('Resident component overlaps a live parent allocation')
    for base in [TEXT_BASE,BSS_BASE]:
        containing=[r for r in regions if r[0]<=base and base+4096<=r[1]]
        if len(containing)!=1 or containing[0][2]!=3:
            raise ValueError('Component page needs the exact existing unused RW transition mapping')
    return dict(component_entry=ENTRY,component_pages_already_mapped=True,
        reserved_transition_span=[TEXT_BASE,BSS_BASE+4096],
        text=dict(base=TEXT_BASE,page_bytes=4096,file_bytes=2412,final_permissions=5),
        BSS=dict(base=BSS_BASE,page_bytes=4096,declared_NOLOAD_bytes=4,final_permissions=3),
        new_input_page=dict(base=INPUT_PAGE,bytes=4096,permissions=3,unused_pattern=0xa5),
        config=dict(pointer=CONFIG,bytes=76,leading_canary=[CONFIG-32,CONFIG],
                    trailing_canary=[CONFIG+76,CONFIG+108]),
        result=dict(pointer=RESULT,bytes=80,leading_canary=[RESULT-32,RESULT],
                    trailing_canary=[RESULT+80,RESULT+112]),
        native_call=dict(entry=ENTRY,r0=CONFIG,r1=RESULT,stack='actual current controller stack'),
        catalog_domain=list(CATALOG_DOMAIN),catalog_requires_actual_returned_allocation_guard=True,
        no_emulator_or_mapping_mutation_performed=True)

def gir_guard_formula(entry_sp):
    if entry_sp&7:
        raise ValueError('Original controller entry stack must be eight-byte aligned')
    p=entry_sp-40
    return dict(component_entry_SP=entry_sp,component_SP=p,setting_one=p+8,
        settings_data_out=p+12,GIR_kind_out=p+7,GIR_local_SP=p-48,
        GIR_guard_cell=p-24,raw_lock_entry_SP=p-56,raw_unlock_entry_SP=p-48)
