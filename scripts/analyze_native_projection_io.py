#!/usr/bin/env python3
"""Map exact firmware USB-device/SGA and conditional GUI projection leads.

Backup-only analysis. Class vtables use startup runtime pointers, including
conditional copies, rather than searching only unrelocated file pointers.
"""
from collections import deque
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC, ARM_CC_AL
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_sdp_activation import trace


def sha(blob): return hashlib.sha256(blob).hexdigest()
def require(test, reason):
    if not test: raise ValueError(reason)


def arm_cfg(image, start, end):
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM);md.detail=True
    queue=deque([start]);seen={};exits=[]
    while queue:
        address=queue.popleft()
        if address in seen:continue
        require(start<=address<end and address%4==0,'ARM CFG left verified function')
        instruction=next(md.disasm(image.read(address,4),address,count=1))
        i=instruction
        row={'address':hex(address),'instruction':i.mnemonic+' '+i.op_str}
        seen[address]=row
        if i.mnemonic=='ldr' and i.operands[-1].type==ARM_OP_MEM:
            operand=i.operands[-1]
            if operand.mem.base==ARM_REG_PC:
                literal=address+8+operand.mem.disp
                row.update(literal_address=hex(literal),literal_value=hex(image.word(literal)))
        if i.mnemonic in ('bl','blx'):
            require(i.operands[0].type==ARM_OP_IMM,'Unexpected indirect ARM call')
            row.update(direct_call=hex(i.operands[0].imm),
                       callee_instruction_set='Thumb' if i.mnemonic=='blx' else 'ARM')
        elif i.mnemonic.startswith('bx'):
            require(i.op_str=='lr','Unexpected ARM computed branch')
            exits.append({'address':hex(address),'kind':'return'})
            if i.cc==ARM_CC_AL:continue
        elif i.mnemonic.startswith('pop') and 'pc' in i.op_str:
            exits.append({'address':hex(address),'kind':'return'})
            if i.cc==ARM_CC_AL:continue
        elif i.mnemonic.startswith('b') and i.operands[0].type==ARM_OP_IMM:
            queue.append(i.operands[0].imm)
            if i.cc==ARM_CC_AL:continue
        queue.append(address+4)
    return {'entry':hex(start),'bounded_end':hex(end),'instruction_set':'ARM',
            'instructions':[seen[a] for a in sorted(seen)],'returns':exits,
            'unresolved_exits':[],'all_local_paths_resolved':True,
            'callees_not_recursively_executed':True}


def gui_class(stock,image,name,type_name,rtti,vtable,count):
    text=image.read(type_name,64).split(b'\0')[0].decode()
    require(text==name,'GUI typename differs')
    require(image.word(rtti+4)==type_name and image.word(vtable-4)==rtti and
            image.word(vtable-8)==0,'GUI RTTI/vtable linkage differs')
    slots=[image.word(vtable+index*4) for index in range(count)]
    section=next(s for s in stock.copies if s['runtime_start']<=vtable<s['runtime_end'])
    return {'typename':name,'typename_runtime':hex(type_name),
            'typeinfo_runtime':hex(rtti),'vtable_runtime':hex(vtable),
            'vtable_file_load_address':hex(stock.runtime_to_load(vtable,count*4)),
            'conditional_startup_copy':section['conditional'],
            'draw_slot2_target':hex(slots[2]),'bounded_slots':[hex(s) for s in slots],
            'live_copy_flag_or_constructor_or_renderer_verified':False,
            'GUI_widget_vtable_not_proven_renderer_context':True}


def main():
    stock=NativeImage();image=RuntimeImage(stock)
    functions={hex(a):trace(image,a,2500) for a in
        (0x1bcf6c,0x1be63c,0x23c1c4,0x1bffc0,0x23c14c,0x1c00f2,
         0x1c001c,0x1c23f4,0x221e46,0x225240,0x22521c,0x223e3e,
         0x44055ee,0x440586e,0x3620e4)}
    require(all(not f['unresolved_exits'] and not f['instruction_limit_reached']
                for f in functions.values()),'Incomplete bounded Thumb function')
    csw=trace(image,0x1be664,250)
    require(csw['unresolved_exits']==[{'address':'0x1be682','target':'0x1be63c',
                                     'reason':'External branch'}],
            'CSW original tail-call differs')
    arm_functions={hex(a):arm_cfg(image,a,b) for a,b in
        [(0x6f2fec,0x6f308c),(0x6f3804,0x6f3810),(0x6f3810,0x6f3840),
         (0x6f3840,0x6f3870),(0x6f3870,0x6f3888),(0x6f4b40,0x6f4d04)]}
    init=arm_functions['0x6f4b40']
    rows={int(row['address'],16):row for row in init['instructions']}
    require(rows[0x6f4b80]['literal_value']=='0x101c2000' and
            rows[0x6f4b84]['direct_call']=='0x221e46' and
            rows[0x6f4bf8]['direct_call']=='0x6f2fec' and
            rows[0x6f4c08]['direct_call']=='0x6f3804',
            'SGA initialization chain differs')
    source_path=image.read(0x6f5124,128).split(b'\0')[0].decode()
    require(source_path==r'gpk\SGA_2D\sga_driver\sga_manager.c',
            'Exact SGA source path differs')
    classes=[gui_class(stock,image,*args) for args in
        [('N3GUI12DrawingBoardE',0x46f9d60,0x46f91ac,0x4700178,39),
         ('N3GUI8PngImageE',0x46fa695,0x46f95c0,0x4704ee0,43)]]
    require(classes[0]['draw_slot2_target']=='0x44055ef' and
            classes[1]['draw_slot2_target']=='0x3620e5','Native draw methods differ')
    veneers=[]
    for entry,target in [(0x448fd10,0x353a9d),(0x448fa60,0x300e49),
                         (0x448fa78,0x3766c5),(0x448fa90,0x3959e9)]:
        require(image.word(entry)==0xe51ff004 and image.word(entry+4)==target,
                'Conditional GUI ARM veneer differs')
        veneers.append({'ARM_entry':hex(entry),'Thumb_target_word':hex(target),
                        'load_address':hex(stock.runtime_to_load(entry,8))})
    draw={int(row['address'],16):row for row in functions['0x3620e4']['instructions']}
    for address,assembly in [(0x3621f2,'ldr r4, [r1, #0x40]'),
                             (0x36222e,'ldr r4, [r1, #0x44]'),
                             (0x36225e,'ldr r4, [r0, #0x48]')]:
        require(draw[address]['instruction']==assembly,'Image renderer slot differs')
    proof_path=ROOT/'evidence/firmware-analysis/native-projection-io-emulation.json'
    proof=json.loads(proof_path.read_text())
    require(proof['all_passed'] and not proof['device_io'],'Fresh offline I/O proof missing')
    for path,expected in proof['source_sha256'].items():
        require(sha((ROOT/path).read_bytes())==expected,'I/O proof dependency changed: '+path)
    deps={Path(__file__).resolve(),proof_path,ROOT/'evidence/firmware-analysis/main_02bd.bin'}
    deps.update(ROOT/path for path in proof['source_sha256'])
    for module in list(sys.modules.values()):
        filename=getattr(module,'__file__',None)
        if filename and Path(filename).resolve().parent==ROOT/'scripts' and filename.endswith('.py'):
            deps.add(Path(filename).resolve())
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),
        'exact_target':{'HWID':1352,'software':'8.00','stock_sha256':EXPECTED},
        'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sorted(deps)},
        'bounded_Thumb_CFGs':functions,'CSW_resolved_external_tail_call':csw,
        'bounded_ARM_CFGs':arm_functions,'conditional_GUI_classes':classes,
        'conditional_GUI_veneers':veneers,
        'USB_device_path':{'builder':'0x1bcf6c','device_personality_flag':'0xf08fd1',
            'vendor_mode_VID_PID':['0x091e','0x0003'],
            'MSC_mode_VID_PID':['0x091e','0x2548'],
            'MSC_interface_class_subclass_protocol':[8,6,80],
            'descriptors_constructed_at_runtime_not_fixed_blob':True,
            'controller_register_base':'0x10200000','FIFO_endpoint2_writer':'0x1c23f4',
            'FIFO_endpoint3_writer':'0x1c001c','CSW':'0x1be664',
            'CSW_tail_call_chain':['0x1be63c','0x23c1c4','0x1bffc0'],
            'worker_wakeup_mask':'0x400','receive_chain':['0x23c14c','0x1c00f2'],
            'personality_switch_is_not_proven_USB_role_switch':True,
            'USB_host_AOA_driver_board_VBUS_ID_or_transfer_completion_verified':False},
        'SD_MMC_false_host_lead':{'initializer':'0x225240','string':'host_info[i].smphr',
            'descendant':'0x223e3e','controller_base':'0x101ed000',
            'associated_strings':'MMC/SD card detection and CMD2/3/6/7/8/17/25',
            'not_used_as_USB_host_evidence':True},
        'SGA_driver':{'manager_source_path':source_path,'initializer_ARM':'0x6f4b40',
            'translated_base_input':'0x101c2000','translation_Thumb':'0x221e46',
            'L1_table_address':'0x03e00000','ID_probe_ARM':'0x6f2fec',
            'probe_context':'0x034dd21c','ID_register_offsets':[hex(a) for a in range(0x7e0,0x800,4)],
            'expected_ID_words':[2,98,45,0,13,240,5,177],
            'full_init_allocation_semaphore_IRQ_and_real_ID_not_executed':True,
            'display_framebuffer_or_H264_decoder_not_established':True},
        'Image_renderer_dispatch':{'widget_draw':'0x3620e4',
            'renderer_virtual_slots':[16,17,18],
            'slot16_call':'0x3621fa','slot17_call':'0x362238',
            'image_argument_offset_in_widget':'0xcc',
            'slot16_argument_offsets':['0xf8','0xfc','0x100'],
            'rectangle_pointer_passed_on_stack':True,
            'actual_renderer_table_pixel_format_surface_present_or_UI_registration_verified':False},
        'all_passed':True,'device_io':False,'firmware_modified':False,
        'native_Android_Auto_running':False,'device_install_candidate':False,
        'sources_for_USB_constant_interpretation':[
            'https://raw.githubusercontent.com/torvalds/linux/v6.12/include/uapi/linux/usb/ch9.h',
            'https://docs.kernel.org/driver-api/usb/gadget.html'],
        'limitations':'Static bounded function CFGs and two conditional RTTI/vtable relationships, supported by separate synthetic-register original-code execution. Direct calls are not recursively analyzed or executed by this script. Native GUI widget vtables are not identified renderer contexts. Conditional runtime activation is unknown. No real USB host/AOA, H264, display pixels, phone, new App, bootloader recovery or installation result.'}
    output=ROOT/'evidence/firmware-analysis/native-projection-io-static.json'
    output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'evidence':str(output.relative_to(ROOT)),'Thumb_CFGs':len(functions),
                     'ARM_CFGs':len(arm_functions),'conditional_GUI_classes':len(classes),
                     'source_dependencies':len(deps),'device_io':False}))


if __name__=='__main__':main()
