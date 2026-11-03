#!/usr/bin/env python3
"""Audit native Android Auto integration gaps against exact firmware/source.

Read-only source and firmware analysis, not a port or an install candidate.
Pinned upstream projects describe an older implementation, not guaranteed
compatibility with the user's current Pixel/Android Auto version.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import zipfile

from analyze_native_sections import NativeImage, ROOT, BASE, EXPECTED
from analyze_native_voice_acceptance import RuntimeImage
from analyze_sdp_activation import trace
from analyze_ui import references


def sha(blob): return hashlib.sha256(blob).hexdigest()
def require(condition, message):
    if not condition: raise ValueError(message)


def main():
    stock = NativeImage()
    image = RuntimeImage(stock)
    snapshot_path = ROOT/'sources/android-auto/source-snapshots.json'
    snapshots = json.loads(snapshot_path.read_text())
    dependencies = {str(snapshot_path.relative_to(ROOT)):sha(snapshot_path.read_bytes())}
    projects = {}
    checked_files = 0
    for source in snapshots['sources']:
        name = source['repository'].rsplit('/',1)[-1]
        archive = ROOT/source['archive']
        require(sha(archive.read_bytes()) == source['sha256'], 'Archive changed')
        require(re.fullmatch('[0-9a-f]{40}',source['commit']), 'Unpinned repository')
        dependencies[str(archive.relative_to(ROOT))] = source['sha256']
        folder = ROOT/'sources/android-auto'/f"{name}-{source['commit']}"
        projects[name] = (folder, source)
        # Verify every extracted file against the frozen downloaded archive.
        with zipfile.ZipFile(archive) as zipped:
            for member in zipped.infolist():
                if member.is_dir(): continue
                path = ROOT/'sources/android-auto'/member.filename
                require(path.read_bytes() == zipped.read(member), 'Extracted source differs')
                dependencies[str(path.relative_to(ROOT))] = sha(path.read_bytes())
                checked_files += 1
    def source_ref(project, relative, needle):
        folder, row = projects[project]
        text = (folder/relative).read_text()
        lines = [n+1 for n,line in enumerate(text.splitlines()) if needle in line]
        require(lines, f'Missing source assertion: {relative}: {needle}')
        return {'path':str((folder/relative).relative_to(ROOT)), 'lines':lines,
            'url':f"{row['repository']}/blob/{row['commit']}/{relative}#L{lines[0]}"}
    facts = {
        'AOA_get_protocol_request51':source_ref('aasdk',
            'include/f1x/aasdk/USB/AccessoryModeProtocolVersionQuery.hpp',
            'ACC_REQ_GET_PROTOCOL = 51'),
        'AOA_send_string_request52':source_ref('aasdk',
            'include/f1x/aasdk/USB/AccessoryModeSendStringQuery.hpp',
            'ACC_REQ_SEND_STRING = 52'),
        'AOA_start_request53':source_ref('aasdk',
            'include/f1x/aasdk/USB/AccessoryModeStartQuery.hpp','ACC_REQ_START = 53'),
        'USB_bulk_endpoint_pair':source_ref('aasdk','src/USB/AOAPDevice.cpp',
            'interfaceDescriptor->bNumEndpoints < 2'),
        'TLS_memory_BIOs':source_ref('aasdk','src/Transport/SSLWrapper.cpp',
            'BIO_new(BIO_s_mem())'),
        'TLS_handshake':source_ref('aasdk','src/Messenger/Cryptor.cpp','doHandshake'),
        'protocol_buffer_service_discovery':source_ref('openauto',
            'src/autoapp/Service/AndroidAutoEntity.cpp','ServiceDiscovery'),
        'H264_AVC_decoder':source_ref('openauto',
            'src/autoapp/Projection/OMXVideoOutput.cpp','OMX_VIDEO_CodingAVC'),
        'Pi_specific_video_backend':source_ref('openauto',
            'src/autoapp/Projection/OMXVideoOutput.cpp','bcm_host_init()'),
        'Qt_alternative_video_backend':source_ref('openauto',
            'src/autoapp/Projection/QtVideoOutput.cpp','QMediaPlayer'),
        'default_480p_geometry_800x480':source_ref('openauto',
            'src/autoapp/Service/ServiceFactory.cpp','QRect(0, 0, 800, 480)'),
        'media_audio_48000_stereo_S16':source_ref('openauto',
            'src/autoapp/Service/ServiceFactory.cpp','RtAudioOutput>(2, 16, 48000)'),
        'speech_audio_16000_mono_S16':source_ref('openauto',
            'src/autoapp/Service/ServiceFactory.cpp','RtAudioOutput>(1, 16, 16000)'),
        'raw_audio_written_to_output':source_ref('openauto',
            'src/autoapp/Service/AudioService.cpp','audioOutput_->write'),
        'sample_format_in_service_discovery':source_ref('openauto',
            'src/autoapp/Service/AudioService.cpp','set_sample_rate'),
        'input_location_config':source_ref('openauto',
            'src/autoapp/Service/InputService.cpp','mutable_touch_screen_config'),
    }
    dependency_assertions = {}
    for project, packages in [('aasdk',['Boost','libusb-1.0','Protobuf','OpenSSL']),
                              ('openauto',['Boost','libusb-1.0','Qt5','Protobuf','OpenSSL'])]:
        dependency_assertions[project] = {p:source_ref(project,'CMakeLists.txt',
            'find_package('+p) for p in packages}
    enums = (projects['aasdk'][0]/'aasdk_proto/VideoResolutionEnum.proto').read_text()
    require(re.findall(r'_(\d+)p\s*=\s*\d',enums) == ['480','720','1080'],
            'Frozen resolution enum changed')
    fps = (projects['aasdk'][0]/'aasdk_proto/VideoFPSEnum.proto').read_text()
    require(re.findall(r'_(\d+)\s*=\s*\d',fps) == ['30','60'], 'Frozen FPS enum changed')
    selected = {'PageTestTouch','PageTestTouchLine','PageTestDisplay',
                'PageUSBMassStorage','PageBackupCamera','PageJpeg','JpegImage'}
    pages = []
    for match in re.finditer(rb'N3GUI([0-9]{1,3})([A-Za-z_][A-Za-z_0-9]*)E\x00',stock.data):
        name = match[2].decode()
        if name not in selected or len(name) != int(match[1]): continue
        for pos in references(stock.data,BASE+match.start()):
            rtti = BASE+pos-4
            for table in references(stock.data,rtti):
                if table < 4 or struct.unpack_from('<I',stock.data,table-4)[0] != 0:continue
                slots = []
                for slot in range(30):
                    pointer = struct.unpack_from('<I',stock.data,table+4+4*slot)[0]
                    if not BASE <= (pointer & ~1) < 0xbd0000:break
                    slots.append({'slot':slot,'pointer':hex(pointer)})
                if slots:pages.append({'class':name,'rtti_load':hex(rtti),
                    'vtable_load':hex(BASE+table+4),'slots':slots})
    require({p['class'] for p in pages} == selected, 'Missing original GUI class')
    require(image.word(0xc0d45c+16) == 0x5c1073,'Touch event vslot changed')
    functions = {hex(a):trace(image,a,2500) for a in [
        0x5c1072,0x3766c4,0x3819d4,0x674266,0x6743f2,
        0x66f170,0x45363c,0x60716e,0x606f9a,0x53ee9c]}
    require(all(not t['instruction_limit_reached'] and not t['unresolved_exits']
                for t in functions.values()),'Unresolved bounded candidate CFG')
    jpeg_doc = ROOT/'sources/deep-research/STA2064.txt'
    text = jpeg_doc.read_text()
    require('JPEG baseline profile decoder' in text and 'USB2.0 OTG' in text,
            'Platform document changed')
    b = stock.data.lower()
    terms = ['h264','h.264','h_264','avcdecoder','framebuffer','usbhost','usb_host','androidauto']
    string_search = {term:[] for term in terms}
    for term in terms:
        start = 0; needle = term.encode()
        while True:
            hit=b.find(needle,start)
            if hit<0:break
            start=hit+1
            string_search[term].append(hex(BASE+hit))
    touch_path = ROOT/'evidence/firmware-analysis/native-projection-touch-emulation.json'
    touch = json.loads(touch_path.read_text())
    require(touch['all_passed'] and len(touch['cases']) == 6,'Missing touch experiment')
    manifests = []
    for path in sorted((ROOT/'staging/native-app-component-emulation').glob('*/manifest.json')):
        manifest=json.loads(path.read_text())
        manifests.append({'voice':path.parent.name,
            'combined_RAM_bytes':manifest['combined_ram_bytes'],
            'remaining_original_3MiB_reservation':manifest['remaining_reservation_bytes'],
            'YUV420_800x480_frame_plus_RGB565_screen_fits_remaining':
                800*480*3//2+480*272*2 <= manifest['remaining_reservation_bytes']})
        dependencies[str(path.relative_to(ROOT))]=sha(path.read_bytes())
    required_paths = [Path(__file__), ROOT/'evidence/firmware-analysis/main_02bd.bin',
        jpeg_doc,ROOT/'sources/deep-research/STA2064.pdf', touch_path,
        ROOT/'evidence/firmware-analysis/native-loaded-playback-emulation.json',
        ROOT/'evidence/firmware-analysis/native-voice-metadata-emulation.json']
    for module in list(sys.modules.values()):
        filename=getattr(module,'__file__',None)
        if filename and Path(filename).resolve().parent == ROOT/'scripts' and filename.endswith('.py'):
            required_paths.append(Path(filename).resolve())
    for path in required_paths:dependencies[str(path.relative_to(ROOT))]=sha(path.read_bytes())
    result = {
        'updated_utc':datetime.now(timezone.utc).isoformat(),'stock_sha256':EXPECTED,
        'exact_target':{'model':'Taiwan nuvi2565RT','HWID':1352,'software':'8.00'},
        'scope':'Native GarminOS Android Auto receiver, with phone doing Android application execution. Offline source/firmware analysis and synthetic stock GUI-event execution only.',
        'all_passed':True,'source_snapshots':snapshots,'archive_files_verified':checked_files,
        'source_facts':facts,'upstream_build_dependencies':dependency_assertions,
        'older_upstream_implementation_current_Pixel_compatibility_unverified':True,
        'original_GUI_candidates':pages,'original_bounded_function_CFGs':functions,
        'native_touch_probe':{'evidence':str(touch_path.relative_to(ROOT)),
            'sha256':sha(touch_path.read_bytes()),'cases_passed':6,
            'real_input_driver_UI_registration_or_phone_verified':False},
        'literal_byte_search':{'terms':string_search,
            'scope':'Case-insensitive exact ASCII byte search in verified MAIN; no software decoder or USB-host absence is proved by missing strings.'},
        'transport':{
            'wired_candidate':'Garmin acts as USB host/AOA accessory; Android phone enters accessory mode; control requests51/52/53 then bulk endpoints.',
            'stock_USB_mass_storage_is_device_role':'Previously observed storage mode cannot by itself provide the USB-host role required by this implementation.',
            'STA2064_OTG_documented':True,'actual_board_host_wiring_VBUS_ID_driver_verified':False,
            'wireless_requirement':'Official wireless Android Auto requires a compatible Wi-Fi path, including5GHz phone support. Existing HFP/SPP Bluetooth alone is not an established wireless projection path.',
            'onboard_WiFi_confirmed':False,'Bluetooth_only_projection_claimed':False},
        'video':{'pinned_backend_codec':'H264/AVC',
            'pinned_resolution_options':['800x480','1280x720','1920x1080'],
            'pinned_FPS_options':[30,60],'unit_screen':[480,272],
            'direct_480x272_negotiation_with_current_phone_verified':False,
            'STA2064_documented_hardware_decoder':'Baseline JPEG; no H264 block documented in this data brief.',
            'actual_H264_hardware_or_software_decoder_identified':False,
            'actual_cpu_clock_RAM_video_performance_measured':False,
            'MJPEG_recording_is_not_H264_decoder_evidence':True},
        'audio':{'pinned_media_format':'48000Hz stereo S16 PCM',
            'pinned_system_speech_format':'16000Hz mono S16 PCM',
            'SBC_decoder_required_for_this_PCM_media_channel':False,
            'candidate_reuse':'Existing offline-tested PCM conversion/native output plumbing; AA channel extraction, real mixer policy/speaker integration and concurrent navigation remain unverified.',
            'prior_HFP_8kHz_success_does_not_verify_AA_audio':True},
        'memory_illustration':{'YUV420_800x480_one_frame_bytes':576000,
            'RGB565_480x272_one_buffer_bytes':261120,
            'two_YUV_frames_plus_two_RGB_buffers_bytes':1674240,
            'existing_preserving_music_component_reservations':manifests,
            'not_a_decoder_requirement_or_whole_board_RAM_limit':True,
            'general_heap_allocation_headroom_unverified':True,
            'AA_build_may_omit_SBC_and_relayout_components':True},
        'official_primary_sources':[
            {'title':'Android Auto platform overview','url':'https://developer.android.com/training/cars/platforms/android-auto'},
            {'title':'USB host/accessory roles','url':'https://developer.android.com/develop/connectivity/usb'},
            {'title':'AOA control/bulk setup','url':'https://source.android.com/docs/core/interaction/accessories/aoa'},
            {'title':'Android Auto wireless requirements','url':'https://support.google.com/androidauto/answer/6348019?hl=en'},
            {'title':'AOAv2 USB audio deprecation, distinct from AA channel audio','url':'https://source.android.com/docs/core/interaction/accessories/aoa2'},
            {'title':'ST STA2064 original data brief mirrored by distributor','url':'https://mm.digikey.com/Volume0/opasdata/d220001/medias/docus/581/STA2064.pdf'}],
        'next_steps':[
            'Trace actual USB role-selection/host driver and board VBUS/ID handling; do not equate OTG silicon with working device host mode.',
            'Locate original framebuffer/surface presentation and touch input dispatch; current stock event-consumer probe does not create a native App.',
            'Investigate ARMv6-compatible H264 software decoding/footprint and measurable performance; original JPEG support is insufficient.',
            'Implement bounded framing/TLS/Protobuf/channel adapters without Qt/libusb POSIX assumptions, then verify against current phone with user present.',
            'Reuse PCM converter/output where justified, and keep voice-package acceptance/UI/lifetime and real speaker/navigation checks open.'],
        'native_Android_Auto_running':False,'phone_session_verified':False,
        'device_install_candidate':False,'device_io':False,'modified_VPM_or_firmware_saved':False,
        'full_goal_complete':False,'source_sha256':dependencies}
    output=ROOT/'evidence/firmware-analysis/native-android-auto-feasibility.json'
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'output':str(output.relative_to(ROOT)),
        'files_verified_against_source_archives':checked_files,
        'GUI_candidates':len(pages),'bounded_CFGs':len(functions),
        'touch_cases_passed':6,'native_Android_Auto_running':False}))


if __name__ == '__main__':main()
