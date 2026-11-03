#!/usr/bin/env python3
"""Actual C AA/TLS control -> owned compressed queue -> software H264/YUV.

The peer and software canvas are local fixtures, never a phone/Garmin screen.
All decoder, queue and control calls are serialized; no original firmware I/O.
"""
import ctypes as C
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import struct
import subprocess
import sys
import time
import zlib

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'staging/android-auto-video-host-v1'
PROOF=ROOT/'evidence/android-auto-video-host-v1.json'
H264PROOF=ROOT/'evidence/android-auto-h264-host-v1.json'
CONTROL=ROOT/'evidence/android-auto-control-host-v1.json'
QUEUE=ROOT/'evidence/android-auto-video-queue-host-v1.json'
H264LIB=ROOT/'staging/android-auto-h264-host-v1/ordinary/libaa-h264-host.so'
CTRLLIB=ROOT/'staging/android-auto-control-host-v1/libaa-control-host.so'
CASES=[]


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


class Frame(C.Structure):
    _fields_=[('planes',C.c_void_p*3),('strides',C.c_size_t*3),('width',C.c_uint32),
              ('height',C.c_uint32),('timestamp',C.c_uint64),('index',C.c_uint64)]


FRAMEFN=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(Frame))


class Config(C.Structure):
    _fields_=[('max_width',C.c_uint32),('max_height',C.c_uint32),
              ('max_nal_bytes',C.c_size_t),('max_au_bytes',C.c_size_t),
              ('callback',FRAMEFN),('user',C.c_void_p)]


class Stats(C.Structure):
    _fields_=[('accepted_packets',C.c_uint64),('accepted_bytes',C.c_uint64),
              ('fed_bytes',C.c_uint64),('last_timestamp',C.c_uint64),
              ('media_session',C.c_int32),('queued_packets',C.c_uint32)]


def bind_video(lib):
    lib.aa_video_context_bytes.restype=C.c_uint32
    lib.aa_video_init.argtypes=[C.c_void_p,C.c_uint32,C.c_void_p]
    for n in ['step','finish','status','decoder_detail','stop']:
        getattr(lib,'aa_video_'+n).argtypes=[C.c_void_p,C.c_uint32]
    lib.aa_video_stats_get.argtypes=[C.c_void_p,C.c_uint32,C.POINTER(Stats)]
    lib.aa_video_control_provider.argtypes=[C.c_void_p,C.c_uint8,C.c_uint32,C.c_int32,
                                          C.c_uint32,C.c_uint64,C.c_void_p,C.c_size_t]
    lib.aa_rgb565_render.argtypes=[C.POINTER(Frame),C.POINTER(C.c_size_t),C.c_void_p,
                                  C.c_size_t,C.c_uint32,C.c_uint32,C.c_size_t,C.c_int,C.c_int]


def bind_h264(lib):
    for n in ['context_size','context_align']:
        getattr(lib,'aa_h264_'+n).restype=C.c_size_t
    lib.aa_h264_workspace_size.argtypes=[C.POINTER(Config)]
    lib.aa_h264_workspace_size.restype=C.c_size_t
    lib.aa_h264_init.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,
                              C.POINTER(Config),C.POINTER(C.c_void_p)]
    for n in ['start','reset','retry','finish','stop','status','destroy']:
        getattr(lib,'aa_h264_'+n).argtypes=[C.c_void_p]
    lib.aa_h264_destroy.restype=None


def aligned(n,align):
    storage=C.create_string_buffer(n+align)
    addr=(C.addressof(storage)+align-1)&~(align-1)
    return storage,C.c_void_p(addr)


def build():
    OUT.mkdir(exist_ok=True)
    lib=OUT/'libaa-video-host.so'
    args=['cc','-shared','-fPIC','-std=c11','-O1','-Wall','-Wextra','-Werror','-DPB_VALIDATE_UTF8=1']
    args+=['-I'+str(ROOT/p) for p in ['native/aa-video','native/aa-h264','native/aa-control',
             'native/aa-message','native/aa-proto','native/aa-proto/generated','native/aa-proto/runtime']]
    args+=[str(ROOT/'native/aa-video/video.c'),str(ROOT/'native/aa-video/rgb565.c'),str(H264LIB),'-o',str(lib)]
    r=subprocess.run(args,cwd=ROOT,capture_output=True)
    assert r.returncode==0,r.stderr.decode()
    return lib,dict(argv=args,exit_code=r.returncode,stderr=r.stderr.decode())


def fixture(name,width,height,profile,frames=6):
    coded=OUT/(name+'.h264');raw=OUT/(name+'.yuv')
    opts='aud=1:repeat-headers=1:ref=2:keyint=4:scenecut=0'
    if profile=='baseline':opts+=':bframes=0:cabac=0'
    else:opts+=':bframes=2:cabac=1'
    args=['ffmpeg','-hide_banner','-loglevel','error','-y','-f','lavfi','-i',
          f'testsrc2=size={width}x{height}:rate=6','-frames:v',str(frames),'-an',
          '-c:v','libx264','-threads','1','-pix_fmt','yuv420p','-profile:v',profile,
          '-preset','veryfast','-qp','23','-x264-params',opts,'-f','h264',str(coded)]
    r=subprocess.run(args,capture_output=True);assert r.returncode==0,r.stderr.decode()
    decode=['ffmpeg','-hide_banner','-loglevel','error','-y','-threads','1','-i',str(coded),
            '-an','-vsync','0','-pix_fmt','yuv420p','-f','rawvideo',str(raw)]
    r=subprocess.run(decode,capture_output=True);assert r.returncode==0,r.stderr.decode()
    data=coded.read_bytes();expected=raw.read_bytes();unit=width*height*3//2
    assert len(expected)==frames*unit
    return dict(name=name,width=width,height=height,frames=frames,data=data,
                expected=[expected[i:i+unit] for i in range(0,len(expected),unit)],
                encoder_argv=args,reference_argv=decode,coded_path=str(coded.relative_to(ROOT)),
                coded_sha256=sha(coded),reference_sha256=sha(raw))


def rgb_reference(yuv,sw,sh,w,h,matrix=1,full=0,pitch=None):
    pitch=pitch or w*2
    out=bytearray([0xA5]*(pitch*h));uv=sw*sh;chroma=sw*sh//4
    coefficients={(1,0):(298,409,100,208,516),(2,0):(298,459,55,136,541),
                  (1,1):(256,359,88,183,454),(2,1):(256,403,48,120,475)}
    yc,rc,gdc,gec,bc=coefficients[matrix,full]
    clip=lambda x:max(0,min(255,x))
    for row in range(h):
        sy=row*sh//h
        for col in range(w):
            sx=col*sw//w;ci=(sy//2)*(sw//2)+sx//2
            c=yuv[sy*sw+sx]-(0 if full else 16)
            d=yuv[uv+ci]-128;e=yuv[uv+chroma+ci]-128
            r=clip((yc*c+rc*e+128)//256);g=clip((yc*c-gdc*d-gec*e+128)//256)
            b=clip((yc*c+bc*d+128)//256);pixel=((r//8)<<11)|((g//4)<<5)|(b//8)
            out[row*pitch+col*2:row*pitch+col*2+2]=pixel.to_bytes(2,'little')
    return bytes(out)


def png_from_rgb565(raw,width,height):
    rgb=bytearray()
    for y in range(height):
        rgb.append(0)
        for x in range(width):
            pixel=int.from_bytes(raw[(y*width+x)*2:(y*width+x)*2+2],'little')
            r=(pixel>>11)&31;g=(pixel>>5)&63;b=pixel&31
            rgb.extend([(r<<3)|(r>>2),(g<<2)|(g>>4),(b<<3)|(b>>2)])
    def chunk(tag,data):return struct.pack('>I',len(data))+tag+data+struct.pack('>I',zlib.crc32(tag+data)&0xffffffff)
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(rgb))+chunk(b'IEND',b'')


def tests(video,h264,ctrl,rxlib,tls,tlshelper,rxhelper,bootlib,boothelper,ch,fixtures,streams):
    heap=C.create_string_buffer(2*1024*1024)
    assert tls.aa_tls_runtime_init(heap,len(heap),int(time.time()))==0
    class Env(ch.Env):
        def __init__(self,cold=False):
            self.frames,self.frame_attempts,self.frame_errors=[],[],[]
            self.frame_pause,self.frame_reenter=False,False
            self.frame_reentry=[];self.rgb=[]
            def frame_callback(_,pointer):
                try:
                    f=pointer.contents
                    raw=b''.join(C.string_at(f.planes[i],f.strides[i]*(f.height if i==0 else f.height//2)) for i in range(3))
                    item=(f.width,f.height,f.timestamp,f.index,raw)
                    self.frame_attempts.append(item)
                    if self.frame_reenter:
                        self.frame_reentry.append(video.aa_video_step(self.vctx,self.pair.sid))
                        self.frame_reentry.append(video.aa_video_stop(self.vctx,self.pair.sid))
                    if self.frame_pause:return 1
                    cap=C.c_size_t*3
                    sizes=cap(f.strides[0]*f.height,f.strides[1]*(f.height//2),f.strides[2]*(f.height//2))
                    target=C.create_string_buffer(480*272*2)
                    assert video.aa_rgb565_render(pointer,sizes,target,len(target),480,272,960,1,0)==0
                    self.rgb.append(target.raw);self.frames.append(item);return 0
                except Exception as e:
                    self.frame_errors.append(repr(e));return -993
            self.frame_callback=FRAMEFN(frame_callback)
            self.cfg=Config(800,480,262144,1048576,self.frame_callback,None)
            self.hstorage,self.hctx=aligned(h264.aa_h264_context_size(),h264.aa_h264_context_align())
            self.workspace=C.create_string_buffer(h264.aa_h264_workspace_size(C.byref(self.cfg)))
            self.decoder=C.c_void_p()
            assert h264.aa_h264_init(self.hctx,h264.aa_h264_context_size(),self.workspace,len(self.workspace),
                                    C.byref(self.cfg),C.byref(self.decoder))==0
            offered=ch.profile()
            keep=offered.channels[1];single=ch.pb('ServiceDiscoveryResponse',head_unit_name='software H264 fixture')
            single.channels.add().CopyFrom(keep)
            super().__init__(ctrl,rxlib,tls,tlshelper,rxhelper,fixtures,bootlib,boothelper,cold=cold,offered=single)
            # The original test provider was never invoked. Quiesce/discard its
            # unused contexts BEFORE binding fresh objects to the actual C queue.
            assert rxlib.aa_receiver_stop(self.receiver,self.pair.sid)==0
            assert self.call('stop')==0
            self.ctrl=C.create_string_buffer(ctrl.aa_control_context_bytes())
            self.receiver=C.create_string_buffer(rxlib.aa_receiver_context_bytes())
            self.vctx=C.create_string_buffer(video.aa_video_context_bytes())
            assert video.aa_video_init(self.vctx,self.pair.sid,self.decoder)==0
            self.provider=ch.PROVIDER(('aa_video_control_provider',video))
            data=single.SerializeToString()
            assert ctrl.aa_test_control_init(self.ctrl,self.pair.sid,data,len(data),self.provider,self.vctx)==0
            assert rxlib.aa_receiver_init(self.receiver,self.pair.storage,self.pair.sid,
                 self.wire,len(self.wire),self.plain,len(self.plain),self.message,len(self.message),
                 4096,self.callback,self.ctrl,1)==0

        def stats(self):
            s=Stats();r=video.aa_video_stats_get(self.vctx,self.pair.sid,C.byref(s));assert r==0,r;return s

        def worker(self):
            for _ in range(2000):
                r=video.aa_video_step(self.vctx,self.pair.sid)
                assert not self.frame_errors,self.frame_errors
                if r!=3:return r
            raise AssertionError('video worker did not yield')

        def eof(self):
            assert self.worker()==0
            r=video.aa_video_finish(self.vctx,self.pair.sid)
            assert r==2,(r,video.aa_video_decoder_detail(self.vctx,self.pair.sid))
            assert video.aa_video_finish(self.vctx,self.pair.sid)==2

        def packets(self,data,sizes=(7,123,4096),stamp=0xFEDCBA9876543210):
            at,turn=0,0
            while at<len(data):
                n=min(sizes[turn%len(sizes)],len(data)-at)
                wire=self.incoming(3,0,raw=struct.pack('>Q',stamp+turn)+data[at:at+n])
                assert self.feed(wire,chunks=(3,17,4096))==0
                self.drain()
                assert self.worker()==0
                at+=n;turn+=1
            return turn

        def close(self):
            assert video.aa_video_stop(self.vctx,self.pair.sid)==0
            h264.aa_h264_destroy(self.decoder)
            super().close()

    # Actual media across arbitrary indication/NAL boundaries, presentation
    # YUV order including Main/High B frames, and a real cold startup.
    artifact=None
    for k,s in enumerate(streams):
        e=Env(cold=k==0);assert e.initial==0;e.prepared(sid=-2147483648)
        packets=e.packets(s['data'],sizes=(1,3,71,4096) if k==0 else (13,211,4096))
        e.eof()
        assert [x[4] for x in e.frames]==s['expected'],(s['name'],len(e.frames),len(s['expected']))
        assert [(x[0],x[1]) for x in e.frames]==[(s['width'],s['height'])]*s['frames']
        assert len([x for x in e.outputs if x[2]==0x8004])==packets
        assert all(ch.parse('AVMediaAckIndication',x[3]).session==-2147483648 for x in e.outputs if x[2]==0x8004)
        st=e.stats();assert st.accepted_packets==packets and st.accepted_bytes==st.fed_bytes==len(s['data'])
        assert st.queued_packets==0
        assert e.rgb[0]==rgb_reference(s['expected'][0],s['width'],s['height'],480,272)
        if s['width']==800:
            p=OUT/'decoded-test-pattern.png';p.write_bytes(png_from_rgb565(e.rgb[0],480,272))
            artifact=dict(path=str(p.relative_to(ROOT)),sha256=sha(p),width=480,height=272,
                          source='decoded locally generated H264 test pattern; NOT Google Maps or Garmin display')
        e.close();CASES.append(s['name']+': real TLS/control/queue -> arbitrary media chunks -> software H264 -> byte-identical FFmpeg YUV and independently checked scaled RGB565')

    s=streams[0];e=Env();e.prepared(sid=-1)
    pieces=[s['data'][:10],s['data'][10:20],s['data'][20:]]
    for packet in pieces[:2]:
        assert e.feed(e.incoming(3,1,raw=packet))==0;e.drain()
    assert e.stats().queued_packets==2 and not e.frames
    assert e.feed(e.incoming(3,1,raw=pieces[2]))==1
    assert len([x for x in e.outputs if x[2]==0x8004])==2
    assert e.worker()==0
    assert e.step()==0;e.drain();assert e.worker()==0;e.eof()
    assert [x[4] for x in e.frames]==s['expected'] and e.stats().accepted_packets==3
    assert len([x for x in e.outputs if x[2]==0x8004])==3
    e.close();CASES.append('two owned compressed slots full: third indication PAUSED without ACK, worker capacity allows one acceptance and all frames remain correct')

    e=Env();e.prepared();e.frame_pause=True
    assert e.feed(e.incoming(3,1,raw=s['data']))==0;e.drain()
    assert e.worker()==1 and not e.frames
    previous=e.frame_attempts[-1]
    assert e.worker()==1 and e.frame_attempts[-1]==previous
    assert e.feed(e.incoming(3,1,raw=b'\x00\x00\x00\x01\x09\xf0'))==0;e.drain()
    assert e.worker()==1 and e.frame_attempts[-1]==previous
    e.frame_pause=False;assert e.worker()==0;e.eof()
    assert [x[4] for x in e.frames]==s['expected']
    e.close();CASES.append('decoded frame PAUSED keeps stable owned YUV; queue preserves unconsumed bitstream and does not re-decode/duplicate frame')

    e=Env();e.prepared();s_reorder=streams[1]
    e.packets(s_reorder['data'])
    e.frame_pause=True
    assert video.aa_video_finish(e.vctx,e.pair.sid)==1
    assert e.worker()==1
    assert video.aa_video_control_provider(e.vctx,3,5,0,0,0,b'x',1)==-600003
    e.frame_pause=False
    assert e.worker()==2
    assert video.aa_video_finish(e.vctx,e.pair.sid)==2
    assert [x[4] for x in e.frames]==s_reorder['expected']
    e.close();CASES.append('EOS reorder frame PAUSED -> worker retry FINISHED accepted; no new media admitted after EOF requested')

    e=Env();e.prepared();e.frame_reenter=True
    e.packets(s['data'],sizes=(len(s['data']),));e.eof()
    assert e.frame_reentry and set(e.frame_reentry)=={-600005}
    e.close();CASES.append('frame callback cannot reenter worker or tear down its queue/decoder while borrowed output is active')

    e=Env();e.prepared(sid=1)
    assert e.feed(e.incoming(3,1,raw=s['data'][:100]))==0;e.drain()
    assert e.stats().queued_packets==1
    assert e.feed(e.incoming(3,0x8002,ch.pb('AVChannelStopIndication')))==0
    assert e.stats().queued_packets==0 and e.stats().media_session==-1
    e.start(3,sid=2);e.packets(s['data']);e.eof()
    assert [x[4] for x in e.frames]==s['expected']
    e.close();CASES.append('STOP discards queued old session and decoder refs; fresh START decodes clean complete stream without stale frames')

    e=Env();e.prepared();e.frame_pause=True
    assert e.feed(e.incoming(3,1,raw=s['data']))==0;e.drain();assert e.worker()==1
    assert e.feed(e.incoming(3,0x8002,ch.pb('AVChannelStopIndication')))==0
    e.frame_pause=False;e.start(3,sid=42);e.packets(s['data']);e.eof()
    assert [x[4] for x in e.frames]==s['expected']
    e.close();CASES.append('STOP cancels held software frame and clears codec state before restart; no physical display mute claim')

    e=Env();e.prepared()
    assert e.feed(e.incoming(3,1,raw=b'not-annex-b'))==0;e.drain()
    r=e.worker()
    if r>=0:r=video.aa_video_finish(e.vctx,e.pair.sid)
    assert r==-600004 and not e.frames
    assert video.aa_video_status(e.vctx,e.pair.sid)==-600004
    e.close();CASES.append('malformed Annex-B accepted only as owned compressed data then fails decoder terminally without publishing frame')

    e=Env();e.prepared()
    assert video.aa_video_control_provider(e.vctx,3,5,99,0,0,b'x',1)==-600003
    assert video.aa_video_control_provider(e.vctx,3,5,0,0,0,None,0)==-600001
    assert video.aa_video_control_provider(e.vctx,3,5,0,0,0,b'x',262145)==-600001
    assert e.stats().accepted_packets==0
    assert video.aa_video_step(e.vctx,e.pair.sid+1)==-600002
    e.close();CASES.append('media session/empty/oversize/stale control guards reject before copying input')

    # Independent renderer controls, including source row strides and preserved
    # output padding; source plane capacities are checked before any pixel read.
    sw,sh=32,24
    y=bytes((i*11)%256 for i in range(sw*sh));u=bytes((i*17)%256 for i in range(sw*sh//4));v=bytes((i*23)%256 for i in range(sw*sh//4))
    raw=y+u+v
    buffers=[C.create_string_buffer(b) for b in [y,u,v]]
    f=Frame((C.c_void_p*3)(*(C.addressof(b) for b in buffers)),(C.c_size_t*3)(sw,sw//2,sw//2),sw,sh,0,0)
    sizes=(C.c_size_t*3)(len(y),len(u),len(v))
    for matrix in [1,2]:
        for full in [0,1]:
            dst=C.create_string_buffer(bytes([0xA5]*(41*2+8)*17))
            assert video.aa_rgb565_render(C.byref(f),sizes,dst,len(dst),41,17,90,matrix,full)==0
            assert dst.raw[:-1]==rgb_reference(raw,sw,sh,41,17,matrix,full,90)
            CASES.append(f'RGB565 fixed-point matrix{matrix}/range{full}, independent absolute-position scaling and output padding')
    # FFmpeg's independent swscale color transform, at original dimensions so
    # its scaler center convention is not conflated with our explicit top-left
    # nearest mapping. RGB565 quantizes to 5/6/5 bits, so compare expanded values
    # within the corresponding quantization/rounding interval, not identical RGB8.
    input_raw=OUT/'color-reference-input.yuv';input_raw.write_bytes(raw)
    for matrix in [1,2]:
        for full in [0,1]:
            m='bt601' if matrix==1 else 'bt709';rg='pc' if full else 'tv'
            args=['ffmpeg','-hide_banner','-loglevel','error','-f','rawvideo','-pix_fmt','yuv420p',
                  '-s',f'{sw}x{sh}','-i',str(input_raw),'-vf',
                  f'scale=iw:ih:flags=neighbor:in_color_matrix={m}:in_range={rg}:out_range=pc',
                  '-frames:v','1','-threads','1','-pix_fmt','rgb24','-f','rawvideo','pipe:1']
            result=subprocess.run(args,capture_output=True)
            assert result.returncode==0,result.stderr.decode()
            oracle=result.stdout;assert len(oracle)==sw*sh*3
            dst=C.create_string_buffer(sw*sh*2)
            assert video.aa_rgb565_render(C.byref(f),sizes,dst,len(dst),sw,sh,sw*2,matrix,full)==0
            maximum=[0,0,0]
            for i in range(sw*sh):
                val=int.from_bytes(dst.raw[i*2:i*2+2],'little')
                channels=[(val>>11)&31,(val>>5)&63,val&31]
                expanded=[(channels[0]<<3)|(channels[0]>>2),
                          (channels[1]<<2)|(channels[1]>>4),(channels[2]<<3)|(channels[2]>>2)]
                for channel in range(3):maximum[channel]=max(maximum[channel],abs(expanded[channel]-oracle[i*3+channel]))
            assert maximum[0]<=10 and maximum[1]<=7 and maximum[2]<=10,(matrix,full,maximum)
            CASES.append(f'FFmpeg independent swscale RGB color oracle matrix{matrix}/range{full} within declared RGB565 quantization tolerance')
    dst=C.create_string_buffer(64*24)
    small=(C.c_size_t*3)(len(y)-1,len(u),len(v))
    assert video.aa_rgb565_render(C.byref(f),small,dst,len(dst),32,24,64,1,0)==-2
    assert video.aa_rgb565_render(C.byref(f),sizes,dst,len(dst)-1,32,24,64,1,0)==-2
    assert video.aa_rgb565_render(C.byref(f),sizes,dst,len(dst),32,24,63,1,0)==-1
    assert video.aa_rgb565_render(C.byref(f),sizes,dst,len(dst),32,24,64,9,0)==-1
    CASES.append('renderer rejects short readable planes/output/pitch and unknown matrix before conversion')
    assert tls.aa_tls_heap_used()==0 and tls.aa_tls_heap_verify()==0
    return dict(queue_context_bytes=video.aa_video_context_bytes(),decoder_context_bytes=h264.aa_h264_context_size(),
                decoder_workspace_bytes=len(e.workspace),TLS_allocator_final_bytes=0),artifact


def main():
    started=time.time()
    control=json.loads(CONTROL.read_text());hp=json.loads(H264PROOF.read_text())
    qp=json.loads(QUEUE.read_text())
    assert control['pass'] and control['case_count']==43 and not control['device_IO']
    assert hp['pass'] and not hp['device_IO'] and not hp['native_guest_executed']
    assert qp['pass'] and qp['category_count']==12 and qp['assertions_per_build']==1312
    assert qp['video_queue_and_renderer_ASan_UBSan_verified']
    assert not qp['software_H264_decode_verified'] and not qp['device_IO']
    for d in [control,hp,qp]:
        for name,pin in d['source_sha256'].items():assert sha(ROOT/name)==pin,name
    for name,pin in hp['upstream_source_sha256'].items():assert sha(ROOT/name)==pin,name
    assert sha(CTRLLIB)==control['compiled_library_sha256']
    codec_build=next(b for b in hp['builds'] if b['name']=='ordinary')
    assert codec_build['shared_library']==str(H264LIB.relative_to(ROOT))
    assert sha(H264LIB)==codec_build['shared_library_sha256']
    sys.path.insert(0,str(ROOT/'staging/android-auto-proto-host-v1/python'))
    ch=module('aa_video_control_fixture',ROOT/'scripts/test_aa_control_host.py')
    tlshelper=module('aa_video_tls_fixture',ROOT/'scripts/test_aa_tls_host.py')
    rxhelper=module('aa_video_rx_fixture',ROOT/'scripts/test_aa_receiver_host.py')
    boothelper=module('aa_video_boot_fixture',ROOT/'scripts/test_aa_bootstrap_host.py')
    tls=C.CDLL(str(ch.TLSLIB));tlshelper.bind(tls)
    ctrl=C.CDLL(str(CTRLLIB));ch.bind(ctrl,rxhelper.View)
    rxlib=C.CDLL(str(ch.RXLIB));rxhelper.bind(rxlib)
    bootlib=C.CDLL(str(ch.BOOTLIB));boothelper.bind(bootlib)
    h264=C.CDLL(str(H264LIB));bind_h264(h264)
    library,buildinfo=build();video=C.CDLL(str(library));bind_video(video)
    tlshelper.OUT=OUT;fixtures=tlshelper.certificates()
    streams=[fixture('baseline-64x48',64,48,'baseline'),fixture('main-bframes-64x48',64,48,'main'),
             fixture('high-bframes-800x480',800,480,'high')]
    runtime,artifact=tests(video,h264,ctrl,rxlib,tls,tlshelper,rxhelper,bootlib,boothelper,ch,fixtures,streams)
    pins=dict(control['source_sha256']);pins.update(hp['source_sha256']);pins.update(qp['source_sha256'])
    pins.update(hp['upstream_source_sha256'])
    for p in ['native/aa-video/video.c','native/aa-video/video.h','native/aa-video/rgb565.c',
              'native/aa-video/rgb565.h','native/aa-video/README.md','scripts/test_aa_video_host.py']:
        pins[p]=sha(ROOT/p)
    proof=dict(schema='android-auto-video-host-v1',pass_=True,case_count=len(CASES),cases=CASES,
        software_H264_decode_verified=True,software_RGB565_surface_verified=True,
        software_video_output_is_hardware_display=False,device_IO=False,native_guest_executed=False,
        original_Garmin_code_executed=False,current_Pixel_interoperability_verified=False,
        Google_acceptance_verified=False,install_candidate=False,Garmin_Android_Auto_or_Google_Maps_running=False,
        hardware_speaker_or_display_or_touch_verified=False,video_queue_and_renderer_ASan_verified=False,
        video_queue_and_renderer_with_synthetic_decoder_ASan_verified=True,
        complete_TLS_control_codec_queue_renderer_ASan_verified=False,
        input_callback_is_C_owned_queue=True,ACK_is_compressed_acceptance_not_decoded_frame=True,
        real_local_TLS_cold_startup_to_H264_software_frames_verified=True,
        prerequisite=dict(control=dict(path=str(CONTROL.relative_to(ROOT)),sha256=sha(CONTROL)),
                          h264=dict(path=str(H264PROOF.relative_to(ROOT)),sha256=sha(H264PROOF)),
                          synthetic_decoder_queue=dict(path=str(QUEUE.relative_to(ROOT)),sha256=sha(QUEUE),
                              categories=12,assertions_per_build=1312,
                              scope='actual video.c/rgb565.c normal+ASan/UBSan with synthetic codec; not TLS/decoding')),
        source_sha256=pins,compiled_library_sha256=sha(library),build=buildinfo,runtime=runtime,
        fixture_streams=[{k:v for k,v in s.items() if k not in ['data','expected']} for s in streams],
        decoded_pattern_artifact=artifact,host_arch=platform.machine(),elapsed_host_seconds=round(time.time()-started,3),
        limitations=['No real phone/USB/AOA/Garmin image or native ABI/performance proof.',
          'Explicit serialized worker calls, not hardware IRQ or OS task/cancel/quiescence.',
          'OpenH264 internally allocates: frontend workspace/input/geometry bounds are not a proven total heap cap.',
          'Timestamp retained by queue/first-VCL policy; no verified phone clock/unit or audiovisual synchronization.',
          'RGB565 uses explicit chosen color matrix/range and nearest scaling; no inferred phone VUI or physical display ABI.',
          'Generated test pattern is not Google Maps, and software frames do not establish native projection or offline Maps.'])
    proof['pass']=proof.pop('pass_')
    PROOF.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(pass_=True,cases=len(CASES),proof=str(PROOF.relative_to(ROOT)),sha256=sha(PROOF),
                         runtime=runtime,software_H264_decode_verified=True,device_IO=False,native_guest_executed=False)))


if __name__=='__main__':main()
