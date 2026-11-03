#!/usr/bin/env python3
"""Our serialized C composition: local TLS, video, outbound input, owned PCM.

No phone/Garmin/USB/display/audio device I/O or original firmware execution.
Backend callbacks copy into software fixtures; they do not play sound.
"""
import ctypes as C
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import platform
import struct
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'staging/android-auto-interactive-host-v1'
PROOF=ROOT/'evidence/android-auto-interactive-host-v1.json'
INPUT=ROOT/'evidence/android-auto-input-host-v1.json'
AUDIO=ROOT/'evidence/android-auto-audio-host-v1.json'
VIDEO=ROOT/'evidence/android-auto-video-host-v1.json'
CTRLLIB=ROOT/'staging/android-auto-control-host-v1/libaa-control-host.so'
VIDEOLIB=ROOT/'staging/android-auto-video-host-v1/libaa-video-host.so'
H264LIB=ROOT/'staging/android-auto-h264-host-v1/ordinary/libaa-h264-host.so'
CASES=[]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

class Viewport(C.Structure):
    _fields_=[(k,C.c_uint32) for k in ['surface_width','surface_height','x','y','width','height']]
class AudioConfig(C.Structure):
    _fields_=[(k,C.c_uint32) for k in ['enabled_mask','packet_bytes_limit','output_bytes_limit','focus_policy','focus_grant_mask']]
class PCM(C.Structure):
    _fields_=[('data',C.c_void_p),('bytes',C.c_size_t),('frames',C.c_size_t),
       ('sample_rate',C.c_uint32),('channels',C.c_uint32),('bit_depth',C.c_uint32),
       ('channel',C.c_uint8),('media_session',C.c_int32),('focus_type',C.c_uint32),
       ('timestamp',C.c_uint64),('frame_offset',C.c_uint64)]
PCM_FN=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(PCM),C.POINTER(C.c_size_t))
class AudioStats(C.Structure):
    _fields_=[(k,C.c_uint64) for k in ['accepted_packets','accepted_bytes','assembled_bytes','backend_bytes','backend_frames','discarded_bytes','last_timestamp']]+\
      [(k,C.c_uint32) for k in ['queued_packets','queued_bytes','pending_bytes','carry_bytes','focus_type']]+\
      [('media_session',C.c_int32)]+[(k,C.c_int) for k in ['streaming','finished','error']]

def bind(lib,View):
    for prefix in ['input','audio','interactive']:
        getattr(lib,'aa_'+prefix+'_context_bytes').restype=C.c_uint32
        for op in ['step','status','stop'] if prefix!='input' else ['pending','status','stop']:
            getattr(lib,'aa_'+prefix+'_'+op).argtypes=[C.c_void_p,C.c_uint32]
    lib.aa_test_interactive_input_init.argtypes=[C.c_void_p,C.c_uint32,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(Viewport)]
    lib.aa_audio_init.argtypes=[C.c_void_p,C.c_uint32,C.POINTER(AudioConfig),PCM_FN,C.c_void_p]
    lib.aa_audio_finish.argtypes=[C.c_void_p,C.c_uint32,C.c_uint8]
    lib.aa_audio_stats_get.argtypes=[C.c_void_p,C.c_uint32,C.c_uint8,C.POINTER(AudioStats)]
    lib.aa_interactive_init.argtypes=[C.c_void_p,C.c_uint32]+[C.c_void_p]*6+[C.c_size_t]
    lib.aa_interactive_tx_peek.argtypes=[C.c_void_p,C.c_uint32,C.POINTER(C.c_void_p),C.POINTER(C.c_size_t)]
    lib.aa_interactive_tx_commit.argtypes=[C.c_void_p,C.c_uint32,C.c_size_t,C.c_int]
    lib.aa_interactive_owner.argtypes=[C.c_void_p,C.c_uint32,C.POINTER(C.c_uint32),C.POINTER(C.c_uint32)]
    lib.aa_interactive_detail.argtypes=[C.c_void_p,C.c_uint32]
    lib.aa_input_touch.argtypes=[C.c_void_p,C.c_uint32,C.c_uint64,C.c_uint32,C.c_int32,C.c_int32]
    lib.aa_input_release_touch.argtypes=[C.c_void_p,C.c_uint32,C.c_uint64]
    lib.aa_input_button.argtypes=[C.c_void_p,C.c_uint32,C.c_uint64,C.c_uint32,C.c_int,C.c_int]
    lib.aa_input_scroll.argtypes=[C.c_void_p,C.c_uint32,C.c_uint64,C.c_int32]

def build():
    OUT.mkdir(parents=True,exist_ok=True)
    shim=OUT/'profile-input-init.c'
    shim.write_text('''/* Test adapter, actual nanopb profile decoding. */
#include "input.h"
int aa_test_interactive_input_init(void *p,uint32_t s,void *control,
 const uint8_t *bytes,size_t n,const struct aa_input_viewport *viewport){
 f1x_aasdk_proto_messages_ServiceDiscoveryResponse profile={0};
 pb_istream_t in=pb_istream_from_buffer(bytes,n);
 if(!pb_decode(&in,f1x_aasdk_proto_messages_ServiceDiscoveryResponse_fields,&profile)||in.bytes_left)return -700004;
 return aa_input_init(p,s,control,&profile,viewport);
}
''')
    m=json.loads((ROOT/'staging/android-auto-input-host-v1/build.json').read_text())
    sources=[ROOT/'native/aa-input/input.c',ROOT/'native/aa-audio/audio.c',ROOT/'native/aa-interactive/interactive.c',shim]+[ROOT/p for p in m['c_sources']]
    includes=['native/aa-input','native/aa-input/generated','native/aa-audio','native/aa-interactive',
        'native/aa-video','native/aa-h264','native/aa-sender','native/aa-control','native/aa-message',
        'native/aa-proto','native/aa-proto/generated','native/aa-proto/runtime']
    lib=OUT/'libaa-interactive-host.so'
    args=['cc','-shared','-fPIC','-std=c11','-O1','-Wall','-Wextra','-Werror','-DPB_VALIDATE_UTF8=1']+\
      ['-I'+str(ROOT/p) for p in includes]+list(map(str,sources))+[str(CTRLLIB),str(VIDEOLIB),'-o',str(lib)]
    r=subprocess.run(args,cwd=ROOT,capture_output=True)
    assert r.returncode==0,r.stderr.decode()
    return lib,shim,dict(argv=args,exit_code=r.returncode,stderr=r.stderr.decode())

def tests(lib,video,h264,ctrl,rx,tls,th,rh,boot,bh,ch,vh,fixtures,stream):
    heap=C.create_string_buffer(2*1024*1024);assert tls.aa_tls_runtime_init(heap,len(heap),int(time.time()))==0
    InputEvent=getattr(importlib.import_module('InputEventIndicationMessage_pb2'),'InputEventIndication')
    def parse_input(raw):
        p=InputEvent();p.ParseFromString(raw);assert p.IsInitialized();return p
    class Env(ch.Env):
        def __init__(self,cold=False,focus_policy=1):
            offered=ch.profile();del offered.channels[0].input_channel.supported_keycodes[:]
            offered.channels[0].input_channel.supported_keycodes.extend([4,0x7e,0x7f,65536])
            self.frames,self.pcm,self.pcm_attempts,self.backend_errors=[],{4:bytearray(),5:bytearray(),6:bytearray()},[],[]
            self.tx_trace=[]
            self.frame_paused=False;self.pcm_paused=False;self.pcm_partial=False
            self.pcm_reenter=False;self.pcm_reentries=[]
            def frame_cb(_,ptr):
                try:
                    f=ptr.contents
                    if self.frame_paused:return 1
                    raw=b''.join(C.string_at(f.planes[i],f.strides[i]*(f.height if i==0 else f.height//2)) for i in range(3))
                    self.frames.append(raw);return 0
                except Exception as e:self.backend_errors.append(repr(e));return -992
            def pcm_cb(_,ptr,consumed):
                consumed[0]=0
                try:
                    p=ptr.contents;raw=C.string_at(p.data,p.bytes)
                    block=2*p.channels
                    assert p.bit_depth==16 and p.bytes%block==0 and p.frames==p.bytes//block
                    assert (p.sample_rate,p.channels)==((48000,2) if p.channel==4 else (16000,1))
                    self.pcm_attempts.append((p.channel,p.media_session,p.timestamp,p.frame_offset,p.focus_type,raw))
                    if self.pcm_reenter:self.pcm_reentries.append(lib.aa_audio_step(self.actx,self.pair.sid))
                    if self.pcm_paused:return 1
                    n=min(len(raw),block) if self.pcm_partial else len(raw)
                    self.pcm[p.channel].extend(raw[:n]);consumed[0]=n
                    return 1 if n<len(raw) else 0
                except Exception as e:self.backend_errors.append(repr(e));return -993
            self.frame_fn=vh.FRAMEFN(frame_cb);self.pcm_fn=PCM_FN(pcm_cb)
            self.cfg=vh.Config(800,480,262144,1048576,self.frame_fn,None)
            self.hstorage,self.hctx=vh.aligned(h264.aa_h264_context_size(),h264.aa_h264_context_align())
            self.workspace=C.create_string_buffer(h264.aa_h264_workspace_size(C.byref(self.cfg)));self.decoder=C.c_void_p()
            assert h264.aa_h264_init(self.hctx,h264.aa_h264_context_size(),self.workspace,len(self.workspace),C.byref(self.cfg),C.byref(self.decoder))==0
            super().__init__(ctrl,rx,tls,th,rh,fixtures,boot,bh,cold=cold,offered=offered)
            # Parent's test provider/receiver/sender have accepted no data. Stop
            # only the receiver/control; discard the untouched sender storage
            # without stop or TLS mutation, before creating the sole real owner.
            assert rx.aa_receiver_stop(self.receiver,self.pair.sid)==0;assert self.call('stop')==0
            self.ctrl=C.create_string_buffer(ctrl.aa_control_context_bytes());self.receiver=C.create_string_buffer(rx.aa_receiver_context_bytes())
            self.sender=C.create_string_buffer(ctrl.aa_sender_context_bytes())
            self.ictx=C.create_string_buffer(lib.aa_input_context_bytes());self.actx=C.create_string_buffer(lib.aa_audio_context_bytes())
            self.vctx=C.create_string_buffer(video.aa_video_context_bytes());self.bctx=C.create_string_buffer(lib.aa_interactive_context_bytes())
            raw=offered.SerializeToString();viewport=Viewport(480,272,0,0,480,272)
            assert lib.aa_test_interactive_input_init(self.ictx,self.pair.sid,self.ctrl,raw,len(raw),C.byref(viewport))==0
            assert video.aa_video_init(self.vctx,self.pair.sid,self.decoder)==0
            cfg=AudioConfig(7,16384,4096,focus_policy,30)
            assert lib.aa_audio_init(self.actx,self.pair.sid,C.byref(cfg),self.pcm_fn,None)==0
            self.provider=ch.PROVIDER(('aa_interactive_control_provider',lib))
            assert ctrl.aa_test_control_init(self.ctrl,self.pair.sid,raw,len(raw),self.provider,self.bctx)==0
            assert lib.aa_interactive_init(self.bctx,self.pair.sid,self.pair.storage,self.ctrl,self.ictx,self.vctx,self.actx,self.sender,len(self.sender))==0
            assert rx.aa_receiver_init(self.receiver,self.pair.storage,self.pair.sid,self.wire,len(self.wire),self.plain,len(self.plain),
                self.message,len(self.message),4096,self.callback,self.ctrl,1)==0

        def bcall(self,name,*args):return getattr(lib,'aa_interactive_'+name)(self.bctx,self.pair.sid,*args)
        def icall(self,name,*args):return getattr(lib,'aa_input_'+name)(self.ictx,self.pair.sid,*args)
        def wire_peek(self):
            ptr,n=C.c_void_p(),C.c_size_t();assert self.bcall('tx_peek',C.byref(ptr),C.byref(n))==0
            return ptr,n.value
        def drain(self,auto_focus=True):
            for _ in range(500):
                if auto_focus:
                    r=self.call('step');assert r in (0,1),r
                r=self.bcall('step');assert r in (0,1,2,3,4),r
                if r==4:return
                ptr,n=self.wire_peek()
                if not n:
                    if r==0:return
                    continue
                wire=C.string_at(ptr,n);owner,token=C.c_uint32(),C.c_uint32()
                assert self.bcall('owner',C.byref(owner),C.byref(token))==0 and token.value
                assert owner.value in (1,2)
                old_state=self.state(wire[0]) if wire[0] else None
                pending=self.icall('pending')
                assert self.bcall('tx_commit',0,0)==1
                p2,n2=self.wire_peek();assert (p2.value,n2)==(ptr.value,n)
                assert self.bcall('tx_commit',3,0)==1
                if wire[0]:assert self.state(wire[0])==old_state
                assert self.icall('pending')==pending
                assert self.bcall('tx_commit',n-3,0)==3
                if wire[1]&8:
                    self.pair.inbio.write(wire[4:]);actual=self.pair.peer.read(16384)
                else:actual=wire[4:]
                assert int.from_bytes(wire[2:4],'big')==len(wire)-4
                assert self.bcall('step') in (3,4)
                self.outputs.append((wire[0],wire[1]&12,int.from_bytes(actual[:2],'big'),actual[2:]))
                self.tx_trace.append((owner.value,token.value,wire[0],int.from_bytes(actual[:2],'big')))
                if actual[:2]==b'\x00\x10':return
            raise AssertionError('bridge TX did not quiesce')
        def bind_input(self,keys=(4,0x7e,0x7f,65536)):
            self.open(1)
            assert self.feed(self.incoming(1,0x8002,ch.pb('BindingRequest',scan_codes=keys)))==0
            assert self.state(1)==6
            assert self.icall('touch',0,0,1,1)==-700003
            self.drain();assert self.state(1)==7
        def focus(self,kind):
            assert self.feed(self.incoming(0,18,ch.pb('AudioFocusRequest',audio_focus_type=kind)))==0
            self.drain()
        def audio_worker(self):
            for _ in range(2000):
                r=lib.aa_audio_step(self.actx,self.pair.sid)
                assert not self.backend_errors,self.backend_errors
                if r!=3:return r
            raise AssertionError('audio worker did not yield')
        def video_worker(self):
            for _ in range(2000):
                r=video.aa_video_step(self.vctx,self.pair.sid)
                assert not self.backend_errors,self.backend_errors
                if r!=3:return r
            raise AssertionError('video worker did not yield')
        def send_media(self,channel,data,timestamp=100):
            r=self.feed(self.incoming(channel,0,raw=struct.pack('>Q',timestamp)+data),chunks=(1,17,4096))
            if r==0:self.drain()
            return r
        def audio_stats(self,channel):
            p=AudioStats();assert lib.aa_audio_stats_get(self.actx,self.pair.sid,channel,C.byref(p))==0;return p
        def close(self):
            assert video.aa_video_stop(self.vctx,self.pair.sid)==0;h264.aa_h264_destroy(self.decoder)
            assert lib.aa_audio_stop(self.actx,self.pair.sid)==0
            assert self.icall('stop')==0
            assert self.bcall('stop')==0 # abandon whole TLS then owner frees it
            assert rx.aa_receiver_stop(self.receiver,self.pair.sid)==0;assert self.call('stop')==0
            self.pair.free()

    e=Env(cold=True);e.discover();e.bind_input();e.open(3);e.setup(3);e.start(3,-2147483648)
    for channel,sid in [(4,-2147483648),(5,-1),(6,2147483647)]:e.open(channel);e.setup(channel);e.start(channel,sid)
    e.focus(1)
    audio={4:struct.pack('<hh',1234,-2345)*101,5:struct.pack('<h',3210)*71,6:struct.pack('<h',-4321)*63}
    sent={k:0 for k in audio};acks={k:0 for k in [3,4,5,6]};at=0;turn=0
    coded=stream['data'];events=[]
    while at<len(coded) or any(sent[k]<len(audio[k]) for k in audio):
        if at<len(coded):
            n=min((1,7,211,4096)[turn%4],len(coded)-at)
            assert e.send_media(3,coded[at:at+n],1000+turn)==0;at+=n;acks[3]+=1;assert e.video_worker()==0
        for k in audio:
            if sent[k]<len(audio[k]):
                n=min((1,3,5,11)[turn%4],len(audio[k])-sent[k]);chunk=audio[k][sent[k]:sent[k]+n]
                assert e.send_media(k,chunk,2000+turn)==0;sent[k]+=n;acks[k]+=1;assert e.audio_worker()==0
        if turn==0:
            assert e.icall('touch',1000000,0,240,136)==0;events.append((0,400,240))
        if turn==1:
            assert e.icall('touch',1000001,2,479,271)==0;events.append((2,798,478))
        if turn==2:
            assert e.icall('release_touch',1000002)==0;events.append((1,798,478))
        e.drain();turn+=1
    assert video.aa_video_finish(e.vctx,e.pair.sid)==2
    assert e.frames==stream['expected']
    for k in audio:
        assert lib.aa_audio_finish(e.actx,e.pair.sid,k)==2
        assert bytes(e.pcm[k])==audio[k]
        assert e.audio_stats(k).backend_frames==len(audio[k])//(4 if k==4 else 2)
    actual=[parse_input(x[3]) for x in e.outputs if x[2]==0x8001]
    assert [(p.touch_event.touch_action,p.touch_event.touch_location[0].x,p.touch_event.touch_location[0].y) for p in actual]==events
    assert all(p.disp_channel==0 and p.touch_event.action_index==0 and p.touch_event.touch_location[0].pointer_id==0 for p in actual)
    for k in acks:
        out=[ch.parse('AVMediaAckIndication',x[3]) for x in e.outputs if x[0]==k and x[2]==0x8004]
        assert len(out)==acks[k] and all(p.value==1 for p in out)
        assert all(p.session=={3:-2147483648,4:-2147483648,5:-1,6:2147483647}[k] for p in out)
    e.close();CASES.append('cold same TLS: all channels plus High800x480 Bframes, arbitrary PCM byte chunks, signed sessions, real encrypted input mapped480x272to800x480, one ACK per indication')

    # The actual pending BindingResponse becomes usable only after all wire
    # bytes and source completion. A real sender, not synthetic bound state.
    e=Env();e.discover();e.open(1)
    assert e.feed(e.incoming(1,0x8002,ch.pb('BindingRequest',scan_codes=[4])))==0
    assert e.state(1)==6 and e.icall('touch',1,0,0,0)==-700003
    assert e.bcall('step')==2;ptr,n=e.wire_peek();wire=C.string_at(ptr,n)
    assert e.bcall('tx_commit',n-1,0)==1 and e.state(1)==6
    assert e.icall('touch',1,0,0,0)==-700003
    assert e.bcall('tx_commit',1,0)==3 and e.state(1)==6
    e.pair.inbio.write(wire[4:]);assert e.pair.peer.read(16384).startswith(b'\x80\x03')
    assert e.bcall('step')==3 and e.state(1)==7
    assert e.icall('touch',1,0,0,0)==0;e.drain()
    p=parse_input(e.outputs[-1][3]);assert p.HasField('touch_event') and len(p.touch_event.touch_location)==1
    assert p.touch_event.touch_location[0].x==p.touch_event.touch_location[0].y==0
    assert e.icall('button',2,0x7e,1,0)==-700004
    e.close();CASES.append('real TLS binding final-byte/source commit gate, origin PRESS message presence, unbound advertised key refused')

    e=Env();e.discover();e.bind_input()
    assert e.icall('button',10,4,1,0)==0
    assert e.icall('button',11,4,1,1)==0
    assert e.icall('button',12,4,0,0)==0
    assert e.icall('scroll',13,-2147483648)==0
    assert e.icall('scroll',14,2147483647)==0
    e.drain();p=[parse_input(x[3]) for x in e.outputs if x[2]==0x8001]
    assert [(x.button_event.button_events[0].is_pressed,x.button_event.button_events[0].long_press) for x in p[:3]]==[(True,False),(True,True),(False,False)]
    assert all(x.button_event.button_events[0].scan_code==4 and x.button_event.button_events[0].meta==0 for x in p[:3])
    assert [x.relative_input_event.relative_input_events[0].delta for x in p[3:]]==[-2147483648,2147483647]
    assert all(x.relative_input_event.relative_input_events[0].scan_code==65536 for x in p[3:])
    e.close();CASES.append('same real TLS sender carries key press/longpress/release and signed32 wheel extremes; independent protobuf semantics')

    e=Env();e.discover();e.bind_input()
    for i in range(8):assert e.icall('scroll',i+1,1)==0
    assert e.icall('touch',100,0,1,1)==1
    assert e.icall('pending')==8;e.drain()
    assert e.icall('touch',100,0,1,1)==0;assert e.icall('release_touch',101)==0;e.drain()
    p=[parse_input(x[3]) for x in e.outputs if x[2]==0x8001]
    assert len(p)==10 and [x.touch_event.touch_action for x in p[8:]]==[0,1]
    e.close();CASES.append('input queuefull PAUSED preserves capture state and timestamp; drain then exact retry publishes one press/release')

    e=Env();e.discover();e.bind_input()
    assert e.icall('scroll',1,1)==0
    assert e.feed(e.incoming(0,11,ch.pb('PingRequest',timestamp=-1)))==0
    e.drain();last=e.outputs[-2:]
    assert {x[2] for x in last}=={12,0x8001}
    assert next(x[1] for x in last if x[2]==12)==0
    assert ch.parse('PingResponse',next(x[3] for x in last if x[2]==12)).timestamp==-1
    assert parse_input(next(x[3] for x in last if x[2]==0x8001)).timestamp==1
    assert e.icall('scroll',2,1)==0;e.drain();assert parse_input(e.outputs[-1][3]).timestamp==2
    e.close();CASES.append('one sender alternates plaintext legacy ping and encrypted input without TLS sequence reset or queue-owner token confusion')

    # Token numbers belong to each source, so equality must never select or
    # prematurely commit the other queue. Arrange equal public tokens through
    # ordinary requests; no private context writes or synthetic TLS output.
    e=Env();e.discover();e.bind_input()
    for i in range(3):
        assert e.icall('scroll',i+1,1)==0;e.drain()
    assert e.tx_trace[-1][:2]==(2,3)
    assert e.icall('scroll',4,1)==0
    assert e.feed(e.incoming(0,11,ch.pb('PingRequest',timestamp=1234)))==0
    e.drain()
    assert e.tx_trace[-2:]==[(1,4,0,12),(2,4,1,0x8001)]
    assert ch.parse('PingResponse',e.outputs[-2][3]).timestamp==1234
    assert parse_input(e.outputs[-1][3]).timestamp==4
    assert e.icall('pending')==0 and e.call('pending')==0
    e.close();CASES.append('actual equal token4 in control/input queues: correct owner commits each exactly once and alternation preserves independent plaintext/cipher messages')

    e=Env();e.discover();e.open(4);e.setup(4);e.start(4,-1);e.focus(1)
    raw=struct.pack('<hhhh',100,-100,200,-200)*30
    e.pcm_paused=True;assert e.send_media(4,raw)==0;assert e.audio_worker()==1
    first=e.pcm_attempts[-1];assert e.audio_worker()==1 and e.pcm_attempts[-1]==first
    e.pcm_paused=False;e.pcm_partial=True
    while len(e.pcm[4])<len(raw):assert e.audio_worker() in (0,1)
    assert bytes(e.pcm[4])==raw and lib.aa_audio_finish(e.actx,e.pair.sid,4)==2
    e.close();CASES.append('real control ACK then backend PAUSED0 stable owned PCM; partial4-byte acceptance retries only suffix without duplication')

    e=Env();e.discover()
    for k in [4,5,6]:e.open(k);e.setup(k);e.start(k,k)
    e.focus(3)
    media=struct.pack('<hh',1000,-1000)*20;speech=struct.pack('<h',123)*20;system=struct.pack('<h',-321)*20
    for k,data in [(4,media),(5,speech),(6,system)]:assert e.send_media(k,data)==0
    assert e.audio_worker()==1 and not e.pcm[4]
    assert bytes(e.pcm[5])==speech and bytes(e.pcm[6])==system
    e.focus(1);assert e.audio_worker()==0 and bytes(e.pcm[4])==media
    e.close();CASES.append('explicit host NAVI focus gate holds media while speech/system progress, then GAIN releases owned media; no hardware policy claim')

    e=Env();e.discover();e.open(4);e.setup(4);e.start(4,1);e.focus(1)
    assert e.send_media(4,b'\x01')==0;assert e.audio_worker()==0
    assert lib.aa_audio_finish(e.actx,e.pair.sid,4)==-700008
    assert e.feed(e.incoming(4,0x8002,ch.pb('AVChannelStopIndication')))==0
    assert e.state(4)==4;e.start(4,2)
    data=struct.pack('<hh',2345,-1234)*10;assert e.send_media(4,data)==0;assert e.audio_worker()==0
    assert bytes(e.pcm[4])==data and lib.aa_audio_finish(e.actx,e.pair.sid,4)==2
    e.close();CASES.append('truncated PCM EOF fails rather than padding; actual control STOP clears carry/error and new session produces only new PCM')

    e=Env();e.discover();e.open(4);e.setup(4);e.start(4,1);e.focus(1)
    old=struct.pack('<hh',111,-111)*12;e.pcm_paused=True
    assert e.send_media(4,old)==0;assert e.audio_worker()==1
    assert e.feed(e.incoming(4,0x8002,ch.pb('AVChannelStopIndication')))==0
    e.pcm_paused=False;e.start(4,2);new=struct.pack('<hh',222,-222)*8
    assert e.send_media(4,new)==0;assert e.audio_worker()==0 and bytes(e.pcm[4])==new
    e.close();CASES.append('control STOP discards pending paused PCM and starts clean new session without stale audio')

    e=Env();e.discover();e.open(4);e.setup(4);e.start(4,1);e.focus(1)
    data=struct.pack('<hh',1234,-2345)*4;e.pcm_reenter=True
    assert e.send_media(4,data)==0;assert e.audio_worker()==0
    assert e.pcm_reentries and set(e.pcm_reentries)=={-700006}
    assert bytes(e.pcm[4])==data;e.close();CASES.append('real PCM backend callback rejects reentry into worker while borrowed output is active')

    e=Env();e.discover();e.bind_input();assert e.icall('scroll',1,1)==0
    assert e.bcall('step')==2;ptr,n=e.wire_peek();assert n
    assert e.bcall('tx_commit',1,1)==-900004
    assert e.bcall('status')==-900004 and e.bcall('detail')==-400007
    assert e.icall('pending')==1
    e.close();CASES.append('failed wire completion terminally invalidates shared sender, does not commit input head, owner discards whole TLS')

    e=Env();e.discover();e.bind_input()
    assert e.feed(e.incoming(0,15,ch.pb('ShutdownRequest',reason=1)))==0
    e.drain();assert e.outputs[-1][2]==16
    assert e.bcall('status')==-900003
    e.close();CASES.append('actual shutdown reply final transport/source completion closes bridge; explicit owner cleanup remains required')
    assert tls.aa_tls_heap_used()==0 and tls.aa_tls_heap_verify()==0
    return dict(bridge_context_bytes=lib.aa_interactive_context_bytes(),input_context_bytes=lib.aa_input_context_bytes(),
        audio_context_bytes=lib.aa_audio_context_bytes(),TLS_allocator_final_bytes=0,
        joint_H264_reference_frames=len(stream['expected']),software_PCM_bytes={str(k):len(v) for k,v in audio.items()})

def main():
    started=time.time();proofs={k:json.loads(p.read_text()) for k,p in [('input',INPUT),('audio',AUDIO),('video',VIDEO)]}
    for d in proofs.values():
        assert d['pass'] and not d['device_IO'] and not d['native_guest_executed']
        for p,pin in d['source_sha256'].items():assert sha(ROOT/p)==pin,p
    sys.path.insert(0,str(ROOT/'staging/android-auto-proto-host-v1/python'))
    sys.path.insert(0,str(ROOT/'staging/android-auto-input-host-v1/python'))
    ch=load('aa_interactive_control',ROOT/'scripts/test_aa_control_host.py')
    vh=load('aa_interactive_video',ROOT/'scripts/test_aa_video_host.py')
    th=load('aa_interactive_tls',ROOT/'scripts/test_aa_tls_host.py')
    rh=load('aa_interactive_rx',ROOT/'scripts/test_aa_receiver_host.py')
    bh=load('aa_interactive_boot',ROOT/'scripts/test_aa_bootstrap_host.py')
    tls=C.CDLL(str(ch.TLSLIB));th.bind(tls);ctrl=C.CDLL(str(CTRLLIB));ch.bind(ctrl,rh.View)
    rx=C.CDLL(str(ch.RXLIB));rh.bind(rx);boot=C.CDLL(str(ch.BOOTLIB));bh.bind(boot)
    video=C.CDLL(str(VIDEOLIB));vh.bind_video(video);h264=C.CDLL(str(H264LIB));vh.bind_h264(h264)
    assert sha(VIDEOLIB)==proofs['video']['compiled_library_sha256']
    library,shim,build_info=build();lib=C.CDLL(str(library));bind(lib,rh.View)
    th.OUT=OUT;fixtures=th.certificates()
    f=next(s for s in proofs['video']['fixture_streams'] if s['width']==800)
    coded=ROOT/f['coded_path'];assert sha(coded)==f['coded_sha256']
    raw=coded.with_suffix('.yuv');assert sha(raw)==f['reference_sha256']
    data=raw.read_bytes();unit=f['width']*f['height']*3//2
    stream=dict(data=coded.read_bytes(),expected=[data[i:i+unit] for i in range(0,len(data),unit)])
    runtime=tests(lib,video,h264,ctrl,rx,tls,th,rh,boot,bh,ch,vh,fixtures,stream)
    pins={};
    for p in proofs.values():pins.update(p['source_sha256'])
    for name in ['native/aa-interactive/interactive.c','native/aa-interactive/interactive.h','native/aa-interactive/README.md','scripts/test_aa_interactive_host.py']:
        pins[name]=sha(ROOT/name)
    pins[str(shim.relative_to(ROOT))]=sha(shim)
    result=dict(schema='android-auto-interactive-host-v1',pass_=True,case_count=len(CASES),cases=CASES,
      real_local_TLS_video_input_audio_integrated=True,software_H264_decode_verified=True,
      real_TLS_control_binding_completion_verified=True,software_PCM_backend_routing_verified=True,
      source_sha256=pins,compiled_library_sha256=sha(library),actual_build=build_info,runtime=runtime,
      prerequisite={k:dict(path=str(p.relative_to(ROOT)),sha256=sha(p)) for k,p in [('input',INPUT),('audio',AUDIO),('video',VIDEO)]},
      device_IO=False,native_guest_executed=False,original_Garmin_code_executed=False,ARM_crosscompile=False,
      current_Pixel_interoperability_verified=False,Google_acceptance_verified=False,
      hardware_display_or_touch_or_speaker_verified=False,install_candidate=False,full_goal_complete=False,
      complete_interactive_pipeline_ASan_verified=False,input_timestamp_clock_sync_verified=False,
      native_audio_ownership_or_mixing_verified=False,multitouch_verified=False,
      host_arch=platform.machine(),elapsed_host_seconds=round(time.time()-started,3),
      limitations=['All caller work serialized, no OS/IRQ/backend cancellation/quiescence proof.',
       'Exact old public protocol only; local peer is not Android Auto/current Pixel/Google.',
       'PCM backend copies bytes without sound; explicit host focus gate is not Garmin audio ownership.',
       'Single pointer policy with calibrated fixture geometry, no hardware driver/rotation/CANCEL/multitouch.',
       'Input and audio component ASan scopes are separate; combined TLS/video/input/audio has no ASan claim.',
       'No native allocator/ABI/performance/display/App/USBhost/VBUS/AOA/install/Maps completion.'])
    result['pass']=result.pop('pass_');PROOF.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(pass_=True,cases=len(CASES),proof=str(PROOF.relative_to(ROOT)),sha256=sha(PROOF),runtime=runtime,
        real_local_TLS_video_input_audio_integrated=True,device_IO=False,native_guest_executed=False)))
if __name__=='__main__':main()
