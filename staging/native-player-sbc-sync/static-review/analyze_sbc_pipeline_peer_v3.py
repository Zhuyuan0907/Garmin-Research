#!/usr/bin/env python3
"""File-only build-v3/source/ABI review. No VM imports or guest execution."""
import hashlib, json, re, struct, tarfile
from pathlib import Path
from datetime import datetime, timezone
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / 'staging/native-player-sbc-sync'
OUT = BASE / 'static-review/sbc-pipeline-build-v3-peer-review.json'
EXPECTED_MAIN = '10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'

def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()
def rel(p): return str(p.relative_to(ROOT))
def require(ok, why):
    if not ok: raise AssertionError(why)
def load(p): return json.loads(p.read_text())
def write(p, value):
    with p.open('x') as f: json.dump(value, f, indent=2); f.write('\n')

class ELF:
    def __init__(self, p):
        self.data = p.read_bytes()
        h = struct.unpack_from('<16sHHIIIIIHHHHHH', self.data)
        require(h[0][:7] == b'\x7fELF\x01\x01\x01' and h[1:3] == (2,40), 'not little-endian ARM ET_EXEC')
        self.entry=h[4]
        self.segments=[]
        for i in range(h[10]):
            t,off,va,pa,fs,ms,fl,al=struct.unpack_from('<8I', self.data,h[5]+i*h[9])
            if t==1:self.segments.append(dict(offset=off,address=va,file_size=fs,memory_size=ms,flags=fl,alignment=al))
        self.sections=[]
        for i in range(h[12]):
            v=struct.unpack_from('<10I',self.data,h[6]+i*h[11]);self.sections.append(v)
        self.symbols=[]
        for s in self.sections:
            if s[1]!=2:continue
            strings=self.sections[s[6]];names=self.data[strings[4]:strings[4]+strings[5]]
            for off in range(s[4],s[4]+s[5],s[9]):
                n,v,z,info,other,idx=struct.unpack_from('<IIIBBH',self.data,off)
                name=names[n:names.find(b'\0',n)].decode()
                self.symbols.append(dict(name=name,value=v,size=z,info=info,section_index=idx))
        self.named={s['name']:s for s in self.symbols if s['name'] and s['section_index']}
        self.maps=sorted((s['value'],s['name'][1]) for s in self.symbols if re.match(r'^\$[adt](\.|$)',s['name']))
    def read(self,a,n):
        s=next((s for s in self.segments if s['address']<=a and a+n<=s['address']+s['file_size']),None)
        require(s is not None,'ELF range is not file-backed')
        o=s['offset']+a-s['address'];return self.data[o:o+n]
    def mode(self,a):
        prior=[m for x,m in self.maps if x<=a];return prior[-1] if prior else None

def packet_frames(b):
    require(b[0]>>6==2,'RTP version')
    end=len(b)-(b[-1] if b[0]&32 else 0);offset=12+4*(b[0]&15)
    if b[0]&16:offset+=4+4*int.from_bytes(b[offset+2:offset+4],'big')
    require(b[offset]&0xf0==0,'nonfragmented declared input');count=b[offset]&15;offset+=1
    out=[]
    for i in range(count):
        require(b[offset]==0x9c,'SBC syncword');hdr=b[offset+1];sub=8 if hdr&1 else 4
        blocks=4*(((hdr>>4)&3)+1);mode=(hdr>>2)&3;channels=1 if mode==0 else 2;bitpool=b[offset+2]
        bits=blocks*bitpool*(channels if mode<=1 else 1)+(sub if mode==3 else 0)
        size=4+sub*channels//2+(bits+7)//8
        require(offset+size<=end,'SBC frame bound')
        out.append(dict(offset=offset,bytes=size,header=hdr,rate=(16000,32000,44100,48000)[hdr>>6],channels=channels,crc_offset=offset+3))
        offset+=size
    require(offset==end,'whole packet framing');return out

def anchor(path, text):
    lines=path.read_text().splitlines();hits=[i+1 for i,l in enumerate(lines) if text in l]
    require(hits,'missing source anchor '+text);return dict(path=rel(path),lines=hits,text=text)

def main():
    build=load(BASE/'build-v3.json');reference=load(BASE/'compressed_input_reference_v1.json')
    require(build['ELF_sha256']=='c170e77c216abb44e6a6570034768ce00deb3226b20d1bd0349b70d1e564a4eb','wrong exact build')
    deps=dict(build['source_sha256']);deps.update(build['generated_sha256']);deps.update(reference['source_sha256'])
    add=[Path(__file__).resolve(),BASE/'build-v3.json',BASE/'build-v3/inputs.json',ROOT/build['ELF'],BASE/'build-v3-terminal-tool-receipt.json',BASE/'compressed_input_reference_v1.json',BASE/'emulate_sbc_sync_v1.py',ROOT/'staging/native-player-mixer-sync/emulate_mixer_sync_v3.py',ROOT/'staging/native-player-session-native-call/emulate_queue_call.py',ROOT/'scripts/emulate_avdtp_media.py',ROOT/'scripts/emulate_native_media_worker.py',ROOT/'evidence/firmware-analysis/avdtp-media-dispatch-emulation.json',ROOT/'evidence/firmware-analysis/native-media-worker-emulation.json',ROOT/'evidence/firmware-analysis/main_02bd.bin']
    add+=sorted((BASE/'build-v3').glob('command-*.json'))+sorted((BASE/'build-v3/source-snapshot').iterdir())
    for p in add:
        digest=sha(p);require(rel(p) not in deps or deps[rel(p)]==digest,'hash collision '+rel(p));deps[rel(p)]=digest
    for path,digest in deps.items():require(sha(ROOT/path)==digest,'changed source '+path)
    require(deps['evidence/firmware-analysis/main_02bd.bin']==EXPECTED_MAIN,'wrong MAIN')
    require(sha(ROOT/build['ELF'])==build['ELF_sha256'],'ELF hash')
    require(load(BASE/'build-v3/inputs.json')==build['source_sha256'],'manifest/input registry difference')
    snapshots=sorted((BASE/'build-v3/source-snapshot').iterdir())
    for (path,digest),snap in zip(build['source_sha256'].items(),snapshots):
        require(snap.name.split('-',1)[1]==Path(path).name and sha(snap)==digest,'source snapshot mismatch')
    require(len(snapshots)==len(build['source_sha256'])==47,'snapshot count')
    commands=[load(p) for p in sorted((BASE/'build-v3').glob('command-*.json'))]
    require(len(commands)==21 and all(c['exit_code']==0 for c in commands),'actual compile command receipts')
    parser_compile=[c for c in commands if str(ROOT/'native/sbc-prototype/voice_media.c') in c['command']]
    require(len(parser_compile)==1 and '-Dvoice_extension_submit_frame=owned_media_submit_frame' in parser_compile[0]['command'],'wrong parser submit binding')
    require('-DVOICE_MEDIA_CONVERT=1' in parser_compile[0]['command'] and '-Dvoice_extension_media_callback=owned_packet_parse' in parser_compile[0]['command'],'wrong parser conversion/binding')
    archive=ROOT/'sources/deep-research/sbc-2.1.tar.xz'
    with tarfile.open(archive,'r:xz') as t:
        for p in [ROOT/'sources/deep-research/sbc-2.1/sbc/sbc.c',*sorted((ROOT/'sources/deep-research/sbc-2.1/sbc').glob('*.h'))]:
            require(t.extractfile('sbc-2.1/sbc/'+p.name).read()==p.read_bytes(),'libsbc archive-source mismatch')
    e=ELF(ROOT/build['ELF']);require(not [s for s in e.symbols if s['name'] and not s['section_index']],'undefined symbols')
    require(e.entry==e.named['aas_initialize']['value'],'ELF entry')
    for name,s in build['symbols'].items():
        require(any(v['name']==name and v['value']==s['value'] and v['size']==s['size'] for v in e.symbols),'manifest symbol mismatch '+name)
    for n,size,addr in [('gather',4096,0x07900000),('source_stack',16384,0x07800000),('slots',16384,0x07902000)]:
        require(e.named[n]['size']==size and e.named[n]['value']==addr,'typed range '+n)
    require(e.named['owned_media_control']['size']==52,'control ABI52')
    for n in ['media_worker_boot','media_worker_entry','media_worker_callback','owned_media_api']:require(n not in e.named,'unexpected GC-retained separate worker '+n)
    for i in range(4):require(e.named['pcm'+str(i)]['value']==0x07700000+i*4096 and e.named['pcm'+str(i)]['size']==4096,'PCM page recipe')
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM);names={s['value']:s['name'] for s in e.symbols if s['size'] and s['name'] and s['section_index']}
    functions=['aas_packet_process','media_queue_callback','media_queue_step','owned_media_consume','owned_packet_parse','owned_media_submit_frame','garmin_sbc_decode_frame','pcm_converter_process','memory_output_submit','continuous_media_read','mh_source_entry','mh_boot_source','mh_request_command','ms_initializer_sync_bridge','mcs_event_begin','mcs_event_end']
    listings={};calls=[]
    for n in functions:
        s=e.named[n];require(e.mode(s['value'])=='a','selected compiled function is not ARM '+n);rows=[]
        for a in range(s['value'],s['value']+s['size'],4):
            if e.mode(a)!='a':continue
            data=e.read(a,4);ins=list(md.disasm(data,a));require(len(ins)==1,'undecodable selected A32 instruction')
            ins=ins[0];row=dict(pc=hex(a),opcode=data.hex(),mnemonic=ins.mnemonic,operands=ins.op_str)
            rows.append(row)
            if ins.mnemonic=='bl' and ins.op_str.startswith('#'):
                target=int(ins.op_str[1:],0);calls.append(dict(function=n,pc=hex(a),opcode=data.hex(),continuation=hex(a+4),target=hex(target),target_symbol=names.get(target)))
        listings[n]=dict(entry=hex(s['value']),size=s['size'],sha256=hashlib.sha256(e.read(s['value'],s['size'])).hexdigest(),original_ELF_opcode_rows=rows)
    expected_edges=[('aas_packet_process','media_queue_callback'),('owned_media_consume','owned_packet_parse'),('owned_media_consume','memory_output_submit'),('owned_media_consume','mcs_event_begin'),('owned_media_consume','mcs_event_end'),('owned_packet_parse','owned_media_submit_frame'),('owned_media_submit_frame','garmin_sbc_decode_frame'),('owned_media_submit_frame','pcm_converter_process')]
    for a,b in expected_edges:require(any(x['function']==a and x['target']==hex(e.named[b]['value']) for x in calls),'missing compiled call '+a+'->'+b)
    require(sum(x['function']=='owned_media_consume' and x['target']==hex(e.named['memory_output_submit']['value']) for x in calls)==1,'whole-packet single submit call site')
    require(not any(x['function']=='owned_media_submit_frame' and x['target']==hex(e.named['memory_output_submit']['value']) for x in calls),'per-frame FIFO publication')
    header=(BASE/'compressed_input_fixtures_v1.h').read_text();arrays={n:bytes(int(x,16) for x in re.findall(r'0x([0-9a-fA-F]{2})\b',data)) for n,data in re.findall(r'static const uint8_t\s+(\w+)\[\]\s*=\s*\{(.*?)\};',header,re.S)}
    packet_rows=[]
    for stream in reference['streams']:
        i=stream['index'];require(len(stream['packets'])==6,'stream fixture count')
        for j,p in enumerate(stream['packets']):
            b=bytes.fromhex(p['packet_hex']);require(arrays['mp_s%d_p%d'%(i,j)]==b,'compiled/reference compressed mismatch')
            frames=packet_frames(b);require(len(frames)==2 and all(f['rate']==stream['rate'] and f['channels']==stream['channels'] for f in frames),'typed frame formats')
            for key in ['expected_continuous_PCM_hex','expected_after_reset_PCM_hex']:require(0<len(bytes.fromhex(p[key]))<=512,'HOST comparison output bound')
            packet_rows.append(dict(stream=i,packet=j,bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),frames=frames))
        bad=bytes.fromhex(stream['bad_later_frame_CRC_packet_hex']);require(arrays[stream['bad_CRC_name']]==bad,'compiled bad CRC fixture')
        normal=bytes.fromhex(stream['packets'][4]['packet_hex']);frames=packet_frames(bad)
        diffs=[k for k in range(13,len(normal)) if normal[k]!=bad[k]]
        require(diffs==[frames[1]['crc_offset']] and normal[diffs[0]]^bad[diffs[0]]==1,'bad input is not solely later SBC CRC byte xor1')
        packet_rows.append(dict(stream=i,bad_second_frame_CRC=True,payload_differences=diffs,first_frame_identical=True,frames=frames))
    typed=BASE/'owned_media_typed_v2.c';source=BASE/'mixer_source_sbc_v1.c';queue=ROOT/'staging/native-owned-media/owned_queue.c';runner=BASE/'emulate_sbc_sync_v1.py'
    anchors=[anchor(typed,x) for x in ['mcs_event_begin(g,g->generation','int result=owned_packet_parse','int ticket=memory_output_submit','tickets[owned_media_control.write]','if (result) { owned_media_control.failed++','mcs_event_end(g,&borrow)','slot->in_flight++','slot->in_flight--;slot->reads++','media_worker_state.tcb']]
    anchors+=[anchor(source,x) for x in ['int r=aas_packet_process','uint32_t bits=WAIT();(void)bits;','if(command){','r=((int (*)(uint32_t,uint32_t))0x3b9b67u)','if(r!=DECODER_CODEC_ERROR)','POST(mh_source_tcb,1u)']]
    anchors+=[anchor(queue,x) for x in ['media_queue_control.producer_busy = 1','memcpy(slots[slot], packet, length)','media_queue_control.count++','int result = media_queue_control.consume','if (!ready)']]
    anchors+=[anchor(runner,x) for x in ['if number == 9:','published[\'owned\'][4]','[0, 0xFFFFFFFA]','expected_after_reset_PCM_hex','if number == 8:','decoder_cursor','explicit output consumer advances']]
    av=load(ROOT/'evidence/firmware-analysis/avdtp-media-dispatch-emulation.json');require(av['stock_sha256']==EXPECTED_MAIN and av['callback_veneer']=='0x42758e','old original receiver proof identity')
    with (ROOT/'evidence/firmware-analysis/main_02bd.bin').open('rb') as f:
        f.seek(0x42758e-0x50000);require(f.read(2)==b'\x38\x47','original BX R7 bytes')
    result=dict(all_passed=True,review_kind='PURE FILE static build/source/opcode/typed-input contract; no VM import or execution',created_utc=datetime.now(timezone.utc).isoformat(),source_sha256=deps,
        build_sha256=deps[rel(BASE/'build-v3.json')],ELF_sha256=build['ELF_sha256'],runner_sha256=deps[rel(runner)],MAIN_sha256=EXPECTED_MAIN,
        verified_file_assertions=dict(build_sources_and_snapshots=47,compile_receipts=21,compiled_function_opcode_ranges=len(listings),normal_packets=18,bad_second_CRC_packets=3,per_frame_FIFO_submit_calls=0,whole_packet_FIFO_submit_call_sites=1,control_bytes=52),
        ELF_segments=e.segments,compiled_functions=listings,compiled_direct_calls=calls,source_anchors=anchors,typed_input_packets=packet_rows,
        source_pipeline=['Source only aas_packet_process copies complete declared packet into preallocated queue slot with producer_busy and epoch check','media_queue_step preserves queued packet on output DEFERRED and invokes registered owned_media_consume only when a free PCM slot exists','owned_media_consume checks actual actor, R+160 callback coherence, typed media/callback leases before original compiled parser','actual libsbc decode and integer FIR per frame only append private gather; complete parse success and current epoch/lease/callback are required before one whole-packet submit','memory_output_submit copies under COPYING lease; ticket becomes locally consumable only after post-copy current-state check, otherwise memory_output_discard','native selected reader holds complete original pull media/callback leases; per-copy in_flight keeps FIFO slot until unlocked copy completes; FIFO generation is distinct from native session epoch'],
        ABI=dict(callback=dict(r0='event F1',r1='status0',r2='temporary handle ignored, not retained',r3='packet bytes',stack_word0='length'),decode=dict(r0='input frame',r1='frame bytes',r2='private512-byte source PCM',r3='capacity512',stack_word0='decoder_result pointer36B'),converter=dict(r0='S16 source samples',r1='samples per channel',r2='private converted PCM',r3='capacity256',stack_word0='written byte count pointer'),submit=dict(r0='private gather',r1='whole packet converted bytes<=3840')),
        negative_controls_contract=dict(second_frame_CRC='Successful first decoder return0 and second return-6; committed/count/lastticket/packet_index unchanged, no published PCM prefix. First gather bytes/stats may change speculatively. Codec/FIR reset before recovery.',Stop='Queue running0/epoch changed rejects new copy before decoder; no new commit/ticket/input index. Current runner compares decoder count and commit/lastticket; future proof should additionally independently check queue-enqueued, FIFO payload/ticket states.',profile='Original277D26 profile1 return10 then profile0 return0 rewrites R+160/list; next consume rejects before decoder when R+160 is no longer mcs_queue_bridge. Packet copy may already have occurred.',recovery='Expected after-reset HOST reference is compared only; no expected bytes seed guest.'),
        original_receiver_reuse=dict(proof='evidence/firmware-analysis/avdtp-media-dispatch-emulation.json',entry=av['incoming_l2cap_handler'],LCID_lookup=av['lcid_lookup'],callback_veneer=av['callback_veneer'],callback_veneer_opcode='3847',local_sep=av['local_sep'],callback_abi=av['callback_abi'],original_handler_releases_mutex_before_callback=True,real_endpoint_registration_verified=False,previous_endpoint_channel_context_and_mutex_fixtures_preserved=True),
        next_receiver_contract=dict(new_source_required=True,current_build_receiver_integrated=False,current_source_WAIT_bits_ignored=True,current_compressed_input='compiled arrays, not live phone or dispatch callback',missing=['copy-only receiver ABI entry, using session/media/callback admission covering complete input copy; never retain original temporary handle or borrowed packet pointer','after successful queue metadata publication POST mh_source_tcb event1 from actual receiver actor; preserve packet enqueue result','Source WAIT event service drains media_queue_step until EMPTY, DEFERRED, Stop or bounded fairness budget; do not require mh_command to process media','on FIFO capacity freed POST this actual Source TCB; existing media_worker_state.tcb remains zero and its notify path is not connected','recheck admission generation, running epoch and R+160 coherence before decode/commit; deny new ingress after Stop or profile mutation','recover actual native SEP registration/channel/current callback publication and receiver TCB lifetime before claiming Bluetooth acceptance'],potential_existing_ingress_API_issue='aas_packet_process is not a cross-actor admission API: it copies before owned_media_consume actor/coherence rejection. Future receiver must split queue enqueue from Source-only step and acquire typed ingress leases.'),
        remaining_fixtures=['three compressed offline fixture streams and corrupted second-frame input, with HOST reference PCM only for comparisons','bounded16KiB codec arena/free no-op, single decoder; not native malloc','opaque original audio handle allocation/query/release, mixer stack/FIFO backing, task construction bookkeeping and audio priority/name services','direct declared Timer/rawmutex/condition cold calls, controller/idle initial descriptor and ready membership inputs','guest-only native call-site BL redirects and veneers; original MAIN file unchanged','hardware activation/output mode and output consumer read-index advance after complete original returns; no DMA/DAC or physical backing','command16 reset request transport and compiled synthetic message17 reset-complete input; no real hardware ACK or STOP_DONE'],
        runtime_next_required_guards=['whole joint CPU+fixture event replay of all real RW zones and unchanged RX sentinels','actual Source TCB/normal System mode and producer media+callback leases through full parser/decoder/converter/submit returns','all packet bytes copied by CPU before queue publication; no transient handle retained','second-frame CRC failure: no memory_output_submit call, no FIFO/ticket/count/lastticket/packet-index mutation; actual first frame0/second-6 return with SP restored','success: single complete gather publication matches actual native reader/mixer bytes, leases held until whole original pull and outer return','Stop and original profile rewrite deny new decoder/FIR work and commit, with prior slots/storage retained rather than false quiescence','capacity DEFERRED does not advance codec/FIR or remove pending queue slot; future Source event retry needed','native raw wait/contention/ACK8 full-return and donation fields checked only at exact synchronization intervals; later mixer timed waits may legitimately update F0909C'],
        limits=['Static opcode/source/typed-input review only. No static CFG is promoted to executed proof; no fresh guest or device operation by reviewer.','Symbol-sized opcode rows skip ELF $d pools and are bounded instruction listings, not exhaustive recursive CFG.','Parser submitted_frames/submitted_pcm_bytes count speculative successful frames before whole-packet publication; these counters are not FIFO commit or audible output evidence.','Code remains single serialized Source producer/single mixer consumer, storage pinned. No full Bluetooth receive registration/event loop, fragmentation/reorder/jitter handling or native exclusivity.','Compiled command handlers discard some send_mixer returns; actual message insertion/full native returns must be checked in bounded runtime; this is not a robust production command API.','No complete player image, App/UI/install/VPM/SIG acceptance, physical speaker/hardware, native allocator, STOP_DONE, exclusive ownership or safe unload is established.'],
        concrete_bounded_run_source_blocker_found=False,guest_executed_by_reviewer=False,complete_player_verified=False,phone_AVDTP_receiver_verified=False,device_io=False)
    write(OUT,result)
    print(json.dumps(dict(all_passed=True,output=rel(OUT),sha256=sha(OUT),sources=len(deps),ELF_sha256=build['ELF_sha256'],guest_executed=False)))

if __name__=='__main__':main()
