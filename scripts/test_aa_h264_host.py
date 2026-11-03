#!/usr/bin/env python3
"""Real software H264 decoding versus independent ffmpeg, Linux host only."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'native/aa-h264'
STAGE=ROOT/'staging/android-auto-h264-host-v1'
PROOF=ROOT/'evidence/android-auto-h264-host-v1.json'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def nals(data):
    # Independent fixture split only; adapter itself receives arbitrary chunks.
    starts=list(re.finditer(b'\x00\x00(?:\x00)?\x01',data))
    return [data[m.end():starts[i+1].start() if i+1<len(starts) else len(data)].rstrip(b'\x00') for i,m in enumerate(starts)]
def annex(units):return b''.join(b'\x00\x00\x00\x01'+n for n in units)
def sps(width,height,profile=66,refs=1):
    bits=''
    def fixed(v,n):
        nonlocal bits;bits+=format(v,'0'+str(n)+'b')
    def ue(v):
        nonlocal bits;x=bin(v+1)[2:];bits+='0'*(len(x)-1)+x
    fixed(profile,8);fixed(0,8);fixed(30,8);ue(0)
    if profile==100:ue(1);ue(0);ue(0);fixed(0,1);fixed(0,1)
    ue(0);ue(0);ue(0);ue(refs);fixed(0,1);ue(width//16-1);ue(height//16-1)
    fixed(1,1);fixed(1,1);fixed(0,1);fixed(0,1);bits+='1';bits+='0'*((-len(bits))%8)
    raw=bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8));out=bytearray();zeros=0
    for b in raw:
        if zeros==2 and b<=3:out.append(3);zeros=0
        out.append(b);zeros=zeros+1 if b==0 else 0
    return b'\x67'+out
def main():
    manifest=json.loads((STAGE/'build.json').read_text())
    assert manifest['pass']
    for name,pin in manifest['source_sha256'].items():assert sha(ROOT/name)==pin,name
    for name,pin in manifest['wrapper_sha256'].items():assert sha(ROOT/name)==pin,name
    receipts=[];cases=[];fixtures=[];mismatches=[];env=dict(os.environ)
    env['ASAN_OPTIONS']='detect_leaks=1:halt_on_error=1';env['UBSAN_OPTIONS']='halt_on_error=1:print_stacktrace=1'
    def run(argv):
        start=time.monotonic();r=subprocess.run([str(a) for a in argv],cwd=ROOT,env=env,text=True,capture_output=True,timeout=120)
        record={'argv':[str(a) for a in argv],'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'elapsed_seconds':time.monotonic()-start}
        receipts.append(record);assert r.returncode==0,record;return r.stdout
    fixture_dir=STAGE/'fixtures';fixture_dir.mkdir(exist_ok=True)
    specifications=[('baseline-small',96,64,8,'baseline',0,0),('main-b-small',128,96,12,'main',2,0),
                    ('high-b-small',128,96,12,'high',3,0),('high-800x480',800,480,6,'high',2,1),
                    ('high-cropped',78,62,7,'high',2,0),
                    ('main-p-small',128,96,8,'main',0,0),('high-p-small',128,96,8,'high',0,0)]
    for name,w,h,count,profile,bframes,aud in specifications:
        bitstream=fixture_dir/(name+'.h264');reference=fixture_dir/(name+'.yuv')
        parameters='keyint=4:min-keyint=4:scenecut=0:aud='+str(aud)+':slices=2:bframes='+str(bframes)
        if profile=='baseline':parameters+=':cabac=0:8x8dct=0'
        if profile=='high':parameters+=':8x8dct=1'
        run(['ffmpeg','-y','-hide_banner','-loglevel','error','-f','lavfi','-i',f'testsrc2=size={w}x{h}:rate=12',
             '-frames:v',str(count),'-c:v','libx264','-threads','1','-preset','medium','-profile:v',profile,
             '-pix_fmt','yuv420p','-x264-params',parameters,'-f','h264',bitstream])
        run(['ffmpeg','-y','-hide_banner','-loglevel','error','-c:v','h264','-i',bitstream,
             '-f','rawvideo','-pix_fmt','yuv420p','-fps_mode','passthrough',reference])
        assert reference.stat().st_size==w*h*3//2*count
        units=nals(bitstream.read_bytes());profile_idc=next(n[1] for n in units if n[0]&31==7)
        assert profile_idc=={'baseline':66,'main':77,'high':100}[profile],(name,profile_idc)
        fixtures.append({'name':name,'bitstream':str(bitstream.relative_to(ROOT)),'bitstream_sha256':sha(bitstream),
                         'reference':str(reference.relative_to(ROOT)),'reference_sha256':sha(reference),
                         'width':w,'height':h,'frames':count,'profile_idc':profile_idc,'bframes_configured':bframes,
                         'nal_types':[n[0]&31 for n in units],'max_nal_bytes':max(map(len,units))})
    # Literal parameter-set controls: geometry validated before any AU decode.
    negative={
        'oversized-coded-816x480':(annex([sps(816,480)]),-2),
        'oversized-coded-800x496':(annex([sps(800,496)]),-2),
        'high-oversized-coded':(annex([sps(1920,1088,100)]),-2),
        'SPS-reference-count-over-16':(annex([sps(96,64,66,17)]),-2),
        'unsupported-SPS-profile':(annex([sps(96,64,88)]),-4),
        'truncated-SPS':(annex([b'\x67\x42']),-3),
        'forbidden-zero-bit':(annex([b'\x87\x80']),-3),
        'unsupported-AVCC-input':(b'\x00\x00\x00\x05\x67\x42',-3),
        'unsupported-extension-NAL':(annex([b'\x74\x80']),-4),
        'PPS-before-SPS':(annex([b'\x68\xce\x3c\x80']),-3),
        'slice-before-parameter-sets':(annex([b'\x65\xb8\x40']),-3),
        'bad-emulation-prevention':(annex([b'\x06\x00\x00\x03\x04\x80']),-3),
        'empty-final-startcode':(b'\x00\x00\x00\x01',-9),
        'split-partial-startcode-at-EOF':(b'\x00\x00',-9),
    }
    for name,(body,code) in negative.items():(fixture_dir/(name+'.h264')).write_bytes(body)
    for build in manifest['builds']:
        binary=STAGE/build['name']/'test_h264'
        flags=['-O2'] if build['name']=='ordinary' else ['-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer']
        run(['g++','-std=c++11','-Wall','-Wextra','-Werror','-pthread']+flags+
            ['-I'+str(BASE),BASE/'test_h264.cpp',ROOT/build['library'],'-o',binary])
        guards=json.loads(run([binary,'guards']));assert guards['pass'];cases.append({'build':build['name'],'name':'API-guards','result':guards})
        for fixture in fixtures:
            for chunk,pause in [(0,0),(1,1),(65535,1)]:
                output=STAGE/'decoded.yuv'
                result=json.loads(run([binary,'decode',ROOT/fixture['bitstream'],output,str(chunk),str(pause)]))
                assert result['status']==2 and result['frames']==fixture['frames'],(fixture['name'],result)
                assert (result['width'],result['height'])==(fixture['width'],fixture['height'])
                actual=output.read_bytes();oracle=(ROOT/fixture['reference']).read_bytes()
                exact=actual==oracle
                if not exact:
                    size=fixture['width']*fixture['height']*3//2
                    oracle_hashes=[hashlib.sha256(oracle[i:i+size]).hexdigest() for i in range(0,len(oracle),size)]
                    mismatch={'build':build['name'],'fixture':fixture['name'],'chunk':chunk,'pause':bool(pause),
                              'differing_bytes':sum(x!=y for x,y in zip(actual,oracle)),
                              'max_absolute_delta':max(abs(x-y) for x,y in zip(actual,oracle)),
                              'decoded_frame_oracle_indices':[oracle_hashes.index(h) if h in oracle_hashes else None
                                  for h in [hashlib.sha256(actual[i:i+size]).hexdigest() for i in range(0,len(actual),size)]]}
                    mismatches.append(mismatch)
                cases.append({'build':build['name'],'name':fixture['name'],'chunk':chunk,'pause_each_frame':bool(pause),
                              'result':result,'decoded_sha256':sha(output),'byte_exact_ffmpeg':exact})
        for name,(_,code) in negative.items():
            result=json.loads(run([binary,'decode',fixture_dir/(name+'.h264'),STAGE/'decoded.yuv','1','0']))
            assert result['status']==code and result['frames']==0,(name,result)
            cases.append({'build':build['name'],'name':name,'expected_error':code,'result':result})
        # NAL and AU caps exercise rejection of otherwise valid streams.
        small=fixtures[0]
        for name,nc,ac in [('NAL-limit',64,512),('AU-limit',small['max_nal_bytes'],small['max_nal_bytes']+4)]:
            result=json.loads(run([binary,'decode',ROOT/small['bitstream'],STAGE/'decoded.yuv','1','0','800','480',str(nc),str(ac)]))
            assert result['status']==-2,(name,result)
            cases.append({'build':build['name'],'name':name,'result':result})
    (STAGE/'decoded.yuv').unlink(missing_ok=True)
    paths=sorted(p for p in BASE.glob('*') if p.is_file())+[ROOT/'scripts/build_aa_h264_host.py',Path(__file__).resolve()]
    proof={'schema':'android-auto-h264-host-v1','pass':not mismatches,
           'bounded_wrapper_and_api_controls_pass':True,'partial_pass':bool(mismatches),
           'ffmpeg_byte_exact_all_fixtures':not mismatches,'comparison_mismatches':mismatches,
           'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in paths},'upstream_source_sha256':manifest['source_sha256'],
           'source':manifest['source'],'build_manifest_sha256':sha(STAGE/'build.json'),
           'actual_subprocess_receipts':receipts,'builds':manifest['builds'],'cases':cases,'case_count':len(cases),'fixtures':fixtures,
           'context_bytes':None,'workspace_formula':'2*max_nal_bytes+4+max_au_bytes+max_width*max_height*3/2',
           'OpenH264_internal_heap_fully_instrumented':False,'allocation_cap_proven':False,'real_time_performance_proven':False,
           'device_IO':False,'native_guest_executed':False,'ARM_crosscompile':False,'original_Garmin_code_executed':False,
           'Pixel_Android_Auto_compatibility_proven':False,'installed_on_Garmin':False,'TLS_control_provider_executed':False,
           'scope':'Ordinary Linux host OpenH264 decoder, arbitrary Annex-B stream chunks, bounded own wrapper buffers and dimensions; not Garmin-installable.',
           'policy':{'profiles':[66,77,100],'chroma':'progressive 8-bit YUV420 only','coded_dimension_cap':'<=configured 800x480 maximum',
                     'FMO_ASO_interlace_SVC_MVC_AVCC':'unsupported; terminal, no guessed resync','max_sps_reference_frames':16,
                     'error_concealment':False,'decoder_threads':0,'output':'copied packed planes; PAUSED owned stable; no re-decode on retry',
                     'timestamp':'first VCL NAL first chunk timestamp passed to codec; no current Pixel PTS guarantee'}}
    PROOF.write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'pass':not mismatches,'bounded_wrapper_and_api_controls_pass':True,
                      'partial_pass':bool(mismatches),'comparison_mismatch_count':len(mismatches),
                      'case_count':len(cases),'fixtures':len(fixtures),'real_reference_frames':sum(f['frames'] for f in fixtures),
                      'proof':str(PROOF.relative_to(ROOT)),'proof_sha256':sha(PROOF)},indent=2))
if __name__=='__main__':main()
