#!/usr/bin/env python3
"""Verify ARMv6 conversion with mathematical/signal invariants, offline.

Expected values use a stateless convolution evaluated at absolute output
positions, independently of the C history/phase/countdown implementation.
Signal checks measure actual emulated output; no Garmin/Bluetooth I/O.
"""
from datetime import datetime, timezone
import hashlib
import json
import math
import random
import struct

from analyze_native_sections import ROOT
from emulate_native_sbc import (Machine, INPUT_PAGE, OUTPUT_PAGE, RESULT_PAGE,
                                PAGE_BYTES, verify_guard_faults)

BUILD=ROOT/'staging/native-pcm-converter'


class Converter(Machine):
    def reset(self,rate,channels):
        status=self.call('pcm_converter_reset',(rate,channels))
        if status==0: self.channels=channels
        return status

    def process(self,pcm,frames=None,cap=None,null_input=False,null_output=False,null_result=False):
        if frames is None: frames=len(pcm)//(2*self.channels)
        if cap is None: cap=frames*2
        if len(pcm)>PAGE_BYTES-32 or not 0<=cap<=PAGE_BYTES-32:
            raise ValueError('PCM outside guarded test capacity')
        source=INPUT_PAGE+PAGE_BYTES-len(pcm)
        output=OUTPUT_PAGE+PAGE_BYTES-cap
        result=RESULT_PAGE+PAGE_BYTES-4
        for page in (INPUT_PAGE,OUTPUT_PAGE,RESULT_PAGE): self.uc.mem_write(page,b'\xa5'*PAGE_BYTES)
        if pcm: self.uc.mem_write(source,pcm)
        status=self.call('pcm_converter_process',
            (0 if null_input else source,frames,0 if null_output else output,cap),
            fifth=0 if null_result else result)
        written=struct.unpack('<I',self.uc.mem_read(result,4))[0] if not null_result else 0
        if written>cap: raise ValueError('Converter reports output beyond capacity')
        if bytes(self.uc.mem_read(output-32,32))!=b'\xa5'*32 or bytes(self.uc.mem_read(result-32,32))!=b'\xa5'*32:
            raise ValueError('Converter changed leading guard')
        if bytes(self.uc.mem_read(output+written,cap-written))!=b'\xa5'*(cap-written):
            raise ValueError('Converter changed unwritten output suffix')
        if status<0 and bytes(self.uc.mem_read(OUTPUT_PAGE,PAGE_BYTES))!=b'\xa5'*PAGE_BYTES:
            raise ValueError('Rejected conversion produced output')
        return status,bytes(self.uc.mem_read(output,written)) if written else b''


def sample_bytes(values): return struct.pack('<'+'h'*len(values),*values)
def unpack(pcm): return struct.unpack('<'+'h'*(len(pcm)//2),pcm)
def sha(data): return hashlib.sha256(data).hexdigest()


def arithmetic_mean(values,channels):
    if channels==1: return list(values)
    return [int((values[n]+values[n+1])/2) for n in range(0,len(values),2)]


def expected_convolution(values,rate,channels,tables):
    mono=arithmetic_mean(values,channels)
    if rate==16000: return sample_bytes(mono)
    count=(len(mono)*16000+rate-1)//rate; output=[]
    for n in range(count):
        position=(n*rate)//16000
        phase=((n*441)%160) if rate==44100 else 0
        kernel=tables[str(rate)][phase]
        value=sum(mono[position-j]*weight for j,weight in enumerate(kernel) if position>=j)
        rounded=(abs(value)+16384)//32768
        if value<0: rounded=-rounded
        output.append(max(-32768,min(32767,rounded)))
    return sample_bytes(output)


def stream(machine,values,rate,channels,sizes=(1,7,16,31,64,128)):
    if machine.reset(rate,channels)!=0: raise ValueError('Converter reset failed')
    chunks=[]; position=0; n=0; frames=len(values)//channels
    while position<frames:
        size=min(sizes[n%len(sizes)],frames-position)
        raw=sample_bytes(values[position*channels:(position+size)*channels])
        status,output=machine.process(raw)
        if status!=0: raise ValueError('Valid conversion rejected')
        chunks.append(output); position+=size; n+=1
    return b''.join(chunks),n


def tone(frames,rate,frequency,channels=2,amplitude=12000):
    result=[]
    for n in range(frames): result.extend([round(amplitude*math.sin(2*math.pi*frequency*n/rate))]*channels)
    return result


def main():
    manifest=json.loads((BUILD/'manifest.json').read_text())
    for source,digest in manifest['source_sha256'].items():
        if sha((ROOT/source).read_bytes())!=digest: raise ValueError('Converter source changed: '+source)
    metadata=json.loads((ROOT/manifest['coefficient_table']).read_text()); tables=metadata['tables']
    # Run fault controls before retaining the long-lived converter engine.
    # With this Unicorn2.1 build, faulting/disposing short ARM engines after
    # constructing it caused a reproducible host segfault on its first call.
    # This order matches the previously verified decoder test harness.
    fault_controls=verify_guard_faults(); machine=Converter(manifest)
    if machine.process(sample_bytes([1,2]),frames=1)[0]!=-22:
        raise ValueError('Uninitialized converter not rejected')
    rng=random.Random(1352); cases=[]
    for rate in (16000,32000,44100,48000):
        for channels in (1,2):
            values=[rng.randint(-32768,32767) for _ in range(1024*channels)]
            actual,calls=stream(machine,values,rate,channels)
            expected=expected_convolution(values,rate,channels,tables)
            if actual!=expected: raise ValueError(f'Convolution disagreement at {rate}/{channels}')
            uniform,uniform_calls=stream(machine,values,rate,channels,(128,))
            if actual!=uniform: raise ValueError('Chunk boundaries changed the stream')
            samples=(1024*16000+rate-1)//rate
            if len(actual)!=samples*2: raise ValueError('Rational sample count incorrect')
            cases.append({'source_rate':rate,'channels':channels,'input_sample_frames':1024,
                          'output_samples':samples,'mixed_chunk_calls':calls,
                          'uniform_chunk_calls':uniform_calls,'pcm_sha256':sha(actual),
                          'absolute_position_convolution_byte_identical':True,
                          'chunk_boundary_invariant':True,'passed':True})
    signals=[]
    for rate in (44100,48000):
        for frequency in (1000,6000,10000,12000):
            values=tone(4096,rate,frequency)
            actual,_=stream(machine,values,rate,2,(128,))
            # Drop initial filter transient. RMS measures total emitted energy,
            # including alias leakage and phase-dependent spurious components.
            output=unpack(actual)[64:]
            rms=math.sqrt(sum(x*x for x in output)/len(output))
            gain=20*math.log10(rms/(12000/math.sqrt(2))) if rms else None
            if frequency<=6000 and (gain is None or not -.2<=gain<=.2):
                raise ValueError(f'Passband tone changed amplitude: {rate}/{frequency}: {gain}')
            if frequency>=10000 and gain is not None and gain> -55:
                raise ValueError(f'Insufficient stopband rejection: {rate}/{frequency}: {gain}')
            signals.append({'rate':rate,'input_hz':frequency,'output_rms_gain_db':gain,
                            'output_rms_s16_units':rms,'output_exactly_zero':not bool(rms),
                            'measurement':'Actual emulated output, transient excluded',
                            'requirement':'within0.2dB' if frequency<=6000 else 'below-55dB',
                            'passed':True})
    # Exactly one second exercises all 160 rational phases repeatedly and
    # establishes count conservation without per-frame rounding drift.
    drift,_=stream(machine,[0]*(44100*2),44100,2,(128,))
    if len(drift)!=32000 or any(drift): raise ValueError('One-second rate count/silence failed')
    # Stereo separation/downmix expectations independent of FIR reference.
    opposite=[]
    for n in range(512):
        value=(n*173)%30000; opposite.extend([value,-value])
    antiphase,_=stream(machine,opposite,48000,2)
    if any(antiphase): raise ValueError('Opposite channels did not cancel')
    dc,_=stream(machine,[12345]*(1024*2),44100,2)
    if any(x!=12345 for x in unpack(dc)[64:]): raise ValueError('Normalized DC gain changed')
    minimum,_=stream(machine,[-32768]*128,16000,1)
    maximum,_=stream(machine,[32767]*128,16000,1)
    if minimum!=sample_bytes([-32768]*128) or maximum!=sample_bytes([32767]*128):
        raise ValueError('16kHz bypass clipped or changed extrema')
    clipping=[]
    for sign,wanted in [(1,32767),(-1,-32768)]:
        values=[0]*97
        for j,weight in enumerate(tables['32000'][0]):
            values[96-j]=32767 if (weight>=0)==(sign>0) else -32768
        actual,_=stream(machine,values,32000,1,(128,))
        expected=expected_convolution(values,32000,1,tables)
        if actual!=expected or unpack(actual)[-1]!=wanted:
            raise ValueError('FIR overshoot wrapped instead of saturating')
        clipping.append({'target_extreme':wanted,'last_output_sample':unpack(actual)[-1],
                         'signed_coefficient_extrema_input':True,'passed':True})
    guards=[]
    input_pcm=sample_bytes([100,-100]*32)
    for name,kwargs,error in [
        ('small_capacity',{'cap':1},-23),('over_128_frames',{'frames':129},-21),
        ('null_input',{'null_input':True},-21),('null_output',{'null_output':True},-21),
        ('null_written',{'null_result':True},-21)]:
        machine.reset(44100,2)
        status,out=machine.process(input_pcm,**kwargs)
        if status!=error or out: raise ValueError('Bad conversion arguments accepted: '+name)
        status,recovered=machine.process(input_pcm)
        machine.reset(44100,2); _,clean=machine.process(input_pcm)
        if status!=0 or recovered!=clean: raise ValueError('Rejected call advanced stream: '+name)
        guards.append({'name':name,'returned':error,'recovery_matches_clean_reset':True,'passed':True})
    for rate,channels in [(22050,2),(44100,0),(48000,3)]:
        if machine.reset(rate,channels)!=-20: raise ValueError('Bad format accepted')
        guards.append({'name':f'bad_format_{rate}_{channels}','returned':-20,'passed':True})
    machine.reset(48000,2)
    if machine.process(b'',frames=0,cap=0)!=(0,b''): raise ValueError('Empty chunk failed')
    guards.append({'name':'empty_chunk','returned':0,'passed':True})
    report={'updated_utc':datetime.now(timezone.utc).isoformat(),
            'build_manifest':'staging/native-pcm-converter/manifest.json',
            'elf_sha256':manifest['elf_sha256'],'configuration_cases':cases,
            'configuration_count':len(cases),'signal_cases':signals,
            'guard_cases':guards,'guard_page_fault_controls':fault_controls,
            'one_second_44100_input_frames':44100,'one_second_output_samples':16000,
            'antiphase_stereo_silent':True,'dc_gain_exact_after_transient':True,
            '16000_mono_bypass_extrema_preserved':True,'all_passed':True,
            'fir_saturation_cases':clipping,
            'unmapped_end_pages_and_leading_canaries':True,
            'memory_hooks_used_for_bounds_claims':False,
            'instructions_executed_total':machine.total_instructions,
            'device_io':False,'audible_output':False,
            'native_avdtp_sbc_pcm_integration_verified':False,
            'native_on_device_verified':False,'real_time_performance_measured':False,
            'source_urls':manifest['sources'],
            'limitations':'Standalone ARMv6 converter with synthetic in-memory PCM only. Absolute-position convolution uses the generated Q15 table, not a second C streaming implementation. Chunk invariance, count/DC/extrema/downmix and actual-output spectral tests support local arithmetic and filtering only. No SBC/AVDTP/native module/stock PCM integration, real scheduling, hardware sample clock, navigation concurrency or audible device output verified. Causal filter uses initial zeros and does not flush its tail. Observed tone rejection is not an exhaustive frequency/noise characterization.'}
    path=ROOT/'evidence/firmware-analysis/native-pcm-converter-emulation.json'
    path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'output':str(path),'configurations':len(cases),
                      'signal_cases':len(signals),'guard_cases':len(guards),
                      'one_second_output_samples':16000,'all_passed':True,'device_io':False}))


if __name__=='__main__': main()
