#!/usr/bin/env python3
"""Exact static font-record/context/parser stream ownership supplement.

Never imports or runs the mutable root candidate or any emulator. Records
that candidate as a new exclusive source snapshot for scoped static review.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import ast
from datetime import datetime, timezone
import hashlib
import json

ROOT=Path('/root/garmin')
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from analyze_native_vpm_acceptance_path import RuntimeImage
from analyze_sdp_activation import trace

OUT=Path(__file__).with_name('font-stream-owner-supplement.json')
CANDIDATE='scripts/probe_native_controller_gir_component.py'
AUDIT='staging/native-player-controller-gir-integration/previous-audit.json'
PRIOR='staging/native-player-controller-gir-integration/resource-static/font-provider-SQL-peer-review.json'
PRIOR_SHA='7b89cc86999a49b61824e67e0c054fff8f15fe09bcb57bb2bf96d6b13aad962f'
ENTRIES=(0x4de236,0x4ddbc2,0x4de0e0,0x26707a,0x266fc4,
    0x2654e4,0x2648c8,0x14f084,0x264d80)


def require(ok,why):
    if not ok:raise ValueError(why)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def sha(path):return digest((ROOT/path).read_bytes())


def check(registry):
    for path,wanted in registry.items():require(sha(path)==wanted,'Frozen dependency changed '+path)


def main():
    require(not OUT.exists(),'Preserve prior supplement')
    require('unicorn' not in sys.modules,'Static analysis must not import emulator modules')
    require(sha(PRIOR)==PRIOR_SHA,'Frozen resource peer review changed')
    protected=json.loads((ROOT/AUDIT).read_text())['protected_sources']
    require(len(protected)==608,'Expected previous immutable608 registry')
    check(protected)
    candidate=(ROOT/CANDIDATE).read_bytes(); candidate_sha=digest(candidate)
    syntax=ast.parse(candidate.decode())
    cls=next(n for n in syntax.body if isinstance(n,ast.ClassDef) and n.name=='ControllerGIRVM')
    candidate_methods=[]
    for name in ['map_verified_file_destination','observe','verify_component_memory']:
        node=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name==name)
        code='\n'.join(candidate.decode().splitlines()[node.lineno-1:node.end_lineno])+'\n'
        candidate_methods.append(dict(name=name,line=node.lineno,end_line=node.end_lineno,
            source=code,method_sha256=digest(code.encode())))
    snapshot=OUT.with_name('root-candidate-review-'+candidate_sha[:16]+'.py')
    require(not snapshot.exists(),'Candidate snapshot already exists')
    im=NativeImage(); image=RuntimeImage(im); functions={}
    for entry in ENTRIES:
        graph=trace(image,entry,2000)
        require(not graph['instruction_limit_reached'],'Static CFG exhausted '+hex(entry))
        for row in graph['instructions']:
            address=int(row['address'],16)
            ins=next(image.md.disasm(image.read(address,4),address,count=1))
            row['bytes']=ins.bytes.hex();row['load_address']=hex(im.runtime_to_load(address,ins.size))
        graph['intrafunction_only_not_transitive_closure']=True
        functions[hex(entry)]=graph
    wanted={
        0x4de242:'str r0, [r5]',0x4de258:'bl #0x4ddbc2',0x4ddbe8:'str r0, [r4]',
        0x4de0ec:'lsls r1, r4, #6',0x4de0f2:'muls r5, r4, r5',0x4de0fc:'str r0, [r1, #4]',
        0x4de1e8:'ldr r0, [r0, r5]',0x4de1ea:'movs r1, r7',0x4de1f0:'bl #0x26707a',
        0x26707c:'movs r4, r0',0x26708e:'movs r0, r4',0x267090:'bl #0x266fc4',
        0x2654e6:'movs r5, r0',0x2654e8:'movs r0, #0x98',0x2654f6:'bl #0x2645c6',
        0x2654fa:'movs r4, r0',0x26551e:'bl #0x14f034',0x265524:'str r0, [r4, #8]',
        0x265526:'beq #0x2655f4',0x2648ca:'movs r4, r1',0x26492c:'ldr r1, [r4, #8]',
        0x26492e:'ldr r0, [sp, #4]',0x264934:'bl #0x14f084',0x14f088:'movs r5, r0',
        0x14f08e:'movs r3, r1',0x14f096:'bl #0x14098c',
        0x264d88:'ldr r1, [r1, #8]',0x264d92:'bl #0x14f050'}
    assertions=[]
    for address,expected in wanted.items():
        ins=next(image.md.disasm(image.read(address,4),address,count=1))
        require(ins.mnemonic+' '+ins.op_str==expected,'Original ownership instruction differs '+hex(address))
        assertions.append(dict(address=hex(address),bytes=ins.bytes.hex(),instruction=expected))
    literals=[]
    for address,expected in {0x4de23a:0x14b4014,0x4de23c:0x14b3fb8,
        0x4de248:0xf071e8,0x4de0e8:0x14b3c60,0x4de0f4:0x14b4014,0x4de1e4:0x14b4014}.items():
        ins=next(image.md.disasm(image.read(address,4),address,count=1))
        pool=((address+4)&~3)+ins.operands[1].mem.disp
        require(image.word(pool)==expected,'Font pointer literal differs')
        literals.append(dict(site=hex(address),instruction=ins.mnemonic+' '+ins.op_str,
            pool=hex(pool),value=hex(expected)))
    with snapshot.open('xb') as f:f.write(candidate)
    dependencies={str(Path(__file__).relative_to(ROOT)),str(snapshot.relative_to(ROOT)),AUDIT,PRIOR,
        'scripts/analyze_native_sections.py','scripts/analyze_native_vpm_acceptance_path.py','scripts/analyze_sdp_activation.py',
        'scripts/emulate_native_player_text.py','scripts/emulate_native_player_external_fonts.py',
        'evidence/firmware-analysis/main_02bd.bin'}
    source_sha={path:sha(path)for path in sorted(dependencies)}
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        scope='Exact static pointer/offset provenance and pure-observation runtime guard proposal; no emulation',
        source_sha256=source_sha,protected_sources=protected,protected_count=len(protected),
        bounded_CFG_count=len(functions),functions=functions,exact_instructions=assertions,exact_pointer_literals=literals,
        original_font_record_provenance=dict(
            metadata='M(i)=14B3C60+64*i, i0..12',record='R(i)=14B4014+816*i',
            context='R(i)+0 contains context pointer C(i); do not assume parser layout in this context',
            context_publication='4DE242 stores C(0)=14B3FB8 into R(0)+0. For i1..12,4DE258 calls4DDBC2(R(i));4DDBE8 stores the allocated native context into R(i)+0.',
            metadata_publication='4DE0EC shifts index by6;4DE0F2 multiplies index by330hex;4DE0FC stores M(i) into R(i)+4. TextVM.fonts source_metadata reads this exact word.',
            parser_context_argument='4DE1E8 loads C(i) from R(i)+0;4DE1EA r1=M(i);4DE1F0 calls26707A.26707C/26708E preserve/pass context to266FC4.',
            transitive_parser_call='Do not infer a full call closure from these bounded graphs; direct2654E4 entry can independently be observed and matched to C(i).'),
        original_parser_stream_record=dict(
            entry='2654E4 r0=C;2654E6 r5=C',allocation='2654E8 supplies98hex bytes;2654F6→2645C6;2654FA r4=P, parser record',
            open='26551E calls14F034(C,filename), original14093E/31D09A below',
            stream_publication='265524 STR r0,[r4,#8] stores H into P+8; next265526 is the BEQ after the originalstore and can be observed before its branch. H=0 means open failed; do not count as resident.',
            reader='2648C8 r0=C/r1=P saved in native frame;2648CA r4=P.26492C r1=word(P+8)=H,26492E r0=savedC atcurrentSP+4,264934→14F084.',
            read_ABI='14F084(r0=C,r1=H,r2=destination,r3=bytecount), with14F088 preservingC and14F08E forwardingH into original14098C.',
            lifetime='264D80(C,P) loads H atP+8 via264D88 and calls14F050/140936 close at264D92, then releases parser allocations. Resident endpoint must not invoke this destructor.'),
        pure_observation_sequence=[
            dict(site='4DE0FE, after4DE0FC',observe='r1=R(i),r0=M(i),word(R(i)+4)==M(i); derivedindex0..12; snapshot R(i)+0=C(i). No host pointer write.'),
            dict(site='2654E4',observe='Capture entryC=r0 and actual native call frame; find exactly one fresh R(i).context==C with source_metadata==M(i). Save per-controller parser frame; do not reset BSS.'),
            dict(site='265524 /265526',observe='Before native store capture r5=C,r4=P,r0=H and exact opcode. After at265526 require sameC/P andword(P+8)==H, positive live guarded98hex backing, exact unmodified native opcode, original opened external stream and active controller. H0 is failedopen, not resident. Preserve actual store event/read result.'),
            dict(site='14F084',observe='Capture C/H pluscaller/destination/count. ResidentH must match the observed265524 owner and exact fresh R(i).context/source_metadata; temporary classifierH may precede parser ownership and must be tracked/closed separately.'),
            dict(site='final initializer endpoint',observe='For external active indices0,1,2,7,8,9,10,12: unique residentH matching exact index/path/context/parser+8. No foreign/dangling/freed parser or unexpected stream owner; at least one14F084 C/H observation. Retain resident streams, contexts, module, raw provider and owner evidence for future callbacks.')],
        external_index_path={str(i):'006-D0952-'+suffix+'.bin'for i,suffix in
            [(0,'05'),(1,'06'),(2,'01'),(7,'07'),(8,'08'),(9,'02'),(10,'03'),(12,'04')]},
        font_endpoint=dict(active_indices=[0,1,2,3,4,5,7,8,9,10,12],inactive_indices=[6,11],
            successful_error='0',missing_error='66hex',current_record='F071F0==14B5004',
            source_metadata='Every R(i)+4==M(i), active C(i) live and nonzero; fresh pointers derive from original publications',
            context_stream_layout='P+8 is the parser stream, NOT C+8. P and C are separate native objects.'),
        root_candidate_static_review=dict(source=CANDIDATE,source_sha256_at_capture=candidate_sha,
            exclusive_snapshot=str(snapshot.relative_to(ROOT)),root_source_is_mutable_not_frozen_by_this_review=True,
            reviewed_methods=candidate_methods,
            scoped_findings=[
                '265526 post-store owner capture and fresh record.context/source_metadata correlation are valid pure observations when tied to the2654E4 original frame and live native parser backing.',
                'Provider mapped-page guard now validates a full span, but its all-handles/all-raw-allocations/all-stock.zeros fallback is storage provenance rather than font-specific ownership. Scope the input ledger accordingly, or narrow tofont_handles/controller stack/declaredfont buffers and exclude critical native objects.',
                'Final font inventory should verify active/missing flags/errors, expected index/path and F071F0; len13 and anymatchingcontext/source_metadata alone do not prove native font selection.',
                'No deterministic execution-blocking bug claimed for the captured candidate; this is static scope review, not a native run. Later root edits require independent hash/snapshot review.']),
        new_native_execution=False,emulator_imported=False,device_io=False,sounds_emitted=False,
        old_sources_artifacts_or_canonical_modified=False,physical_App_or_accepted_package_proof=False,
        limits='Bounds and native offset/argument assignments are exact MAIN static evidence. Proposed observations require a separate actual native run. This does not prove real FAT/font hardware I/O, live IRQ scheduling, complete renderer/UI, physical App, package acceptance or safe stream/module destruction.')
    check(protected);check(source_sha)
    with OUT.open('x',encoding='utf-8')as f:f.write(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(report=str(OUT.relative_to(ROOT)),sha256=digest(OUT.read_bytes()),
        candidate_sha256_at_capture=candidate_sha,protected=len(protected),CFGs=len(functions),
        instruction_checks=len(assertions),literal_checks=len(literals))))


if __name__=='__main__':main()
