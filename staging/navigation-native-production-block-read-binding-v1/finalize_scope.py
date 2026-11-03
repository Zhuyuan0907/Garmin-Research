#!/usr/bin/env python3
"""Host-only witness audit and seal. Does not open MAIN or IMG."""
from pathlib import Path
import hashlib
import json
import os
import sys
import time

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
    s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def put(name,value):
    p=HERE/name;assert not p.exists();p.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n')

def prepare():
    ledger=json.loads((HERE/'read-ledger.json').read_bytes())
    assert ledger['bytes']==2856 and ledger['bytes']<=32768
    assert stat(ROOT/'evidence/firmware-analysis/main_02bd.bin')==ledger['MAIN_stat']
    pins=json.loads((HERE/'input-bindings.json').read_bytes())
    for pin in pins['files']:
        p=ROOT/pin['path'];b=p.read_bytes()
        assert len(b)==pin['bytes'] and sha(b)==pin['sha256'] and stat(p)==pin['stat']
    rows={};captures=[]
    def add(row,path):
        row=dict(row);a=int(row['address'],16)
        if 'instruction' in row:
            row['mnemonic'],_,row['operands']=row.pop('instruction').partition(' ')
        row['source_path']=path
        if a in rows:assert rows[a]['bytes']==row['bytes'],hex(a)
        rows[a]=row
    old='staging/navigation-native-ap-mount-registry-binding-v1/windows-type1read.json'
    for path in [ROOT/old]+sorted(HERE.glob('windows-*.json')):
        d=json.loads(path.read_bytes())
        for w in d['windows']:
            assert sha(bytes.fromhex(w['raw_hex']))==w['sha256']
            for r in w['instructions']:add(r,str(path.relative_to(ROOT)))
    reused=json.loads((HERE/'reused-primary-functions.json').read_bytes())
    for fn in reused['functions'].values():
        for r in fn['instructions']:add(r,str((HERE/'reused-primary-functions.json').relative_to(ROOT)))
    for batch in ledger['batches']:
        p=ROOT/batch['path'];b=p.read_bytes();assert sha(b)==batch['sha256']
        d=json.loads(b);assert d['MAIN_stat_before']==d['MAIN_stat_after']==ledger['MAIN_stat']
        captures.append(dict(path=batch['path'],sha256=sha(b),readbytes=d['explicit_read_bytes'],operations=d['explicit_read_operations']))
    assert sum(x['readbytes']for x in captures)==2856
    def witness(name,addresses,meaning):
        return dict(name=name,instructions=[rows[a]for a in addresses],meaning=meaning,
            static_primary_bytes=True,all_instructions_not_claimed_executed=True)
    witnesses=[
      witness('True drive lowerops assignment and caller argument',[
        0x3fe806,0x3fe808,0x3fe80a,0x3fe80e,0x3fe810,0x3fe828,0x3fe82a,0x3fe82c,0x3fe82e,0x3fe830,
        0x24e83a,0x24e840,0x24e870,0x24e872,0x24e880,0x24e892,0x24e89e,0x24e8a0,0x24e8a2,0x24e8a4,0x24e8a6],
        '24E8A0 stores original fourth argument r3 at drive+20. Caller 3FE830 supplies physical storage context+64; 64-byte drive slots are indexed through initialized F001A8. This identifies a real registered path, not live AP drive selection.'),
      witness('Registered lowerops read target and next-stage policy',[
        0x3feb1c,0x3feb1e,0x3feb3e,0x3feb40,0x3feb4c,0x3feb50,0x3feb52,0x3feb54,0x3feb56,
        0x3feb58,0x3feb5c,0x3feb70,0x3feb72,0x3feb8c,0x3feb8e,
        0x3feaf8,0x3feafa,0x3feafc,0x3feafe,0x1d84c8,0x1d84d6,0x1d84d8],
        '3FEB40 writes 3FEA37 to context+6C = lowerops+8. Context+8C is cached 1E2CCB when context+C4 is nonzero, otherwise copied raw context+C, whose original 1D84C4 provider writes 225B19. Live cache choice and initializer execution are unknown.'),
      witness('Production adapter physical-sector ABI and extent count',list(range(0x3a1456,0x3a1486,2)),
        'Original storage exponent at geometry+6 shifts remaining bytes to sectors. Count is min(requested sectors, extent+8 minus relative sector). BLX3A147E gets drive ordinal byte+1, extent physical sector+4 plus relative, count sectors, destination. Returned count must match. IMG 4K/8K exponent is a different layer.'),
      witness('Partition checks, count clamp, physical-sector translation',[
        0x3fea3c,0x3fea40,0x3fea42,0x3fea44,0x3fea46,0x3fea48,0x3fea4c,0x3fea4e,0x3fea50,0x3fea52,
        0x3fea54,0x3fea56,0x3fea58,0x3fea5a,0x3fea5e,0x3fea60,0x3fea62,0x3fea66,0x3fea68,
        0x3fea9c,0x3fea9e,0x3feaa0,0x3feaa2,0x3feaa4,0x3feaa8,0x3feaaa,0x3feaac,
        0x3feaae,0x3feab0,0x3feab2,0x3feab4,0x3feab6],
        '3FEA36 accepts ordinal<2; checks partition active, sector<count, storage identity and ready byte; clamps r1+r2 to partition count, then adds partition first sector and dispatches context+8C. The 32-bit addition has no separate carry check in this selected fragment. No literal 128MiB restriction appears here; this is not an exclusion of other storage/window restrictions.'),
      witness('SD block interface and runtime card capacity guard',[
        0x225b22,0x225b2e,0x225b30,0x225b34,0x225b38,0x225b40,0x225b48,
        0x225acc,0x225aea,0x225af2,0x225af6,0x225afa,0x225afc,0x225afe,
        0x225784,0x225786,0x22578a,0x22578e,0x225792,0x225794,0x225796,
        0x225798,0x22579a,0x22579c,0x22579e,0x2257a0,0x2257a2,
        0x2257ae,0x2257b0,0x2257b2,0x2257b4,0x2257d2],
        'True 225B18 block interface calls225ACC→22577C. Capacity limit is derived from runtime card byte-capacity words at12787C0+slot*64+28/+2C, shifted right9 to sectors, with ordinal/present guard and remaining-count clamp. 2257D2 reaches command primitive224296 beyond the executed stop. Actual card fields, MMIO/DMA and live board state were not read or executed.')
    ]
    assert len(witnesses)==5
    put('five-exact-witnesses.json',dict(schema='production-block-read-five-primary-witnesses/v1',witnesses=witnesses))
    cpu=json.loads((HERE/'read-binding-cpu-proof.json').read_bytes())
    assert cpu['completed_cases']==1 and cpu['completed_original_instructions']==62
    assert cpu['stop']=='0x225b18' and cpu['unknown_function_returns_faked'] is False
    put('proof.json',dict(schema='native-production-block-read-registration-proof/v1',
      all_assigned_bounded_checks_passed=True,closed_with_live_binding_gap=True,
      source_sha256=sha((HERE/'probe_read_binding.py').read_bytes()),
      capture_source_sha256=sha((HERE/'capture_windows.py').read_bytes()),
      fresh_MAIN_bytes=2856,fresh_MAIN_operations=ledger['operations'],MAIN_limit=32768,
      IMG_bytes=0,IMG_operations=0,whole_MAIN_or_IMG_hash=False,device_operations=0,
      captures=captures,source_pins_verified=True,MAIN_stat_stable=True,
      five_witnesses_sha256=sha((HERE/'five-exact-witnesses.json').read_bytes()),
      sole_CPU_case_sha256=sha((HERE/'read-binding-cpu-proof.json').read_bytes()),
      original_CPU_cases=1,original_instructions=62,
      precise_binding=dict(drive_lowerops_store='24E8A0 2162',caller='3FE830 supplies context+64',
        lowerops_read_store='3FEB40 e066: context+6C ← 3FEA37',
        raw_read_provider='1D84D8 2160: context+C ← 225B19',
        raw_or_cached_copy='3FEB8E raw context+C; 3FEB5C cached 1E2CCB',
        partition_dispatch='3FEAB6 b847 after physical-sector translation',
        SD_capacity_guard='225794..2257A2 runtime64bit bytecapacity>>9'),
      synthetic_fixture=cpu['fixture'],CPU_stop_before_SD_body=True,
      no_unknown_callback_return=True,live_AP_drive_ordinal_or_cache_policy_proven=False,
      board_capacity_or_storage_IO_proven=False,renderer_proven=False,
      literal_128MiB_guard_identified=False,AP_renderer_root_cause_established=False,
      v3_fixed=False,physical_acceptance=False,App_completed=False,
      full_address_update_completed=False,firmware_or_authorization_modified=False,
      previous_closed_suites_rerun=False,shared_or_sealed_inputs_modified=False,
      corrections=[
        '24E8A0 drive+20 is the fourth incoming argument saved atSP+10 after PUSH plus SUB. 3A0F76 fileobject+20 and2D31D0 ordinal inventory+20 are different objects, not lowerops stores.',
        'New type1_mount_full_prologue starts at39EAC0 in the middle of the parser, not a function prologue; drive_registration_cluster overlaps unrelated MMIO code. These heuristic labels are preserved but not claimed as true control-flow or primary binding witnesses.',
        'Linear disassembly across embedded literal pools in3FEA6C..9A and1D84E4..EA is not reachable code; only selected exact instructions and the actual guest trace establish control.'
      ],
      remaining_blockers=[
        'True production lowerops registration exists, but live AP selector4D→drive ordinal→partition storage/cache selection is not observed.',
        'Context storage initializer and SD present/bytecapacity words are runtime data; no board/MMIO/DMA operation or storage-byte result was executed.',
        'The sole case supplies mid-function adapter state and explicit non-cache inventories; it does not execute cold registration, filesystem mount, or AP admission.',
        'No evidence establishes a fixed128MiB guard, v3 road regression cause, renderer acceptance or fix. Runtime card count guards are not Garmin IMG container capacity.'
      ],
      minimum_next_frontier='Bind actual startup selection into24E83A drive ordinal and context+C4 cache choice, or a separately authorized new22577C→224296 command/window ABI; keep live/MMIO results unknown.',
      all_scope_handles_closed=True))
    (HERE/'HANDOFF.txt').write_text('''NEW navigation-native-production-block-read-binding-v1 — finite read-only result

True lowerops registration: 24E8A0 (2162) writes original fourth argument r3
to drive+20. Caller3FE830 supplies storage-context+64. 3FEB40 (e066)
writes3FEA37 at context+6C, therefore lowerops+8. Original3FEA36 checks
ordinal<2, active partition, sector<count, storage identity/ready; clamps
count and adds partition first sector before BLX3FEAB6. Its next callback
at context+8C is cached1E2CCB or raw225B19 according to a real branch.
The original1D84C4 provider writes raw225B19 at context+C. Live AP mapping
and cache selection remain unknown; no guessed ops callback is used.

One original CPU case EXIT0/chunk88c095:62instructions3A1456→3FEA36→
225B18 entry stop. Explicit synthetic512-byte sector frame/inventories,
non-cache selection. Original extent min16→6 and partition min6→2;
physical-sector addition produces0x40802, destination unchanged. This
fixture request exceeds128MiB, not evidence of live storage capacity.
No unknown return hooks, SD callback body, board MMIO/DMA or I/O ran.

Static225B18→225ACC→22577C exposes a runtime card capacity guard from
64-bit byte-capacity words+28/+2C, right-shift9, then start/count checks.
2257D2→224296 is a later command frontier. No fixed128MiB or IMG8K guard
has been identified in these exact fragments; other windows or board
restrictions remain unexcluded. This is not AP admission/render success.

Five exact instruction-byte witnesses; freshMAIN2856B/32768B, IMG0.
Startup-copy mapping was used, full MAIN/IMG hashes and closed mount,
matrix/registry cases were not rerun. The older1MB primary-static file
was hash/stat pinned and only8 selected function objects were reused;
it is not relabeled as a newer sealed input. Heuristic capture labels
and literal-pool linear disassembly are corrected in proof.json.

All handles closed. No firmware, authorization, device, shared sealed,
canonical/report, audio or install candidate changes. v3 cause/fix,
board read acceptance, renderer, App/full address completion are false.
Stop here. Next smallest gap: actual AP live ordinal/cache registration
binding or a separately bounded22577C→224296 command/window ABI.
''')
    put('host-final-audit.json',dict(schema='production-block-read-final-host-audit/v1',
      PID=os.getpid(),time_ns=time.time_ns(),MAIN_opened=False,IMG_opened=False,
      guest_rerun=False,all_checks_passed=True,all_handles_closed=True,
      proof_sha256=sha((HERE/'proof.json').read_bytes())))
    print(json.dumps(dict(proof_sha256=sha((HERE/'proof.json').read_bytes()),
      CPU_sha256=sha((HERE/'read-binding-cpu-proof.json').read_bytes()),
      MAIN_bytes=2856,MAIN_operations=ledger['operations'],IMG_bytes=0,handles_closed=True)))

def seal():
    assert (HERE/'host-final-audit.json').exists() and not (HERE/'sealed-files.json').exists()
    paths=sorted(p for p in HERE.iterdir() if p.is_file())
    for p in paths:p.chmod(0o444)
    rows=[dict(path=str(p.relative_to(ROOT)),bytes=p.stat().st_size,
               sha256=sha(p.read_bytes()),mode='0444')for p in paths]
    seal=dict(schema='sealed-production-block-read-binding-files/v1',
      all_assigned_checks_passed=True,files=rows,all_handles_closed=True,
      seal_excludes_itself=True)
    put('sealed-files.json',seal);(HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps(dict(seal_sha256=sha((HERE/'sealed-files.json').read_bytes()),
      files=len(rows)+1,all_0444=True,handles_closed=True)))

if __name__=='__main__':
    if sys.argv[1:]==['--seal']:seal()
    else:assert not sys.argv[1:];prepare()
