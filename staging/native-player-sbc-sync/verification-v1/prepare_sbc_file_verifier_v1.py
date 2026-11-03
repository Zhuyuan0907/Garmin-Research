#!/usr/bin/env python3
"""NEW file-only verifier source, copied from frozen sync V6 without importing it."""
from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parents[3]
BASE=Path(__file__).resolve().parent
parent=ROOT/'staging/native-player-mixer-sync/verification-v3/verify_mixer_sync_v3_files_v6.py'
digest=hashlib.sha256(parent.read_bytes()).hexdigest()
assert digest=='9366f293c57bdbe85faac76be97614ceb805988d7880f52ed4a06afa5acfc0be'
s=parent.read_text().split('\ndef main():',1)[0]
s=s.replace("BASE = ROOT / 'staging/native-player-mixer-sync'","BASE = ROOT / 'staging/native-player-sbc-sync'")
s=s.replace("name=d['name'];rp=Replay(d,n,elf,symbols);rp.cold()","name=d['name'];normal_case=name.endswith('native_reuse_reselect_reset');crc_case='later_CRC' in name;stop_case='Stop' in name;profile_case='profile' in name;rp=Replay(d,n,elf,symbols);rp.cold()")
s=s.replace('len(self.z)==24','len(self.z)==26').replace('len(specs)==27','len(specs)==29').replace("'24 tracked whole zones'","'26 tracked whole zones'")
s=s.replace('tracked_whole_zones=24,actual_RW_zones_from_frozen_parent_permission_recipe=23','tracked_whole_zones=26,actual_RW_zones_from_frozen_parent_permission_recipe=25')
s=s.replace("prepare_sync_checkpoints(rp,d,symbols)\n    counts=rp.run()","prepare_sync_checkpoints(rp,d,symbols)\n    prepare_sbc_checkpoints(rp,d,symbols)\n    counts=rp.run()")
s=s.replace("name.startswith('Stop')","stop_case").replace("d['name'].startswith('Stop')","('Stop' in d['name'])")
s=s.replace("name.startswith('original_profile')","profile_case").replace("name.startswith('normal')","(normal_case or crc_case)")
s=s.replace("name.startswith(('normal','Stop'))","(normal_case or stop_case)")
s=s.replace("selectors=2 if name.startswith(('normal','Stop')) else 1","selectors=2 if (normal_case or stop_case) else 1")
s=s.replace("expected_count=32 if (normal_case or crc_case) else 8","expected_count=32 if normal_case else (16 if crc_case else 8)")
s=s.replace("final_status[48]==16","final_status[48]==(16 if normal_case else 8)")
lo=s.index("    commands=d['commands'];expect_commands=")
hi=s.index('    # Callback installs must be native or compiled CPU stores, never seeded.',lo)
s=s[:lo]+'''    commands=d['commands'];expected_commands={
        'mono16_native_reuse_reselect_reset':[1,2,3,4],
        'joint44_native_reuse_reselect_reset':[1,2,3,4],
        'stereo48_native_reuse_reselect_reset':[1,2,3,4],
        'joint44_Stop_rejects_compressed_input':[1,5,8],
        'joint44_later_CRC_reject_and_recover':[1,9,2],
        'stereo48_profile_rewrite_rejects_decode':[1,6,8]}[name]
    require([x['command'] for x in commands]==expected_commands,'Actual compressed-source commands')
    reference=load(BASE/'compressed_input_reference_v1.json')['streams'][d['stream_index']]
    audio=b'';cycle=0;music_bytes=0;silence_bytes=0;reset_pending=False;packet_index=0
    for cmd in commands:
        if cmd['command']<=4:
            key='expected_after_reset_PCM_hex' if reset_pending else 'expected_continuous_PCM_hex'
            pcm=bytes.fromhex(reference['packets'][packet_index][key]);reset_pending=False;packet_index+=1
            expected=pcm+bytes(1792-len(pcm));cycle+=1;music_bytes+=len(pcm);silence_bytes+=1792-len(pcm)
            require(bytes.fromhex(cmd['HOST_expected_PCM_hex'])==pcm,'Frozen expected PCM comparison identity')
            require(bytes.fromhex(cmd['PCM_hex'])==expected and cmd['bytes']==1792 and cmd['source_PCM_bytes']==len(pcm) and cmd['original_self_posted_underrun_silence_bytes']==1792-len(pcm),'Actual decoded/FIR PCM and underrun bytes')
            audio+=expected
        else:
            require(cmd['PCM_hex']=='' and cmd['bytes']==0 and cmd['source_PCM_bytes']==0,'Failed/stopped/revoked no new ring publication')
            if cmd['command']==9:reset_pending=True
        require(all(cmd['state'][k]==0 for k in (2,6,7,8,12)),'Command lease/completion endpoints')
    require(b''.join(total_PCM)==audio,'Actual native fullreturn chunks equal independently checked command PCM')
    require(final_status[3]==final_status[4]==len(full) and final_status[14]==len(audio),'Actual compiled pulls/fullreturns/byte counters')
    expected_count=32 if normal_case else (16 if crc_case else 8);require(len(full)==expected_count,'Actual expected native fullreturns')
    selectors=2 if (normal_case or stop_case) else 1;require(len(d['selector_bridge_entries'])==selectors and final_status[42]==final_status[43]==selectors,'Actual selector counts')
    if normal_case or crc_case:
        require(sites['0x2fa536']>0 and sites['0x2fa572']>0 and final_status[5]==0 and final_status[48]==(16 if normal_case else 8),'Both original fullcallroutes/current FIFO ticket')
        require(word(z,RECORD+0x108)==symbols['memory_output_read']['value'],'Leased original-selector reader installed')
    else:
        require(final_status[41]==1 and word(z,g+20*4)==0,'Actual capability revoked')
        require(final_status[5]==(2 if stop_case else 1),'Actual local Stop/profile denial counters')
    require(len(reset_rows)==(1 if (normal_case or stop_case) else 0),'Actual exact reset transport count')
''' + s[hi:]
s=s.replace('music_bytes=512*cycle,underrun_silence_bytes=1280*cycle','music_bytes=music_bytes,underrun_silence_bytes=silence_bytes')
s=s.replace('    return counts\n\ndef prepare_sync_checkpoints','    counts.update(verify_sbc_pipeline(d,rp,symbols,reference))\n    return counts\n\ndef prepare_sync_checkpoints')
# Every post-baseline fixture is denied access to compiled data/FIFO/packet/stack,
# not merely the old fixed BSS range from the raw-PCM image.
s=s.replace("require(not (a<0x07005000 and a+len(after)>0x07004000),'Fixture seeded compiled capability/ticket state')", "require(not any(sec['flags']&3==3 and a<sec['address']+sec['size'] and a+len(after)>sec['address'] for sec in self.elf.sections if sec['size']),'Fixture seeded compiled data/payload/capability state')")
# Preserve every source/opcode check; cache only immutable Capstone decode.
s=s.replace('self.eventchecks=defaultdict(list)','self.eventchecks=defaultdict(list);self.decode_cache={}')
s=s.replace("ins=next(MD[thumb].disasm(raw,pc,count=1));require(ins.size==len(raw),'Instruction complete')", "key=(pc,thumb,raw);ins=self.decode_cache.get(key)\n        if ins is None:ins=next(MD[thumb].disasm(raw,pc,count=1));self.decode_cache[key]=ins\n        require(ins.size==len(raw),'Instruction complete')")
with (BASE/'verify_sbc_sync_v1_files_v1.py').open('x') as f:f.write(s+'\n'+(BASE/'sbc_file_verifier_extension_v1.py').read_text())
with (BASE/'source-copy-provenance-v1.json').open('x') as f:json.dump(dict(file_only=True,parent=str(parent.relative_to(ROOT)),parent_sha256=digest,new_source='staging/native-player-sbc-sync/verification-v1/verify_sbc_sync_v1_files_v1.py',changes=['Namespace/output/input registry and SBC ELF identity','26 tracked/25 trueRW plus unchanged RX sentinel per case; three actual finalRX dumps retained','No inherited hardcoded512-byte rawPCM expectation; actual HOST compressed reference bytes and six-case identities checked','Every post-baseline fixture denied all compiled writable sections; immutable decode cache only','New SBC entry/return/lease/queue/gather/FIFO whole-packet CRC/Stop/profile checks appended','Complete inherited native builders/FIFO/fullreturn/mutex/condition/ACK8 proof predicates retained']),f,indent=2);f.write('\n')
print(json.dumps(dict(all_passed=True,source='staging/native-player-sbc-sync/verification-v1/verify_sbc_sync_v1_files_v1.py',source_sha256=hashlib.sha256((BASE/'verify_sbc_sync_v1_files_v1.py').read_bytes()).hexdigest(),guest_execution=False)))
