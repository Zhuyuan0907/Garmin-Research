#!/usr/bin/env python3
"""Export exact firmware and editable research; never invent original sources."""
import sys,json,hashlib,shutil,re,struct,subprocess,zipfile,os
from pathlib import Path
from datetime import datetime,timezone
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'staging/garminos-vscode-workspace-v1';PROJECT=OUT/'GarminOS-2565RT-research'
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def put(path,text):
 p=PROJECT/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text,encoding='utf-8');return p
def js(path,data):return put(path,json.dumps(data,ensure_ascii=False,indent=2)+'\n')
def copy(src,dst):
 p=PROJECT/dst;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/src,p);return p
def main():
 assert not OUT.exists(),'New export namespace required';OUT.mkdir();PROJECT.mkdir()
 n=NativeImage();raw=n.data;ctx=json.loads((ROOT/'staging/native-player-kernel-context/kernel-context-static-preflight.json').read_text())
 inputs={str(Path(__file__).relative_to(ROOT)):sha(Path(__file__))}
 def record(p):inputs[str(p.relative_to(ROOT))]=sha(p)
 for src,dst in [('evidence/firmware-analysis/main_02bd.bin','binaries/MAIN.bin'),('evidence/firmware-analysis/boot_0008.bin','binaries/BOOT.bin'),('evidence/firmware-analysis/voice-modules/Chinese_Big5_MeiLing/DLLIMG.BIN','binaries/original_MeiLing_DLLIMG.bin')]:
  p=ROOT/src;target=PROJECT/dst;target.parent.mkdir(exist_ok=True);os.link(p,target);record(p)
 # Proven mixed-mode basic blocks retain instruction bytes, gaps remain incbin.
 modes={'ARM':Cs(CS_ARCH_ARM,CS_MODE_ARM),'Thumb':Cs(CS_ARCH_ARM,CS_MODE_THUMB)};blocks={};symbols=[]
 for key,f in ctx['functions'].items():
  text=['; Exact bounded CFG; not a complete operating-system disassembly.','; Names are research labels, original source symbols unavailable.']
  for row in f['instructions']:
   a=int(row['address'],16);ins=next(modes[row['mode']].disasm(n.read(a,4),a,count=1));assert ins.mnemonic+' '+ins.op_str==row['instruction']
   b=n.read(a,ins.size);blocks[a]=(b,row['mode'],row['instruction'])
   text.append(f'{a:08X}  {b.hex():10s}  [{row["mode"]:5s}]  {row["instruction"]}')
  put(f'disassembly/kernel/sub_{int(key,16):08X}.asm','\n'.join(text)+'\n')
  symbols.append(dict(name={0x2fcf44:'kernel_normal_event_post',0x2fd034:'kernel_normal_event_wait',0x358ec4:'kernel_saved_context_restore',0x358e70:'kernel_context_helper',0x300d08:'kernel_mutex_contention'}[int(key,16)],address=key,entry_mode=f['entry_mode'],scope='verified bounded mixed-mode CFG',listing=f'disassembly/kernel/sub_{int(key,16):08X}.asm'))
 assembly=['/* Byte-exact firmware representation; NOT recovered original Garmin source. */','/* Verified kernel instructions shown as bytes; all unknown bytes are incbin. */','.section .firmware,"a",%progbits','.global garmin_main_image','garmin_main_image:']
 cursor=0
 for a,(b,mode,ins)in sorted(blocks.items()):
  offset=a-0x50000;assert offset>=cursor
  if offset>cursor:assembly.append(f'.incbin "binaries/MAIN.bin", {cursor}, {offset-cursor}')
  assembly.append(f'.byte '+','.join(f'0x{x:02x}'for x in b)+f' /* {a:08X} {mode}: {ins} */');cursor=offset+len(b)
 if cursor<len(raw):assembly.append(f'.incbin "binaries/MAIN.bin", {cursor}, {len(raw)-cursor}')
 assembly+=['.global garmin_main_image_end','garmin_main_image_end:'];put('assembly/main_image.S','\n'.join(assembly)+'\n')
 js('evidence/native-sections.json',dict(load_base=0x50000,MAIN_sha256=sha(PROJECT/'binaries/MAIN.bin'),copies=n.copies,zero_fills=n.zeros,startup_trace=n.startup_trace,scope='Recovered static startup ranges; physical RAM state and conditional startup flag unmeasured.'))
 copy('staging/native-player-kernel-context/kernel-context-static-preflight.json','evidence/kernel-context-static-preflight.json');record(ROOT/'staging/native-player-kernel-context/kernel-context-static-preflight.json')
 copy('evidence/firmware-analysis/platform.json','evidence/platform.json');record(ROOT/'evidence/firmware-analysis/platform.json')
 tags=[]
 for pattern in [b'OS20',b'OS21',b'Linux version',b'GarminOS',b'Processor\\STA2064',b'ThreadX',b'Nucleus']:
  hits=[]
  for m in re.finditer(re.escape(pattern),raw):
   a=m.start();start=raw.rfind(b'\0',max(0,a-128),a)+1;end=raw.find(b'\0',a,min(len(raw),a+256));end=end if end!=-1 else a+len(pattern)
   hits.append(dict(file_offset=a,load_address=hex(0x50000+a),context=raw[start:end].decode('ascii','backslashreplace')))
  tags.append(dict(pattern=pattern.decode('ascii'),count=len(hits),hits=hits))
 js('evidence/os-string-observations.json',dict(MAIN_sha256=sha(PROJECT/'binaries/MAIN.bin'),observations=tags,absence_proves_no_Linux=False,OS20_exact_vendor_or_version_verified=False,interpretation='GarminOS/OS20 task strings plus custom native context switching support an OS20-based native environment. Strings alone cannot identify the entire OS or exclude embedded code/resources.'))
 previews=[('voice_select_load',0x240498,256),('voice_version_getter',0x2744f6,64),('diagnostic_AudVer_callsite',0x6817c0,64),('audio_kind_selector',0x4caf2e,128),('audio_generic_seek',0x4caea8,128),('audio_memory_setup',0x5e759e,128),('audio_memory_read',0x5e75ba,128),('audio_memory_write',0x5e75f0,128),('audio_memory_seek',0x5e7622,128),('boot_section_initializer',0xebd90,0xc0),('original_BIN_read',0x1fb3a2,48)]
 for name,a,length in previews:
  md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.skipdata=True;lines=['; Linear Thumb preview only; may contain data or cross function/mode boundaries.','; Use verified CFG listings for the five kernel functions.']
  for ins in md.disasm(n.read(a,length),a):lines.append(f'{ins.address:08X}  {ins.bytes.hex():12s} {ins.mnemonic} {ins.op_str}')
  put(f'disassembly/previews/{name}.asm','\n'.join(lines)+'\n');symbols.append(dict(name=name,address=hex(a),entry_mode='Thumb',scope='bounded linear preview, not complete CFG',listing=f'disassembly/previews/{name}.asm'))
 js('symbols/functions.json',symbols)
 for p in sorted((ROOT/'native').rglob('*')):
  if p.is_file()and('__pycache__'not in p.parts)and(p.suffix in('.c','.h','.S','.ld','.py','.md','.txt','.json')or p.name.startswith('COPYING')):
   copy(str(p.relative_to(ROOT)),'research/'+str(p.relative_to(ROOT)));record(p)
 for name in ('analyze_native_sections.py','analyze_native_kernel_context.py','analyze_native_loader.py','analyze_native_audio_registration.py','analyze_native_voice_acceptance.py','analyze_tts_vpm.py','analyze_sdp_activation.py','build_native_sbc.py','build_native_source_worker.py'):
  p=ROOT/'scripts'/name
  if p.exists():copy(str(p.relative_to(ROOT)),'research/'+str(p.relative_to(ROOT)));record(p)
 # Keep upstream code and licenses needed to inspect the SBC wrapper.
 upstream=ROOT/'sources/deep-research/sbc-2.1'
 if upstream.exists():
  for p in upstream.rglob('*'):
   if p.is_file()and(p.suffix in('.c','.h','.in','.am','.ac','.txt','.m4')or p.name in('COPYING','COPYING.LIB','AUTHORS','README','ChangeLog')):
    copy(str(p.relative_to(ROOT)),'research/'+str(p.relative_to(ROOT)));record(p)
 pb=ROOT/'staging/native-platform-readonly-probe'
 for name in ('platform_cache_marker_entry_v1.c','platform-probe-source-contract-v1.json','platform-micro-v1-proof.json','ROOT-platform-micro-file-bundle-v1.json','platform-candidate-reader-v1-proof.json','ROOT-platform-reader-file-proof-v1.json'):
  dst=('experiments/platform-probe/'if name.endswith('.c')else'evidence/platform-probe/')+name;copy(str((pb/name).relative_to(ROOT)),dst);record(pb/name)
 pm=json.loads((pb/'strict_marker/manifest.json').read_text());js('experiments/platform-probe/original-layout.json',dict(IMAGE=0x02d4bb74,original_entry=pm['original_entry'],original_ram=pm['original_ram'],original_sha256=pm['original_sha256'],reference_combined_sha256=pm['binary_sha256'],physical_CPU_unknown=True))
 put('tools/verify_workspace.py','''#!/usr/bin/env python3
import json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
 m=json.loads((ROOT/'manifest.json').read_text()); failures=[]
 for path,item in m['files'].items():
  p=ROOT/path
  if not p.is_file() or p.stat().st_size!=item['bytes'] or hashlib.sha256(p.read_bytes()).hexdigest()!=item['sha256']:failures.append(path)
 if failures:raise SystemExit('Changed/missing files: '+', '.join(failures))
 print('Verified',len(m['files']),'files; exact target HWID1352/SW8.00. This does not prove physical execution.')
if __name__=='__main__':main()
''')
 put('tools/disassemble.py','''#!/usr/bin/env python3
"""Explicit address/range/mode decoder, not automatic source recovery."""
import argparse,hashlib,json
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser();p.add_argument('--address',type=lambda x:int(x,0),required=True);p.add_argument('--bytes',type=lambda x:int(x,0),default=128);p.add_argument('--mode',choices=['ARM','Thumb'],required=True);p.add_argument('--runtime',action='store_true');p.add_argument('--output',type=Path);a=p.parse_args()
 raw=(ROOT/'binaries/MAIN.bin').read_bytes();m=json.loads((ROOT/'manifest.json').read_text());assert hashlib.sha256(raw).hexdigest()==m['files']['binaries/MAIN.bin']['sha256']
 load=a.address
 if a.runtime:
  ranges=json.loads((ROOT/'evidence/native-sections.json').read_text())['copies'];hits=[r for r in ranges if r['runtime_start']<=a.address and a.address+a.bytes<=r['runtime_end']];assert len(hits)==1,'Runtime range has no unique initialized file backing (BSS cannot be decoded from the file)';r=hits[0];load=r['load_start']+a.address-r['runtime_start']
 off=load-0x50000;assert a.bytes>0 and 0<=off and off+a.bytes<=len(raw)
 md=Cs(CS_ARCH_ARM,CS_MODE_ARM if a.mode=='ARM'else CS_MODE_THUMB);md.skipdata=True
 text='; Explicit linear decode, code/data and mode must be checked.\\n'+''.join(f'{i.address:08X}  {i.bytes.hex():12s} {i.mnemonic} {i.op_str}\\n'for i in md.disasm(raw[off:off+a.bytes],a.address))
 if a.output:a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(text)
 else:print(text,end='')
if __name__=='__main__':main()
''')
 put('tools/build_byteexact_image.py','''#!/usr/bin/env python3
"""Reassemble a byte representation; NOT rebuild original Garmin source."""
import subprocess,hashlib,json,tempfile,argparse,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path);a=p.parse_args();expected=json.loads((ROOT/'manifest.json').read_text())['files']['binaries/MAIN.bin']['sha256']
 with tempfile.TemporaryDirectory(prefix='garmin-byte-exact-')as t:
  obj=Path(t)/'main.o';binary=Path(t)/'main.bin'
  subprocess.run(['arm-linux-gnueabi-as','assembly/main_image.S','-o',str(obj)],cwd=ROOT,check=True)
  subprocess.run(['arm-linux-gnueabi-objcopy','-O','binary','--only-section=.firmware',str(obj),str(binary)],check=True)
  actual=hashlib.sha256(binary.read_bytes()).hexdigest();assert actual==expected,'Reassembled bytes differ'
  if a.output:a.output.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(binary,a.output)
  print('Byte-exact representation verified:',actual,'(not recompilation of recovered original code)')
if __name__=='__main__':main()
''')
 put('tools/build_platform_probe.py','''#!/usr/bin/env python3
"""Build our standalone diagnostic extension; no VPM packaging/device I/O."""
from pathlib import Path
import json,struct,hashlib,subprocess
ROOT=Path(__file__).resolve().parents[1]
def main():
 d=ROOT/'build/platform-probe';d.mkdir(parents=True,exist_ok=True);layout=json.loads((ROOT/'experiments/platform-probe/original-layout.json').read_text());raw=(ROOT/'binaries/original_MeiLing_DLLIMG.bin').read_bytes();assert hashlib.sha256(raw).hexdigest()==layout['original_sha256'];image=layout['IMAGE'];offset=(layout['original_ram']+31)&~31
 ld=d/'entry.ld';ld.write_text(f'ENTRY(cache_marker_entry)\\noriginal_tts_entry = {layout["original_entry"]:#x};\\nSECTIONS {{ . = {image+offset:#x}; .entry : {{ KEEP(*(.text.cache_marker_entry)) }} .text : {{ *(.text*) }} .rodata : {{ *(.rodata*) }} . = ALIGN(32); .data : {{ *(.data*) }} . = ALIGN(32); .bss (NOLOAD) : {{ __marker_bss_start = .; *(.bss*) *(COMMON) __marker_bss_end = .; }} __combined_ram_bytes = . - {image:#x}; /DISCARD/ : {{ *(.comment) *(.note*) *(.ARM.exidx*) *(.ARM.extab*) }} }}\\n')
 elf=d/'probe.elf';flat=d/'probe.bin';src=ROOT/'experiments/platform-probe/platform_cache_marker_entry_v1.c'
 cmd=['arm-linux-gnueabi-gcc','-Os','-march=armv4t','-marm','-mfloat-abi=soft','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-nostdlib','-static','-no-pie','-DCONTROL=0',f'-Wl,-T,{ld}','-Wl,--build-id=none',str(src),'-o',str(elf)];subprocess.run(cmd,check=True);subprocess.run(['arm-linux-gnueabi-objcopy','-O','binary',str(elf),str(flat)],check=True)
 assert not subprocess.check_output(['arm-linux-gnueabi-nm','-u',str(elf)],text=True).strip()
 syms={}
 for line in subprocess.check_output(['arm-linux-gnueabi-nm','-n',str(elf)],text=True).splitlines():
  p=line.split()
  if len(p)==3:syms[p[2]]=int(p[0],16)
 combined=bytearray(raw)+bytes(offset-len(raw))+flat.read_bytes();struct.pack_into('<3I',combined,0,0xea000000|(((offset-8)//4)&0xffffff),syms['__combined_ram_bytes'],len(combined));assert combined[12:len(raw)]==raw[12:]
 out=d/'combined-research-only.bin';out.write_bytes(combined);digest=hashlib.sha256(combined).hexdigest();(d/'build.json').write_text(json.dumps(dict(combined_sha256=digest,reference_same_bytes=digest==layout['reference_combined_sha256'],commands=[cmd],symbols=syms,device_IO=False,installable_firmware=False),indent=2)+'\\n');print('Diagnostic built:',digest,'same bytes as Pi reference:',digest==layout['reference_combined_sha256'],'no device action')
if __name__=='__main__':main()
''')
 put('tools/find_strings.py','''#!/usr/bin/env python3
import argparse,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('text');a=p.parse_args();raw=(ROOT/'binaries/MAIN.bin').read_bytes()
for m in re.finditer(re.escape(a.text.encode('utf-8')),raw):
 off=m.start();start=raw.rfind(b'\\0',max(0,off-128),off)+1;end=raw.find(b'\\0',off,min(len(raw),off+256));end=end if end!=-1 else off+len(a.text.encode());print(f'file {off:#x} load {0x50000+off:#x}',repr(raw[start:end]))
''')
 put('requirements.txt','capstone==5.0.7\n')
 put('reconstruction/README.md','''這個目錄放研究用的語意重建，不是原廠 C/C++ 原始碼。編译產物不會等於原廠韌體；原函式、型別、名稱與分支必須以二進位證據核對。已驗證的逐指令核心 CFG 在 `disassembly/kernel/`。\n''')
 put('reconstruction/startup_memory_model.c','''/* Research semantic model, not recovered original source or flashable code.
 * Exact operations are documented in evidence/native-sections.json.
 * Conditional ranges depend on the startup hardware flag, not measured here. */
#include <stdint.h>
#include <stddef.h>
void research_copy_words(uint32_t *destination,const uint32_t *source,size_t bytes) {
    /* Observed stock helper advances source/destination in 4-byte units. */
    for(size_t i=0;i<bytes/4;i++) destination[i]=source[i];
}
void research_zero_words(uint32_t *destination,size_t bytes) {
    for(size_t i=0;i<bytes/4;i++) destination[i]=0;
}
/* These helpers express copy/zero intent, not startup flags, exceptions,
   barriers, peripheral mappings, or the complete initialization sequence. */
''')
 put('reconstruction/native_abi_notes.h','''/* Research labels for exact HWID1352/SW8.00; not original SDK. */
#ifndef GARMIN_RESEARCH_ABI_NOTES_H
#define GARMIN_RESEARCH_ABI_NOTES_H
#define RESEARCH_MAIN_LOAD_BASE 0x00050000u
#define RESEARCH_KERNEL_POST_ARM 0x002fcf44u
#define RESEARCH_KERNEL_WAIT_THUMB 0x002fd035u
#define RESEARCH_KERNEL_RESTORE_ARM 0x00358ec4u
#define RESEARCH_TCB_SAVED_SP_OFFSET 12u
#define RESEARCH_VOICE_SELECTOR_THUMB 0x00240499u
#define RESEARCH_VOICE_VERSION_GETTER_THUMB 0x002744f7u
#define RESEARCH_VOICE_RUNTIME_IMAGE 0x02d4bb74u
/* Odd function-pointer bit selects Thumb; CFG/listing address has bit0 clear.
   Event signatures, TCB initialization and live ownership are separate work.
   Addresses are not proven physical RAM permissions or callable from an App. */
#endif
''')
 put('docs/OS-evidence.md','''# 這台系統目前能判斷到哪裡

目標是台灣 nüvi 2565RT，HWID 1352，SW 8.00。這份 MAIN 的 SHA-256 固定在 manifest.json；不能把 2585 或國外 HWID1371 的結論套用到此機。

韌體直接包含 `GarminOS`、`gpk\\gps_st\\garminos\\os20\\gps_st_os20_task.c`、`OS20_root_task_ws` 與 `Out of OS20 tasks`。核心五個有界函式已逐指令分析，包含自訂任務 SP 儲存、CPSR／SPSR 恢復及 ARM／Thumb 切換。這些證據較支持 GarminOS／OS20 的原生任務環境，而不是一般 Linux 程式。OS20 的確切供應商、版本及全機組成尚未確認；沒有找到 `Linux version` 字串並不能獨自證明全機沒有 Linux。

STA2064 建置路徑在韌體內，支援該平台的推論；實際 CPU 型號仍待只讀診斷實機結果。模擬器 ARM1176／ARM926 的 MIDR 是模型輸入，不能拿來識別車機。

Garmin 官方 Linux 開源頁：<https://developer.garmin.com/open-source/linux/>。2026-10-05 讀取其 nüvi25xx 連結，檔名分別是 `nuvi_2585_tw-V4.50-sources.tar.bz2` 和 `nuvi_2585_tw-V3.20-sources.tar.bz2`。這是 2585 的開源套件，不能稱為本機 2565RT 8.00 的完整原始碼。也沒有在本輪下载或移植它們。

`arm-linux-gnueabi-gcc` 是交叉編譯器的名字。我們的診斷使用 freestanding／nostdlib，沒有 Linux 動態載入器或 unresolved runtime；編譯器名字不能證明目標系統使用 Linux。
''')
 put('docs/RESEARCH-STATUS.md','''# 已完成與未完成

實機已驗證：透過 Pi 模擬 HFP 通話可以播放旋律與 Android 手機音樂；診斷頁 Play WAV 有聲；語音 DLL 診斷標記 M7Q9／WFFF 可以顯示，原美玲語音已還原，使用者確認 Aud Ver 回到 2.10。

離線已驗證：原廠元件載入、40個介面、原kernel任務切換，以及有界 SBC／PCM／音源生命週期與若干入口保護。最新只讀 CPU 診斷通過44個微測試和2個原廠候選載入器情境；檔案核對44個微測試及2個載入器情境完成。正向模擬載入器顯示0B76，是模型結果。

未完成：實機 CPU／模式／記憶體權限與完整播放器載入；手機直接A2DP；菜單App；導航共存、重連與安全卸載；Android Auto。此專案沒有可直接刷入的完整OS或App，也沒有對車機執行寫入。

原生 App 與原生音訊研究持續；Android Auto 後續，Google Maps 暫後；麥克風功能已取消。整體進度估計37%，原生App35%，原生音訊60%；百分比是研究估計，不是可運作功能占比。
''')
 put('docs/GETTING-STARTED.md','''# 在 VS Code 研究

1. 解壓縮，開啟 `GarminOS-research.code-workspace`，先讀 README.md 和 docs/OS-evidence.md。
2. 安裝 Python 3.10 以上，在終端執行 `python tools/verify_workspace.py`；Windows 可用 `py`。
3. 若需要自行反組譯：`python -m pip install -r requirements.txt`。
4. 執行 `python tools/disassemble.py --address 0x2744f6 --bytes 64 --mode Thumb`，查看 Aud Ver 版本讀取函式。
5. 在 symbols/functions.json 找入口位址，再用 `disassembly/kernel/` 查看已驗證混合模式 CFG。普通預覽只有線性解碼，不能推定全部內容都是程式。
6. 想修改我們的程式，從 experiments/platform-probe/platform_cache_marker_entry_v1.c 或 research/native/sbc-prototype/ 開始。它們是研究者寫的 C／組合語言。

要組譯 byte-exact representation 或建置診斷檔，使用 Linux／WSL，裝 `binutils-arm-linux-gnueabi gcc-arm-linux-gnueabi`，再用 VS Code 的對應 task。任務不會寫車機。MAIN 的組譯任務只是對原二進位的 `.byte`／`.incbin` 表示做位元組核對，並非把原廠 C/C++ 重新編譯。

Ghidra／IDA 匯入 binaries/MAIN.bin 時，起始 load base 是0x50000，little-endian ARM/Thumb mixed mode。這是 raw MAIN，不是 ELF；startup 五個copy與五個zero範圍見 evidence/native-sections.json，部分位址是runtime而非file load address。BSS没有原檔內容，不能用0填充猜實機狀態。工具預設讀load address；`--runtime`只支援唯一有檔案對應的startup-copy範圍。

research/scripts 是原 Pi 研究環境的參考腳本，保留原始內容，可能依賴未放入此專案的 fixtures／staging。可攜式入口是 tools/；不宣稱每個歷史腳本能直接在Windows執行。
''')
 put('docs/PROVENANCE.md','''# 來源與涵蓋範圍

原廠MAIN／BOOT二進位取自已核實的台灣HWID1352 8.00更新韌體；original_MeiLing_DLLIMG.bin 取自已備份的原廠美玲語音包。Garmin原有著作權仍屬原權利人，本專案没有替原廠韌體宣告開源授權。

research/native、experiments/platform-probe 是本研究撰寫的程式，含離線原型與固定地址。reconstruction 是語意模型，不是反編譯出原廠完整C++。disassembly/kernel 是有來源證據的有界反組譯；其他preview明确標示線性解碼限制。assembly/main_image.S 涵蓋整份 MAIN 位元組，但大量內容使用 .incbin，不能當成理解或復原了全部程式。

SBC 上游來源來自 kernel.org/libsbc 2.1，LGPL-2.1-or-later，原始碼與原授權說明保留在 research/sources/deep-research/sbc-2.1/。本包未附完整導航機磁碟備份、個人路線／收藏／配對資訊／GarminDevice.xml／單機序號。

manifest.json 包含每個交付檔案的 SHA-256。手動編輯檔案後核對工具會報告差異；這是正常的變更偵測，請自行保存版本。匯出物驗證與韌體行為驗證是不同證據。
''')
 put('README.md','''# GarminOS 2565RT 逆向研究工作區

這是可在 VS Code 閱讀與修改的研究專案，針對台灣 nüvi 2565RT、HWID1352、軟體8.00。**它不是 Garmin 原廠完整原始碼，也不是可直接刷入的作業系統。** 原始二進位沒有原廠的變數名稱、完整型別、註解或建置專案；不能可靠地憑空復原那些資訊。

建議從 [操作說明](docs/GETTING-STARTED.md) 和 [系統證據](docs/OS-evidence.md) 開始。選好的函式名稱、位址與入口模式在 symbols/functions.json；五個已驗證核心CFG在 disassembly/kernel/。想看我們寫的真正C程式，開 experiments/platform-probe/ 或 research/native/。語意模型在 reconstruction/，完整原二進位在 binaries/。

專案提供原MAIN／BOOT、原語音DLL、位址與初始化區段、反組譯、原生音訊與藍牙研究源碼、只讀診斷程式、SHA-256核對與可攜式工具。原生播放器尚未安裝在實機；App菜單與手機直接A2DP仍在研究。詳細來源及限制見 docs/PROVENANCE.md 和 docs/RESEARCH-STATUS.md。

Garmin 官方 [Linux 開源頁](https://developer.garmin.com/open-source/linux/) 的25xx連結實際指向2585的3.20／4.50套件；沒有據此認定2565RT也是Linux。這台原韌體存在GarminOS／OS20任務路徑，證據已放入evidence/os-string-observations.json。

快速核對：`python tools/verify_workspace.py`。解壓後用VS Code開啟 `GarminOS-research.code-workspace`。所有提供的VS Code tasks只做本機分析或建置，不操作GarminUSB／藍牙。
''')
 js('GarminOS-research.code-workspace',dict(folders=[dict(path='.')],settings={'files.associations':{'*.asm':'asm','*.S':'asm'},'search.exclude':{'binaries/**':True,'build/**':True},'files.exclude':{'**/__pycache__':True}}))
 js('.vscode/extensions.json',dict(recommendations=['ms-python.python','ms-vscode.cpptools','13xforever.language-x86-64-assembly']))
 tasks=[('Verify workspace',['tools/verify_workspace.py']),('Show original voice version getter',['tools/disassemble.py','--address','0x2744f6','--bytes','64','--mode','Thumb']),('Find OS20 evidence',['tools/find_strings.py','OS20']),('Verify byte-exact assembly (Linux/WSL)',['tools/build_byteexact_image.py']),('Build read-only probe (Linux/WSL)',['tools/build_platform_probe.py'])]
 js('.vscode/tasks.json',dict(version='2.0.0',tasks=[dict(label=label,type='process',command='${command:python.interpreterPath}',args=args,options=dict(cwd='${workspaceFolder}'),problemMatcher=[])for label,args in tasks]))
 js('.vscode/c_cpp_properties.json',dict(version=4,configurations=[dict(name='Research C',includePath=['${workspaceFolder}/**'],defines=[],cStandard='c11',cppStandard='c++17',intelliSenseMode='linux-gcc-arm')]))
 put('.gitignore','build/\n.venv/\n__pycache__/\n*.pyc\n')
 files={str(p.relative_to(PROJECT)):dict(bytes=p.stat().st_size,sha256=sha(p))for p in sorted(PROJECT.rglob('*'))if p.is_file()}
 js('manifest.json',dict(kind='reverse-engineering-workspace-not-original-source',target=dict(model='Taiwan nuvi2565RT',HWID=1352,SW='8.00',physical_CPU_unverified=True),original_source_recovered=False,full_MAIN_bytes_included=True,verified_kernel_CFGs=5,linear_previews=len(previews),research_symbol_count=len(symbols),files=files,created_utc=datetime.now(timezone.utc).isoformat()))
 tests=[]
 for name,args in [('integrity',['tools/verify_workspace.py']),('disassemble',['tools/disassemble.py','--address','0x2744f6','--bytes','64','--mode','Thumb']),('byte_exact_assembly',['tools/build_byteexact_image.py']),('probe_build',['tools/build_platform_probe.py'])]:
  r=subprocess.run([sys.executable,*args],cwd=PROJECT,capture_output=True,text=True);assert r.returncode==0,(name,r.stdout,r.stderr);tests.append(dict(name=name,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr));print(json.dumps(dict(test=name,exit_code=0)),flush=True)
 assert json.loads((PROJECT/'build/platform-probe/build.json').read_text())['reference_same_bytes'],'Same compiler source build differs'
 # Derived build outputs are optional scratch; export only manifest-covered files.
 downloads=ROOT/'reports/downloads';downloads.mkdir(exist_ok=True);archive=downloads/'GarminOS-2565RT-research-v1.zip';assert not archive.exists()
 with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6)as z:
  for p in sorted(PROJECT.rglob('*')):
   if p.is_file()and 'build'not in p.relative_to(PROJECT).parts:z.write(p,'GarminOS-2565RT-research/'+str(p.relative_to(PROJECT)))
 with zipfile.ZipFile(archive)as z:
  assert z.testzip()is None
  manifest=json.loads(z.read('GarminOS-2565RT-research/manifest.json'))
  for p,item in manifest['files'].items():assert hashlib.sha256(z.read('GarminOS-2565RT-research/'+p)).hexdigest()==item['sha256'],p
  assert len(z.namelist())==len(files)+1
 result=dict(all_passed=True,project_path=str(PROJECT.relative_to(ROOT)),archive_path=str(archive.relative_to(ROOT)),archive_bytes=archive.stat().st_size,archive_sha256=sha(archive),manifest_sha256=sha(PROJECT/'manifest.json'),files=len(files)+1,tests=tests,original_source_recovered=False,full_MAIN_bytes_included=True,verified_kernel_CFGs=5,linear_previews=len(previews),source_sha256=inputs,device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat())
 (OUT/'export-verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items()if k not in('source_sha256','tests')},ensure_ascii=False),flush=True)
if __name__=='__main__':main()
