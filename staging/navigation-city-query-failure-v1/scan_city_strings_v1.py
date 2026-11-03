#!/usr/bin/env python3
"""Read-only city/provider/source strings in exact MAIN; evidence only, no caller claims."""
import sys,re,struct,hashlib,json,datetime
from pathlib import Path
ROOT=Path('/root/garmin');sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED,BASE as LOAD_BASE
BASE=Path(__file__).resolve().parent
im=NativeImage();rows=[]
keywords=re.compile(r'city|cities|address|Taiwan|TWN|HWM|unicode|codepage|code_page|Chinese',re.I)
for encoding,pattern in [('ascii',rb'[ -~]{5,}'),('utf16le',rb'(?:[ -~]\x00){5,}')]:
 for m in re.finditer(pattern,im.data):
  text=m.group().decode('ascii' if encoding=='ascii' else 'utf-16le')
  if keywords.search(text):
   a=LOAD_BASE+m.start();runtime=[]
   try:runtime=[im.load_to_runtime(a,len(m.group()))]
   except ValueError:pass
   rows.append({'text':text,'encoding':encoding,'load_address':hex(a),'runtime_addresses':[hex(x) for x in runtime]})
assert len(rows)<1500
result={'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'stock_MAIN_sha256':EXPECTED,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'matched':rows,'string_presence_is_not_caller_or_provider_proof':True,'device_IO':False,'actual_query_executed':False}
(BASE/'city-provider-string-inventory-v1.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
for row in rows:
 if re.search(r'city|cities|addr.*manager|HWM',row['text'],re.I):print(row['load_address'],row['encoding'],row['text'])
