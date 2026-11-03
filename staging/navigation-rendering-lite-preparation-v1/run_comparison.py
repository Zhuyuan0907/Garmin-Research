#!/usr/bin/env python3
"""Print a reproducible baseline/lite command; launch Java only with --execute.

This tool only builds into this preparation namespace. It never packages or
installs a map, mutates report/canonical files, or replaces frozen evidence.
"""
from pathlib import Path
import argparse,hashlib,json,datetime,subprocess,os
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()

def resource_gate():
 active=[]
 for p in Path('/proc').iterdir():
  if not p.name.isdigit() or int(p.name)==os.getpid():continue
  try:b=(p/'cmdline').read_bytes().replace(b'\0',b' ')
  except (PermissionError,FileNotFoundError,ProcessLookupError):continue
  # Only actual ingestion executables, not this source's strings or shell readers.
  if (b'prepare_taiwan_address_ingestion.py' in b and (b.startswith(b'python') or b.startswith(b'/usr/bin/python'))) or (b.startswith(b'osmium ') and b'tags-filter' in b):active.append(p.name)
 available=next(int(x.split()[1])*1024 for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
 if active:raise SystemExit('Refuse Java: source ingestion processes still active: '+','.join(active))
 if available<1536*1024*1024:raise SystemExit('Refuse Java: MemAvailable below 1536MiB')
 return {'source_scan_processes':active,'MemAvailable_bytes':available}

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--variant',choices=['baseline','lite'],required=True);ap.add_argument('--fixture',action='store_true');ap.add_argument('--execute',action='store_true',help='Root only after confirming source scan ended and RAM freed. Default prints command without launching Java.');a=ap.parse_args()
 j=json.loads((OUT/'compile-inputs.json').read_text());style=OUT/(a.variant+'-style')
 for r in j['fixed_inputs']:
  p=ROOT/r['path'];assert p.is_file() and p.stat().st_size==r['bytes'] and sha(p)==r['sha256'],str(p)
 proof=json.loads((OUT/'source-preparation-proof.json').read_text())
 for r in proof['file_identity_controls']:
  assert sha(style/r['path'])==r[a.variant+'_sha256']
 mode='fixture' if a.fixture else 'real-tile';dest=OUT/'runs'/f'{mode}-{a.variant}'
 command=['nice','-n','10','java','-Xmx96m' if a.fixture else '-Xmx768m','-cp',j['classpath'],'uk.me.parabola.mkgmap.main.Main','--max-jobs=1','--route','--index','--housenumbers','--gmapsupp','--code-page=65001','--name-tag-list=name:zh-Hant,name:zh,name,int_name','--drive-on=right','--country-name=Taiwan','--country-abbr=TWN','--region-name=Taiwan','--region-abbr=TW','--location-autofill=is_in']
 if not a.fixture:command+=['--bounds='+str(ROOT/j['bounds'])]
 command+=['--style-file='+str(style),'--family-id=7053','--product-id=1','--family-name=OSM TW 2026-10-01 Search v2','--series-name=OSM Taiwan Search v2','--description=OSM TW 2026-10-01 Search v2','--copyright-file='+str(ROOT/j['copyright']),'--license-file='+str(ROOT/j['license']),'--output-dir='+str(dest),'--mapname=70530020',str(OUT/'tiny-fixture.osm' if a.fixture else ROOT/j['source_tile'])]
 info={'variant':a.variant,'mode':mode,'prepared_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':command,'cwd':str(OUT),'same_controlled_FID_and_mapname':True,'device_installable':False,'execution_requested':a.execute}
 if not a.execute:
  print(json.dumps(info,ensure_ascii=False,indent=2));return
 info['resources']=resource_gate()
 assert not dest.exists(),'One-shot output exists; preserve previous success/failure, use a new namespace for another run.'
 dest.mkdir(parents=True);(dest/'start.json').write_text(json.dumps(info,indent=2)+'\n')
 with (dest/'mkgmap.log').open('x') as f:p=subprocess.run(command,cwd=OUT,stdout=f,stderr=subprocess.STDOUT)
 info.update(actual_exit_code=p.returncode,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),real_device_acceptance=False,full_Taiwan_coverage=False,performance_verified=False)
 if p.returncode==0:
  info['outputs']=[{'path':str(x.relative_to(ROOT)),'bytes':x.stat().st_size,'sha256':sha(x)} for x in sorted(dest.glob('*.img'))]
 (dest/'terminal-receipt.json').write_text(json.dumps(info,indent=2)+'\n');print(json.dumps({'variant':a.variant,'actual_exit_code':p.returncode,'receipt':str(dest/'terminal-receipt.json')}))
 raise SystemExit(p.returncode)
if __name__=='__main__':main()
