from pathlib import Path
import hashlib,json,stat
HERE=Path(__file__).resolve().parent
files=[]
for p in sorted(HERE.iterdir()):
    if p.name=="sealed-files.json":continue
    st=p.lstat()
    if not stat.S_ISREG(st.st_mode):raise RuntimeError("nonregular research output")
    if st.st_size>65536:raise RuntimeError("unexpected oversized research artifact")
    raw=p.read_bytes();p.chmod(0o444)
    files.append({"path":str(p.relative_to(HERE.parents[1])),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"mode":"0444"})
if sum(f["bytes"] for f in files)>131072:raise RuntimeError("research output exceeds128KiB")
seal={"schema":"android-garmin-hfp-research-seal/v1","all_assigned_checks_passed":True,"runtime_success":False,"device_IO":False,"research_stop":True,"files":files}
f=HERE/"sealed-files.json";f.write_text(json.dumps(seal,ensure_ascii=False,indent=2)+"\n");f.chmod(0o444)
print(json.dumps({"all_assigned_checks_passed":True,"runtime_success":False,"file_count":len(files),"total_bytes":sum(f["bytes"] for f in files),"seal_sha256":hashlib.sha256(f.read_bytes()).hexdigest(),"proof_sha256":hashlib.sha256((HERE/"proof.json").read_bytes()).hexdigest(),"summary_sha256":hashlib.sha256((HERE/"feasibility-summary.json").read_bytes()).hexdigest(),"sources_sha256":hashlib.sha256((HERE/"sources.json").read_bytes()).hexdigest(),"stop":True},sort_keys=True))
