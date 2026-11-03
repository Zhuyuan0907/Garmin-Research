#!/usr/bin/env python3
"""Only our new portable C assembler is compiled/run for ordinary Linux host."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import time
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/"native/aa-message"
EVIDENCE=ROOT/"evidence/android-auto-message-host-v1.json"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def main():
    started=utc();receipts=[];results={};passed=False
    cc=os.environ.get("AA_MESSAGE_HOST_CC","cc")
    def run(label,argv,expect=0,env=None):
        now=utc();clock=time.monotonic()
        try:
            r=subprocess.run(argv,cwd=ROOT,env=env,text=True,stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,timeout=60,check=False)
        except Exception as exc:
            receipts.append({"label":label,"argv":argv,"started_utc":now,
                "finished_utc":utc(),"seconds":time.monotonic()-clock,"exception":repr(exc)})
            raise
        receipts.append({"label":label,"argv":argv,"started_utc":now,
            "finished_utc":utc(),"seconds":time.monotonic()-clock,"exit_code":r.returncode,
            "stdout":r.stdout,"stderr":r.stderr,"expected_exit":expect})
        if expect=="assertion-exit-2":
            if r.returncode!=2 or "FAIL:" not in r.stderr:
                raise RuntimeError(label+" did not fail an assertion")
        elif r.returncode!=expect:raise RuntimeError(label+" exited "+str(r.returncode))
        return r
    provenance=json.loads((BASE/"provenance.json").read_text())
    try:
        for rel,pin in provenance["sources"].items():
            p=ROOT/rel
            if p.stat().st_size!=pin["bytes"] or sha(p)!=pin["sha256"]:
                raise RuntimeError("upstream reference changed "+rel)
        compiler=run("compiler-version",[cc,"--version"]).stdout.splitlines()[0]
        common=[cc,"-std=c11","-Wall","-Wextra","-Werror","-Wpedantic","-I",str(BASE)]
        source=str(BASE/"message.c");tests=str(BASE/"test_message.c")
        with tempfile.TemporaryDirectory(prefix=".host-message-v1-",dir=BASE) as d:
            temp=Path(d);normal=temp/"message-tests";san=temp/"message-tests-sanitized"
            run("compile-host",common+["-O2",source,tests,"-o",str(normal)])
            normal_sha=sha(normal);r=run("run-host",[str(normal)])
            match=re.search(r"^RESULT (.+)$",r.stdout,re.MULTILINE)
            if not match:raise RuntimeError("normal result missing")
            results["normal"]=json.loads(match.group(1))
            run("compile-host-asan-ubsan",common+["-O1","-g","-fno-omit-frame-pointer",
                "-fsanitize=address,undefined",source,tests,"-o",str(san)])
            san_sha=sha(san)
            env=dict(os.environ,ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
                     UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
            r=run("run-host-asan-ubsan",[str(san)],env=env)
            match=re.search(r"^RESULT (.+)$",r.stdout,re.MULTILINE)
            if not match:raise RuntimeError("sanitized result missing")
            results["asan_ubsan"]=json.loads(match.group(1))
            if results["normal"]!=results["asan_ubsan"]:raise RuntimeError("test counts differ")
            original=Path(source).read_text()
            mutations=[
                ("channel-check-removed","f->channel!=p->channel || properties!=p->flags", "properties!=p->flags"),
                ("short-last-published","if(kind==AA_MESSAGE_LAST && f->bytes!=(size_t)total-p->bytes)","if(0)"),
                ("accepted-status-cleared","p->bytes+=f->bytes;++p->fragments;*accepted=1;","p->bytes+=f->bytes;++p->fragments;*accepted=0;"),
                ("first-fragment-not-copied","for(i=0;i<f->bytes;++i)p->storage[p->bytes+i]=f->payload[i];","if(kind!=AA_MESSAGE_FIRST)for(i=0;i<f->bytes;++i)p->storage[p->bytes+i]=f->payload[i];")]
            controls=[]
            for name,old,new in mutations:
                if original.count(old)!=1:raise RuntimeError("mutation anchor changed "+name)
                mutant=temp/(name+".c");mutant.write_text(original.replace(old,new));binary=temp/name
                run("compile-control-"+name,common+["-O2",str(mutant),tests,"-o",str(binary)])
                r=run("run-control-"+name,[str(binary)],expect="assertion-exit-2")
                controls.append({"name":name,"source_sha256":sha(mutant),"binary_sha256":sha(binary),
                                 "observed_exit_code":r.returncode,"failure":r.stderr.strip()})
            results["mutation_controls"]=controls
            results["binary_hashes"]={"normal":normal_sha,"asan_ubsan":san_sha}
        passed=True
    except Exception as exc:
        results["failure"]=str(exc);raise
    finally:
        source_pins={str(p.relative_to(ROOT)):{"sha256":sha(p),"bytes":p.stat().st_size}
          for p in [BASE/"message.c",BASE/"message.h",BASE/"test_message.c",BASE/"README.md",
                    BASE/"COPYING",BASE/"provenance.json",Path(__file__).resolve()]}
        proof={"schema":"android-auto-message-host-v1","started_utc":started,"finished_utc":utc(),
            "success":passed,"compiler":locals().get("compiler"),
            "platform":{"system":platform.system(),"machine":platform.machine()},
            "source_files":source_pins,"upstream_reference":provenance,"results":results,
            "actual_subprocess_receipts":receipts,"compiled_test_artifacts_retained":False,
            "scope":{"linux_host_C_executed":True,"complete_plaintext_fragments_supplied":True,
                "wire_parser_integrated":False,"tls_authenticated_or_decrypted":False,
                "garmin_firmware_or_instructions_read_or_executed":False,"arm_guest_or_emulator_executed":False,
                "existing_native_producer_imported":False,"garmin_callsite_modified":False,"device_io":False,
                "phone_tested":False,"current_pixel_compatibility_proven":False,
                "installed_or_installable":False,"android_auto_running_on_garmin":False,
                "google_maps_running_on_garmin":False},
            "integration_contract":"Pop an accepted final fragment even when callback is PAUSED; retry owned complete message without refeeding ciphertext/plaintext. Push pending new fragments returns PAUSED with accepted=0."}
        EVIDENCE.write_text(json.dumps(proof,indent=2)+"\n")
    print(json.dumps({"success":passed,"evidence":str(EVIDENCE.relative_to(ROOT)),"sha256":sha(EVIDENCE),"results":results},indent=2))
if __name__=="__main__":main()
