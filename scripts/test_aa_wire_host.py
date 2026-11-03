#!/usr/bin/env python3
"""Compile/test only new aa-wire Linux-host C, no native/firmware imports."""
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

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "native/aa-wire"
EVIDENCE = ROOT / "evidence/android-auto-wire-host-v1.json"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def main():
    started = utc()
    cc = os.environ.get("AA_WIRE_HOST_CC", "cc")
    receipts = []
    passed = False
    results = {}
    def run(label, argv, expected=0, env=None):
        before = utc(); clock = time.monotonic()
        r = subprocess.run(argv, cwd=ROOT, env=env, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=60, check=False)
        receipt = {"label": label, "argv": argv, "started_utc": before,
                   "finished_utc": utc(), "seconds": time.monotonic()-clock,
                   "exit_code": r.returncode, "stdout": r.stdout,
                   "stderr": r.stderr, "expected_exit": expected}
        receipts.append(receipt)
        if expected == "nonzero":
            if r.returncode == 0: raise RuntimeError(label+" mutation unexpectedly passed")
        elif r.returncode != expected:
            raise RuntimeError(label+" failed with "+str(r.returncode))
        return r
    try:
        version = run("compiler-version", [cc,"--version"]).stdout.splitlines()[0]
        common = [cc,"-std=c11","-Wall","-Wextra","-Werror","-Wpedantic",
                  "-I",str(BASE)]
        source = str(BASE/"wire.c"); tests = str(BASE/"test_wire.c")
        with tempfile.TemporaryDirectory(prefix=".host-wire-v1-",dir=BASE) as temporary:
            temp=Path(temporary)
            normal=temp/"wire-tests"; sanitized=temp/"wire-tests-sanitized"
            run("compile-host",common+["-O2",source,tests,"-o",str(normal)])
            normal_sha=sha(normal)
            r=run("run-host",[str(normal)])
            match=re.search(r"^RESULT (.+)$",r.stdout,re.MULTILINE)
            if not match:raise RuntimeError("host result missing")
            results["normal"]=json.loads(match.group(1))
            run("compile-host-asan-ubsan",common+["-O1","-g","-fno-omit-frame-pointer",
                "-fsanitize=address,undefined",source,tests,"-o",str(sanitized)])
            sanitized_sha=sha(sanitized)
            environment=dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
                             UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
            r=run("run-host-asan-ubsan",[str(sanitized)],env=environment)
            match=re.search(r"^RESULT (.+)$",r.stdout,re.MULTILINE)
            if not match:raise RuntimeError("sanitized result missing")
            results["asan_ubsan"]=json.loads(match.group(1))
            if results["normal"]!=results["asan_ubsan"]:
                raise RuntimeError("normal/sanitized test counts differ")
            original=Path(source).read_text()
            mutations=[
                ("first-total-discarded", "? read32(p->header + 4) : 0;", "? 0 : 0;"),
                ("first-extension-skipped", "p->header_needed = 8;\n                continue;", "p->header_needed = 4;"),
                ("paused-frame-discarded",
                 "if (status == AA_WIRE_PAUSED) return leave(p, AA_WIRE_PAUSED);",
                 "if (status == AA_WIRE_PAUSED) status = AA_WIRE_OK;")]
            # Each deliberately wrong parser is independent host code generated
            # from ONLY our new source. No instruction/binary/guest mutation.
            controls=[]
            for name,old,new in mutations:
                if original.count(old)!=1:raise RuntimeError("mutation anchor missing "+name)
                mutant=temp/(name+".c"); mutant.write_text(original.replace(old,new))
                # read32 becomes unused for the first mutation; keep strict
                # compilation by preserving a harmless standalone invocation.
                if name=="first-total-discarded":
                    mutant.write_text(mutant.read_text().replace("frame.payload = p->storage;",
                        "(void)read32(p->header);\n            frame.payload = p->storage;"))
                out=temp/name
                run("compile-negative-control-"+name,common+["-O2",str(mutant),tests,"-o",str(out)])
                r=run("run-negative-control-"+name,[str(out)],expected="nonzero")
                if r.returncode!=2 or "FAIL:" not in r.stderr:
                    raise RuntimeError("negative control did not fail an assertion "+name)
                controls.append({"name":name,"mutant_source_sha256":sha(mutant),
                    "binary_sha256":sha(out),"observed_exit_code":r.returncode,
                    "failure":r.stderr.strip()})
            results["mutation_controls"]=controls
            results["binary_hashes"]={"normal":normal_sha,"asan_ubsan":sanitized_sha}
        passed=True
    except Exception as exc:
        results["failure"]=str(exc)
        raise
    finally:
        provenance=json.loads((BASE/"provenance.json").read_text())
        pins={str(p.relative_to(ROOT)):{"sha256":sha(p),"bytes":p.stat().st_size}
              for p in [BASE/"wire.c",BASE/"wire.h",BASE/"test_wire.c",
                        BASE/"README.md",BASE/"COPYING",BASE/"provenance.json",
                        Path(__file__).resolve()]}
        proof={"schema":"android-auto-wire-host-v1","started_utc":started,
            "finished_utc":utc(),"success":passed,"compiler":locals().get("version"),
            "platform":{"system":platform.system(),"machine":platform.machine(),
                        "python":platform.python_version()},
            "source_files":pins,"upstream_reference":provenance,"results":results,
            "actual_subprocess_receipts":receipts,
            "compiled_test_artifacts_retained":False,
            "scope":{"linux_host_C_executed":True,
                "garmin_firmware_or_instruction_read":False,"garmin_firmware_executed":False,
                "arm_guest_or_emulator_executed":False,"existing_native_producer_imported":False,
                "garmin_callsite_modified":False,"usb_device_io":False,
                "phone_tested":False,"tls_authenticated_or_decrypted":False,
                "plaintext_message_assembly":False,"current_pixel_compatibility_proven":False,
                "installed_or_installable":False,"android_auto_running_on_garmin":False,
                "google_maps_running_on_garmin":False},
            "next_integration_requirement":"Feed opaque frames into a real TLS/decrypted-message layer with matching lifecycle, capacity and callback retention; FIRST plaintext total cannot validate ciphertext length."}
        EVIDENCE.write_text(json.dumps(proof,indent=2)+"\n")
    print(json.dumps({"success":passed,"evidence":str(EVIDENCE.relative_to(ROOT)),
                      "sha256":sha(EVIDENCE),"results":results},indent=2))

if __name__=="__main__":
    main()
