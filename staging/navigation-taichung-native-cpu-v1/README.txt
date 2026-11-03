Bounded original CPU check of the actual Taichung candidate

Source: probe_actual_candidate_native_v1.py
Proof: actual-Taichung-candidate-original-CPU-proof-v1.json

Actual run exited0, session88957. Initial chunkfadf66; terminal chunk56df0a.
Proof SHA-256:
74093c0e8220be2e79d5ff11aa0d8105070385ce77570a3d4fc013031f4cd600

Candidate:
staging/navigation-taichung-native-candidate-v1/gmapprom1.img
100945920bytes, root full-readback SHA-256 reference:
3c03d0a09e24165f27b7ed275535552bfb3ea10defe0f492de6f51dfdaf9b00b
This probe did not repeat its whole-file hash or copy it.

The actual candidate FAT supplies its772-byte MDR header. The original native
header parser output supplies the directory decoder. The original directory
output supplies packed-record decoding. All offsets are derived from that
actual parser/directory output; no original or previous-candidate offset is
used to select candidate records. Original directory output reports L3 w0=23,
stride112,47870records; L4 contains2396236records.

Four actual selected parents:
  ID12924 一新一街     first2133949 count42
  ID15867 台灣大道六段 first2273518 count123
  ID16707 民權路       first2320045 count93
  ID18164 豐勢路       first2395510 count727
All firstchildren exceed the original L4 end2133948. Their numeric values
remain below4194304; this actual-candidate test does not independently exercise
a set high23rd bit. The previous synthetic width boundary proof stays separate.

Fourteen actual new leaves:
  一新一街1號
  台灣大道六段488號/989號
  民權路6/8/138/140/142/144/146/148/150號
  豐勢路9號/1366號
The nine Minquan payloads match the previously installed trial byte-for-byte,
including original existing LBL references and raw24coordinates. All14newleaf
bytes and decoded fields match the separate current producer rows. Parent
first/count/flags/name expectations come from producer-selected ranges;
remaining parent fields are CPU/direct-wire checks backed by the root's
separate original-preservation proof.

All18record prefixes reach0x0448F740, where they stop before metadata/registry.
The only function hooks supply underlying filesystem open/read/mapping. No
successful metadata, registry, query, sort, UI, or result is supplied. Each
record uses actual candidate bytes plus its actual following4bytes, ending at
an unmapped next page. This guards the supplied slice tail; it is not a claim
of complete native-reader memory-bound validation.

The actual GMP header supplies the LBL pointer. Its actual LBL header is input
to the original parser fragments. Each original native primary reference then
feeds original address arithmetic and the encoding10byte loop with a bounded
64-byte actual candidate window. All18labels match their independent names.
Host CP950 decoding displays the actual copied bytes. LBL blocks use explicit
staged stack/context inputs and are separate fragments, not a continued full
metadata/getter call.

Total actual candidate bytes read:60970, including FAT metadata. Source stat
was unchanged. Frozen harness methods were imported; their old main/cases did
not run. No closed suite, full record scan, installation, USB, service change,
canonical/report update, ZIP mutation, or performance benchmark was performed.
NativeImage verifies the exact Taiwan HWID1352 SW8.00 MAIN once for original
instructions; that is separate from the bounded map reads and makes no live
hardware claim.

Remaining integration work: complete metadata/provider/JAI/query behavior,
search ordering, UI and physical candidate acceptance/search/routing. This
proof does not establish a nationwide update or broader device-test success.
