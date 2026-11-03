# Coherent AP control rollback binding preflight

The pure-host adapter supports only `eightK_end_mirror`. It does not open/stat an IMG, write a file, expose a CLI, install or discover a device. The original `native_8k_stock_restore.py` remains unchanged at SHA43e041518baa72bfbdbc26c627d435749c4bf85adf7882e47ffcfb655c46fe5f.

Fixed identities:

| View | Bytes | SHA256 |
| --- | ---: | --- |
| Coherent8K actual input |153346048|9af1e68e1308bf28deeb7f7d4c7cfab88efd0063c38f4f2df77fcde352990dd3|
| Declared inverse old-v3 view |153346048|1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360|
| Exact original STOCK4K stream |96739328|864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2|
| Coherent expanded4K, unsupported here |153337856|8749b2614f0ef4cfb3ac631dd316b35dd3551e3ab97d2ac058f13a89052f50f6|

`prepare_fixed_inputs()` reads only pinned small plan/proof/header/seal/helper/recipe/binding files. The closed879499-byte stock recipe decompresses once to1779988 bytes. The old actual-v3 binding is recomputed by the unchanged helper and must match byte-parsed logical content exactly. Its source identity, all six component allocations and table descriptors remain unchanged. The inverse512 header matches the old helper's exact expected4096 header prefix. This is a declared reversible view, not direct old-helper acceptance of the coherent header.

Future authorized use, not run in this scope: load fixed inputs once; pass a caller-owned regular read-only `rb` descriptor to `verified_eightk_overlay`. It verifies exact corrected512 bytes, fullsize, actual coherent fullSHA, computed inverse fullSHA, EOF and immutable fd identity before returning any view. The view retains true fileno/mode identity and only supplies bounded read/seek/tell; it cannot write or close the borrowed source. It substitutes original bytes only for reads intersecting the first512 bytes; the only differing byte is452 (224→208). Body bytes and all new content stay untouched. A read or seek detects source stat changes.

Feed that verified view into the unchanged helper's `restored_stock_blocks` with the closed recipe and old binding. Consume through generator EOF, compare exact STOCK size/SHA and record original fd/path final stat and handle closure. The old helper still verifies strict8K header/FAT, all allocations, MDR header/directory and native profile; stock original header/FAT/L3/padding and lower stock prefixes are reconstructed by the existing recipe. No second full backup or restored IMG is needed. Real coherent-file final path/stat/receipt must first be sealed and bound; a newly materialized file has its own inode and must not inherit old source inode claims.

Ordinary-host preflight f60f26 EXIT0 passed8 methods: actual-fd inverse bounded reads via old helper, body preservation, wrong corrected header/fullSHA/inverseSHA, read-write fd refusal, post-verification source mutation and retained old guards. Each synthetic buffer/file is at most8192 bytes. The direct old helper rejects a corrected8K header at its exact-header guard; it rejects expanded4K153337856 bytes at its existing32768×4096 limit. Synthetic guards use a declared production length with small fake data and do not prove a full real container parse. No actual candidate full hash, full inverse hash, stock generator or native/UI/device result was executed here. Convenience generator production runtime is untested.

Expanded4K has a different actual FAT/layout and exceeds the old4K geometry/size profile. It needs a separately pinned exact descriptor and strict supported-profile API. Do not weaken arbitrary-file guards. Header byte15/opaque checksum, admission, UI, routes, renderer root cause and installability remain unknown/false. Old helpers, images, seals and reports are untouched. This finite preparation is sealed and stopped.
