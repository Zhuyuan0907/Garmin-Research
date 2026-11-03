# Local AP header control materializer preparation

The fixed catalog binds the closed geometry-v2 plan/proof/seal. The two names are `eightK_end_mirror` and `expanded_fourK_geometry`. No source IMG was read or generated in this scope. Ordinary-host synthetic tests passed17 methods (396f0a EXIT0); real512-byte saved headers were used with synthetic bodies.

Metadata only (also the no-argument default):

```
python3 scripts/materialize_ap_header_control_v1.py --list
```

Future explicit local generation, not executed here; the output parent must already exist:

```
python3 scripts/materialize_ap_header_control_v1.py --control eightK_end_mirror --output /root/garmin/staging/AP-eightK-control.img.disabled
```

The CLI has no arbitrary manifest/source option. Source regular-file/inode/stat pins and full512 header are checked before creating a partial. Source EOF/size/fullSHA and computed virtual fullSHA must match the catalog. After fsync, the owned partial is reopened O_RDONLY|O_NOFOLLOW, inode/stat/size/EOF and actual saved fullSHA are verified separately; source stats are checked again. Atomic link publication refuses an existing destination. Symlink destinations and staging parent components are refused. Only the owned partial can be removed.

The error JSON receipt records `published`. A failure after successful publication, including directory fsync failure, preserves the verified final and reports published=true. Do not interpret every nonzero CLI status as no output. Existing foreign output/partial files are preserved. Hash fields are `source_actual_full_sha256`, `generated_computed_full_sha256` and `actual_saved_output_sha256`.

The tests demonstrate actual synthetic saved-file readback (including deliberate corruption), body preservation, wrong hashes/header/stat refusal, atomic race refusal, partial ownership, fsync/write failures and explicit guards under host Python -O. The first synthetic proof's fixture_max_bytes4096 denotes its base; the extra-length refusal uses4097 bytes, still below8KiB. Full real materialization, original-device acceptance/UI/routes/rendering/root cause, opaque checksum policy and installability remain false. No rollback adapter is supplied. No USB, discovery, native guest, PBF, MAIN, audio, installation, ZIP or shared report mutation occurs.

Source code, tests, catalog, proof and actual terminal receipt are sealed. Stop after this finite preparation; production --list may be run independently by root.
