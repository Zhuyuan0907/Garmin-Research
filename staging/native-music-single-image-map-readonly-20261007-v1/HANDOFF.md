# Exact map compatibility review

The adapter's 11 fixed code/state addresses match the exact older continuous manifest SHA 50a2dd7f312b2aa34ae9cd3283a20968840fa32edb7667bde0d62b1d73afaabe. Runtime/Source views agree at source level; the remaining private views are not a complete ABI verification. Five read source hashes match the same manifest and frozen controller registry.

The older continuous image has no umc_/umcn_/native_player_ exports or GUI/controller/adapter units. The adapter ARM recipe links only three relocatable objects. Its ten controller functions have a concrete table in host_controls.c, whose other providers and state are fixtures. The binding helper always returns UMCN_BINDING_MISSING and does not initialize missing ownership/session/context/residency fields; it also does not clear caller-supplied values in those fields.

Parent independently confirmed a later loaded-v2 image includes the controller in one link. That does not bind these older absolute addresses or add the absent adapter/GUI providers. No generic relocation delta was applied. The next useful file-only evidence is that later image's exact final state/function/table provider map and linker membership, not an inference from the older map.

Source content: 12 files, 139,365 B, each <=64 KiB, aggregate <=150 KiB. Index/metadata discovery I/O is separate and not claimed as a complete total. All selected source handles closed; no native target, guest, compile, producer import, ELF/firmware/RAM body, device/DBus or audio activity. The local JavaScript selector parse failure occurred before a tool call and read no files.

Read terminal receipts: c9fe26 / df8932 / 2c89d6, each EXIT 0. Sealer receipt is recorded separately after its real terminal return. Output hashes bind emitted UTF-8 bytes plus actual size/stat; no independent artifact full readback is claimed. Shared inputs and old seals remain unchanged.

Ownership, STOP_DONE, native App, direct phone A2DP, speaker and installability remain false. Review complete; STOP.
