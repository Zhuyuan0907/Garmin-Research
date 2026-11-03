One actual primary-source北屯區 geometry is now ready as a separate prerequisite.

`geometry.json`144,506B SHAc4b4c2a842af2042ca4fff893fb9e5ccd33940ffe27e445aa3222121269d49b3.
`source-membership.json`4,204B SHAd624ec02eb3b79331cd4041a77a093b4dcf2bc14765578eca70196f88a9e0e84.
`beitun_membership.BeitunMembership(directory=...,engine_path=...)` provides:

- assess_source_point('台中市','北屯區',latitude_string,longitude_string)
- assess_raw24('台中市','北屯區',latitude_wire_u24,longitude_wire_u24)

Each returns eligible/status plus exact source relation and native-name context.
The API pins geometry, membership/proof and the existing pure signed-winding
engine. Raw24 uses exact rational values, not rounding back to OSM7 decimals.
Wrong city/district refuses instead of assigning or normalizing another name.
Booleans/invalid raw24, invalid source coordinates and excess source precision
are refused. Source city spelling臺中市→native台中市 is an explicit observed
name relationship in the dataset, not a general alias mapper.

Existing small admin PBF4,349,834B SHA5b8cd8d...949c7d was used, not the full
327MB Taiwan PBF. Actual city-parent-only getid verifies relation2921154
(臺中市/TW-TXG) has exact relation2959946 subarea member. Old selected closure
has390relations/388complete/allclosed=false;2959946 individually complete,
one outer ring/no missing ways/nodes. New actual getid-r includes target北屯區
plus42 recursive source subarea里 relations,5,803nodes/173ways. These children
are present as source references; the target district's own outer boundary is
exported. No village polygon union substitutes for it. check-refs-r/export
passed with the target name/admin_level7 and closed exported ring.

The initial source assumed getid-r would return one total relation and stopped
EXIT1/f3656c at that assertion. The original assumption source and failure
receipt are preserved. The corrected run reused the835,376B extraction; it did
not rerun the PBF extraction. Actual corrected preparation EXIT0/80d17c; actual
new wrapper/identity7controls EXIT0/988247. No old21city/KH/flat/CPU suite replay.

For sourcegroup37506/node8280986017,敦富六街368號:
source point24.1882244/120.7079937 and raw24[1127253,5625400] both pass this exact
source北屯區 geometry. Native cityrecord0x10000008/districtrecord0x2000004a are
the existing names; this is primary-source geographic membership, not OEM
territory verification or device acceptance. Source historical aliases,
official street authenticity/physical newroad and native query/UI remain unproved.

The closed fullDB prototype's earlier geometrygap stays unchanged: this is NEW
evidence that can be joined later by its explicit seal, rather than rewriting
old proofs. No original DB/newIMG/package/canonical/report/device operation.
install_candidate=false. All handles and temporary controls are closed/removed.
Scope complete; see proof.json/new-membership-control-proof.json/actual-receipts.json
and sealed-files.json for exact identity, command exits and limitations.
