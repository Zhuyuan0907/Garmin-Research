# Bounded public Android Auto protobuf schemas

This is an ordinary Linux-host serialization layer, not GarminOS source code,
an installed application, or a proven Pixel Android Auto implementation. The
schemas are the exact public aasdk files at commit
`046b3b381595509d0939fa84b14a90978f46ff63`; the complete 45-file import closure
is retained under `schema/`. Their original GPL notices remain intact.

`proto.h` includes 19 control-service message types and the nanopb C runtime.
The public names follow generated nanopb conventions:
`f1x_aasdk_proto_messages_ServiceDiscoveryResponse`, its `_init_zero` and
`_init_default` initializers, and its `_fields` descriptor. All nested channel
descriptors and enum types are available through those includes. The local
build manifest lists the 48 required C source files and include directories.

The generator and runtime are pinned nanopb 0.4.9.1 from the official release.
The runtime is unmodified and its license is retained in `runtime/LICENSE.txt`.
Protoc 21.12 comes from the official protobuf release; archive/source hashes
and generation command results are recorded under
`staging/android-auto-proto-host-v1/`. Separate `bounded.options` controls all
static storage. No generated callbacks, dynamic fields, or malloc are enabled.
Compile every translation unit with `PB_VALIDATE_UTF8=1` and never define
`PB_ENABLE_MALLOC`.

## Capacities and ownership

The principal limits are eight channels, 128 binding scan codes, eight AV
setup configuration indexes, four audio configurations, four video
configurations, and 64 advertised input key codes. Identity strings use
64-byte C arrays, so their maximum is 63 UTF-8 bytes plus the terminating NUL.
Other imported fields also have explicit bounds in the options file. These
are implementation limits, not guarantees about a current Android phone.

Call `pb_decode` with a complete caller-owned plaintext protobuf payload and
a fresh zero/default-initialized object. A failed decode can partially modify
the object; discard it. Successful decode copies the data into the object,
so it does not retain the source payload. Supply a bounded output stream to
`pb_encode`; on failure discard its partially written bytes. Generated
`ServiceDiscoveryResponse_size` is 8,294 bytes, larger than the root sender's
8,192-byte slot. A particular advertised service configuration must actually
encode within the slot before publication; the schema maximum alone does not
establish that.

## Protobuf policy and limits

Unknown fields are skipped and are not preserved on reencoding. Scalar
duplicates select the last value. Repeated primitives accept legal packed
and unpacked encodings but are rejected when their fixed element count is
exceeded. Proto2 required fields must be present, even if the numeric value is
zero; proto3 default values may be omitted. Ping timestamps are signed
`int64`, not `uint64`; unsigned-64 coverage in the host test concerns nanopb's
varint primitive and an independent test-only Python schema.

The unmodified nanopb runtime does not enforce enum value membership the same
way as Python's closed proto2 enum implementation. The control dispatcher
must validate status/focus/configuration enum values before interpreting
them. Protobuf strings containing embedded NUL also lose their suffix when
represented and reencoded as static C strings. Identity strings here are C
display labels; applications requiring exact protobuf-string fidelity must
reject embedded NUL before decode or use a different generated field type.
UTF-8 validation alone does not resolve embedded-NUL semantics.

## Verification

`scripts/test_aa_proto_host.py` builds ordinary GCC and ASan/UBSan executables,
tests required/default/malformed/limit behavior, and compares all 19 message
types with the independent Python protobuf runtime. It also decodes an
independently constructed C service response in Python, tests negative
`int32` and signed-64 extremes, and checks runtime object dependencies for
heap allocation symbols. The test records observed cross-runtime semantic
limits rather than hiding them. Proof is written only after actual successful
completion to `evidence/android-auto-proto-host-v1.json`.

These tests have no USB/Bluetooth/device I/O, original Garmin instructions,
Garmin guest execution, ARM cross-compilation, TLS/wire pipeline invocation,
or phone-session verification. Bounds, protocol policy, and integration
remain caller responsibilities.
