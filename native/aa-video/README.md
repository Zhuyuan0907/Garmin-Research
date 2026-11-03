# Owned Android Auto video queue and software RGB565 surface

This is our Linux-host prototype. It does not install an App in GarminOS,
execute original Garmin instructions, use a phone or USB device, or display
pixels on a Garmin screen.

`video.c` implements the provider interface from `aa-control`. MEDIA accepts
and copies a whole compressed indication into one of two 262,144-byte slots.
The control ACK acknowledges this ownership transfer, not successful H.264
decoding or physical presentation. A full queue returns PAUSED without accepting
the input. The caller must serialize control, worker and teardown calls.

`aa_video_step()` feeds the queued bytes to `aa-h264`, advances only the exact
consumed prefix, and retries a decoder-owned output frame before consuming more
input. It is an explicit caller-driven worker, not an OS task or IRQ handler.
Packet boundaries do not define H.264 access-unit boundaries. Signed media
session values and 64-bit packet timestamps are retained; they do not establish
the phone's clock units or audiovisual synchronization.

STOP clears queued bytes and decoder state while allowing a later START on the
configured channel. Final EOF rejects new input. A frame held at EOF may return
PAUSED and subsequently FINISHED through `aa_video_step()`. Terminal decoder
errors are sticky until the owner tears down this context. `aa_video_stop()`
guards synchronous reentry during decoder teardown. None of these operations
prove asynchronous callback quiescence, immediate display blanking or speaker
muting.

`rgb565.c` converts a borrowed YUV420 frame into a caller-owned little-endian
RGB565 surface. The caller explicitly chooses BT.601 or BT.709 and full or
limited range, supplies readable plane capacities and output stride, and keeps
the frame alive during conversion. Nearest scaling uses the source pixel at
`floor(destination_position * source_size / destination_size)`. Output padding
is preserved. The converter does not infer phone VUI metadata or call a native
framebuffer API.

The full host integration harness is `scripts/test_aa_video_host.py`. Its
fixture peer uses actual local TLS and compiled control/receiver callbacks;
FFmpeg independently decodes generated Baseline/Main/High H.264 streams for
comparison. A generated 480×272 image, when a successful run records it, is a
decoded test pattern rather than Google Maps or a Garmin screen. Test success
must be established by the current proof and actual terminal result.

The compressed queue, workspace and dimension limits do not cap OpenH264's
internal heap. Real-time performance, native allocation and display APIs,
current-phone interoperability, touch, audio ownership and a device installation
package remain separate work.
