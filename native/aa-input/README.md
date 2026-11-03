# Serialized public Android Auto input prototype

This is our Linux-host input encoder. It neither loads an App into GarminOS nor
reads a touchscreen, acquires a clock, uses USB, or establishes Pixel acceptance.
The fixed public aasdk schema describes PRESS (0), RELEASE (1) and DRAG (2).
Its repeated locations do not establish Android multi-pointer or CANCEL
semantics. This API deliberately implements one pointer, buttons and a wheel.

The caller supplies exactly the profile passed to `aa_control_init()`. The
encoder derives advertised touch dimensions and supported keys from that
profile. Its provider accepts channel-open and binding requests. Input remains
unavailable until the real control reports BOUND, after the entire successful
binding response has been committed to transport. Binding stores the requested
key subset; an advertised key that was not bound is rejected.

Touch maps a calibrated local viewport into the explicitly advertised coordinate
domain using floor(position × touch_dimension / viewport_dimension). This is an
explicit policy aligned with our nearest software renderer, not a guarantee
from OpenAuto: the fixed OpenAuto code advertises local touch dimensions while
scaling events to a different video domain. PRESS outside the viewport is
rejected. Once captured, DRAG and RELEASE clamp outside coordinates to its
edges so a pointer can be released. `aa_input_release_touch()` emits RELEASE at
the last accepted coordinate on capture loss; it does not invent CANCEL.
Rotation, calibration and display geometry changes remain the owner's work.

All calls use a caller-provided uint64 microsecond timestamp in one nondecreasing
domain. Equal timestamps and uint64 extremes are representable. The encoder
does not synchronize clocks with a phone. Proto3 zero values may be omitted,
but touch-event and location message presence is maintained for an origin PRESS.
`disp_channel` remains zero, matching the pinned source; it is not set to the
video channel identifier.

Eight 256-byte owned output slots preserve input order. Logical pointer/key
state advances only after successful enqueue; PAUSED means no acceptance and
the caller must retry the same event. Long press requires an already-held key.
Wheel events use the bound SCROLL_WHEEL code 65536 and a nonzero signed delta.
Queue peek is borrowed until commit or stop. The owner must use one serialized
sender for control and input, remember the originating queue and token, and
commit the matching queue only after the final wire byte succeeds. Transport
failure abandons the entire TLS session.

Stop discards unsent events without emitting releases. An orderly owner must
release held input while bound, drain it, then tear down. There is no async
callback quiescence or physical display lifecycle guarantee. New generated
files use a separate 10-schema closure and the existing unmodified nanopb
runtime; the control43/proto/video20 source pins remain unchanged.
