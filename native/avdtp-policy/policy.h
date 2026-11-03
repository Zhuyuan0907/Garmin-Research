#ifndef GARMIN_AVDTP_POLICY_H
#define GARMIN_AVDTP_POLICY_H
#include <stdint.h>

/* Caller owns these objects. Single actor; snapshots must be coherent and
 * taken under the appropriate native lock. Callback session IDs are captured
 * when work is queued, never inferred from reused LCIDs. No OS binding here.
 * local_receive_mtu is the local receive limit, not the peer receive MTU
 * stored in the stock channel entry.
 * Configuration input is the complete SetConfiguration body, before the stock
 * acceptance reply. Validation output must not alias input or guard storage.
 */
struct music_config {
    uint32_t local_seid, remote_seid, codec_word, rate, channels;
    uint32_t blocks, subbands, allocation, mode;
};
struct music_guard {
    uint32_t active, session, local_seid, remote_seid, codec_word;
};
struct music_native_view {
    uint32_t state, pending, local_seid, remote_seid;
    uint32_t channel_index, sep_channel_index, lcid, type, owner_sep;
    uint32_t flags, codec_word, local_receive_mtu;
};
enum music_policy_error {
    MUSIC_BAD_ARGUMENT=-10, MUSIC_BAD_SEID=-11, MUSIC_BAD_SERVICE=-12,
    MUSIC_UNSUPPORTED_SERVICE=-13, MUSIC_BAD_CODEC=-14, MUSIC_BAD_SESSION=-15,
    MUSIC_BUSY=-16, MUSIC_BAD_STATE=-17, MUSIC_BAD_CHANNEL=-18,
    MUSIC_BAD_PACKET_SIZE=-19
};
uint32_t music_config_bytes(void);
uint32_t music_guard_bytes(void);
uint32_t music_view_bytes(void);
int music_validate_configuration(const uint8_t *,uint32_t,uint32_t,struct music_config *);
int music_guard_bind(struct music_guard *,uint32_t,const struct music_config *);
int music_guard_unbind(struct music_guard *,uint32_t);
int music_guard_packet(const struct music_guard *,uint32_t,const struct music_native_view *,uint32_t);
/* Consumed frame length on success; caller must still verify SBC CRC/decode.
 * Input starts at an SBC frame, after RTP/SBC packet header parsing.
 */
int music_guard_frame(const struct music_guard *,uint32_t,const uint8_t *,uint32_t);
#endif
