/*
 * Stable wire and decoder ABI for optional dc-tool telemetry modules.
 *
 * The wire format is deliberately byte-addressed rather than a packed C
 * struct: Dreamcast and host code may have different alignment rules, and a
 * decoder module may be built for either a 32- or 64-bit host.  All multibyte
 * wire values are little-endian.  One complete frame occupies one DC22
 * console-push payload; frames are never concatenated or split.
 */
#ifndef DCTOOL_TELEMETRY_H
#define DCTOOL_TELEMETRY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DCTOOL_TELEMETRY_MAGIC              "DCTM"
#define DCTOOL_TELEMETRY_WIRE_VERSION       1u
#define DCTOOL_TELEMETRY_HEADER_SIZE        20u
#define DCTOOL_TELEMETRY_FRAME_MAX          1440u

#define DCTOOL_TELEMETRY_OFF_MAGIC          0u
#define DCTOOL_TELEMETRY_OFF_VERSION        4u
#define DCTOOL_TELEMETRY_OFF_KIND           5u
#define DCTOOL_TELEMETRY_OFF_HEADER_SIZE    6u
#define DCTOOL_TELEMETRY_OFF_FLAGS          7u
#define DCTOOL_TELEMETRY_OFF_PAYLOAD_SIZE   8u
#define DCTOOL_TELEMETRY_OFF_SCHEMA_ID     10u
#define DCTOOL_TELEMETRY_OFF_SEQUENCE      12u
#define DCTOOL_TELEMETRY_OFF_CRC32         16u

enum dctool_telemetry_kind {
    DCTOOL_TELEMETRY_KIND_SCHEMA = 1,
    DCTOOL_TELEMETRY_KIND_SAMPLE = 2,
    DCTOOL_TELEMETRY_KIND_ERROR  = 3
};

static inline uint16_t dctool_telemetry_read_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t dctool_telemetry_read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline void dctool_telemetry_write_le16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static inline void dctool_telemetry_write_le32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static inline uint32_t dctool_telemetry_crc32_update(uint32_t crc,
                                                     const uint8_t *data,
                                                     uint32_t size)
{
    uint32_t i;

    while(size--)
    {
        crc ^= *data++;
        for(i = 0; i < 8; ++i)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return crc;
}

/* The caller must first establish that frame_size is at least HEADER_SIZE.
 * The checksum field itself is omitted from the calculation. */
static inline uint32_t dctool_telemetry_frame_crc32(const uint8_t *frame,
                                                    uint32_t frame_size)
{
    uint32_t crc = dctool_telemetry_crc32_update(
        0xffffffffu, frame, DCTOOL_TELEMETRY_OFF_CRC32);
    crc = dctool_telemetry_crc32_update(
        crc, frame + DCTOOL_TELEMETRY_HEADER_SIZE,
        frame_size - DCTOOL_TELEMETRY_HEADER_SIZE);
    return ~crc;
}

/* Decoder modules emit synchronously during decode(); they must not retain the
 * callback, context, frame, or any pointed-to storage after decode returns.
 * Text need not be one line, but every emitted byte is copied into dc-tool's
 * existing bounded, nonblocking console sink before decode returns. */
typedef void (*dctool_telemetry_emit_fn)(void *context,
                                         const char *text,
                                         uint32_t size);

enum dctool_telemetry_decode_result {
    DCTOOL_TELEMETRY_DECODE_OK     = 0,
    DCTOOL_TELEMETRY_DECODE_IGNORE = 1,
    DCTOOL_TELEMETRY_DECODE_ERROR  = -1
};

typedef int (*dctool_telemetry_decode_fn)(
    const uint8_t *frame,
    uint32_t frame_size,
    dctool_telemetry_emit_fn emit,
    void *emit_context);

#define DCTOOL_TELEMETRY_DECODER_ABI_V1 1u
#define DCTOOL_TELEMETRY_DECODER_ENTRY  "dctool_telemetry_decoder_get_v1"

typedef struct dctool_telemetry_decoder_v1 {
    uint32_t abi_version;
    uint32_t struct_size;
    const char *name;
    dctool_telemetry_decode_fn decode;
} dctool_telemetry_decoder_v1_t;

typedef const dctool_telemetry_decoder_v1_t *
    (*dctool_telemetry_decoder_get_v1_fn)(void);

#ifdef __cplusplus
}
#endif

#endif /* DCTOOL_TELEMETRY_H */
