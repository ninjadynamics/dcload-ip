/*
 * Network controller input for the ps2link fork (P4), host side.
 *
 * Wire format: byte-identical to the "Network input (P4)" block of ps2link's
 * include/hostlink.h. Byte-addressed, little-endian, one datagram per state:
 *   0 magic "PKIN"   4 payload version   5 flags (bit 0: end of session)
 *   6 size (u16, whole datagram, header .. PS2LINK_INPUT_WIRE_MAX)
 *   8 session (u32, nonzero)   12 sequence (u32, strictly increasing)
 *  16 payload, opaque to ps2link. Version 1 (host modules and the program):
 *     16 buttons (u16, libpad PAD_* bits, active high)
 *     18 lx, 19 ly, 20 rx, 21 ry (u8, 0x80 = centre)
 *     22 l2, 23 r2 (u8 analog trigger, 0 = released)
 *     24 valid_ms (u16)
 * ps2link checks only the header, so a new payload version changes this host
 * and the program, never ps2link.
 *
 * Input module ABI: an optional shared library, loaded with --input, that
 * exports PS2_INPUT_MODULE_ENTRY. ps2client polls it at the send rate and
 * owns the transport; a module only reports the current controller state.
 */
#ifndef PS2LINK_INPUT_H
#define PS2LINK_INPUT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PS2LINK_INPUT_PORT         0x4712  /* ps2link P5 command port; dcload takes any */
#define PS2LINK_INPUT_MAGIC        "PKIN"
#define PS2LINK_INPUT_HEADER_SIZE  16u
#define PS2LINK_INPUT_WIRE_MAX     120u
#define PS2LINK_INPUT_FLAG_END     0x01u
#define PS2LINK_INPUT_V1           1u
#define PS2LINK_INPUT_V1_SIZE      26u

/* libpad button bits (ps2sdk libpad.h), active high on the wire. */
#define PS2_PAD_SELECT    0x0001u
#define PS2_PAD_L3        0x0002u
#define PS2_PAD_R3        0x0004u
#define PS2_PAD_START     0x0008u
#define PS2_PAD_UP        0x0010u
#define PS2_PAD_RIGHT     0x0020u
#define PS2_PAD_DOWN      0x0040u
#define PS2_PAD_LEFT      0x0080u
#define PS2_PAD_L2        0x0100u
#define PS2_PAD_R2        0x0200u
#define PS2_PAD_L1        0x0400u
#define PS2_PAD_R1        0x0800u
#define PS2_PAD_TRIANGLE  0x1000u
#define PS2_PAD_CIRCLE    0x2000u
#define PS2_PAD_CROSS     0x4000u
#define PS2_PAD_SQUARE    0x8000u

#define PS2_PAD_AXIS_CENTRE 0x80u

typedef struct ps2_input_state {
    uint16_t buttons;          /* PS2_PAD_* bits */
    uint8_t lx, ly, rx, ry;    /* 0 = left/up, 0x80 = centre, 0xff = right/down */
    uint8_t l2, r2;            /* analog triggers, 0 = released, 0xff = full */
} ps2_input_state_t;

#define PS2_INPUT_MODULE_ABI_V1  1u
#define PS2_INPUT_MODULE_ENTRY   "ps2_input_module_get_v1"

typedef struct ps2_input_module_v1 {
    uint32_t abi_version;      /* PS2_INPUT_MODULE_ABI_V1 */
    uint32_t struct_size;      /* sizeof(ps2_input_module_v1_t) */
    const char *name;
    int  (*start)(void);                      /* 0 = ready */
    int  (*poll)(ps2_input_state_t *state);   /* 0 = state filled, <0 = stop */
    void (*stop)(void);
} ps2_input_module_v1_t;

typedef const ps2_input_module_v1_t *(*ps2_input_module_get_v1_fn)(void);

/* Encodes one version 1 datagram; returns its size. */
static inline uint32_t ps2link_input_encode_v1(uint8_t out[PS2LINK_INPUT_V1_SIZE],
                                               uint32_t session, uint32_t sequence,
                                               const ps2_input_state_t *state,
                                               uint16_t valid_ms, uint8_t flags)
{
    out[0] = 'P'; out[1] = 'K'; out[2] = 'I'; out[3] = 'N';
    out[4] = (uint8_t)PS2LINK_INPUT_V1;
    out[5] = flags;
    out[6] = (uint8_t)PS2LINK_INPUT_V1_SIZE;
    out[7] = 0;
    for (int i = 0; i < 4; i++) {
        out[8 + i] = (uint8_t)(session >> (8 * i));
        out[12 + i] = (uint8_t)(sequence >> (8 * i));
    }
    out[16] = (uint8_t)state->buttons;
    out[17] = (uint8_t)(state->buttons >> 8);
    out[18] = state->lx;
    out[19] = state->ly;
    out[20] = state->rx;
    out[21] = state->ry;
    out[22] = state->l2;
    out[23] = state->r2;
    out[24] = (uint8_t)valid_ms;
    out[25] = (uint8_t)(valid_ms >> 8);
    return PS2LINK_INPUT_V1_SIZE;
}

#ifdef __cplusplus
}
#endif

#endif /* PS2LINK_INPUT_H */
