/*
 * HyperSolar fork (P8): network controller input.
 *
 * dc-tool --input streams full controller states as datagrams in the ps2link
 * P4 wire format (ps2client's ps2link-input.h): 0 "PKIN", 4 payload version,
 * 5 flags, 6 size (u16, whole datagram), 8 session, 12 sequence, 16 payload.
 * dcload checks only that header and keeps the newest accepted datagram,
 * verbatim; the payload belongs to the host modules and the program.
 */
#ifndef __NETINPUT_H__
#define __NETINPUT_H__

#include "packet.h"

#define CMD_INPUT             "PKIN"
#define NETINPUT_HEADER_SIZE  16
#define NETINPUT_WIRE_MAX     120
#define NETINPUT_RECORD_SIZE  128   /* seq_head, datagram (zero padded), seq_tail */

/* Network side, from the receive loop. */
void cmd_input(ip_header_t *ip, const unsigned char *data, int len);

/* Syscall 23: one non-blocking receive pass, then the newest datagram into
 * the caller's record. Returns its sequence (0 = none yet) or -1 for a bad
 * record. dcload writes program memory only inside this call. */
int input_poll(unsigned char *record, unsigned int size);

#endif
