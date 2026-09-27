/*
 * HyperSolar fork (P8): network controller input (netinput.h).
 *
 * The same acceptance rules as ps2link P4 (iop/netInput.c): a datagram from
 * the dc-tool host, header-sized to NETINPUT_WIRE_MAX, whose size field
 * matches, with a nonzero session and a sequence that only rises within a
 * session. A new session supersedes the old one. Nothing is queued: the
 * newest datagram replaces the last.
 */
#include <string.h>
#include "commands.h"
#include "adapter.h"
#include "netinput.h"

static unsigned char input_datagram[NETINPUT_WIRE_MAX] __attribute__((aligned(4)));
static unsigned int input_len = 0;
static unsigned int input_session = 0;
static unsigned int input_seq = 0;       /* sequence of input_datagram, 0 = none */

static unsigned int rd16(const unsigned char *p)
{
	return (unsigned int)p[0] | ((unsigned int)p[1] << 8);
}

static unsigned int rd32(const unsigned char *p)
{
	return rd16(p) | (rd16(p + 2) << 16);
}

void cmd_input(ip_header_t *ip, const unsigned char *data, int len)
{
	unsigned int session, seq;

	/* Only the dc-tool host may drive the pad; the datagram is complete. */
	if (len < NETINPUT_HEADER_SIZE || len > NETINPUT_WIRE_MAX ||
	    tool_ip == 0 || ntohl(ip->src) != tool_ip ||
	    rd16(data + 6) != (unsigned int)len)
		return;

	session = rd32(data + 8);
	seq = rd32(data + 12);
	if (session == 0 || seq == 0)
		return;
	if (session == input_session && seq <= input_seq)
		return; /* duplicate or reordered */

	input_session = session;
	input_seq = seq;
	memcpy(input_datagram, data, len);
	input_len = len;
}

int input_poll(unsigned char *record, unsigned int size)
{
	unsigned int seq, i;

	if (!record || ((unsigned int)record & 3) || size != NETINPUT_RECORD_SIZE)
		return -1;

	/* Take whatever arrived since the last syscall, without waiting. */
	loop_nonblock = 1;
	bb->loop(0);
	loop_nonblock = 0;

	seq = input_seq;
	*(unsigned int *)record = seq;
	memcpy(record + 4, input_datagram, input_len);
	for (i = input_len; i < NETINPUT_WIRE_MAX; i++)
		record[4 + i] = 0;
	*(unsigned int *)(record + 4 + NETINPUT_WIRE_MAX) = seq;
	return (int)seq;
}
