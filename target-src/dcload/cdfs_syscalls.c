/*
 * This file is part of the dcload Dreamcast ethernet loader
 *
 * Copyright (C) 2001 Andrew Kieschnick <andrewk@austin.rr.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <string.h>
#include "syscalls.h"
#include "packet.h"
#include "net.h"
#include "adapter.h"
#include "commands.h"

// Leave this as an int.
static int gdStatus = 0;

/* Modern KOS (2.x 2025+ syscall layer) treats gdGdcReqCmd's return as a command
   HANDLE and requires it positive: `if(cmd_hnd <= 0) return ERR_SYS;`. The 2001
   contract of returning 0 on success now reads as "failed to queue" and every
   redirected cdfs command dies silently (read_toc fails -> /cd opens ENODEV).
   Old KOS just passes the handle back to gdGdcGetCmdStat (which ignores it),
   so positive handles are backward-compatible. */
static int gdCmdHnd = 0;

static int gd_next_hnd(void)
{
	if (++gdCmdHnd <= 0)
		gdCmdHnd = 1;
	return gdCmdHnd;
}

struct TOC {
	unsigned int entry[99];
	unsigned int first, last;
	unsigned int dunno;
};

int gdGdcReqCmd(int cmd, int *param)
{
	command_3int_t * command = (command_3int_t *)(pkt_buf + ETHER_H_LEN + IP_H_LEN + UDP_H_LEN);
	struct TOC *toc;
	int i;

	switch (cmd) {
	case 16: /* read sectors (PIO) */
	case 17: /* read sectors (DMA): modern KOS's fs_iso9660 reads with this one. Same
	            param layout ({start_sec, num_sec, buffer, is_test} - the BIOS ABI),
	            except the buffer is a PHYSICAL address (0x0Cxxxxxx): our network
	            handler's CPU stores go through the P0 cacheable mirror, which hits
	            the same cache lines KOS reads back through 0x8C - coherent. KOS's
	            DMA path only blocks on the G1 IRQ semaphore when the command
	            reports PROCESSING; we complete synchronously and report COMPLETED,
	            so the no-IRQ path falls through clean (verified against KOS 2.3.0
	            cdrom_read_sectors_dma_irq + cdrom_vblank). */

		memcpy(command->id, CMD_CDFSREAD, 4);
		command->value0 = htonl(param[0]);
		command->value1 = htonl(param[2]);
		command->value2 = htonl(param[1]*2048);
		build_send_packet(sizeof(command_3int_t));
		bb->loop(0);

		param[3] = 0;
		gdStatus = 2;

		return gd_next_hnd();
		break;
	case 19: /* read toc */
		toc = (struct TOC *)param[1];
		toc->entry[0] = 0x41000096; /* CTRL = 4, ADR = 1, LBA = 150 */
		for(i=1; i<99; i++)
			toc->entry[i] = -1;
		toc->first = 0x41010000; /* first = track 1 */
		toc->last = 0x41010000; /* last = track 1 */
		gdStatus = 2;
		return gd_next_hnd();
		break;
	case 24: /* init disc */
		gdStatus = 2;
		return gd_next_hnd();
		break;
	default:
		gdStatus = 0;
		return 0; /* modern KOS: 0 = failed to queue (was -1) */
		break;
	}

}

void gdGdcExecServer(void)
{
}

int gdGdcGetCmdStat(int f, int *status)
{
	(void) f; // unused

	if (gdStatus == 0)
		status[0] = 0;
	return gdStatus;
}

void gdGdcGetDrvStat(int *param)
{
	/* param[0] (drive status) was never written: KOS reads uninitialized stack,
	   sees it flip-flop, and re-inits the ISO cache on nearly every /cd open
	   ("fs_iso9660: disc change detected" spam). 1 = CD_STATUS_PAUSED (disc
	   present, idle) - a stable, valid answer for a redirected image. */
	param[0] = 1;
	param[1] = 32;
}

int gdGdcChangeDataType(int *param)
{
	(void) param; // unused

	return 0;
}

void gdGdcInitSystem(void)
{
}
