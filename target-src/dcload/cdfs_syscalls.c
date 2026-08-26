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
#include "cdfs.h"

// Leave this as an int.
static int gdStatus = 0;

/* Modern KOS (2.x 2025+ syscall layer) treats gdGdcReqCmd's return as a command
   HANDLE and requires it positive: `if(cmd_hnd <= 0) return ERR_SYS;`. The 2001
   contract of returning 0 on success now reads as "failed to queue" and every
   redirected cdfs command dies silently (read_toc fails -> /cd opens ENODEV).
   Old KOS just passes the handle back to gdGdcGetCmdStat (which ignores it),
   so positive handles are backward-compatible. */
static int gdCmdHnd = 0;

/* P7 transaction state lives in the resident loader, not in KOS. A tagged
   completion is the only packet allowed to release a redirected read; generic
   RETV packets remain valid for all ordinary syscalls but cannot manufacture a
   successful CDFS transfer. */
static volatile unsigned int cdfs_p7_txid;
static volatile unsigned int cdfs_p7_last_txid;
static volatile int cdfs_p7_status;
static volatile int cdfs_p7_is_active;
static volatile int cdfs_p7_is_complete;
static unsigned int cdfs_p7_next_txid;
static int cdfs_p7_timeout_seconds = 9;

void cdfs_p7_begin(unsigned int txid, unsigned int bytes)
{
	unsigned long long packets =
		((unsigned long long)bytes + 1439ULL) / 1440ULL;
	unsigned long long usec = 5000000ULL + packets * 3000ULL;
	unsigned int seconds = (unsigned int)((usec + 999999ULL) / 1000000ULL);

	if(seconds < 9)
		seconds = 9;
	if(seconds > 48)
		seconds = 48;
	cdfs_p7_timeout_seconds = (int)seconds;
	cdfs_p7_txid = txid;
	cdfs_p7_status = -1;
	cdfs_p7_is_complete = 0;
	cdfs_p7_is_active = 1;
}

void cdfs_p7_cancel(unsigned int txid)
{
	if(cdfs_p7_txid == txid)
	{
		cdfs_p7_is_active = 0;
		cdfs_p7_is_complete = 0;
	}
}

int cdfs_p7_active(void)
{
	/* Keep the guard through the receive-loop exit. A queued generic RETV in
	   the same NIC batch must not run after the tagged completion and stop RX. */
	return cdfs_p7_is_active || cdfs_p7_is_complete;
}

int cdfs_p7_matches(unsigned int txid)
{
	return cdfs_p7_is_active && txid != 0 && cdfs_p7_txid == txid;
}

void cdfs_p7_transfer_started(void)
{
	/* Requests retry quickly while entirely lost. Once the host proves receipt
	   with a matching tagged PART/DONE, use the size-scaled deadline selected at
	   begin. It is the host's conservative packet budget plus three seconds,
	   with a nine-second floor for ordinary reads. */
	if(cdfs_p7_is_active && timeout_loop > 0)
		timeout_loop = cdfs_p7_timeout_seconds;
}

int cdfs_p7_complete(unsigned int txid, int status)
{
	if(cdfs_p7_is_active && cdfs_p7_txid == txid)
	{
		cdfs_p7_status = status;
		cdfs_p7_last_txid = txid;
		cdfs_p7_is_complete = 1;
		cdfs_p7_is_active = 0;
		escape_loop = 1;
		return 1;
	}
	/* The host may retry a completion whose ACK was lost. ACK it again, but do
	   not mutate or release whatever newer transaction may now be active. */
	return txid != 0 && txid == cdfs_p7_last_txid;
}

int cdfs_p7_result(unsigned int txid, int *status)
{
	if(!cdfs_p7_is_complete || cdfs_p7_last_txid != txid)
		return 0;
	if(status)
		*status = cdfs_p7_status;
	cdfs_p7_is_complete = 0;
	return 1;
}

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
		if(param[0] < 150 || param[1] <= 0 ||
		   (unsigned int)param[1] > 8192u || param[2] == 0)
		{
			param[3] = -1;
			gdStatus = -1;
			return gd_next_hnd();
		}

		if(DCTOOL_HAS_CDFS_P7)
		{
			command_4int_t *request = (command_4int_t *)command;
			unsigned int txid;
			unsigned int bytes = (unsigned int)param[1] * 2048u;
			int status = -1;
			int attempt;

			if(++cdfs_p7_next_txid == 0)
				cdfs_p7_next_txid = 1;
			txid = cdfs_p7_next_txid;
			cdfs_p7_begin(txid, bytes);
			if(!cmd_cdfs_p7_bulk_begin(txid, (unsigned int)param[2], bytes))
			{
				cdfs_p7_cancel(txid);
				param[3] = -1;
				gdStatus = -1;
				return gd_next_hnd();
			}
			for(attempt = 0; attempt < 4; attempt++)
			{
				memcpy(request->id, CMD_CDFSREAD_P7, 4);
				request->value0 = htonl(txid);
				request->value1 = htonl(param[0]);
				request->value2 = htonl(param[2]);
				request->value3 = htonl(bytes);
				build_send_packet(sizeof(command_4int_t));

				/* PMCR-backed inside both adapter loops, so this remains bounded
				   even while KOS has the global interrupt mask held. */
				timeout_loop = 1;
				bb->loop(0);
				timeout_loop = 0;
				if(cdfs_p7_result(txid, &status))
				{
					cmd_cdfs_p7_bulk_end(txid);
					param[3] = status;
					gdStatus = status == 0 ? 2 : -1;
					return gd_next_hnd();
				}
			}
			cdfs_p7_cancel(txid);
			cmd_cdfs_p7_bulk_end(txid);
			param[3] = -1;
			gdStatus = -1;
			return gd_next_hnd();
		}

		/* P6 compatibility for old hosts/CDs. The P7 feature is negotiated
		   explicitly, so neither side silently interprets the other protocol. */
		memcpy(command->id, CMD_CDFSREAD, 4);
		command->value0 = htonl(param[0]);
		command->value1 = htonl(param[2]);
		command->value2 = htonl((unsigned int)param[1] * 2048u);
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
