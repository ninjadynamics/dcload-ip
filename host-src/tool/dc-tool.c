/*
 * dc-tool, a tool for use with the dcload ethernet loader
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "config.h" // needed for newer BFD library

#ifdef WITH_BFD
#include <bfd.h>
#else
  #ifdef MACOS
  #include <libelf/libelf.h>
  #else
  #include <libelf.h>
  #endif
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include <sys/time.h>
#include <unistd.h>
#include <utime.h>
#ifndef __MINGW32__
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include "syscalls.h"
#include "dc-io.h"
#include "commands.h"
#include "telemetry.h"
#include "input.h"

#include "utils.h"

int _nl_msg_cat_cntr;

#define DEBUG(x, ...) fprintf(stderr, "DEBUG: "); fprintf(stderr, x, __VA_ARGS__)

#define CatchError(x) if(x) return -1;

#define VERSION PACKAGE_VERSION
#define DCTOOL_LEGACY_SYSCALL_PORT 31313
// Really should be using ports in the range 49152-65535, so dcload v2 does.
#define DCTOOL_DEFAULT_SYSCALL_PORT 53535
// FIXED local (host-side) ports. Without a bind, connect() picks an ephemeral
// port, and the target memorizes it at cmd_execute (tool_port) as the ONE
// address it sends every syscall to — console logs and CDFS reads alike — for
// the life of the program. A later `-o` reattach on a fresh ephemeral port
// would handshake fine (cmd_version replies to the packet's source) yet never
// receive the game's traffic. Binding every session to the same well-known
// local port is what makes reattach possible at all.
#define DCTOOL_LOCAL_PORT        53534
#define DCTOOL_LOCAL_PORT_LEGACY 53533

// A running program's resident dcload accepts NIC packets only while a syscall
// poll is executing. The KOS-wide service makes those polls regular, but a
// single fire-and-forget reboot can still be lost. Send a short burst to cover
// the next poll and ordinary UDP loss. Total span
// (REBOOT_RETRIES * REBOOT_RETRY_USEC) must stay
// well under the post-reboot NIC re-init/link-negotiation gap (~1s of deafness),
// so a DC that reboots mid-burst can't catch a later packet and reboot-loop.
#define REBOOT_RETRIES   8
#define REBOOT_RETRY_USEC 10000
/* Reset is a one-shot control operation, so request/response is appropriate.
 * A running KOS program services dcload through a low-rate background poll;
 * allow several poll periods, retransmitting VERSION on ordinary UDP loss.
 * The legacy port gets the same bounded chance for older loaders. */
#define REBOOT_PROBE_ATTEMPT_USEC     250000
#define REBOOT_HANDSHAKE_TIMEOUT_USEC 3000000

/* KOS prints this immediately before its first redirected ISO9660 transaction.
 * If that request datagram disappears, the P6 target waits forever with IRQs
 * masked and dc-tool has no request to answer.  Arm a narrowly-scoped host
 * watchdog from the console signature and automate the same RETV nudge used by
 * `dc-tool -o`; the first CDFS request or any later console output proves that
 * initialization progressed and disarms it. */
#define CDFS_AUTO_RETRY_USEC 3000000U
static const unsigned char cdfs_change_marker[] =
    "fs_iso9660: disc change detected";
static unsigned int cdfs_auto_retry_started = 0;
static unsigned int cdfs_marker_matched = 0;
static int cdfs_auto_retry_armed = 0;

static int cdfs_marker_feed(const unsigned char *data, unsigned int size)
{
    unsigned int i;

    for(i = 0; i < size; i++)
    {
        if(data[i] == cdfs_change_marker[cdfs_marker_matched])
        {
            cdfs_marker_matched++;
            if(cdfs_marker_matched == sizeof(cdfs_change_marker) - 1)
            {
                cdfs_marker_matched = 0;
                return 1;
            }
        }
        else
        {
            cdfs_marker_matched =
                (data[i] == cdfs_change_marker[0]) ? 1U : 0U;
        }
    }

    return 0;
}

static int cdfs_console_has_progress(const unsigned char *data,
                                     unsigned int size)
{
    unsigned int i;

    /* Some stdio paths may emit the line ending separately from the text.
     * That is still the marker write, not proof that ISO initialization moved
     * on to another log statement. */
    for(i = 0; i < size; i++)
        if(data[i] != '\r' && data[i] != '\n')
            return 1;

    return 0;
}

static void cdfs_auto_retry_arm(void)
{
    cdfs_auto_retry_started = time_in_usec();
    cdfs_auto_retry_armed = 1;
}

static void cdfs_auto_retry_disarm(void)
{
    cdfs_auto_retry_armed = 0;
}

#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifndef HAVE_GETOPT
/* The following code for getopt is from the libc-source of FreeBSD,
 * it might be changed a little bit.
 * Florian Schulze (florian.proff.schulze@gmx.net)
 */

/*
 * Copyright (c) 1987, 1993, 1994
 * The Regents of the University of California. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by the University of
 *    California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
#if 0
static char sccsid[] = "@(#)getopt.c 8.3 (Berkeley) 4/27/95";
#endif
static const char rcsid[] = "$FreeBSD$";
#endif /* LIBC_SCCS and not lint */

int     opterr = 1,             /* if error message should be printed */
        optind = 1,             /* index into parent argv vector */
        optopt,                 /* character checked for validity */
        optreset;               /* reset getopt */
char    *optarg;                /* argument associated with option */

#define BADCH   (int)'?'
#define BADARG  (int)':'
#define EMSG    ""

char *__progname=PACKAGE;

/*
 * getopt -- Parse argc/argv argument vector.
 */
int getopt(int nargc, char * const *nargv, const char *ostr)
{
        extern char *__progname;
        static char *place = EMSG;              /* option letter processing */
        char *oli;                              /* option letter list index */
        int ret;

        if (optreset || !*place) {              /* update scanning pointer */
                optreset = 0;
                if (optind >= nargc || *(place = nargv[optind]) != '-') {
                        place = EMSG;
                        return (-1);
                }
                if (place[1] && *++place == '-') {      /* found "--" */
                        ++optind;
                        place = EMSG;
                        return (-1);
                }
        }                                       /* option letter okay? */
        if ((optopt = (int)*place++) == (int)':' ||
            !(oli = strchr(ostr, optopt))) {
                /*
                 * if the user didn't specify '-' as an option,
                 * assume it means -1.
                 */
                if (optopt == (int)'-')
                        return (-1);
                if (!*place)
                        ++optind;
                if (opterr && *ostr != ':')
                        (void)fprintf(stderr,
                            "%s: illegal option -- %c\n", __progname, optopt);
                return (BADCH);
       }
        if (*++oli != ':') {                    /* don't need argument */
                optarg = NULL;
                if (!*place)
                        ++optind;
        }
        else {                                  /* need an argument */
                if (*place)                     /* no white space */
                        optarg = place;
                else if (nargc <= ++optind) {   /* no arg */
                        place = EMSG;
                        if (*ostr == ':')
                                ret = BADARG;
                        else
                               ret = BADCH;
                        if (opterr)
                                (void)fprintf(stderr,
                                    "%s: option requires an argument -- %c\n",
                                    __progname, optopt);
                        return (ret);
                }
                else                            /* white space */
                        optarg = nargv[optind];
                place = EMSG;
                ++optind;
        }
        return (optopt);                        /* dump back option letter */
}
#else
// This is defined elsewhere if the above #if isn't used...
extern char *optarg;
#endif

int gdb_socket_started = 0;
char *path = 0;
#ifdef __MINGW32__
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
/* Winsock SOCKET is defined as an unsigned int, so -1 won't work here */
SOCKET dcsocket_legacy = 0;
SOCKET dcsocket = 0;
SOCKET gdb_server_socket = 0;
SOCKET socket_fd = 0; // For GDB
SOCKET global_socket = 0; // Stores whichever global socket gets used
#else
int dcsocket_legacy = 0;
int dcsocket = 0;
int gdb_server_socket = -1;
int socket_fd = 0; // For GDB
int global_socket = 0; // Stores whichever global socket gets used
unsigned int nochroot = 0;
#endif

void cleanup(char **fnames)
{
    int counter = 0;

    dc_console_sink_shutdown();
    dctool_telemetry_decoder_unload();

    for(; counter < 4; counter++)
    {
      if(fnames[counter] != 0)
      {
	       free(fnames[counter]);
      }
    }

#ifdef __MINGW32__
    if(dcsocket)
    {
      closesocket(dcsocket);
    }

    if(dcsocket_legacy)
    {
      closesocket(dcsocket_legacy);
    }
#else
    if(dcsocket)
    {
      close(dcsocket);
    }

    if(dcsocket_legacy)
    {
      close(dcsocket_legacy);
    }
#endif

	// Handle GDB
	if (gdb_socket_started)
  {
		gdb_socket_started = 0;

		// Send SIGTERM to the GDB Client, telling remote DC program has ended
		char gdb_buf[16];
		strcpy(gdb_buf, "+$X0f#ee\0");

#ifdef __MINGW32__
		send(socket_fd, gdb_buf, strlen(gdb_buf), 0);
		sleep(1);
		closesocket(socket_fd);
		closesocket(gdb_server_socket);
#else
		write(socket_fd, gdb_buf, strlen(gdb_buf));
		sleep(1);
		close(socket_fd);
		close(gdb_server_socket);
#endif
	}

#ifdef __MINGW32__
	WSACleanup();
#endif
}

unsigned int time_in_usec(void)
{
    struct timeval thetime;

    gettimeofday(&thetime, NULL);

    return (unsigned int)(thetime.tv_sec * 1000000) + (unsigned int)thetime.tv_usec;
}

/* 250000 = 0.25 seconds */
#define PACKET_TIMEOUT 250000

static int recv_matching(unsigned char *buffer, char *command, int timeout);
static int recv_matching_p7(unsigned char *buffer, const char *command,
                            unsigned int txid, int minimum_size, int timeout);
struct timeval starttime = {0}, endtime = {0};

// Adapter type detection
// Each adapter needs different values for things like Dreamcast RX FIFO sizes
#define BBA_MODEL 0400
#define LAN_MODEL 0300

unsigned int installed_adapter = 0;
unsigned int legacy = 0; // To know if this should use old 1024-byte sizes for packets or new 1440-sizes
unsigned int force_legacy = 0; // Force 1024-byte bulk transfers with -l
unsigned int fast_mode = 0; // to force dc-tool to not use any delays for higher speed

// How long to wait for DC to empty its RX FIFO, in microseconds
#define BBA_RX_FIFO_DELAY_TIME DREAMCAST_BBA_RX_FIFO_DELAY_TIME
#define LAN_RX_FIFO_DELAY_TIME DREAMCAST_LAN_RX_FIFO_DELAY_TIME

unsigned int rx_fifo_delay = PACKET_TIMEOUT/51; // Default for compatibility with old dcload-ip versions

#define BBA_RX_FIFO_DELAY_COUNT DREAMCAST_BBA_RX_FIFO_DELAY_COUNT
#define LAN_RX_FIFO_DELAY_COUNT DREAMCAST_LAN_RX_FIFO_DELAY_COUNT
// Number of packets to send before waiting for DC to empty its RX FIFO

unsigned int rx_fifo_delay_count = 15; // Default for compatibility with old dcload-ip versions

// Get the version of dc-tool encoded in a uint as (major << 16) | (minor << 8) | patch,
// since this program is more likely to get patch version bumps than either of the other two.
// Presumably a max version of 255.255.255 is OK. :P
unsigned int encoded_tool_ver = 0;

void make_encoded_tool_version()
{
  int i = 1, c = 0; // Indices
  unsigned char *ver_uchar = (unsigned char *)&encoded_tool_ver;

  // 1 byte per version unit
  while(VERSION[c] != '\0')
  {
    if(VERSION[c] == '.')
    {
      c++;
      i++;
    }
    else
    {
      ver_uchar[i] *= 10;
      ver_uchar[i] += VERSION[c] - '0';
      c++;
    }
  }

  encoded_tool_ver = ntohl(encoded_tool_ver);
}

// Both send_data() and recv_data() use this to set up communications between dc-tool and dc-load
int prepare_comms(unsigned char *buffer)
{
  if(!installed_adapter) // This is how we know that this function has run before
  {
    // First check for the type of adapter installed (only need to do this once)
    make_encoded_tool_version(); // Only need to set encoded dc-tool version once, and it's only needed for this version info handshake

    // Unless 'force_legacy' is set, first we use the v2.0.0+ socket to determine whether or not dcload is v2.0.0+ or legacy:
    // Legacy dcload will reply on 31313. Note that response port is not the primary means of version detection,
    // so, in the event that something ever changes about this in the future, ports won't come back to bite anyone.
    if(force_legacy)
    {
      global_socket = dcsocket_legacy;
    }
    else
    {
      global_socket = dcsocket;
    }

    int flip = 0;

    do
    {
      // Stuff the encoded dc-tool version into the address field
      // dcload v2.0.0 will know what to do with this; prior versions will ignore it
      /* The stock protocol couples version 0 to 1024-byte payloads. After a
         legacy-size upload we re-advertise the real version before execute. */
      send_cmd(CMD_VERSION, force_legacy ? 0 : encoded_tool_ver,
               force_legacy ? 0 : DCTOOL_FEATURES, NULL, 0);
    }
    while(recv_response(buffer, PACKET_TIMEOUT) == -1);

    while(memcmp(((command_t *)buffer)->id, CMD_VERSION, 4))
    {
      printf("prepare_comms: No response to CMD_VERSION, retrying... %c%c%c%c\n",buffer[0],buffer[1],buffer[2],buffer[3]);
      do
      {
        // Alternate checking each socket
        flip ^= 0x1;
        if(flip)
        {
          global_socket = dcsocket_legacy;
        }
        else
        {
          global_socket = dcsocket;
        }
        send_cmd(CMD_VERSION, force_legacy ? 0 : encoded_tool_ver,
                 force_legacy ? 0 : DCTOOL_FEATURES, NULL, 0);
      }
      while (recv_response(buffer, PACKET_TIMEOUT) == -1);
    }

    // Close the socket we don't need, then set parameters
    if(global_socket == dcsocket)
    {
#ifdef __MINGW32__
      closesocket(dcsocket_legacy);
#else
      close(dcsocket_legacy);
#endif
    }
    else // global_socket == dcsocket_legacy
    {
#ifdef __MINGW32__
        closesocket(dcsocket);
#else
        close(dcsocket);
#endif
    }

    // As of version 2.0.0 the 'version' command now stuffs a numeric adapter
    // type into the previously unused command->address field :)
    installed_adapter = ntohl(((command_t*)buffer)->address);

    if(installed_adapter == BBA_MODEL)
    {
      printf("%s\n", ((command_t*)buffer)->data);
      if(force_legacy)
      {
        printf("Forcing 1024-byte payloads...\n");
        legacy = 1;
      }

      if(!fast_mode)
      {
        rx_fifo_delay = BBA_RX_FIFO_DELAY_TIME; // microseconds
        rx_fifo_delay_count = BBA_RX_FIFO_DELAY_COUNT; // packets per burst
      } 
      else
      {
        rx_fifo_delay = 0;
      }
    }
    else if(installed_adapter == LAN_MODEL)
    {
      printf("%s\n", ((command_t*)buffer)->data);
      if(force_legacy)
      {
        printf("Forcing 1024-byte payloads...\n");
        legacy = 1;
      }

      if(!fast_mode)
      {
        rx_fifo_delay = LAN_RX_FIFO_DELAY_TIME; // microseconds
        rx_fifo_delay_count = LAN_RX_FIFO_DELAY_COUNT; // packets per burst
      }
      else
      {
        rx_fifo_delay = 0;
      }
    }
    else // legacy dcload has 0 there
    {
      // Alternatively, it means someone is using an old version of dcload-ip and really needs to upgrade.
      printf("Unknown adapter or old version of dcload-ip detected.\nDefaulting to legacy Broadband Adapter settings...\n");
      installed_adapter = BBA_MODEL;
      legacy = 1;
      // Default rx_fifo_delay and rx_fifo_delay_count are already set for legacy
    }
  }

  return 0;
}

/* -l is needed only while moving a large binary: version 0 is the stock
 * protocol's signal for FIFO-safe 1024-byte chunks. Leaving the target at
 * version 0 after upload also disables v2 fire-and-forget console writes,
 * turning every printf back into an acknowledged syscall. Re-advertise our
 * real version before execute/console service, then use normal v2 transfers
 * for the occasional runtime fileserver request. This works with existing v2
 * loader CDs; no target-side protocol extension is required. */
static int promote_v2_after_legacy_transfer(unsigned char *buffer)
{
  if(!force_legacy || !legacy)
    return 0;

  do
  {
    send_cmd(CMD_VERSION, encoded_tool_ver, DCTOOL_FEATURES, NULL, 0);
  }
  while(recv_response(buffer, PACKET_TIMEOUT) == -1);

  while(memcmp(((command_t *)buffer)->id, CMD_VERSION, 4))
  {
    do
    {
      send_cmd(CMD_VERSION, encoded_tool_ver, DCTOOL_FEATURES, NULL, 0);
    }
    while(recv_response(buffer, PACKET_TIMEOUT) == -1);
  }

  legacy = 0;
  printf("Restored dcload-ip v2 protocol features after 1024-byte transfer.\n");
  return 0;
}

/* receive total bytes from dc and store in data */
int recv_data(void *data, unsigned int dcaddr, unsigned int total, unsigned int quiet)
{
  unsigned char buffer[2048];
  unsigned char *i;
  int c;
  int packets = 0;
  unsigned int start;
  int retval;

  // v2.0.0: set up the socket, do version and adapter identification, set globals
  if(prepare_comms(buffer) < 0)
    return -1;

  // old 1024 sizes
  // This if() looks awful because some ARM chips don't have integer divide, so
  // hardcoding 1024 and 1440 sizes removes those divides. This is because GCC
  // has some tricks for certain "nice" numbers (I don't know if there's an
  // official GCC term for them), and both 1024 and 1440 count as nice numbers.
  if(legacy)
  {
    unsigned char *map = (unsigned char *)malloc((total+1023)/1024);
    memset(map, 0, (total+1023)/1024);

    // Start thropughput timer
    gettimeofday(&starttime, 0);

    // Receive the data!

    if (!quiet)
    {
      send_cmd(CMD_SENDBIN, dcaddr, total, NULL, 0);
    }
    else
    {
      send_cmd(CMD_SENDBINQ, dcaddr, total, NULL, 0);
    }

    start = time_in_usec();

    while (((time_in_usec() - start) < PACKET_TIMEOUT)&&(packets < ((total+1023)/1024 + 1)))
    {
      memset(buffer, 0, 2048);

      retval = recv_response(buffer, PACKET_TIMEOUT);

      if (retval > 0)
      {
        start = time_in_usec();
        if (memcmp(((command_t *)buffer)->id, CMD_DONEBIN, 4))
        {
          if ( ((ntohl(((command_t *)buffer)->address) - dcaddr)/1024) >= ((total + 1024)/1024) )
          {
            printf("Obviously bad packet, avoiding segfault\n");
            fflush(stdout);
          }
          else
          {
            map[ (ntohl(((command_t *)buffer)->address) - dcaddr)/1024 ] = 1;
            i = data + (ntohl(((command_t *)buffer)->address) - dcaddr);

            memcpy(i, buffer + 12, ntohl(((command_t *)buffer)->size));
          }
        }
        packets++;
      }
    }

    for(c = 0; c < (total+1023)/1024; c++)
    {
      if (!map[c])
      {
        if ( (total - c*1024) >= 1024)
        {
          send_cmd(CMD_SENDBINQ, dcaddr + c*1024, 1024, NULL, 0);
        }
        else
        {
          send_cmd(CMD_SENDBINQ, dcaddr + c*1024, total - c*1024, NULL, 0);
        }

        start = time_in_usec();
        retval = recv_response(buffer, PACKET_TIMEOUT);

        if (retval > 0)
        {
          start = time_in_usec();

          if (memcmp(((command_t *)buffer)->id, CMD_DONEBIN, 4))
          {
            map[ (ntohl(((command_t *)buffer)->address) - dcaddr)/1024 ] = 1;
            /* printf("recv_data: got chunk for %p, %d bytes\n",
            (void *)ntohl(((command_t *)buffer)->address), ntohl(((command_t *)buffer)->size)); */
            i = data + (ntohl(((command_t *)buffer)->address) - dcaddr);

            memcpy(i, buffer + 12, ntohl(((command_t *)buffer)->size));
          }

          // Get the DONEBIN
          retval = recv_response(buffer, PACKET_TIMEOUT);
        }

        // Force us to go back and recheck
        // XXX This should be improved after recv_data can return errors.
        c = -1;
      }
    }

    gettimeofday(&endtime, 0);

    free(map);
  }
  else // New 1440 sizes
  {
    unsigned char *map = (unsigned char *)malloc((total+1439)/1440);
    memset(map, 0, (total+1439)/1440);

    // Start thropughput timer
    gettimeofday(&starttime, 0);

    // Receive the data!

    if (!quiet)
    {
      send_cmd(CMD_SENDBIN, dcaddr, total, NULL, 0);
    }
    else
    {
      send_cmd(CMD_SENDBINQ, dcaddr, total, NULL, 0);
    }

    start = time_in_usec();

    while (((time_in_usec() - start) < PACKET_TIMEOUT)&&(packets < ((total+1439)/1440 + 1)))
    {
      memset(buffer, 0, 2048);

      retval = recv_response(buffer, PACKET_TIMEOUT);

      if (retval > 0)
      {
        start = time_in_usec();
        if (memcmp(((command_t *)buffer)->id, CMD_DONEBIN, 4))
        {
          if ( ((ntohl(((command_t *)buffer)->address) - dcaddr)/1440) >= ((total + 1440)/1440) )
          {
            printf("Obviously bad packet, avoiding segfault\n");
            fflush(stdout);
          }
          else
          {
            map[ (ntohl(((command_t *)buffer)->address) - dcaddr)/1440 ] = 1;
            i = data + (ntohl(((command_t *)buffer)->address) - dcaddr);

            memcpy(i, buffer + 12, ntohl(((command_t *)buffer)->size));
          }
        }
        packets++;
      }
    }

    for(c = 0; c < (total+1439)/1440; c++)
    if (!map[c])
    {
      if ( (total - c*1440) >= 1440)
      {
        send_cmd(CMD_SENDBINQ, dcaddr + c*1440, 1440, NULL, 0);
      }
      else
      {
        send_cmd(CMD_SENDBINQ, dcaddr + c*1440, total - c*1440, NULL, 0);
      }

      start = time_in_usec();
      retval = recv_response(buffer, PACKET_TIMEOUT);

      if (retval > 0)
      {
        start = time_in_usec();

        if (memcmp(((command_t *)buffer)->id, CMD_DONEBIN, 4))
        {
          map[ (ntohl(((command_t *)buffer)->address) - dcaddr)/1440 ] = 1;
          /* printf("recv_data: got chunk for %p, %d bytes\n",
          (void *)ntohl(((command_t *)buffer)->address), ntohl(((command_t *)buffer)->size)); */
          i = data + (ntohl(((command_t *)buffer)->address) - dcaddr);

          memcpy(i, buffer + 12, ntohl(((command_t *)buffer)->size));
        }

        // Get the DONEBIN
        retval = recv_response(buffer, PACKET_TIMEOUT);
      }

      // Force us to go back and recheck
      // XXX This should be improved after recv_data can return errors.
      c = -1;
    }

    gettimeofday(&endtime, 0);

    free(map);
  }

  return 0;
}

/* Legacy executable/file bulk sender. P6 depends on its historical complete-
 * or-wait semantics; transaction-bounded CDFS uses send_data_p7 below. */
static int send_data_internal(unsigned char *addr, unsigned int dcaddr,
                              unsigned int size)
{
    unsigned char buffer[2048] = {0};
    unsigned char * i = 0;
    unsigned int a = dcaddr;
    unsigned int start = 0;
    unsigned int count = 0;
    if (!size)
	   return -1;

     if(prepare_comms(buffer) < 0)
       return -1;

    // Send the data!
    do
    {
	send_cmd(CMD_LOADBIN, dcaddr, size, NULL, 0);
    }
    while(recv_matching(buffer, CMD_LOADBIN, PACKET_TIMEOUT) == -1);

    // Start throughput timer
    gettimeofday(&starttime, 0);

    // old 1024 sizes
    if(legacy)
    {
      for(i = addr; i < (addr + size); i += 1024)
      {
        if ((addr + size - i) >= 1024)
        {
  	       send_cmd(CMD_PARTBIN, dcaddr, 1024, i, 1024);
  	    }
  	    else
        {
  	       send_cmd(CMD_PARTBIN, dcaddr, (addr + size) - i, i, (addr + size) - i);
  	    }

        dcaddr += 1024;

      	/* give the DC a chance to empty its rx fifo
      	 * this prevents buffer overflows and dropped packets
      	 */
      	count++;
      	if (count == rx_fifo_delay_count)
        {
    	    start = time_in_usec();
    	    while ((time_in_usec() - start) < rx_fifo_delay);
    		  count = 0;
        }
      }
    }
    else // 1440 sizes
    {
      for(i = addr; i < (addr + size); i += 1440)
      {
        if ((addr + size - i) >= 1440)
        {
           send_cmd(CMD_PARTBIN, dcaddr, 1440, i, 1440);
        }
        else
        {
           send_cmd(CMD_PARTBIN, dcaddr, (addr + size) - i, i, (addr + size) - i);
        }

        dcaddr += 1440;

        /* give the DC a chance to empty its rx fifo
         * this prevents buffer overflows and dropped packets
         */
        count++;
        if (count == rx_fifo_delay_count)
        {
          start = time_in_usec();
          while ((time_in_usec() - start) < rx_fifo_delay);
          count = 0;
        }
      }
    }

    // Finish up sending and check for dropped packets (if not in fast mode)
    if(!fast_mode)
    {
      /* delay a bit to try to make sure all data goes out before CMD_DONEBIN.
       * The classic flat 25ms is fine once per ELF section but brutal on the
       * runtime /cd fileserver (hundreds of small CDFS reads per stage load).
       * The rx-fifo pacing above already drains all but the final sub-burst,
       * so small transfers only need ~1ms; keep 25ms for bulk uploads. */
      unsigned int drain = (size > 65536) ? PACKET_TIMEOUT/10 : 1000;
      start = time_in_usec();
      while ((time_in_usec() - start) < drain);
    }

    do
    {
	send_cmd(CMD_DONEBIN, 0, 0, NULL, 0);
    }
    while (recv_matching(buffer, CMD_DONEBIN, PACKET_TIMEOUT) == -1);

    while ( ntohl(((command_t *)buffer)->size) != 0) {
        unsigned int missing_addr = ntohl(((command_t *)buffer)->address);
        unsigned int missing_size = ntohl(((command_t *)buffer)->size);
        if(missing_addr < a ||
           missing_size > size || missing_addr - a > size - missing_size)
            return -1;
/*	printf("%d bytes at 0x%x were missing, resending\n", ntohl(((command_t *)buffer)->size),ntohl(((command_t *)buffer)->address)); */
	send_cmd(CMD_PARTBIN, missing_addr, missing_size,
                 addr + (missing_addr - a), missing_size);

	do
	{
	    send_cmd(CMD_DONEBIN, 0, 0, NULL, 0);
	}
	while (recv_matching(buffer, CMD_DONEBIN, PACKET_TIMEOUT) == -1);
    }

    gettimeofday(&endtime, 0);

    return 0;
}

int send_data(unsigned char *addr, unsigned int dcaddr, unsigned int size)
{
    return send_data_internal(addr, dcaddr, size);
}

static int send_cdfs_p7_part(unsigned int txid, unsigned int destination,
                             const unsigned char *data, unsigned int size)
{
    /* command_t starts four bytes off an 8-byte boundary in the target RX
     * buffer. Two metadata words after its 12-byte header put the actual data
     * at +20, restoring the alignment required by SH4_aligned_memcpy. */
    unsigned char payload[8 + 1440];
    unsigned int value;

    if(!data || size == 0 || size > 1440)
        return -1;
    value = htonl(size);
    memcpy(payload, &value, sizeof(value));
    value = 0;
    memcpy(payload + 4, &value, sizeof(value));
    memcpy(payload + 8, data, size);
    return send_command(CMD_CDFSPART_P7, txid, destination,
                        payload, size + 8);
}

int send_data_p7(unsigned char *addr, unsigned int dcaddr, unsigned int size,
                 unsigned int txid, unsigned int timeout_usec)
{
    unsigned char buffer[2048] = {0};
    unsigned char *cursor;
    unsigned int base = dcaddr;
    unsigned int count = 0;
    unsigned int sent = 0;
    unsigned int start;
    unsigned int transfer_start = time_in_usec();
    int packet_size;

#define P7_EXPIRED() \
    (time_in_usec() - transfer_start >= timeout_usec)

    if(!addr || !size || !txid || !timeout_usec || dcaddr > 0xffffffffu - size)
        return -1;

    gettimeofday(&starttime, 0);
    while(sent < size)
    {
        unsigned int chunk = size - sent;
        cursor = addr + sent;
        if(chunk > 1440)
            chunk = 1440;
        if(P7_EXPIRED() ||
           send_cdfs_p7_part(txid, dcaddr, cursor, chunk) < 0)
            return -1;
        dcaddr += chunk;
        sent += chunk;

        count++;
        if(count == rx_fifo_delay_count)
        {
            start = time_in_usec();
            while((time_in_usec() - start) < rx_fifo_delay)
                ;
            count = 0;
        }
    }

    if(!fast_mode)
    {
        unsigned int drain = (size > 65536) ? PACKET_TIMEOUT/10 : 1000;
        start = time_in_usec();
        while((time_in_usec() - start) < drain)
            ;
    }

    for(;;)
    {
        command_3int_t *response;
        unsigned int missing_addr;
        unsigned int missing_size;
        unsigned int offset;
        unsigned int expected;

        do
        {
            if(P7_EXPIRED() ||
               send_command(CMD_CDFSBULKDONE_P7, txid, 0, NULL, 0) < 0)
                return -1;
            packet_size = recv_matching_p7(buffer, CMD_CDFSBULKDONE_P7,
                                           txid, sizeof(command_3int_t),
                                           PACKET_TIMEOUT);
        }
        while(packet_size < 0);

        response = (command_3int_t *)buffer;
        missing_addr = ntohl(response->value1);
        missing_size = ntohl(response->value2);
        if(missing_size == 0)
        {
            if(missing_addr != 0)
                return -1;
            break;
        }
        if(P7_EXPIRED() || missing_addr < base || missing_size > 1440u ||
           missing_addr - base >= size ||
           missing_size > size - (missing_addr - base))
            return -1;
        offset = missing_addr - base;
        if((offset % 1440u) != 0)
            return -1;
        expected = size - offset;
        if(expected > 1440u)
            expected = 1440u;
        if(missing_size != expected ||
           send_cdfs_p7_part(txid, missing_addr, addr + offset,
                             missing_size) < 0)
            return -1;
    }

    gettimeofday(&endtime, 0);
#undef P7_EXPIRED
    return 0;
}

void usage(void)
{
    printf("\n%s %s by Andrew \"ADK\" Kieschnick\nAugmented by Moopthehedgehog\n\n", PACKAGE, VERSION);
    printf("-x <filename>  Upload and execute <filename>\n");
    printf("-u <filename>  Upload <filename>\n");
    printf("-d <filename>  Download to <filename>\n");
    printf("-a <address>   Set address to <address> (default: 0x0c010000)\n");
    printf("-s <size>      Set size to <size>\n");
    printf("-t <ip>:<port> Connect to <ip>:<port> (port optional, default: %s:53535)\n",DREAMCAST_IP);
    printf("-n             Do not attach console and fileserver\n");
    printf("-q             Do not clear screen before download\n");
#ifndef __MINGW32__
    printf("-m <path>      Map /pc/ on KOS side to <path> (no chroot or super-user requirement)\n");
    printf("-c <path>      Chroot to <path> (must be super-user)\n");
#endif
    printf("-i <isofile>   Enable cdfs redirection using iso image <isofile>\n");
    printf("-r             Reset (only works when dcload is in control)\n");
    printf("-o             Reattach console and fileserver to a running program (no upload, no reboot)\n");
    printf("--decode <module>  Decode framed binary telemetry with an optional .dll/.so module\n");
    printf("--input <module>   Stream controller input to the program (-x, -o; dcload P8);\n");
    printf("                   'none' streams with no module (control commands, e.g. go).\n");
    printf("                   Repeat to combine; a bare name loads input-<name>.so. While\n");
    printf("                   streaming, 127.0.0.1:18209 takes list/load/unload/reload.\n");
    printf("-g             Start a GDB server\n");
    printf("-l             Force 1024-byte bulk-transfer payloads (dcload-ip v2+ only)\n");
    printf("-f             Disable FIFO delays for MUCH faster speeds (may increase packet loss)\n");
    printf("-h             Usage information (you\'re looking at it)\n\n");
}

/* Got to make sure WinSock is initalized */
#ifdef __MINGW32__
int start_ws()
{
    WSADATA wsaData;
    int failed = 0;
    failed = WSAStartup(MAKEWORD(2,2), &wsaData);
    if ( failed != NO_ERROR ) {
	log_error("WSAStartup");
	return 1;
    }

	return 0;
}
#endif

// dcload v2.0.0+ UDP port number
unsigned int dcload_portnum = DCTOOL_DEFAULT_SYSCALL_PORT;

// Legacy and new mode sockets
int open_sockets(char *hostname)
{
    struct sockaddr_in sin;
    struct sockaddr_in sin_legacy;
    struct hostent *host = 0;

    dcsocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    dcsocket_legacy = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

#ifndef __MINGW32__
    if ((dcsocket < 0) || (dcsocket_legacy < 0)) {
#else
    if ((dcsocket == INVALID_SOCKET) || (dcsocket_legacy == INVALID_SOCKET)) {
#endif
	log_error("socket");
	return -1;
    }

    bzero(&sin, sizeof(sin));
    bzero(&sin_legacy, sizeof(sin_legacy));

    sin.sin_family = AF_INET;
    sin_legacy.sin_family = AF_INET;

    // So, dcload is actually the server in this client-server setup
    // However, dc-tool gets to pick the port

    sin.sin_port = htons(dcload_portnum);
    sin_legacy.sin_port = htons(DCTOOL_LEGACY_SYSCALL_PORT);

    // On many platforms, leading-zeros in an octet cause the octet to be
    // interpreted as octal, so they should always be removed before trying to
    // connect.
    // --tsowell

    // Try to remove leading zeros from hostname...
		cleanup_ip_address(hostname);
    host = gethostbyname(hostname);

		if (!host) {
			// definitely, we can't do nothing
			log_error("gethostbyname");
			return -1;
		}

    memcpy((char *)&sin.sin_addr, host->h_addr, host->h_length);
    memcpy((char *)&sin_legacy.sin_addr, host->h_addr, host->h_length);

    // Bind fixed local ports (see DCTOOL_LOCAL_PORT above): the target memorizes
    // our source port at execute time and sends all syscall traffic there, so it
    // must be the same port on every run for `-o` reattach to work. UDP has no
    // TIME_WAIT, so a Ctrl-C'd instance frees the port immediately; a bind error
    // here means another dc-tool is still running.
    {
	struct sockaddr_in local;
	bzero(&local, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port = htons(DCTOOL_LOCAL_PORT);
	if (bind(dcsocket, (struct sockaddr *)&local, sizeof(local)) < 0) {
	    log_error("bind (is another dc-tool running?)");
	    return -1;
	}
	local.sin_port = htons(DCTOOL_LOCAL_PORT_LEGACY);
	if (bind(dcsocket_legacy, (struct sockaddr *)&local, sizeof(local)) < 0) {
	    log_error("bind legacy (is another dc-tool running?)");
	    return -1;
	}
    }

    // Connect legacy port first so that v2.0.0+ port won't conflict
    if (connect(dcsocket_legacy, (struct sockaddr *)&sin_legacy, sizeof(sin_legacy)) < 0) {
	log_error("connect_legacy");
	return -1;
    }

    // Connect v2.0.0+ port
    if (connect(dcsocket, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
  log_error("connect");
  return -1;
    }

#ifdef __MINGW32__
    unsigned long flags = 1;
	  int failed = 0;
    int failed_legacy = 0;
    failed = ioctlsocket(dcsocket, FIONBIO, &flags);
    failed_legacy = ioctlsocket(dcsocket_legacy, FIONBIO, &flags);
    if ((failed == SOCKET_ERROR) || (failed_legacy == SOCKET_ERROR)) {
	log_error("ioctlsocket");
	return -1;
    }
#else
    fcntl(dcsocket, F_SETFL, O_NONBLOCK);
    fcntl(dcsocket_legacy, F_SETFL, O_NONBLOCK);
#endif

    return 0;
}

int recv_response(unsigned char *buffer, int timeout)
{
    unsigned int started;

    if(timeout <= 0)
        return -1;
    started = time_in_usec();
    for(;;)
    {
        unsigned int elapsed = time_in_usec() - started;
        struct timeval wait;
        fd_set readfds;
        int ready;
        int rv;

        if(elapsed >= (unsigned int)timeout)
            return -1;
        elapsed = (unsigned int)timeout - elapsed;
        wait.tv_sec = elapsed / 1000000U;
        wait.tv_usec = elapsed % 1000000U;
        FD_ZERO(&readfds);
        FD_SET(global_socket, &readfds);
#ifdef __MINGW32__
        ready = select(0, &readfds, NULL, NULL, &wait);
        if(ready == SOCKET_ERROR)
        {
            if(WSAGetLastError() == WSAEINTR)
                continue;
            return -1;
        }
#else
        ready = select(global_socket + 1, &readfds, NULL, NULL, &wait);
        if(ready < 0)
        {
            if(errno == EINTR)
                continue;
            return -1;
        }
#endif
        if(ready == 0)
            return -1;
        rv = recv(global_socket, (void *)buffer, 2048, 0);
        if(rv >= 0)
            return rv;
#ifdef __MINGW32__
        if(WSAGetLastError() != WSAEWOULDBLOCK &&
           WSAGetLastError() != WSAEINTR)
            return -1;
#else
        if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            return -1;
#endif
    }
}

/* Wait for the response whose id matches `command`, draining anything else.
 * Stale packets are real on this link: a command retransmitted after a lost
 * reply gets answered twice, and the duplicate reply then arrives at the NEXT
 * handshake. The stock code treated any mismatch as a protocol error and
 * re-sent CMD_LOADBIN — with an already-advanced dcaddr in the DONEBIN case —
 * desyncing the target into an unrecoverable retry loop while the DC spins in
 * its IRQ-masked CDFS wait (machine freeze, physical reset required). A game
 * console push caught here is printed instead of lost. Returns the matching
 * packet size, or -1 on timeout (caller resends its command and retries). */
static int recv_matching(unsigned char *buffer, char *command, int timeout)
{
    unsigned int start = time_in_usec();
    unsigned int elapsed = 0;

    do
    {
        int packet_size = recv_response(buffer, timeout - elapsed);
        if(packet_size == -1)
            return -1;
        /* UDP preserves datagram boundaries, but a malformed/empty datagram
         * must not make the dispatcher compare four stale stack bytes. */
        if(packet_size < 4)
        {
            elapsed = time_in_usec() - start;
            continue;
        }
        if(packet_size >= COMMAND_LEN &&
           !memcmp(((command_t *)buffer)->id, command, 4))
            return packet_size;
        if(!memcmp(((command_t *)buffer)->id, CMD_WRITE_PUSH, 4))
            dc_write_push(buffer, packet_size, NULL, NULL);
        elapsed = time_in_usec() - start;
    }
    while(elapsed < (unsigned int)timeout);

    return -1;
}

/* P7 bulk replies are matched by command AND transaction. Draining an old
 * same-ID datagram is mandatory: the four city windows reuse one target
 * scratch address, so ID-only matching would let a delayed DONE from window N
 * falsely complete window N+1. */
static int recv_matching_p7(unsigned char *buffer, const char *command,
                            unsigned int txid, int minimum_size, int timeout)
{
    unsigned int start = time_in_usec();
    unsigned int elapsed = 0;

    do
    {
        int packet_size = recv_response(buffer, timeout - elapsed);
        if(packet_size == -1)
            return -1;
        if(packet_size >= minimum_size && packet_size >= COMMAND_LEN &&
           !memcmp(((command_t *)buffer)->id, command, 4) &&
           ntohl(((command_t *)buffer)->address) == txid)
            return packet_size;
        if(packet_size >= 4 &&
           !memcmp(((command_t *)buffer)->id, CMD_WRITE_PUSH, 4))
            dc_write_push(buffer, packet_size, NULL, NULL);
        else if(packet_size >= 4 &&
                !memcmp(((command_t *)buffer)->id, CMD_CDFSACK_P7, 4))
            dc_cdfs_p7_ack(buffer, packet_size);
        dc_cdfs_p7_poll();
        elapsed = time_in_usec() - start;
    }
    while(elapsed < (unsigned int)timeout);

    return -1;
}

int send_command(char *command, unsigned int addr, unsigned int size, unsigned char *data, unsigned int dsize)
{
    unsigned char c_buff[2048];
    unsigned int tmp;
    int error = 0;

    if(dsize > sizeof(c_buff) - COMMAND_LEN || (dsize != 0 && data == NULL))
        return -1;
    memcpy(c_buff, command, 4);
    tmp = htonl(addr);
    memcpy(c_buff + 4, &tmp, 4);
    tmp = htonl(size);
    memcpy(c_buff + 8, &tmp, 4);
    if (data != 0)
	memcpy(c_buff + 12, data, dsize);

    error = send(global_socket, (void *)c_buff, 12+dsize, 0);

    if(error == -1) {
#ifndef __MINGW32__
	if(errno == EAGAIN)
		return 0;
	fprintf(stderr, "error: %s\n", strerror(errno));
#else
	/* WSAEWOULDBLOCK is a non-fatal error,  so continue */
	if(WSAGetLastError() == WSAEWOULDBLOCK)
	    return 0;

	fprintf(stderr, "error: %d\n", WSAGetLastError());
#endif

	return -1;
    }

    return 0;
}

/* Synchronize reset with the target's polling service. VERSION is safe to
 * retransmit and its reply proves that resident dcload code has actually run;
 * unlike the ordinary prepare_comms() loop, this wait remains bounded. */
static int probe_reset_service(unsigned char *buffer)
{
    unsigned int started = time_in_usec();

    for(;;)
    {
	unsigned int elapsed = time_in_usec() - started;
	unsigned int remaining;
	unsigned int wait_usec;

	if(elapsed >= REBOOT_HANDSHAKE_TIMEOUT_USEC)
	    return 0;
	remaining = REBOOT_HANDSHAKE_TIMEOUT_USEC - elapsed;
	wait_usec = remaining < REBOOT_PROBE_ATTEMPT_USEC
	          ? remaining : REBOOT_PROBE_ATTEMPT_USEC;
	if(send_command(CMD_VERSION, encoded_tool_ver, DCTOOL_FEATURES,
	                NULL, 0) < 0)
	    return 0;
	if(recv_matching(buffer, CMD_VERSION, wait_usec) >= 0)
	    return 1;
    }
}

unsigned int upload(char *filename, unsigned int address)
{
    int inputfd;
    int size = 0;
    int sectsize;
    unsigned char *inbuf;

    double stime, etime;
#ifdef WITH_BFD
    bfd *somebfd;
#else
    Elf *elf;
    Elf32_Ehdr *ehdr;
    Elf32_Shdr *shdr;
    Elf_Scn *section = NULL;
    Elf_Data *data;
    char *section_name;
    size_t index;
#endif

#ifdef WITH_BFD
    if ((somebfd = bfd_openr(filename, 0))) {
        if (bfd_check_format(somebfd, bfd_object)) {
            /* try bfd first */
            asection *section;

            printf("File format is %s, ", somebfd->xvec->name);
            address = somebfd->start_address;
            size = 0;
            printf("start address is 0x%08x\n", address);

            gettimeofday(&starttime, 0);

            for (section = somebfd->sections; section != NULL; section = section->next) {
                if ((section->flags & SEC_HAS_CONTENTS) && (section->flags & SEC_LOAD)) {
                    sectsize = bfd_section_size(section);
                    printf("Section %s, ",section->name);
                    printf("lma 0x%x, ", (unsigned int)section->lma);
                    printf("size %d\n",sectsize);

                    if (sectsize) {
                        size += sectsize;
                        inbuf = malloc(sectsize);
                        bfd_get_section_contents(somebfd, section, inbuf, 0, sectsize);

                        if(send_data(inbuf, section->lma, sectsize) == -1)
                            return -1;

                        free(inbuf);
                    }
                }
            }

            bfd_close(somebfd);
            goto done_transfer;
        }

        bfd_close(somebfd);
    }
#else /* !WITH_BFD -- use libelf */
    if(elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "libelf initialization error: %s\n", elf_errmsg(-1));
        return -1;
    }

    if((inputfd = open(filename, O_RDONLY | O_BINARY)) < 0) {
        log_error(filename);
        return -1;
    }

    if(!(elf = elf_begin(inputfd, ELF_C_READ, NULL))) {
        fprintf(stderr, "Cannot read ELF file: %s\n", elf_errmsg(-1));
        return -1;
    }

    if(elf_kind(elf) == ELF_K_ELF) {
        if(!(ehdr = elf32_getehdr(elf))) {
            fprintf(stderr, "Unable to read ELF header: %s\n", elf_errmsg(-1));
            return -1;
        }

        address = ehdr->e_entry;
        printf("File format is ELF, start address is 0x%08x\n", address);

        /* Retrieve the index of the ELF section containing the string table of
           section names */
        if(elf_getshdrstrndx(elf, &index)) {
            fprintf(stderr, "Unable to read section index: %s\n", elf_errmsg(-1));
            return -1;
        }

        gettimeofday(&starttime, 0);
        while((section = elf_nextscn(elf, section))) {
            if(!(shdr = elf32_getshdr(section))) {
                fprintf(stderr, "Unable to read section header: %s\n", elf_errmsg(-1));
                return -1;
            }

            if(!(section_name = elf_strptr(elf, index, shdr->sh_name))) {
                fprintf(stderr, "Unable to read section name: %s\n", elf_errmsg(-1));
                return -1;
            }

            if(!shdr->sh_addr)
                continue;

            /* Check if there's some data to upload. */
            data = elf_getdata(section, NULL);
            if(!data->d_buf || !data->d_size)
                continue;

            printf("Section %s, lma 0x%08x, size %d\n", section_name,
                   shdr->sh_addr, shdr->sh_size);
            size += shdr->sh_size;

            do {
                if(send_data(data->d_buf, shdr->sh_addr + data->d_off,
                             data->d_size) == -1)
                    return -1;
            } while((data = elf_getdata(section, data)));
        }

        elf_end(elf);
        close(inputfd);
        goto done_transfer;
    }
    else {
        elf_end(elf);
        close(inputfd);
    }
#endif /* WITH_BFD */
    /* if all else fails, send raw bin */
    inputfd = open(filename, O_RDONLY | O_BINARY);

    if (inputfd < 0) {
        log_error(filename);
        return -1;
    }

    printf("File format is raw binary, start address is 0x%08x\n", address);

    size = lseek(inputfd, 0, SEEK_END);
    lseek(inputfd, 0, SEEK_SET);

    inbuf = malloc(size);
    read(inputfd, inbuf, size);
    close(inputfd);

    // v2.0.0+ Data transfer timekeeping is inside send_data() now
    if(send_data(inbuf, address, size) == -1)
        return -1;

done_transfer:
    stime = starttime.tv_sec + starttime.tv_usec / 1000000.0;
    etime = endtime.tv_sec + endtime.tv_usec / 1000000.0;

    printf("Transferred %d bytes at %f bytes / sec\n", size, (double) size / (etime - stime));
    fflush(stdout);

    return address;
}

int download(char *filename, unsigned int address,
	      unsigned int size, unsigned int quiet)
{
    int outputfd;

    unsigned char *data;
    double stime, etime;

    outputfd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);

    if (outputfd < 0) {
	log_error(filename);
	return -1;
    }

    data = malloc(size);

    recv_data(data, address, size, 0);

    printf("Received %d bytes\n", size);

    stime = starttime.tv_sec + starttime.tv_usec / 1000000.0;
    etime = endtime.tv_sec + endtime.tv_usec / 1000000.0;

    printf("Transferred at %f bytes / sec\n", (double) size / (etime - stime));
    fflush(stdout);

    write(outputfd, data, size);

    close(outputfd);
    free(data);

    return 0;
}

int execute(unsigned int address, unsigned int console, unsigned int cdfsredir)
{
    unsigned char buffer[2048];

    if(!legacy || force_legacy) // dcload-ip v2+ conditions
    {
      printf("Sending execute command (0x%08x, console=%d, cdfsredir=%d)...",address | 0xa0000000,console,cdfsredir);
    }
    else
    {
      printf("Sending execute command (0x%08x, console=%d, cdfsredir=%d)...",address,console,cdfsredir);
    }

    do
	send_cmd(CMD_EXECUTE, address, (cdfsredir << 1) | console, NULL, 0);
    while (recv_response(buffer, PACKET_TIMEOUT) == -1);

    printf("executing\n");
    return 0;
}

int do_console(char *path, char *isofile)
{
    int isofd = -1;
    int packet_size;
    unsigned char buffer[2048];

    if (isofile) {
	isofd = open(isofile, O_RDONLY | O_BINARY);
	if (isofd < 0)
	    log_error(isofile);
    }

    /* Flush the upload/execute banner once, then keep all runtime target
     * console writes off this network-serving thread. */
    fflush(stdout);
    if(dc_console_sink_init() < 0)
        fprintf(stderr, "dc-tool: async console sink unavailable; target output disabled\n");

#ifndef __MINGW32__
    if (!nochroot && path){
      if (chroot(path))
	      log_error(path);
    }
#endif

    while (1) {
	while((packet_size = recv_response(buffer, PACKET_TIMEOUT)) == -1) {
	    dc_cdfs_p7_poll();
	    if(cdfs_auto_retry_armed &&
	       (time_in_usec() - cdfs_auto_retry_started) >= CDFS_AUTO_RETRY_USEC) {
		/* This is deliberately the same one-shot recovery P6's manual
		 * `dc-tool -o` uses.  It is only armed by KOS's exact disc-change
		 * line, so a quiet game can never receive a stray RETV. */
		dc_console_sink_notice(
		    "dcload: CDFS silent for 3 seconds; sending P6 auto-retry nudge\n");
		if(send_command(CMD_RETVAL, 0, 0, NULL, 0) == -1)
		    return -1;
		cdfs_auto_retry_disarm();
	    }
	}
	/* Continuous console traffic must not postpone a lost-ACK completion
	 * retry; polling only on socket-idle timeouts made that accidental. */
	dc_cdfs_p7_poll();
	if(packet_size < 4)
	    continue;

	if (!(memcmp(buffer, CMD_EXIT, 4))) {
	    dc_console_sink_shutdown();
	    return -1;
	}
	if (!(memcmp(buffer, CMD_FSTAT, 4)))
	    CatchError(dc_fstat(buffer));
	if (!(memcmp(buffer, CMD_WRITE_OLD, 4)))
	    CatchError(dc_write(buffer));
  if (!(memcmp(buffer, CMD_WRITE, 4)))
	    CatchError(dc_write(buffer));
	if (!(memcmp(buffer, CMD_WRITE_PUSH, 4))) {
	    const unsigned char *payload = NULL;
	    unsigned int count = 0;
	    int telemetry;

	    telemetry = dc_write_push(buffer, packet_size, &payload, &count);
	    /* Binary telemetry shares DC22 transport but is not console text. Do
	       not let arbitrary bit patterns enter the CDFS marker state machine. */
	    if(!telemetry && count &&
	       cdfs_marker_feed(payload, count))
		cdfs_auto_retry_arm();
	    else if(!telemetry && count && cdfs_auto_retry_armed &&
		    cdfs_console_has_progress(payload, count))
		cdfs_auto_retry_disarm();
	}
	if (!(memcmp(buffer, CMD_READ, 4)))
	    CatchError(dc_read(buffer));
	if (!(memcmp(buffer, CMD_OPEN, 4)))
	    CatchError(dc_open(buffer));
	if (!(memcmp(buffer, CMD_CLOSE, 4)))
	    CatchError(dc_close(buffer));
	if (!(memcmp(buffer, CMD_CREAT, 4)))
	    CatchError(dc_creat(buffer));
	if (!(memcmp(buffer, CMD_LINK, 4)))
	    CatchError(dc_link(buffer));
	if (!(memcmp(buffer, CMD_UNLINK, 4)))
	    CatchError(dc_unlink(buffer));
	if (!(memcmp(buffer, CMD_CHDIR, 4)))
	    CatchError(dc_chdir(buffer));
	if (!(memcmp(buffer, CMD_CHMOD, 4)))
	    CatchError(dc_chmod(buffer));
	if (!(memcmp(buffer, CMD_LSEEK, 4)))
	    CatchError(dc_lseek(buffer));
	if (!(memcmp(buffer, CMD_TIME, 4)))
	    CatchError(dc_time(buffer));
	if (!(memcmp(buffer, CMD_STAT, 4)))
	    CatchError(dc_stat(buffer));
	if (!(memcmp(buffer, CMD_UTIME, 4)))
	    CatchError(dc_utime(buffer));
	if (!(memcmp(buffer, CMD_BAD, 4)))
	    fprintf(stderr, "command 15 should not happen... (but it did)\n");
	if (!(memcmp(buffer, CMD_OPENDIR, 4)))
	    CatchError(dc_opendir(buffer));
	if (!(memcmp(buffer, CMD_CLOSEDIR, 4)))
	    CatchError(dc_closedir(buffer));
	if (!(memcmp(buffer, CMD_READDIR, 4)))
	    CatchError(dc_readdir(buffer));
	if (!(memcmp(buffer, CMD_CDFSACK_P7, 4)))
	    dc_cdfs_p7_ack(buffer, packet_size);
	if (!(memcmp(buffer, CMD_CDFSREAD_P7, 4))) {
	    cdfs_auto_retry_disarm();
	    CatchError(dc_cdfs_p7_read_sectors(isofd, buffer, packet_size));
	}
	if (!(memcmp(buffer, CMD_CDFSREAD, 4))) {
	    /* A received request proves the disc-change-to-first-read gap was not
	       the lost-request wedge. Disarm before the synchronous bulk send: an
	       idle timer must never inject RETV into a legitimate later syscall. */
	    cdfs_auto_retry_disarm();
	    CatchError(dc_cdfs_redir_read_sectors(isofd, buffer, packet_size));
	}
	if (!(memcmp(buffer, CMD_GDBPACKET, 4)))
	    CatchError(dc_gdbpacket(buffer));
    }
    if(!(memcmp(buffer, CMD_REWINDDIR, 4)))
        CatchError(dc_rewinddir(buffer));

    return 0;
}

int open_gdb_socket(int port)
{
  struct sockaddr_in server_addr;

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons( port );
  server_addr.sin_addr.s_addr = htonl( INADDR_LOOPBACK );

  gdb_server_socket = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP );
#ifdef __MINGW32__
	if ( gdb_server_socket == INVALID_SOCKET) {
#else
  if ( gdb_server_socket < 0 ) {
#endif
	log_error( "error creating gdb server socket" );
	return -1;
  }

  const int enable_reuse_addr = 1;
  
#ifdef _WIN32
  /* For Windows this cast is necessary on modern GCC... */  
  int checkopt = setsockopt(gdb_server_socket, SOL_SOCKET, SO_REUSEADDR, 
                            (char *) &enable_reuse_addr, sizeof(enable_reuse_addr));
#else
  /* ... but maybe it's necessary for other OS as well? */	
  int checkopt = setsockopt(gdb_server_socket, SOL_SOCKET, SO_REUSEADDR, 
                            &enable_reuse_addr, sizeof(enable_reuse_addr));
#endif
	
#ifdef __MINGW32__
  if( checkopt == SOCKET_ERROR ) {
#else 
  if( checkopt < 0 ) {
#endif 
    log_error( "warning: failed to set gdb socket options" );
  }

  int checkbind = bind( gdb_server_socket, (struct sockaddr*)&server_addr, sizeof( server_addr ) );
#ifdef __MINGW32__
	if( checkbind == SOCKET_ERROR ) {
#else
  if ( checkbind < 0 ) {
#endif
	log_error( "error binding gdb server socket" );
	return -1;
  }

  int checklisten = listen( gdb_server_socket, 0 );
#ifdef __MINGW32__
	if ( checklisten == SOCKET_ERROR ) {
#else
  if ( checklisten < 0 ) {
#endif
	log_error( "error listening to gdb server socket" );
	return -1;
    }

    return 0;
}

#ifdef __MINGW32__
#define AVAILABLE_OPTIONS		"x:u:d:a:s:t:i:nlqhrgfo"
#else
#define AVAILABLE_OPTIONS		"x:u:d:a:s:t:m:c:i:nlqhrgfo"
#endif

/* Preserve the historical short-option parser: remove the one long option in
 * a single argv pass before getopt sees it. Both `--decode module` and
 * `--decode=module` are accepted, in any position. */
static int extract_decoder_option(int *argc, char **argv,
                                  const char **decoder_path)
{
    int read_index;
    int write_index = 1;

    for(read_index = 1; read_index < *argc; ++read_index)
    {
        const char *arg = argv[read_index];
        const char *path = NULL;

        if(!strcmp(arg, "--decode"))
        {
            if(read_index + 1 >= *argc)
            {
                fprintf(stderr, "dc-tool: --decode requires a module path\n");
                return -1;
            }
            path = argv[++read_index];
        }
        else if(!strncmp(arg, "--decode=", 9))
        {
            path = arg + 9;
        }
        if(path && !*path)
        {
            fprintf(stderr, "dc-tool: --decode requires a module path\n");
            return -1;
        }

        if(path)
        {
            if(*decoder_path)
            {
                fprintf(stderr, "dc-tool: --decode may be specified only once\n");
                return -1;
            }
            *decoder_path = path;
        }
        else
        {
            argv[write_index++] = argv[read_index];
        }
    }
    argv[write_index] = NULL;
    *argc = write_index;
    return 0;
}

/* --input may repeat and appears in any position, like --decode. A module
 * that is missing or incompatible is an error: control was requested. */
static int extract_input_options(int *argc, char **argv)
{
    int read_index;
    int write_index = 1;

    for(read_index = 1; read_index < *argc; ++read_index)
    {
        const char *arg = argv[read_index];
        const char *name = NULL;

        if(!strcmp(arg, "--input"))
        {
            if(read_index + 1 >= *argc)
            {
                fprintf(stderr, "dc-tool: --input requires a module\n");
                return -1;
            }
            name = argv[++read_index];
        }
        else if(!strncmp(arg, "--input=", 8))
        {
            name = arg + 8;
        }

        if(name)
        {
            if(!*name || input_load_module(name) < 0)
                return -1;
        }
        else
        {
            argv[write_index++] = argv[read_index];
        }
    }
    argv[write_index] = NULL;
    *argc = write_index;
    return 0;
}

int main(int argc, char *argv[])
{
    unsigned int address = 0x0c010000;
    unsigned int size = 0;
    unsigned int console = 1;
    unsigned int quiet = 0;
    unsigned char command = 0;
    unsigned int cdfs_redir = 0;
    int someopt;
    const char *decoder_path = NULL;

    /* Dynamically allocated, so it should be freed */
    char *filename = 0;
    char *isofile = 0;
    char *hostname = strdup(DREAMCAST_IP);
    char *cleanlist[4] = { 0, 0, 0, 0 };

    if(extract_decoder_option(&argc, argv, &decoder_path) < 0)
        return -1;
    if(extract_input_options(&argc, argv) < 0)
        return -1;

    if (argc < 2) {
	usage();
	return 0;
    }

#ifdef __MINGW32__
	if(start_ws())
		return -1;
#endif

    if(decoder_path)
        (void)dctool_telemetry_decoder_load(decoder_path);

	someopt = getopt(argc, argv, AVAILABLE_OPTIONS);
    while (someopt > 0) {
	switch (someopt) {
	case 'x':
	    if (command) {
		fprintf(stderr, "You can only specify one of -x, -u, -d, and -r\n");
		goto doclean;
	    }
	    command = 'x';
	    filename = malloc(strlen(optarg) + 1);
	    cleanlist[0] = filename;
	    strcpy(filename, optarg);
	    break;
	case 'u':
	    if (command) {
		fprintf(stderr, "You can only specify one of -x, -u, -d, and -r\n");
		goto doclean;
	    }
	    command = 'u';
	    filename = malloc(strlen(optarg) + 1);
	    cleanlist[0] = filename;
	    strcpy(filename, optarg);
	    break;
	case 'd':
	    if (command) {
		fprintf(stderr, "You can only specify one of -x, -u, -d, and -r\n");
		goto doclean;
	    }
	    command = 'd';
	    filename = malloc(strlen(optarg) + 1);
	    cleanlist[0] = filename;
	    strcpy(filename, optarg);
	    break;
#ifndef __MINGW32__
  case 'm':
      if (path) {
    fprintf(stderr, "-m and -c options are mutually exclusive, choose one\n");
    goto doclean;
      }
      nochroot = 1;
      path = realpath(optarg, NULL);
      if (path == NULL) {
        fprintf(stderr, "-m option with invalid path '%s'  \n", optarg);
        goto doclean;
      }
      set_mappath(path);
      cleanlist[1] = path;
      break;
	case 'c':
	    if (path) {
		fprintf(stderr, "-m and -c options are mutually exclusive, choose one\n");
		goto doclean;
	    }
      nochroot = 0;
	    path = malloc(strlen(optarg) + 1);
	    cleanlist[1] = path;
	    strcpy(path, optarg);
	    break;
#endif
	case 'i':
	    cdfs_redir = 1;
	    isofile = malloc(strlen(optarg) + 1);
	    cleanlist[2] = isofile;
	    strcpy(isofile, optarg);
	    break;
	case 'a':
	    address = strtoul(optarg, NULL, 0);
	    break;
	case 's':
	    size = strtoul(optarg, NULL, 0);
	    break;
	case 't':
	    hostname = malloc(strlen(optarg) + 1);
	    cleanlist[3] = hostname;
	    strcpy(hostname, optarg);

      unsigned int portcheck = 0;
      while((hostname[portcheck] != '\0') && (hostname[portcheck] != ':'))
      {
        portcheck++;
      }

      if(hostname[portcheck] == ':') // We have a dcload IP port override
      {
        // Null-terminate the IP string by overwriting the ':'
        hostname[portcheck++] = '\0';
        dcload_portnum = 0; // clear the v2.0.0+ default port

        // Fill in port override
        while(hostname[portcheck] != '\0')
        {
          dcload_portnum *= 10;
          dcload_portnum += hostname[portcheck++] - '0';
        }
      }

	    break;
	case 'n':
	    console = 0;
	    break;
  case 'l':
      force_legacy = 1;
      break;
	case 'q':
	    quiet = 1;
	    break;
	case 'h':
	    usage();
	    cleanup(cleanlist);
	    return 0;
	    break;
	case 'r':
	    if (command) {
		fprintf(stderr, "You can only specify one of -x, -u, -d, and -r\n");
		goto doclean;
	    }
	    command = 'r';
	    break;
	case 'o':
	    if (command) {
		fprintf(stderr, "You can only specify one of -x, -u, -d, -r, and -o\n");
		goto doclean;
	    }
	    command = 'o';
	    break;
	case 'g':
	    printf("Starting a GDB server on port 2159\n");
	    open_gdb_socket(2159);
		gdb_socket_started = 1;
	    break;
    case 'f':
        printf("Enabling fast transfer mode\n");
        fast_mode = 1;
        break;
	default:
	/* The user obviously mistyped something */
	    usage();
	    goto doclean;
	    break;
	}
	someopt = getopt(argc, argv, AVAILABLE_OPTIONS);
    }

    if (quiet)
	printf("Quiet download\n");

    if (cdfs_redir & (!console))
	console = 1;

    if (console & (command=='x'))
	printf("Console enabled\n");

#ifndef __MINGW32__
  if (path) {  	
    if (nochroot) {
      printf("Mapping /pc/ to <%s>\n", path);
    } else {
      printf("Chrooting to <%s>\n", path);
    }
  }
#endif

    if (cdfs_redir & (command=='x'))
	printf("Cdfs redirection enabled\n");

  if (open_sockets(hostname)<0) // Random port socket for dcload >= 2.0.0
  {
    fprintf(stderr, "Error opening sockets\n");
    goto doclean;
  }

    switch (command) {
    case 'x':
	printf("Upload <%s>\n", filename);
	address = upload(filename, address);

	if (address == -1)
	    goto doclean;

	{
	    unsigned char comms_buffer[2048];
	    if(promote_v2_after_legacy_transfer(comms_buffer) == -1)
	        goto doclean;
	}

  if(!legacy || force_legacy) // force_legacy is only valid for dcload-ip v2+
  {
    // Supposed to use the uncached area for this kind of thing, which dcload v2.0.0+ does
    printf("Executing at <0x%x>\n", address | 0xa0000000);
  }
  else // legacy = 1
  {
    printf("Executing at <0x%x>\n", address);
  }

	/* The stream starts before execution: dcload keeps only the newest
	   state until the program polls it (dcload P8 syscall 23). */
	if(input_start(hostname) < 0)
	    goto doclean;
	if(execute(address, console, cdfs_redir))
	    goto doclean;
	if (console)
	    do_console(path, isofile);
	break;
    case 'u':
	printf("Upload <%s> at <0x%x>\n", filename, address);
	if(upload(filename, address))
	    goto doclean;
	break;
    case 'd':
	if (!size) {
	    fprintf(stderr, "You must specify a size (-s <size>) with download (-d <filename>)\n");
	    goto doclean;
	}
	printf("Download %d bytes at <0x%x> to <%s>\n", size, address, filename);
	if(download(filename, address, size, quiet) == -1)
	    goto doclean;
	break;
    case 'o':
	printf("Reattaching console/fileserver...\n");
	{
	    /* Recover from a Ctrl-C'd dc-tool without touching the running game:
	       like standalone -r, nothing before this point ran prepare_comms(),
	       so run the handshake here to assign global_socket / the negotiated
	       v2 port. Its CMD_VERSION doubles as the revive signal — the target's
	       console_revive() clears console_dead on every attach, so the game's
	       fire-and-forget log stream resumes at this address, and with -i the
	       /cd fileserver below answers CDFS reads again. The game services the
	       inbound CMD_VERSION through bb->loop() during its console/file
	       syscall windows, exactly like the reset burst. No upload, no reboot:
	       the program keeps running throughout. */
	    unsigned char comms_buffer[2048];
	    if(prepare_comms(comms_buffer) < 0)
	        goto doclean;
	    if(promote_v2_after_legacy_transfer(comms_buffer) == -1)
	        goto doclean;
	}
	/* Unwedge nudge: if the game is stuck in the loader's unbounded CDFS wait
	   (it issued a read while no host was serving), that spin is the one
	   consumer polling the NIC right now — a single gratuitous CMD_RETVAL
	   completes the wait, the bogus read fails cleanly up in KOS, and the
	   game's next retry reaches the revived fileserver. If nothing is wedged
	   the packet is swallowed by the next syscall's non-blocking RX pass (at
	   worst costing one failed probe retry). */
	send_command(CMD_RETVAL, 0, 0, NULL, 0);
	printf("Reattached, serving console%s\n", isofile ? " + cdfs redirection" : "");
	if(input_start(hostname) < 0)
	    goto doclean;
	do_console(path, isofile);
	break;
    case 'r':
	printf("Resetting...\n");
	{
	    int handshake_ok = 0;
	    int reboot_try;
	    int reboot_sent = 0;
	    unsigned char comms_buffer[2048];

	    /* A KOS-wide service polls resident dcload independently of game output.
	       Synchronize with it before RBOT so reset does not depend on a telemetry
	       printf. Always advertise the real v2 feature set here: -l controls bulk
	       payload size, not reset or the running program's console contract. */
	    make_encoded_tool_version();
	    global_socket = dcsocket;
	    if(probe_reset_service(comms_buffer))
	        handshake_ok = 1;
	    if(!handshake_ok)
	    {
	        global_socket = dcsocket_legacy;
	        if(probe_reset_service(comms_buffer))
	            handshake_ok = 1;
	    }
	    if(!handshake_ok)
	        printf("No dcload reset-service reply after 6 seconds; "
	               "sending an unconfirmed reboot fallback.\n");

	    /* Burst RBOT on both already-open sockets. This removes the old socket-0
	       failure without making the VERSION reply a prerequisite, covers both
	       the v2 and legacy destination ports, and still spans far less than the
	       post-reboot link-negotiation gap. */
	    for(reboot_try = 0; reboot_try < REBOOT_RETRIES; reboot_try++)
	    {
		unsigned int reboot_start;
		global_socket = dcsocket;
		if(send_command(CMD_REBOOT, 0, 0, NULL, 0) == 0)
		    reboot_sent = 1;
		global_socket = dcsocket_legacy;
		if(send_command(CMD_REBOOT, 0, 0, NULL, 0) == 0)
		    reboot_sent = 1;
		reboot_start = time_in_usec();
		while((time_in_usec() - reboot_start) < REBOOT_RETRY_USEC)
		    ;
	    }
	    if(!reboot_sent)
	        goto doclean;
	}
	break;
    default:
	usage();
	break;
    }

    input_stop();
    cleanup(cleanlist);
    return 0;

/* Failed (I hate gotos...) */
doclean:
    input_stop();
    cleanup(cleanlist);
    return -1;
}
