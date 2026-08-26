#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include "packet.h"

typedef struct __attribute__ ((packed, aligned(4))) {
	unsigned char id[4];
	unsigned int address;
	unsigned int size;
	unsigned char data[]; // Make flexible array member
} command_t;

#define CMD_EXECUTE  "EXEC" /* execute */
#define CMD_LOADBIN  "LBIN" /* begin receiving binary */
#define CMD_PARTBIN  "PBIN" /* part of a binary */
#define CMD_DONEBIN  "DBIN" /* end receiving binary */
#define CMD_SENDBIN  "SBIN" /* send a binary */
#define CMD_SENDBINQ "SBIQ" /* send a binary, quiet */
#define CMD_VERSION  "VERS" /* send version info */
#define CMD_RETVAL   "RETV" /* return value */
#define CMD_CDFSDONE_P7 "DC24" /* tagged CDFS completion: txid, status */
#define CMD_CDFSACK_P7  "DC25" /* target acknowledgement: txid, status */
#define CMD_CDFSPART_P7 "DC26" /* tagged bulk payload: txid, destination, data */
#define CMD_CDFSBULKDONE_P7 "DC27" /* tagged bulk verify: txid, missing range */
#define CMD_REBOOT   "RBOT" /* reboot */
#define CMD_MAPLE    "MAPL" /* Maple packet */
#define CMD_PMCR 		 "PMCR" /* Performance counter packet */

#define COMMAND_LEN  12

extern unsigned int tool_ip;
extern unsigned char tool_mac[6];
extern unsigned short tool_port;
// Format is a uint, encoded like this: (major << 16) | (minor << 8) | patch
extern unsigned int tool_version;
extern unsigned int tool_features;

#define DCTOOL_MAJOR ((tool_version & 0x00ff0000) >> 16)
#define DCTOOL_MINOR ((tool_version & 0x0000ff00) >> 8)
#define DCTOOL_PATCH (tool_version & 0x000000ff)
#define DCTOOL_FEATURE_CDFS_P7 0x00000001u
#define DCTOOL_HAS_CDFS_P7 (tool_features & DCTOOL_FEATURE_CDFS_P7)

void cmd_reboot(void);
void cmd_execute(ether_header_t * ether, ip_header_t * ip, udp_header_t * udp, command_t * command);
void cmd_loadbin(ip_header_t * ip, udp_header_t * udp, command_t * command);
void cmd_highspeed_partbin(udp_header_t * udp, unsigned int udp_data_size);
void cmd_partbin(command_t *command, unsigned int packet_size);
void cmd_donebin(ip_header_t * ip, udp_header_t * udp, command_t * command);
void cmd_sendbinq(ip_header_t * ip, udp_header_t * udp, command_t * command);
void cmd_sendbin(ip_header_t * ip, udp_header_t * udp, command_t * command);
void cmd_version(ip_header_t * ip, udp_header_t * udp, command_t * command);
void cmd_retval(ip_header_t * ip, udp_header_t * udp, command_t * command);
void cmd_maple(ip_header_t * ip, udp_header_t * udp, command_t * command);
void cmd_pmcr(ip_header_t * ip, udp_header_t * udp, command_t * command);
void cmd_cdfs_p7_complete(ip_header_t *ip, udp_header_t *udp,
                          command_t *command);
int cmd_cdfs_p7_bulk_begin(unsigned int txid, unsigned int destination,
                           unsigned int size);
void cmd_cdfs_p7_bulk_end(unsigned int txid);
int cmd_cdfs_p7_bulk_ready(unsigned int txid);
void cmd_cdfs_p7_part(command_t *command, unsigned int packet_size);
void cmd_cdfs_p7_done(ip_header_t *ip, udp_header_t *udp,
                      command_t *command, unsigned int packet_size);

#endif
