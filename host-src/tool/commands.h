#ifndef __COMMANDS_H__
#define __COMMANDS_H__

struct _command_t {
	unsigned char id[4];
	unsigned int address;
	unsigned int size;
	unsigned char data[]; // Make flexible array member
} __attribute__ ((packed));

typedef struct _command_t command_t;

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

#define CMD_REBOOT   "RBOT"  /* reboot */

#define CMD_MAPLE		 "MAPL" /* Maple packet */
#define CMD_PMCR		 "PMCR" /* Performance counter packet */

/* Explicit VERSION-handshake feature bits. The version number alone cannot
 * distinguish this fork's transaction-safe CDFS protocol from stock 2.0.3. */
#define DCTOOL_FEATURE_CDFS_P7 0x00000001u
#define DCTOOL_FEATURES DCTOOL_FEATURE_CDFS_P7

#define COMMAND_LEN  12

#endif
