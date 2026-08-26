#ifndef __CDFS_H__
#define __CDFS_H__

void cdfs_redir_enable(void);
void cdfs_p7_begin(unsigned int txid, unsigned int bytes);
void cdfs_p7_cancel(unsigned int txid);
int cdfs_p7_active(void);
int cdfs_p7_matches(unsigned int txid);
void cdfs_p7_transfer_started(void);
int cdfs_p7_complete(unsigned int txid, int status);
int cdfs_p7_result(unsigned int txid, int *status);
void cdfs_redir_save(void);
void cdfs_redir_disable(void);
void cdfs_redir_enable(void);

#endif
