#ifndef KEYD_SELFCHECK_H
#define KEYD_SELFCHECK_H

/* Start-up self-check (systemd ExecStartPre): exercises every module that needs no partition,
 * card or provisioned file. Returns 0 when everything passed. */
int keyd_self_check(void);

#endif
