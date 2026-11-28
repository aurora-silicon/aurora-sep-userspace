/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * The request pam_aurora_touchid sends to aurora-touchid-rearm after a PAM
 * stack has accepted a password:
 *
 *   "AURORA-REARM-1\n" <user> '\0' <password> '\0' [<field> '\0' ...]
 *
 * Newer modules add "service=<PAM_SERVICE>" and "host=local" or "host=remote"
 * (PAM_RHOST set); older ones, or a request that would not fit, send none.
 * The service trusts the fields only from a root caller, and uses them only to
 * let the boot's first password of an account without prints arm Touch ID
 * (see aurora-touchid-rearm's serve()).
 *
 * and the one-line answer:
 *
 *   "ok rearmed\n"        Touch ID was locked; it is re-armed.
 *   "ok armed\n"          The first password since boot armed Touch ID.
 *   "ok boot-wait-ended\n" The first password since boot, of an account
 *                         without enrolled fingerprints, ended the wait after
 *                         boot; a lockout still holds.
 *   "ok cleared\n"        The password cleared pending failed matches.
 *   "ok noted\n"          The password restarted the driver's password clock.
 *   "ok not-locked\n"     Touch ID was not locked; nothing was checked.
 *   "ok no-prints\n"      Touch ID was not locked and the account has no
 *                         enrolled fingerprints; nothing was checked.
 *   "refused <why>\n"     The request was not allowed or the password did not
 *                         verify.
 *   "error <why>\n"       The driver could not re-arm.
 */
#ifndef AURORA_REARM_PROTO_H
#define AURORA_REARM_PROTO_H

#define AURORA_REARM_SOCKET      "/run/aurora-touchid-rearm.sock"
#define AURORA_REARM_MAGIC       "AURORA-REARM-1\n"
#define AURORA_REARM_FIELD_SERVICE "service="
#define AURORA_REARM_FIELD_LOCAL   "host=local"
#define AURORA_REARM_FIELD_REMOTE  "host=remote"
#define AURORA_REARM_MAX_REQUEST 1024
#define AURORA_REARM_MAX_REPLY   128
#define AURORA_REARM_TIMEOUT_S   10

#endif
