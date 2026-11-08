/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * The request pam_aurora_touchid sends to aurora-touchid-rearm after a PAM
 * stack has accepted a password:
 *
 *   "AURORA-REARM-1\n" <user> '\0' <password> '\0'
 *
 * and the one-line answer:
 *
 *   "ok rearmed\n"        Touch ID was locked; it is re-armed.
 *   "ok not-locked\n"     Touch ID was not locked; nothing was checked.
 *   "refused <why>\n"     The request was not allowed or the password did not
 *                         verify.
 *   "error <why>\n"       The driver could not re-arm.
 */
#ifndef AURORA_REARM_PROTO_H
#define AURORA_REARM_PROTO_H

#define AURORA_REARM_SOCKET      "/run/aurora-touchid-rearm.sock"
#define AURORA_REARM_MAGIC       "AURORA-REARM-1\n"
#define AURORA_REARM_MAX_REQUEST 1024
#define AURORA_REARM_MAX_REPLY   128
#define AURORA_REARM_TIMEOUT_S   10

#endif
