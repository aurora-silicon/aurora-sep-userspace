/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * DESIGN DRAFT. The request pam_aurora_userbag sends to aurora-userbag-helper:
 *
 *   "AURORA-USERBAG-1\n" <op> '\0' <user> '\0' <secret> '\0' [<new secret> '\0']
 *
 * op "unlock": a PAM stack accepted <secret> as the password of <user>; open
 *              that user's key bag with it.
 * op "change": the password of <user> changed from <secret> to <new secret>;
 *              re-key the bag (needs the kernel's SEP_BIO_KEYBAG_CHANGE).
 *
 * The one-line answer:
 *
 *   "ok unlocked\n" | "ok changed\n" | "ok no-bag\n"   (the user has no bag)
 *   "refused <why>\n"   the caller may not ask, or the enclave refused the secret
 *   "error <why>\n"     the driver could not do it
 */
#ifndef AURORA_USERBAG_PROTO_H
#define AURORA_USERBAG_PROTO_H

#define AURORA_USERBAG_SOCKET      "/run/aurora-userbag.sock"
#define AURORA_USERBAG_MAGIC       "AURORA-USERBAG-1\n"
#define AURORA_USERBAG_MAX_REQUEST 1024
#define AURORA_USERBAG_MAX_REPLY   128
#define AURORA_USERBAG_TIMEOUT_S   10

#endif
