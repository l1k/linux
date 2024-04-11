/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/spdm.yaml */
/* YNL-GEN uapi header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _UAPI_LINUX_SPDM_NETLINK_H
#define _UAPI_LINUX_SPDM_NETLINK_H

#define SPDM_FAMILY_NAME	"spdm"
#define SPDM_FAMILY_VERSION	1

enum {
	SPDM_A_SIG_DEVICE = 1,
	SPDM_A_SIG_RSP_CODE,
	SPDM_A_SIG_SLOT,
	SPDM_A_SIG_HASH_ALGO,
	SPDM_A_SIG_SIG_OFFSET,
	SPDM_A_SIG_REQ_NONCE_OFFSET,
	SPDM_A_SIG_RSP_NONCE_OFFSET,
	SPDM_A_SIG_COMBINED_SPDM_PREFIX,
	SPDM_A_SIG_TRANSCRIPT,

	__SPDM_A_SIG_MAX,
	SPDM_A_SIG_MAX = (__SPDM_A_SIG_MAX - 1)
};

enum {
	SPDM_CMD_SIG = 1,

	__SPDM_CMD_MAX,
	SPDM_CMD_MAX = (__SPDM_CMD_MAX - 1)
};

#define SPDM_MCGRP_SIG	"sig"

#endif /* _UAPI_LINUX_SPDM_NETLINK_H */
