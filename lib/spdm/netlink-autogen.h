/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/spdm.yaml */
/* YNL-GEN kernel header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_SPDM_GEN_H
#define _LINUX_SPDM_GEN_H

#include <net/netlink.h>
#include <net/genetlink.h>

#include <uapi/linux/spdm_netlink.h>
#include <netlink-autogen.h>
#include <uapi/linux/spdm.h>
#include <uapi/linux/hash_info.h>

enum {
	SPDM_NLGRP_SIG,
};

extern struct genl_family spdm_nl_family;

#endif /* _LINUX_SPDM_GEN_H */
