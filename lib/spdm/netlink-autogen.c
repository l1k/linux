// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/spdm.yaml */
/* YNL-GEN kernel source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <net/netlink.h>
#include <net/genetlink.h>

#include <uapi/linux/spdm_netlink.h>
#include <netlink-autogen.h>
#include <uapi/linux/spdm.h>
#include <uapi/linux/hash_info.h>

/* Ops table for spdm */
static const struct genl_split_ops spdm_nl_ops[] = {
};

static const struct genl_multicast_group spdm_nl_mcgrps[] = {
	[SPDM_NLGRP_SIG] = { "sig", },
};

struct genl_family spdm_nl_family __ro_after_init = {
	.name		= SPDM_FAMILY_NAME,
	.version	= SPDM_FAMILY_VERSION,
	.netnsok	= true,
	.parallel_ops	= true,
	.module		= THIS_MODULE,
	.split_ops	= spdm_nl_ops,
	.n_split_ops	= ARRAY_SIZE(spdm_nl_ops),
	.mcgrps		= spdm_nl_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(spdm_nl_mcgrps),
};
