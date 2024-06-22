.. SPDX-License-Identifier: GPL-2.0

=================================
Documentation for /proc/sys/spdm/
=================================

Copyright (C) 2024 Intel Corporation

This directory allows tuning Security Protocol and Data Model (SPDM)
parameters.  SPDM enables device authentication, measurement, key
exchange and encrypted sessions.

max_signatures_size
===================

Maximum amount of memory occupied by the log of signatures (per device,
in bytes, 16 MiB by default).

The log is meant for re-verification of signatures by remote attestation
services which do not trust the kernel to have verified the signatures
correctly or which want to apply policy constraints of their own.
A signature is computed over the transcript (a concatenation of all
SPDM messages exchanged with the device during an authentication
sequence).  The transcript can be a few kBytes or up to several MBytes
in size, hence this parameter prevents the log from consuming too much
memory.

The kernel always stores the most recent signature in the log even if it
exceeds ``max_signatures_size``.  Additionally as many older signatures
are kept in the log as this limit allows.

If you reduce the limit, signatures are purged immediately to free up
memory.
