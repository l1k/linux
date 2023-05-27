# SPDX-License-Identifier: GPL-2.0
#
# DMTF Security Protocol and Data Model (SPDM)
# https://www.dmtf.org/dsp/DSP0274
#
# Copyright (C) 2024 Intel Corporation

obj-$(CONFIG_SPDM) += spdm.o

spdm-y := core.o req-authenticate.o
spdm-$(CONFIG_SYSFS) += req-sysfs.o
