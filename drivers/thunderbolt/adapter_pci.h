/* SPDX-License-Identifier: GPL-2.0 */
/*
 * PCIe adapters on a Thunderbolt switch serve as endpoints for PCI tunnels.
 * Each may be attached to an upstream or downstream port of the PCIe switch
 * integrated into a Thunderbolt controller.
 *
 * Copyright (C) 2018 Lukas Wunner <lukas@wunner.de>
 */

#ifndef ADAPTER_PCI_H_
#define ADAPTER_PCI_H_

#include <linux/notifier.h>

int tb_pci_notifier_call(struct notifier_block *nb, unsigned long action,
			 void *data);
int tb_pci_correlate(struct pci_dev *pdev, void *data);

#endif
