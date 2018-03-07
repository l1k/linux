// SPDX-License-Identifier: GPL-2.0
/*
 * PCIe adapters on a Thunderbolt switch serve as endpoints for PCI tunnels.
 * Each may be attached to an upstream or downstream port of the PCIe switch
 * integrated into a Thunderbolt controller.
 *
 * Copyright (C) 2018 Lukas Wunner <lukas@wunner.de>
 */

#include "tb.h"
#include "tunnel_pci.h"
#include "adapter_pci.h"

/**
 * tb_is_pci_adapter() - whether given PCI device is a Thunderbolt PCIe adapter
 * @pdev: PCI device
 *
 * For simplicity this function returns a false positive in the following cases
 * and callers need to make sure they can handle that:
 * * Upstream port on a host controller
 * * Downstream port to the XHCI on a host controller
 * * Downstream port on non-chainable endpoint controllers such as Port Ridge
 */
static bool tb_is_pci_adapter(struct pci_dev *pdev)
{
	/* downstream ports with devfn 0 are reserved for the NHI */
	return pdev->is_thunderbolt &&
	       (pci_pcie_type(pdev) == PCI_EXP_TYPE_UPSTREAM ||
		(pci_pcie_type(pdev) == PCI_EXP_TYPE_DOWNSTREAM &&
		 pdev->devfn));
}

/**
 * tb_pci_find_port() - locate Thunderbolt port for given PCI device
 * @pdev: PCI device
 *
 * Walk up the PCI hierarchy from @pdev to discover the sequence of
 * PCIe upstream and downstream ports leading to the host controller.
 * Then walk down the Thunderbolt daisy-chain following the previously
 * discovered sequence along the tunnels we've established.
 *
 * Return the port corresponding to @pdev, or %NULL if none was found.
 *
 * This function needs to be called under the global Thunderbolt lock
 * to prevent tb_switch and tb_pci_tunnel structs from going away.
 */
static struct tb_port *tb_pci_find_port(struct tb *tb, struct pci_dev *pdev)
{
	struct tb_cm *tcm = tb_priv(tb);
	struct tb_pci_tunnel *tunnel;
	struct pci_dev *parent_pdev;
	struct tb_port *parent_port;
	struct tb_port *port;

	if (!tb_is_pci_adapter(pdev))
		return NULL;

	/* base of the recursion: we've reached the host controller */
	if (pdev->bus == tb->upstream->subordinate) {
		tb_sw_for_each_port(tb->root_switch, port)
			if (port->pci.devfn == pdev->devfn)
				return port;

		return NULL;
	}

	/* recurse up the PCI hierarchy */
	parent_pdev = pci_upstream_bridge(pdev);
	if (!parent_pdev)
		return NULL;

	parent_port = tb_pci_find_port(tb, parent_pdev);
	if (!parent_port)
		return NULL;

	switch (parent_port->config.type) {
	case TB_TYPE_PCIE_UP:
		/*
		 * A PCIe upstream adapter is the parent of
		 * a PCIe downstream adapter on the same switch.
		 */
		tb_sw_for_each_port(parent_port->sw, port)
			if (port->config.type == TB_TYPE_PCIE_DOWN &&
			    port->pci.devfn == pdev->devfn)
				return port;
		return NULL;
	case TB_TYPE_PCIE_DOWN:
		/*
		 * A PCIe downstream adapter is the parent of
		 * a PCIe upstream adapter at the other end of a tunnel.
		 */
		list_for_each_entry(tunnel, &tcm->tunnel_list, list)
			if (tunnel->down_port == parent_port)
				return tunnel->up_port;
		return NULL;
	default:
		return NULL;
	}
}

/**
 * tb_pci_notifier_call() - Thunderbolt PCI bus notifier
 * @nb: Notifier block embedded in struct tb_cm
 * @action: Notifier action
 * @data: PCI device
 *
 * On addition of PCI device @data, correlate it with a PCIe adapter on the
 * Thunderbolt bus and store a pointer to the PCI device in struct tb_port.
 * On deletion, reset the pointer to %NULL.
 */
int tb_pci_notifier_call(struct notifier_block *nb, unsigned long action,
			 void *data)
{
	struct tb_cm *tcm = container_of(nb, struct tb_cm, pci_notifier);
	struct tb *tb = tb_from_priv(tcm);
	struct device *dev = data;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct tb_port *port;

	if ((action != BUS_NOTIFY_ADD_DEVICE &&
	     action != BUS_NOTIFY_DEL_DEVICE) || !tb_is_pci_adapter(pdev))
		return NOTIFY_DONE;

	mutex_lock(&tb->lock);
	port = tb_pci_find_port(tb, pdev);
	if (!port)
		goto out;

	switch (action) {
	case BUS_NOTIFY_ADD_DEVICE:
		port->pci.dev = pdev;
		tb_port_info(port, "correlates with %s\n", pci_name(pdev));
		break;
	case BUS_NOTIFY_DEL_DEVICE:
		port->pci.dev = NULL;
		tb_port_info(port, "no longer correlates with %s\n",
			     pci_name(pdev));
		break;
	}
out:
	mutex_unlock(&tb->lock);
	return NOTIFY_DONE;
}

/**
 * tb_pci_correlate() - Correlate given PCI device with a Thunderbolt port
 * @pdev: PCI device
 * @data: Thunderbolt bus
 *
 * Correlate @pdev with a PCIe adapter on Thunderbolt bus @data and store a
 * pointer to the PCI device in struct tb_port.  Intended to be used as a
 * pci_walk_bus() callback.
 */
int tb_pci_correlate(struct pci_dev *pdev, void *data)
{
	struct tb *tb = data;
	struct tb_port *port;

	port = tb_pci_find_port(tb, pdev);
	if (port) {
		port->pci.dev = pdev;
		tb_port_info(port, "correlates with %s\n", pci_name(pdev));
	}

	return 0;
}
