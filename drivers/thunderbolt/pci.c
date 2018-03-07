// SPDX-License-Identifier: GPL-2.0
/*
 * Thunderbolt driver - PCIe Adapters
 *
 * PCIe Adapters on a Router serve as endpoints for PCIe tunnels.
 * Each of them corresponds to a PCIe Upstream or Downstream port
 * visible to system software.  On Platform Integrated Host Routers,
 * PCIe Adapters are visible as Root Ports.
 *
 * Copyright (C) 2018 Lukas Wunner <lukas@wunner.de>
 * Copyright (C) 2024 Intel Corporation
 */

#include <linux/notifier.h>

#include "tb.h"
#include "tunnel.h"

/**
 * tb_pci_find_port() - locate PCIe Adapter corresponding to given PCI device
 * @tb: Thunderbolt domain
 * @pdev: PCI device
 *
 * Recurse up the PCI hierarchy from @pdev in search for the Host Router of
 * domain @tb.  On the way back from the recursion, match up PCIe Adapters
 * with pci_dev's using the Device/Function number obtained from DROM (or
 * via the Router Operation "Get PCIe Downstream Entry Mapping").
 *
 * Return the PCIe Adapter corresponding to @pdev, or %NULL if none was found.
 *
 * This function needs to be called under the global Thunderbolt lock
 * to prevent tb_switch and tb_tunnel structs from going away.
 */
static struct tb_port *tb_pci_find_port(struct tb *tb, struct pci_dev *pdev)
{
	struct tb_cm *tcm = tb_priv(tb);
	struct tb_tunnel *tunnel;
	struct pci_dev *parent_pdev;
	struct tb_port *parent_port;
	struct tb_port *port;

	if (pdev->class >> 8 != PCI_CLASS_BRIDGE_PCI)
		return NULL;

	/* base of the recursion: we've reached the Host Router */
	if (pdev->bus == tcm->pci_root) {
		tb_switch_for_each_port(tb->root_switch, port)
			if (port->devfn == pdev->devfn)
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
		 * A PCIe Upstream Adapter is the parent of
		 * a PCIe Downstream Adapter on the same switch.
		 */
		tb_switch_for_each_port(parent_port->sw, port)
			if (port->config.type == TB_TYPE_PCIE_DOWN &&
			    port->devfn == pdev->devfn)
				return port;
		return NULL;
	case TB_TYPE_PCIE_DOWN:
		/*
		 * A PCIe Downstream Adapter is the parent of
		 * a PCIe Upstream Adapter at the other end of a tunnel.
		 */
		list_for_each_entry(tunnel, &tcm->tunnel_list, list)
			if (tunnel->src_port == parent_port)
				return tunnel->dst_port;
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
 * On addition of PCI device @data, associate it with a PCIe adapter in the
 * Thunderbolt domain by storing a pointer to the PCI device in struct tb_port.
 * On deletion, reset the pointer to %NULL.
 */
static int tb_pci_notifier_call(struct notifier_block *nb,
				unsigned long action, void *data)
{
	struct tb_cm *tcm = container_of(nb, struct tb_cm, pci_notifier);
	struct tb *tb = tb_from_priv(tcm);
	struct device *dev = data;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct tb_port *port;

	if ((pdev->class >> 8 != PCI_CLASS_BRIDGE_PCI) ||
	    (action != BUS_NOTIFY_ADD_DEVICE &&
	     action != BUS_NOTIFY_DEL_DEVICE))
		return NOTIFY_DONE;

	mutex_lock(&tb->lock);
	port = tb_pci_find_port(tb, pdev);
	if (!port)
		goto out;

	switch (action) {
	case BUS_NOTIFY_ADD_DEVICE:
		port->pdev = pdev;
		tb_port_dbg(port, "associated with %s\n", pci_name(pdev));
		break;
	case BUS_NOTIFY_DEL_DEVICE:
		port->pdev = NULL;
		tb_port_dbg(port, "no longer associated with %s\n",
			    pci_name(pdev));
		break;
	}
out:
	mutex_unlock(&tb->lock);
	return NOTIFY_DONE;
}

/**
 * tb_pci_associate() - Associate given PCI device with a Thunderbolt port
 * @pdev: PCI device
 * @data: Thunderbolt bus
 *
 * Associate @pdev with a PCIe adapter in Thunderbolt domain @data by storing a
 * pointer to the PCI device in struct tb_port.  Intended to be used as a
 * pci_walk_bus() callback.
 */
static int tb_pci_associate(struct pci_dev *pdev, void *data)
{
	struct tb *tb = data;
	struct tb_port *port;

	port = tb_pci_find_port(tb, pdev);
	if (port) {
		port->pdev = pdev;
		tb_port_dbg(port, "associated with %s\n", pci_name(pdev));
	}

	return 0;
}

void tb_pci_init(struct tb_cm *tcm, struct tb_nhi *nhi)
{
	tcm->pci_notifier.notifier_call = tb_pci_notifier_call;

	/*
	 * Platform Integrated Host Routers establish PCIe tunnels below Root
	 * Ports on the PCI root bus.  Standalone Host Routers establish them
	 * below Downstream Ports on the NHI's parent bus.
	 */
	if (pci_is_root_bus(nhi->pdev->bus))
		tcm->pci_root = nhi->pdev->bus;
	else
		tcm->pci_root = nhi->pdev->bus->parent;
}

void tb_pci_start_associate(struct tb *tb, struct tb_cm *tcm)
{
	bus_register_notifier(&pci_bus_type, &tcm->pci_notifier);
	pci_walk_bus(tcm->pci_root, tb_pci_associate, tb);
}

void tb_pci_stop_associate(struct tb_cm *tcm)
{
	bus_unregister_notifier(&pci_bus_type, &tcm->pci_notifier);
}
