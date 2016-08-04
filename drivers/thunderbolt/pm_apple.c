// SPDX-License-Identifier: GPL-2.0
/*
 * Power down Thunderbolt controller on Macs when nothing is plugged in
 *
 * Copyright (C) 2019 Lukas Wunner <lukas@wunner.de>
 *
 * Apple provides the following means for power control in ACPI:
 *
 * * On Macs with Thunderbolt 1 Gen 1 controllers (Light Ridge, Eagle Ridge):
 *   * XRPE method ("Power Enable"), takes argument 1 or 0, toggles a GPIO pin
 *     to switch the controller on or off.
 *   * XRIN named object (alternatively _GPE), contains number of a GPE which
 *     fires as long as something is plugged in (regardless of power state).
 *   * XRIL method ("Interrupt Low"), returns 0 as long as something is
 *     plugged in, 1 otherwise.
 *   * XRIP and XRIO methods, unused by macOS driver.
 *
 * * On Macs with Thunderbolt 1 Gen 2 controllers (Cactus Ridge 4C):
 *   * XRIN not only fires as long as something is plugged in, but also as long
 *     as the controller's CIO switch is powered up.
 *   * XRIL method changed its meaning, it returns 0 as long as the CIO switch
 *     is powered up, 1 otherwise.
 *   * Additional SXFP method ("Force Power"), accepts only argument 0,
 *     switches the controller off.  This carries out just the raw power
 *     change, unlike XRPE which disables the link on the PCIe Root Port
 *     in an orderly fashion before switching off the controller.
 *   * Additional SXLV, SXIO, SXIL methods to utilize the Go2Sx and Ok2Go2Sx
 *     pins (see background below).  Apparently SXLV toggles the value given to
 *     the POC via Go2Sx (0 or 1), SXIO changes the direction (0 or 1) and SXIL
 *     returns the value received from the POC via Ok2Go2Sx.
 *   * On some Macs, additional XRST method, takes argument 1 or 0, asserts or
 *     deasserts a GPIO pin to reset the controller.
 *   * On Macs introduced 2013, XRPE was renamed TRPE.
 *
 * * On Macs with Thunderbolt 2 controllers (Falcon Ridge 4C and 2C):
 *   * SXLV, SXIO, SXIL methods to utilize Go2Sx and Ok2Go2Sx are gone.
 *   * On the MacPro6,1 which has multiple Thunderbolt controllers, each NHI
 *     device has a separate XRIN GPE and separate TRPE, SXFP and XRIL methods.
 *
 * Background:
 *
 * * Gen 1 controllers (Light Ridge, Eagle Ridge) had no power management
 *   and no ability to distinguish whether a DP or Thunderbolt device is
 *   plugged in.  Apple put an ARM Cortex MCU (NXP LPC1112A) on the logic board
 *   which snoops on the connector lines and, depending on the type of device,
 *   sends an HPD signal to the GPU or fires the Thunderbolt XRIN doorbell
 *   interrupt.  The switches for the 3.3V and 1.05V power rails of the
 *   Thunderbolt controller are toggled by a GPIO pin on the southbridge.
 *
 * * On gen 2 controllers (Cactus Ridge 4C), Intel integrated the MCU into the
 *   controller and called it POC.  This caused a change of semantics for XRIN
 *   and XRIL.  The POC is powered by a separate 3.3V rail which is active even
 *   in sleep state S4.  It only draws a very small current.  The regular 3.3V
 *   and 1.05V power rails are no longer controlled by the southbridge but by
 *   the POC.  In other words the controller powers *itself* up and down!  It's
 *   instructed to do so with the Go2Sx pin.  Another pin, Ok2Go2Sx, allows the
 *   controller to indicate if it is ready to power itself down.  Apple wires
 *   Go2Sx and Ok2Go2Sx to the same GPIO pin on the southbridge, hence the pin
 *   is used bidirectionally.  A third pin, Force Power, is intended by Intel
 *   for debug only but Apple abuses it for XRPE/TRPE and SXFP.  They utilize
 *   Go2Sx and Ok2Go2Sx only on Cactus Ridge, presumably because the controller
 *   somehow requires that.  On Falcon Ridge they forego these pins and rely
 *   solely on Force Power.
 *
 * Implementation Notes:
 *
 * * To conform to Linux' hierarchical power management model, power control
 *   is governed by the topmost PCI device of the controller, which is the
 *   upstream bridge.  The controller is powered down once all child devices
 *   of the upstream bridge have suspended and its autosuspend delay has
 *   elapsed.
 *
 * * The autosuspend delay is user configurable via sysfs and should be lower
 *   or equal to that of the NHI since hotplug events are not acted upon if
 *   the NHI has suspended but the controller has not yet powered down.
 *   However the delay should not be zero to avoid frequent power changes
 *   (e.g.  multiple times just for lspci -vv) since powering up takes 2 sec.
 *   (Powering down is almost instantaneous.)
 */

#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/pm_domain.h>
#include <linux/pm_runtime.h>
#include "tb.h"

/**
 * struct tb_pm - Thunderbolt power management data
 * @tb: Pointer to the Thunderbolt domain this PM data belongs to
 * @pm_domain: PM domain assigned to controller's PCIe upstream bridge
 * @wake_gpe: GPE used as hotplug interrupt during powerdown
 * @set: ACPI method to power controller up/down
 * @get: ACPI method to query power state of controller
 */
struct tb_pm {
	struct tb *tb;
	struct dev_pm_domain pm_domain;
	unsigned long long wake_gpe;
	acpi_handle set;
	acpi_handle get;
};

/*
 * The dev_pm_ops assigned to the upstream bridge use pr_*() instead of dev_*()
 * to get a "thunderbolt" prefix on messages, rather than "pcieport".
 */
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME " %s: " fmt, dev_name(dev)

#define to_pm(dev) container_of(dev->pm_domain, struct tb_pm, pm_domain)

static int upstream_prepare(struct device *dev)
{
	struct tb_pm *pm = to_pm(dev);

	if (pm_runtime_active(dev))
		return 0;

	/* prevent interrupts during system sleep transition */
	if (ACPI_FAILURE(acpi_disable_gpe(NULL, pm->wake_gpe))) {
		pr_err("cannot disable wake GPE, resuming\n");
		pm_request_resume(dev);
		return -EAGAIN;
	}

	return DPM_DIRECT_COMPLETE;
}

static void upstream_complete(struct device *dev)
{
	struct tb_pm *pm = to_pm(dev);

	if (pm_runtime_active(dev))
		return;

	/*
	 * If the controller was powered down before system sleep, calling XRPE
	 * to power it up will fail on the next runtime resume.  An additional
	 * call to XRPE is necessary to reset the power switch first.
	 */
	pr_debug("resetting power switch\n");
	if (ACPI_FAILURE(acpi_execute_simple_method(pm->set, NULL, 0))) {
		pr_err("cannot call pm->set method\n");
		dev->power.runtime_error = -EIO;
	}

	if (ACPI_FAILURE(acpi_enable_gpe(NULL, pm->wake_gpe))) {
		pr_err("cannot enable wake GPE, resuming\n");
		pm_request_resume(dev);
	}
}

static int upstream_runtime_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct tb_pm *pm = to_pm(dev);
	unsigned long long powered_down;
	int ret, i;

	/* children are effectively in D3cold once upstream goes to D3hot */
	pci_bus_set_current_state(pdev->subordinate, PCI_D3cold);

	ret = dev->bus->pm->runtime_suspend(dev);
	if (ret) {
		pci_wakeup_bus(pdev->subordinate);
		return ret;
	}

	pr_debug("powering down\n");
	pdev->current_state = PCI_D3cold;
	if (ACPI_FAILURE(acpi_execute_simple_method(pm->set, NULL, 0))) {
		pr_err("cannot call pm->set method, resuming\n");
		goto err_resume;
	}

	/*
	 * On Cactus Ridge the wake GPE fires as long as the CIO switch is
	 * powered up.  Poll until it's powered down before enabling the GPE.
	 * macOS polls up to 300 times with a 1 ms delay, just mimic that.
	 */
	for (i = 0; i < 300; i++) {
		if (ACPI_FAILURE(acpi_evaluate_integer(pm->get,
					      NULL, NULL, &powered_down))) {
			pr_err("cannot call pm->get method, resuming\n");
			goto err_resume;
		}
		if (powered_down)
			break;
		usleep_range(800, 1200);
	}
	if (!powered_down) {
		pr_notice("refused to power down, resuming\n");
		goto err_resume;
	}

	if (ACPI_FAILURE(acpi_enable_gpe(NULL, pm->wake_gpe))) {
		pr_err("cannot enable wake GPE, resuming\n");
		goto err_resume;
	}

	return 0;

err_resume:
	acpi_execute_simple_method(pm->set, NULL, 1);
	dev->bus->pm->runtime_resume(dev);
	pci_wakeup_bus(pdev->subordinate);
	return -EAGAIN;
}

static int upstream_runtime_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct tb_pm *pm = to_pm(dev);
	int ret;

	if (!dev->power.is_prepared &&
	    ACPI_FAILURE(acpi_disable_gpe(NULL, pm->wake_gpe))) {
		pr_err("cannot disable wake GPE, disabling runtime pm\n");
		pm_runtime_disable(&pm->tb->nhi->pdev->dev);
	}

	pr_debug("powering up\n");
	if (ACPI_FAILURE(acpi_execute_simple_method(pm->set, NULL, 1))) {
		pr_err("cannot call pm->set method\n");
		return -ENODEV;
	}

	ret = dev->bus->pm->runtime_resume(dev);

	/* wake children to force pci_restore_state() after D3cold */
	pci_wakeup_bus(pdev->subordinate);

	return ret;
}

static u32 nhi_wake(acpi_handle gpe_device, u32 gpe_number, void *ctx)
{
	struct device *nhi_dev = ctx;

	WARN_ON(pm_request_resume(nhi_dev) < 0);
	return ACPI_INTERRUPT_HANDLED;
}

void tb_pm_apple_init(struct tb *tb)
{
	struct device *nhi_dev = &tb->nhi->pdev->dev;
	struct acpi_handle *nhi_handle;
	struct tb_pm *pm;

	/* no PM support for Alpine Ridge yet */
	if (tb->root_switch->generation >= 3)
		goto err_rpm_get;

	pm = kzalloc(sizeof(*pm), GFP_KERNEL);
	if (!pm)
		goto err_free;

	nhi_handle = ACPI_HANDLE(nhi_dev);
	if (!nhi_handle) {
		dev_err(nhi_dev, "cannot find ACPI handle\n");
		goto err_free;
	}

	/* Macs introduced 2011/2012 have XRPE, 2013+ have TRPE */
	if (ACPI_FAILURE(acpi_get_handle(nhi_handle, "XRPE", &pm->set)) &&
	    ACPI_FAILURE(acpi_get_handle(nhi_handle, "TRPE", &pm->set))) {
		dev_err(nhi_dev, "cannot find pm->set method\n");
		goto err_free;
	}

	if (ACPI_FAILURE(acpi_get_handle(nhi_handle, "XRIL", &pm->get))) {
		dev_err(nhi_dev, "cannot find pm->get method\n");
		goto err_free;
	}

	if (ACPI_FAILURE(acpi_evaluate_integer(nhi_handle, "XRIN", NULL,
							&pm->wake_gpe))) {
		dev_err(nhi_dev, "cannot find wake GPE\n");
		goto err_free;
	}

	if (ACPI_FAILURE(acpi_install_gpe_handler(NULL, pm->wake_gpe,
			  ACPI_GPE_LEVEL_TRIGGERED, nhi_wake, nhi_dev))) {
		dev_err(nhi_dev, "cannot install GPE handler\n");
		goto err_free;
	}

	pm->pm_domain.ops		  = *tb->upstream->dev.bus->pm;
	pm->pm_domain.ops.prepare	  =  upstream_prepare;
	pm->pm_domain.ops.complete	  =  upstream_complete;
	pm->pm_domain.ops.runtime_suspend =  upstream_runtime_suspend;
	pm->pm_domain.ops.runtime_resume  =  upstream_runtime_resume;
	pm->tb				  =  tb;
	dev_pm_domain_set(&tb->upstream->dev, &pm->pm_domain);

	tb->pm = pm;
	return;

err_free:
	kfree(pm);
	dev_err(nhi_dev, "controller will stay powered up permanently\n");
err_rpm_get:
	pm_runtime_get_noresume(nhi_dev);
}

void tb_pm_apple_fini(struct tb *tb)
{
	struct device *nhi_dev = &tb->nhi->pdev->dev;
	struct tb_pm *pm = tb->pm;

	if (!pm) {
		/* tb_pm_apple_init() failed */
		pm_runtime_put_noidle(nhi_dev);
		return;
	}

	tb->pm = NULL;
	dev_pm_domain_set(&tb->upstream->dev, NULL);

	if (ACPI_FAILURE(acpi_remove_gpe_handler(NULL, pm->wake_gpe,
						 nhi_wake)))
		dev_err(nhi_dev, "cannot remove GPE handler\n");

	kfree(pm);
}
