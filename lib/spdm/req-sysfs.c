// SPDX-License-Identifier: GPL-2.0
/*
 * DMTF Security Protocol and Data Model (SPDM)
 * https://www.dmtf.org/dsp/DSP0274
 *
 * Requester role: sysfs interface
 *
 * Copyright (C) 2023-24 Intel Corporation
 */

#include "spdm.h"

#include <linux/pci.h>

/**
 * dev_to_spdm_state() - Retrieve SPDM session state for given device
 *
 * @dev: Responder device
 *
 * Returns a pointer to the device's SPDM session state,
 *	   %NULL if the device doesn't have one or
 *	   %ERR_PTR if it couldn't be determined whether SPDM is supported.
 *
 * In the %ERR_PTR case, attributes are visible but return an error on access.
 * This prevents downgrade attacks where an attacker disturbs memory allocation
 * or communication with the device in order to create the appearance that SPDM
 * is unsupported.  E.g. with PCI devices, the attacker may foil CMA or DOE
 * initialization by simply hogging memory.
 */
static struct spdm_state *dev_to_spdm_state(struct device *dev)
{
	if (dev_is_pci(dev))
		return pci_dev_to_spdm_state(to_pci_dev(dev));

	/* Insert mappers for further bus types here. */

	return NULL;
}

/* authenticated attribute */

static umode_t spdm_attrs_are_visible(struct kobject *kobj,
				      struct attribute *a, int n)
{
	struct device *dev = kobj_to_dev(kobj);
	struct spdm_state *spdm_state = dev_to_spdm_state(dev);

	if (!spdm_state)
		return SYSFS_GROUP_INVISIBLE;

	return a->mode;
}

static ssize_t authenticated_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct spdm_state *spdm_state = dev_to_spdm_state(dev);
	int rc;

	if (IS_ERR(spdm_state))
		return PTR_ERR(spdm_state);

	if (sysfs_streq(buf, "re")) {
		rc = spdm_authenticate(spdm_state);
		if (rc)
			return rc;
	} else {
		return -EINVAL;
	}

	return count;
}

static ssize_t authenticated_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct spdm_state *spdm_state = dev_to_spdm_state(dev);

	if (IS_ERR(spdm_state))
		return PTR_ERR(spdm_state);

	return sysfs_emit(buf, "%u\n", spdm_state->authenticated);
}
static DEVICE_ATTR_RW(authenticated);

static struct attribute *spdm_attrs[] = {
	&dev_attr_authenticated.attr,
	NULL
};

const struct attribute_group spdm_attr_group = {
	.attrs = spdm_attrs,
	.is_visible = spdm_attrs_are_visible,
};

/* certificates attributes */

static umode_t spdm_certificates_are_visible(struct kobject *kobj,
					     const struct bin_attribute *a,
					     int n)
{
	struct device *dev = kobj_to_dev(kobj);
	struct spdm_state *spdm_state = dev_to_spdm_state(dev);
	u8 slot = a->attr.name[4] - '0';

	if (IS_ERR_OR_NULL(spdm_state))
		return SYSFS_GROUP_INVISIBLE;

	if (!(spdm_state->supported_slots & BIT(slot)))
		return 0;

	return a->attr.mode;
}

static ssize_t spdm_cert_read(struct file *file, struct kobject *kobj,
			      struct bin_attribute *a, char *buf, loff_t off,
			      size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct spdm_state *spdm_state = dev_to_spdm_state(dev);
	u8 slot = a->attr.name[4] - '0';
	size_t header_size, cert_size;

	/*
	 * Serialize with spdm_authenticate() as it may change hash_len,
	 * slot_sz[] and slot[] members in struct spdm_state.
	 */
	guard(mutex)(&spdm_state->lock);

	/*
	 * slot[] is prefixed by the 4 + H header per SPDM 1.0.0 table 15.
	 * The header is not exposed to user space, only the certificates are.
	 */
	header_size = sizeof(struct spdm_cert_chain) + spdm_state->hash_len;
	cert_size = spdm_state->slot_sz[slot] - header_size;

	if (!spdm_state->slot[slot])
		return 0;
	if (!count)
		return 0;
	if (off > cert_size)
		return 0;
	if (off + count > cert_size)
		count = cert_size - off;

	memcpy(buf, (u8 *)spdm_state->slot[slot] + header_size + off, count);
	return count;
}

static BIN_ATTR(slot0, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot1, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot2, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot3, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot4, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot5, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot6, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot7, 0444, spdm_cert_read, NULL, 0xffff);

static struct bin_attribute *spdm_certificates_bin_attrs[] = {
	&bin_attr_slot0,
	&bin_attr_slot1,
	&bin_attr_slot2,
	&bin_attr_slot3,
	&bin_attr_slot4,
	&bin_attr_slot5,
	&bin_attr_slot6,
	&bin_attr_slot7,
	NULL
};

const struct attribute_group spdm_certificates_group = {
	.name = "certificates",
	.bin_attrs = spdm_certificates_bin_attrs,
	.is_bin_visible = spdm_certificates_are_visible,
};
