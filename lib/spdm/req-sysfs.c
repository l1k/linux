// SPDX-License-Identifier: GPL-2.0
/*
 * DMTF Security Protocol and Data Model (SPDM)
 * https://www.dmtf.org/dsp/DSP0274
 *
 * Requester role: sysfs interface
 *
 * Copyright (C) 2023-25 Intel Corporation
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

	/* Insert mappers for further bus types here */

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
			      const struct bin_attribute *a, char *buf,
			      loff_t off, size_t count)
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
	header_size = sizeof(struct spdm_cert_chain) +
		      hash_digest_size[spdm_state->base_hash_alg];
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

static const struct bin_attribute *spdm_certificates_bin_attrs[] = {
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

/**
 * struct spdm_log_entry - log entry representing one received SPDM signature
 *
 * @list: List node.  Added to the @log list in struct spdm_state.
 * @sig: sysfs attribute of received signature (located at end of transcript).
 * @req_nonce: sysfs attribute of requester nonce (located within transcript).
 * @rsp_nonce: sysfs attribute of responder nonce (located within transcript).
 * @transcript: sysfs attribute of transcript (concatenation of all SPDM
 *	messages exchanged during an authentication sequence) sans trailing
 *	signature (to simplify signature verification by user space).
 * @combined_prefix: sysfs attribute of combined_spdm_prefix
 *	(SPDM 1.2.0 margin no 806, needed to verify signature).
 * @spdm_context: sysfs attribute of spdm_context
 *	(SPDM 1.2.0 margin no 803, needed to create combined_spdm_prefix).
 * @hash_alg: sysfs attribute of hash algorithm (needed to verify signature).
 * @sig_name: Name of @sig attribute (with prepended signature counter).
 * @req_nonce_name: Name of @req_nonce attribute.
 * @rsp_nonce_name: Name of @rsp_nonce attribute.
 * @transcript_name: Name of @transcript attribute.
 * @combined_prefix_name: Name of @combined_prefix attribute.
 * @spdm_context_name: Name of @spdm_context attribute.
 * @hash_alg_name: Name of @hash_alg attribute.
 * @counter: Signature counter (needed to create certificate_chain symlink).
 * @version: Negotiated SPDM version
 *	(SPDM 1.2.0 margin no 803, needed to create combined_spdm_prefix).
 * @slot: Slot which was used to generate the signature
 *	(needed to create certificate_chain symlink).
 */
struct spdm_log_entry {
	struct list_head list;
	struct bin_attribute sig;
	struct bin_attribute req_nonce;
	struct bin_attribute rsp_nonce;
	struct bin_attribute transcript;
	struct bin_attribute combined_prefix;
	struct dev_ext_attribute spdm_context;
	struct dev_ext_attribute hash_alg;
	char sig_name[sizeof(__stringify(UINT_MAX) "_signature")];
	char req_nonce_name[sizeof(__stringify(UINT_MAX) "_requester_nonce")];
	char rsp_nonce_name[sizeof(__stringify(UINT_MAX) "_responder_nonce")];
	char transcript_name[sizeof(__stringify(UINT_MAX) "_transcript")];
	char combined_prefix_name[sizeof(__stringify(UINT_MAX) "_combined_spdm_prefix")];
	char spdm_context_name[sizeof(__stringify(UINT_MAX) "_type")];
	char hash_alg_name[sizeof(__stringify(UINT_MAX) "_hash_algorithm")];
	u32 counter;
	u8 version;
	u8 slot;
};

/**
 * spdm_create_log_entry() - Allocate log entry for one received SPDM signature
 *
 * @spdm_state: SPDM session state
 * @spdm_context: SPDM context (needed to create combined_spdm_prefix)
 * @slot: Slot which was used to generate the signature
 *	(needed to create certificate_chain symlink)
 * @req_nonce_off: Requester nonce offset within the transcript
 * @rsp_nonce_off: Responder nonce offset within the transcript
 *
 * Allocate and populate a struct spdm_log_entry upon device authentication.
 * Publish it in sysfs if the device has already been registered through
 * device_add().
 */
