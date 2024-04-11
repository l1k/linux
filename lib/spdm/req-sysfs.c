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

	rc = spdm_authenticate(spdm_state);
	if (rc)
		return rc;

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

static struct bin_attribute *spdm_signatures_bin_attrs[] = {
	NULL
};

const struct attribute_group spdm_signatures_group = {
	.name = "signatures",
	.bin_attrs = spdm_signatures_bin_attrs,
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
 * @version: Negotiated SPDM version
 *	(SPDM 1.2.0 margin no 803, needed to create combined_spdm_prefix).
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
	u8 version;
};

static void spdm_unpublish_log_entry(struct spdm_state *spdm_state,
				     struct spdm_log_entry *log)
{
	const char *group = spdm_signatures_group.name;
	struct kobject *kobj = &spdm_state->dev->kobj;

	sysfs_remove_bin_file_from_group(kobj, &log->sig, group);
	sysfs_remove_bin_file_from_group(kobj, &log->req_nonce, group);
	sysfs_remove_bin_file_from_group(kobj, &log->rsp_nonce, group);
	sysfs_remove_bin_file_from_group(kobj, &log->transcript, group);
	sysfs_remove_bin_file_from_group(kobj, &log->combined_prefix, group);
	sysfs_remove_file_from_group(kobj, &log->spdm_context.attr.attr, group);
	sysfs_remove_file_from_group(kobj, &log->hash_alg.attr.attr, group);
}

static void spdm_publish_log_entry(struct spdm_state *spdm_state,
				   struct spdm_log_entry *log)
{
	const char *group = spdm_signatures_group.name;
	struct kobject *kobj = &spdm_state->dev->kobj;
	int rc;

	rc = sysfs_add_bin_file_to_group(kobj, &log->sig, group);
	if (rc)
		goto err;

	rc = sysfs_add_bin_file_to_group(kobj, &log->req_nonce, group);
	if (rc)
		goto err;

	rc = sysfs_add_bin_file_to_group(kobj, &log->rsp_nonce, group);
	if (rc)
		goto err;

	rc = sysfs_add_bin_file_to_group(kobj, &log->transcript, group);
	if (rc)
		goto err;

	rc = sysfs_add_bin_file_to_group(kobj, &log->combined_prefix, group);
	if (rc)
		goto err;

	rc = sysfs_add_file_to_group(kobj, &log->spdm_context.attr.attr, group);
	if (rc)
		goto err;

	rc = sysfs_add_file_to_group(kobj, &log->hash_alg.attr.attr, group);
	if (rc)
		goto err;

	return;
err:
	dev_err(spdm_state->dev,
		"Failed to publish event log entry: %d\n", rc);
	spdm_unpublish_log_entry(spdm_state, log);
}

static ssize_t spdm_read_combined_prefix(struct file *file,
					 struct kobject *kobj,
					 struct bin_attribute *attr,
					 char *buf, loff_t off, size_t count)
{
	struct spdm_log_entry *log = attr->private;

	/*
	 * SPDM 1.0 and 1.1 do not add a combined prefix to the hash
	 * before computing the signature, so return an empty file.
	 */
	if (log->version <= 0x11)
		return 0;

	void *tmp __free(kfree) = kmalloc(SPDM_COMBINED_PREFIX_SZ, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	spdm_create_combined_prefix(log->version, log->spdm_context.var, tmp);
	memcpy(buf, tmp + off, count);
	return count;
}

/**
 * spdm_create_log_entry() - Allocate log entry for one received SPDM signature
 *
 * @spdm_state: SPDM session state
 * @spdm_context: SPDM context (used to create combined_spdm_prefix)
 * @req_nonce_off: Requester nonce offset within the transcript
 * @rsp_nonce_off: Responder nonce offset within the transcript
 *
 * Allocate and populate a struct spdm_log_entry upon device authentication.
 * Publish it in sysfs if the device has already been registered through
 * device_add().
 */
void spdm_create_log_entry(struct spdm_state *spdm_state,
			   const char *spdm_context,
			   size_t req_nonce_off, size_t rsp_nonce_off)
{
	struct spdm_log_entry *log = kmalloc(sizeof(*log), GFP_KERNEL);
	if (!log)
		return;

	*log = (struct spdm_log_entry) {
		.version	   = spdm_state->version,
		.list		   = LIST_HEAD_INIT(log->list),

		.sig = {
			.attr.name = log->sig_name,
			.attr.mode = 0444,
			.read	   = sysfs_bin_attr_simple_read,
			.private   = spdm_state->transcript_end -
				     spdm_state->sig_len,
			.size	   = spdm_state->sig_len },

		.req_nonce = {
			.attr.name = log->req_nonce_name,
			.attr.mode = 0444,
			.read	   = sysfs_bin_attr_simple_read,
			.private   = spdm_state->transcript + req_nonce_off,
			.size	   = SPDM_NONCE_SZ },

		.rsp_nonce = {
			.attr.name = log->rsp_nonce_name,
			.attr.mode = 0444,
			.read	   = sysfs_bin_attr_simple_read,
			.private   = spdm_state->transcript + rsp_nonce_off,
			.size	   = SPDM_NONCE_SZ },

		.transcript = {
			.attr.name = log->transcript_name,
			.attr.mode = 0444,
			.read	   = sysfs_bin_attr_simple_read,
			.private   = spdm_state->transcript,
			.size	   = spdm_state->transcript_end -
				     spdm_state->transcript -
				     spdm_state->sig_len },

		.combined_prefix = {
			.attr.name = log->combined_prefix_name,
			.attr.mode = 0444,
			.read	   = spdm_read_combined_prefix,
			.private   = log,
			.size	   = spdm_state->version <= 0x11 ? 0 :
				     SPDM_COMBINED_PREFIX_SZ },

		.spdm_context = {
			.attr.attr.name = log->spdm_context_name,
			.attr.attr.mode = 0444,
			.attr.show = device_show_string,
			.var	   = (char *)spdm_context },

		.hash_alg = {
			.attr.attr.name = log->hash_alg_name,
			.attr.attr.mode = 0444,
			.attr.show = device_show_string,
			.var	   = (char *)spdm_state->base_hash_alg_name },
	};

	snprintf(log->sig_name, sizeof(log->sig_name),
		 "%u_signature", spdm_state->log_counter);
	snprintf(log->req_nonce_name, sizeof(log->req_nonce_name),
		 "%u_requester_nonce", spdm_state->log_counter);
	snprintf(log->rsp_nonce_name, sizeof(log->rsp_nonce_name),
		 "%u_responder_nonce", spdm_state->log_counter);
	snprintf(log->transcript_name, sizeof(log->transcript_name),
		 "%u_transcript", spdm_state->log_counter);
	snprintf(log->combined_prefix_name, sizeof(log->combined_prefix_name),
		 "%u_combined_spdm_prefix", spdm_state->log_counter);
	snprintf(log->spdm_context_name, sizeof(log->spdm_context_name),
		 "%u_type", spdm_state->log_counter);
	snprintf(log->hash_alg_name, sizeof(log->hash_alg_name),
		 "%u_hash_algorithm", spdm_state->log_counter);

	sysfs_bin_attr_init(&log->sig);
	sysfs_bin_attr_init(&log->req_nonce);
	sysfs_bin_attr_init(&log->rsp_nonce);
	sysfs_bin_attr_init(&log->transcript);
	sysfs_bin_attr_init(&log->combined_prefix);
	sysfs_attr_init(&log->spdm_context.attr.attr);
	sysfs_attr_init(&log->hash_alg.attr.attr);

	list_add_tail(&log->list, &spdm_state->log);
	spdm_state->log_counter++;

	/* Steal transcript pointer ahead of spdm_free_transcript() */
	spdm_state->transcript = NULL;

	if (device_is_registered(spdm_state->dev))
		spdm_publish_log_entry(spdm_state, log);
}

/**
 * spdm_destroy_log() - Destroy log of received SPDM signatures
 *
 * @spdm_state: SPDM session state
 *
 * Be sure to call spdm_unpublish_log() beforehand.
 */
void spdm_destroy_log(struct spdm_state *spdm_state)
{
	struct spdm_log_entry *log, *tmp;

	list_for_each_entry_safe(log, tmp, &spdm_state->log, list) {
		list_del(&log->list);
		kvfree(log->transcript.private);
		kfree(log);
	}
}

/**
 * spdm_publish_log() - Publish log of received SPDM signatures in sysfs
 *
 * @spdm_state: SPDM session state
 *
 * sysfs attributes representing received SPDM signatures are not static,
 * but created dynamically upon authentication.  If a device was authenticated
 * before it became visible in sysfs, the attributes could not be created.
 * This function retroactively creates those attributes in sysfs after the
 * device has become visible through device_add().
 */
void spdm_publish_log(struct spdm_state *spdm_state)
{
	struct spdm_log_entry *log;

	list_for_each_entry(log, &spdm_state->log, list)
		spdm_publish_log_entry(spdm_state, log);
}
EXPORT_SYMBOL_GPL(spdm_publish_log);

/**
 * spdm_unpublish_log() - Unpublish log of received SPDM signatures in sysfs
 *
 * @spdm_state: SPDM session state
 *
 * Remove sysfs attributes representing received SPDM signatures before the
 * device is unregistered through device_del().
 */
void spdm_unpublish_log(struct spdm_state *spdm_state)
{
	struct spdm_log_entry *log;

	list_for_each_entry(log, &spdm_state->log, list)
		spdm_unpublish_log_entry(spdm_state, log);
}
EXPORT_SYMBOL_GPL(spdm_unpublish_log);
