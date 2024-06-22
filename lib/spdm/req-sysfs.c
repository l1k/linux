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

/* signatures attributes */

static struct bin_attribute *spdm_signatures_bin_attrs[] = {
	NULL
};

const struct attribute_group spdm_signatures_group = {
	.name = "signatures",
	.bin_attrs = spdm_signatures_bin_attrs,
};

static unsigned int spdm_max_log_sz = SZ_16M; /* per device */

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

static void spdm_unpublish_log_entry(struct kobject *kobj,
				     struct spdm_log_entry *log)
{
	const char *group = spdm_signatures_group.name;

	sysfs_remove_bin_file_from_group(kobj, &log->sig, group);
	sysfs_remove_bin_file_from_group(kobj, &log->req_nonce, group);
	sysfs_remove_bin_file_from_group(kobj, &log->rsp_nonce, group);
	sysfs_remove_bin_file_from_group(kobj, &log->transcript, group);
	sysfs_remove_bin_file_from_group(kobj, &log->combined_prefix, group);
	sysfs_remove_file_from_group(kobj, &log->spdm_context.attr.attr, group);
	sysfs_remove_file_from_group(kobj, &log->hash_alg.attr.attr, group);

	char cert_chain[sizeof(__stringify(UINT_MAX) "_certificate_chain")];
	snprintf(cert_chain, sizeof(cert_chain), "%u_certificate_chain",
		 log->counter);

	sysfs_remove_link_from_group(kobj, group, cert_chain);
}

static void spdm_publish_log_entry(struct kobject *kobj,
				   struct spdm_log_entry *log)
{
	const char *group = spdm_signatures_group.name;
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

	char cert_chain[sizeof(__stringify(UINT_MAX) "_certificate_chain")];
	snprintf(cert_chain, sizeof(cert_chain), "%u_certificate_chain",
		 log->counter);

	char slot[sizeof("slot0")];
	snprintf(slot, sizeof(slot), "slot%hhu", log->slot);

	rc = sysfs_add_link_to_sibling_group(kobj, group, cert_chain,
					     spdm_certificates_group.name,
					     slot);
	if (rc)
		goto err;

	return;

err:
	dev_err(kobj_to_dev(kobj),
		"Failed to publish signature log entry in sysfs: %d\n", rc);
	spdm_unpublish_log_entry(kobj, log);
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

static void spdm_destroy_log_entry(struct spdm_state *spdm_state,
				   struct spdm_log_entry *log)
{
	spdm_state->log_sz -= log->transcript.size + log->sig.size +
			      sizeof(*log);

	list_del(&log->list);
	kvfree(log->transcript.private);
	kfree(log);
}

static void spdm_shrink_log(struct spdm_state *spdm_state)
{
	while (spdm_state->log_sz > spdm_max_log_sz &&
	       !list_is_singular(&spdm_state->log)) {
		struct spdm_log_entry *log =
			list_first_entry(&spdm_state->log, typeof(*log), list);

		if (device_is_registered(spdm_state->dev))
			spdm_unpublish_log_entry(&spdm_state->dev->kobj, log);

		spdm_destroy_log_entry(spdm_state, log);
	}
}

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
void spdm_create_log_entry(struct spdm_state *spdm_state,
			   const char *spdm_context, u8 slot,
			   size_t req_nonce_off, size_t rsp_nonce_off)
{
	struct spdm_log_entry *log = kmalloc(sizeof(*log), GFP_KERNEL);
	if (!log)
		return;

	*log = (struct spdm_log_entry) {
		.slot		   = slot,
		.version	   = spdm_state->version,
		.counter	   = spdm_state->log_counter,
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
	spdm_state->log_sz += log->transcript.size + log->sig.size +
			      sizeof(*log);

	/* Purge oldest log entries if max log size is exceeded */
	spdm_shrink_log(spdm_state);

	/* Steal transcript pointer ahead of spdm_free_transcript() */
	spdm_state->transcript = NULL;

	if (device_is_registered(spdm_state->dev))
		spdm_publish_log_entry(&spdm_state->dev->kobj, log);
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
	struct kobject *kobj = &spdm_state->dev->kobj;
	struct kernfs_node *grp_kn __free(kernfs_put);
	struct spdm_log_entry *log;

	grp_kn = kernfs_find_and_get(kobj->sd, spdm_signatures_group.name);
	if (WARN_ON(!grp_kn))
		return;

	mutex_lock(&spdm_state->lock);
	list_for_each_entry(log, &spdm_state->log, list) {
		struct kernfs_node *sig_kn __free(kernfs_put);

		/*
		 * Skip over log entries created in-between device_add() and
		 * spdm_publish_log() as they've already been published.
		 */
		sig_kn = kernfs_find_and_get(grp_kn, log->sig_name);
		if (sig_kn)
			continue;

		spdm_publish_log_entry(kobj, log);
	}
	mutex_unlock(&spdm_state->lock);
}
EXPORT_SYMBOL_GPL(spdm_publish_log);

/**
 * spdm_destroy_log() - Destroy log of received SPDM signatures
 *
 * @spdm_state: SPDM session state
 *
 * Be sure to unregister the device through device_del() beforehand,
 * which implicitly unpublishes the log in sysfs.
 */
void spdm_destroy_log(struct spdm_state *spdm_state)
{
	struct spdm_log_entry *log, *tmp;

	list_for_each_entry_safe(log, tmp, &spdm_state->log, list)
		spdm_destroy_log_entry(spdm_state, log);
}

#ifdef CONFIG_SYSCTL
static int proc_max_log_sz(const struct ctl_table *table, int write,
			   void *buffer, size_t *lenp, loff_t *ppos)
{
	unsigned int old_max_log_sz = spdm_max_log_sz;
	struct spdm_state *spdm_state;
	int rc;

	rc = proc_douintvec_minmax(table, write, buffer, lenp, ppos);
	if (rc)
		return rc;

	/* Purge oldest log entries if max log size has been reduced */
	if (write && spdm_max_log_sz < old_max_log_sz) {
		mutex_lock(&spdm_state_mutex);
		list_for_each_entry(spdm_state, &spdm_state_list, list) {
			mutex_lock(&spdm_state->lock);
			spdm_shrink_log(spdm_state);
			mutex_unlock(&spdm_state->lock);
		}
		mutex_unlock(&spdm_state_mutex);
	}

	return 0;
}

static struct ctl_table spdm_ctl_table[] = {
	{
		.procname	= "max_signatures_size",
		.data		= &spdm_max_log_sz,
		.maxlen		= sizeof(spdm_max_log_sz),
		.mode		= 0644,
		.proc_handler	= proc_max_log_sz,
		.extra1		= SYSCTL_ZERO,
				  /*
				   * 2 GiB limit avoids filename collision on
				   * wraparound of unsigned 32-bit log_counter
				   */
		.extra2		= SYSCTL_INT_MAX,
	},
};

static int __init spdm_init(void)
{
	register_sysctl_init("spdm", spdm_ctl_table);
	return 0;
}
fs_initcall(spdm_init);
#endif /* CONFIG_SYSCTL */
