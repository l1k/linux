// SPDX-License-Identifier: GPL-2.0
/*
 * Component Measurement and Authentication (CMA-SPDM, PCIe r6.2 sec 6.31)
 *
 * Copyright (C) 2021 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022-24 Intel Corporation
 */

#define dev_fmt(fmt) "CMA: " fmt

#include <keys/x509-parser.h>
#include <linux/asn1_decoder.h>
#include <linux/oid_registry.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/pm_runtime.h>
#include <linux/spdm.h>

#include "cma.asn1.h"
#include "pci.h"

/* Keyring that userspace can poke certs into */
static struct key *pci_cma_keyring;

/*
 * The spdm_requester.c library calls pci_cma_validate() to check requirements
 * for Leaf Certificates per PCIe r6.1 sec 6.31.3.
 *
 * pci_cma_validate() parses the Subject Alternative Name using the ASN.1
 * module cma.asn1, which calls pci_cma_note_oid() and pci_cma_note_san()
 * to compare an OtherName against the expected name.
 *
 * The expected name is constructed beforehand by pci_cma_construct_san().
 *
 * PCIe r6.2 drops the Subject Alternative Name spec language, even though
 * it continues to require "the leaf certificate to include the information
 * typically used by system software for device driver binding".  Use the
 * Subject Alternative Name per PCIe r6.1 for lack of a replacement and
 * because it is the de facto standard among existing products.
 */
#define CMA_NAME_MAX sizeof("Vendor=1234:Device=1234:CC=123456:"	  \
			    "REV=12:SSVID=1234:SSID=1234:1234567890123456")

struct pci_cma_x509_context {
	struct pci_dev *pdev;
	enum OID last_oid;
	char expected_name[CMA_NAME_MAX];
	unsigned int expected_len;
	unsigned int found:1;
};

int pci_cma_note_oid(void *context, size_t hdrlen, unsigned char tag,
		     const void *value, size_t vlen)
{
	struct pci_cma_x509_context *ctx = context;

	ctx->last_oid = look_up_OID(value, vlen);

	return 0;
}

int pci_cma_note_san(void *context, size_t hdrlen, unsigned char tag,
		     const void *value, size_t vlen)
{
	struct pci_cma_x509_context *ctx = context;

	/* These aren't the drOIDs we're looking for. */
	if (ctx->last_oid != OID_CMA)
		return 0;

	if (tag != ASN1_UTF8STR ||
	    vlen != ctx->expected_len ||
	    memcmp(value, ctx->expected_name, vlen) != 0) {
		pci_err(ctx->pdev, "Invalid X.509 Subject Alternative Name\n");
		return -EINVAL;
	}

	ctx->found = true;

	return 0;
}

static unsigned int pci_cma_construct_san(struct pci_dev *pdev, char *name)
{
	unsigned int len;
	u64 serial;

	len = snprintf(name, CMA_NAME_MAX,
		       "Vendor=%04hx:Device=%04hx:CC=%06x:REV=%02hhx",
		       pdev->vendor, pdev->device, pdev->class, pdev->revision);

	if (pdev->hdr_type == PCI_HEADER_TYPE_NORMAL)
		len += snprintf(name + len, CMA_NAME_MAX - len,
				":SSVID=%04hx:SSID=%04hx",
				pdev->subsystem_vendor, pdev->subsystem_device);

	serial = pci_get_dsn(pdev);
	if (serial)
		len += snprintf(name + len, CMA_NAME_MAX - len,
				":%016llx", serial);

	return len;
}

static int pci_cma_validate(struct device *dev,
			    struct x509_certificate *leaf_cert)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct pci_cma_x509_context ctx;
	int ret;

	if (!leaf_cert->raw_san) {
		pci_err(pdev, "Missing X.509 Subject Alternative Name\n");
		return -EINVAL;
	}

	ctx.pdev = pdev;
	ctx.found = false;
	ctx.expected_len = pci_cma_construct_san(pdev, ctx.expected_name);

	ret = asn1_ber_decoder(&cma_decoder, &ctx, leaf_cert->raw_san,
			       leaf_cert->raw_san_size);
	if (ret == -EBADMSG || ret == -EMSGSIZE)
		pci_err(pdev, "Malformed X.509 Subject Alternative Name\n");
	if (ret < 0)
		return ret;

	if (!ctx.found) {
		pci_err(pdev, "Missing X.509 OtherName with CMA OID\n");
		return -EINVAL;
	}

	return 0;
}

#define PCI_DOE_FEATURE_CMA 1

static ssize_t pci_doe_transport(void *priv, struct device *dev,
				 const void *request, size_t request_sz,
				 void *response, size_t response_sz)
{
	struct pci_doe_mb *doe = priv;
	ssize_t rc;

	/*
	 * CMA-SPDM operation in non-D0 states is optional (PCIe r6.2
	 * sec 6.31.3).  The spec does not define a way to determine
	 * if it's supported, so resume to D0 unconditionally.
	 */
	rc = pm_runtime_resume_and_get(dev);
	if (rc)
		return rc;

	rc = pci_doe(doe, PCI_VENDOR_ID_PCI_SIG, PCI_DOE_FEATURE_CMA,
		     request, request_sz, response, response_sz);

	pm_runtime_put(dev);

	return rc;
}

void pci_cma_init(struct pci_dev *pdev)
{
	struct pci_doe_mb *doe;

	if (IS_ERR(pci_cma_keyring))
		return;

	if (!pci_is_pcie(pdev))
		return;

	doe = pci_find_doe_mailbox(pdev, PCI_VENDOR_ID_PCI_SIG,
				   PCI_DOE_FEATURE_CMA);
	if (!doe)
		return;

	pdev->spdm_state = spdm_create(&pdev->dev, pci_doe_transport, doe,
				       PCI_DOE_MAX_PAYLOAD, pci_cma_keyring,
				       pci_cma_validate);
	if (!pdev->spdm_state)
		return;

	/*
	 * Keep spdm_state allocated even if initial authentication fails
	 * to allow for provisioning of certificates and reauthentication.
	 */
	spdm_authenticate(pdev->spdm_state);
}

void pci_cma_destroy(struct pci_dev *pdev)
{
	if (!pdev->spdm_state)
		return;

	spdm_destroy(pdev->spdm_state);
}

__init static int pci_cma_keyring_init(void)
{
	pci_cma_keyring = keyring_alloc(".cma", KUIDT_INIT(0), KGIDT_INIT(0),
					current_cred(),
					(KEY_POS_ALL & ~KEY_POS_SETATTR) |
					KEY_USR_VIEW | KEY_USR_READ |
					KEY_USR_WRITE | KEY_USR_SEARCH,
					KEY_ALLOC_NOT_IN_QUOTA |
					KEY_ALLOC_SET_KEEP, NULL, NULL);
	if (IS_ERR(pci_cma_keyring)) {
		pr_err("PCI: Could not allocate .cma keyring\n");
		return PTR_ERR(pci_cma_keyring);
	}

	return 0;
}
arch_initcall(pci_cma_keyring_init);
