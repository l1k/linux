// SPDX-License-Identifier: GPL-2.0
/*
 * Component Measurement and Authentication (CMA-SPDM, PCIe r6.1 sec 6.31)
 *
 * The spdm_requester.c library calls pci_cma_validate() to check requirements
 * for X.509 Leaf Certificates per PCIe r6.1 sec 6.31.3.
 *
 * It parses the Subject Alternative Name using the ASN.1 module cma.asn1,
 * which calls pci_cma_note_oid() and pci_cma_note_san() to compare an
 * OtherName against the expected name.
 *
 * The expected name is constructed beforehand by pci_cma_construct_san().
 *
 * Copyright (C) 2023 Intel Corporation
 */

#define dev_fmt(fmt) "CMA: " fmt

#include <keys/x509-parser.h>
#include <linux/asn1_decoder.h>
#include <linux/oid_registry.h>
#include <linux/pci.h>

#include "cma.asn1.h"
#include "pci.h"

#define CMA_NAME_MAX sizeof("othername:UTF8STRING:PCISIG:"		  \
			    "Vendor=1234:Device=1234:CC=123456:"	  \
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

	if (vlen != ctx->expected_len ||
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

int pci_cma_validate(struct device *dev, struct x509_certificate *leaf_cert)
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
