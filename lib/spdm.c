// SPDX-License-Identifier: GPL-2.0
/*
 * DMTF Security Protocol and Data Model (SPDM)
 * https://www.dmtf.org/dsp/DSP0274
 *
 * Copyright (C) 2021-22 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022 Intel Corporation
 */

#define dev_fmt(fmt) "SPDM: " fmt

#include <linux/asn1_encoder.h>
#include <linux/asn1_ber_bytecode.h>
#include <linux/bitfield.h>
#include <linux/cred.h>
#include <linux/dev_printk.h>
#include <linux/digsig.h>
#include <linux/idr.h>
#include <linux/key.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/spdm.h>

#include <crypto/akcipher.h>
#include <crypto/hash.h>
#include <crypto/public_key.h>
#include <keys/asymmetric-type.h>
#include <keys/user-type.h>
#include <asm/unaligned.h>

/* SPDM versions supported by this implementation */
#define SPDM_MIN_VER 0x11
#define SPDM_MAX_VER 0x12

#define SPDM_CACHE_CAP			BIT(0)		/* response only */
#define SPDM_CERT_CAP			BIT(1)
#define SPDM_CHAL_CAP			BIT(2)
#define SPDM_MEAS_CAP_MASK		GENMASK(4, 3)	/* response only */
#define   SPDM_MEAS_CAP_NO		0		/* response only */
#define   SPDM_MEAS_CAP_MEAS		1		/* response only */
#define   SPDM_MEAS_CAP_MEAS_SIG	2		/* response only */
#define SPDM_MEAS_FRESH_CAP		BIT(5)		/* response only */
#define SPDM_ENCRYPT_CAP		BIT(6)
#define SPDM_MAC_CAP			BIT(7)
#define SPDM_MUT_AUTH_CAP		BIT(8)
#define SPDM_KEY_EX_CAP			BIT(9)
#define SPDM_PSK_CAP_MASK		GENMASK(11, 10)
#define   SPDM_PSK_CAP_NO		0
#define   SPDM_PSK_CAP_PSK		1
#define   SPDM_PSK_CAP_PSK_CTX		2		/* response only */
#define SPDM_ENCAP_CAP			BIT(12)		/* deprecated */
#define SPDM_HBEAT_CAP			BIT(13)
#define SPDM_KEY_UPD_CAP		BIT(14)
#define SPDM_HANDSHAKE_ITC_CAP		BIT(15)
#define SPDM_PUB_KEY_ID_CAP		BIT(16)
#define SPDM_CHUNK_CAP			BIT(17)		/* 1.2 only */
#define SPDM_ALIAS_CERT_CAP		BIT(18)		/* 1.2 response only */
#define SPDM_SET_CERT_CAP		BIT(19)		/* 1.2 response only */
#define SPDM_CSR_CAP			BIT(20)		/* 1.2 response only */
#define SPDM_CERT_INST_RESET_CAP	BIT(21)		/* 1.2 response only */

/* SPDM capabilities supported by this implementation */
#define SPDM_CAPS			(SPDM_CERT_CAP | SPDM_CHAL_CAP)

/* SPDM capabilities required from responders */
#define SPDM_MIN_CAPS			(SPDM_CERT_CAP | SPDM_CHAL_CAP)

/*
 * SPDM cryptographic timeout of this implementation:
 * Assume calculations may take up to 1 sec on a busy machine, which equals
 * roughly 1 << 20.  That's within the limits mandated for responders by CMA
 * (1 << 23 usec, PCIe r6.0 sec 6.31.3) and DOE (1 sec, PCIe r6.0 sec 6.30.2).
 * Used in GET_CAPABILITIES exchange.
 */
#define SPDM_CTEXPONENT			20

/*
 * Todo
 * - Secure channel setup.
 * - Multiple slot support.
 * - Measurement support (over secure channel or within CHALLENGE_AUTH.
 * - Support more core algorithms (not CMA does not require them, but may use
 *   them if present.
 * - Extended algorithm, support.
 */
/*
 * Discussions points
 * 3. Currently only implement one flow - so ignore whether we have certs cached.
 *    Could implement the alternative flows, but at cost of complexity.
 * 4. Keyring management. How to ensure we can easily check root key against
 *    keys in appropriate keyring, but ensure we can't cross check keys
 *    from different devices.  Current solution of one keyring per SPDM has issues
 *    around cleanup when an error occurs.
 *
 * 1.2.1 changes - not necessarily supported
 * - Alias certificates. Device creates certificates that can incorportate some
 *   mutable information into the keys - hence we may not be able to cache them?
 */

#define SPDM_ASYM_RSASSA_2048		BIT(0)
#define SPDM_ASYM_RSAPSS_2048		BIT(1)
#define SPDM_ASYM_RSASSA_3072		BIT(2)
#define SPDM_ASYM_RSAPSS_3072		BIT(3)
#define SPDM_ASYM_ECDSA_ECC_NIST_P256	BIT(4)
#define SPDM_ASYM_RSASSA_4096		BIT(5)
#define SPDM_ASYM_RSAPSS_4096		BIT(6)
#define SPDM_ASYM_ECDSA_ECC_NIST_P384	BIT(7)
#define SPDM_ASYM_ECDSA_ECC_NIST_P521	BIT(8)
#define SPDM_ASYM_SM2_ECC_SM2_P256	BIT(9)
#define SPDM_ASYM_EDDSA_ED25519		BIT(10)
#define SPDM_ASYM_EDDSA_ED448		BIT(11)

#define SPDM_HASH_SHA_256		BIT(0)
#define SPDM_HASH_SHA_384		BIT(1)
#define SPDM_HASH_SHA_512		BIT(2)
#define SPDM_HASH_SHA3_256		BIT(3)
#define SPDM_HASH_SHA3_384		BIT(4)
#define SPDM_HASH_SHA3_512		BIT(5)
#define SPDM_HASH_SM3_256		BIT(6)

/* SPDM algorithms supported by this implementation */
#define SPDM_ASYM_ALGOS		       (SPDM_ASYM_RSASSA_3072		| \
					SPDM_ASYM_ECDSA_ECC_NIST_P256	| \
					SPDM_ASYM_ECDSA_ECC_NIST_P384)
#define SPDM_HASH_ALGOS		       (SPDM_HASH_SHA_256		| \
					SPDM_HASH_SHA_384)

/*
 * Common header shared by all messages.
 * Note that the meaning of param1 and param2 is message dependent.
 */
struct spdm_header {
	u8 version;
	u8 code;  /* RequestResponseCode */
	u8 param1;
	u8 param2;
} __packed;

#define SPDM_REQ 0x80
#define SPDM_GET_VERSION 0x84

struct spdm_get_version_req {
	u8 version;
	u8 code;
	u8 param1;
	u8 param2;
} __packed;

struct spdm_get_version_rsp {
	u8 version;
	u8 code;
	u8 param1;
	u8 param2;

	u8 reserved;
	u8 version_number_entry_count;
	__le16 version_number_entries[];
} __packed;

#define SPDM_GET_CAPABILITIES 0xE1
#define SPDM_MIN_DATA_TRANSFER_SIZE 42 /* SPDM 1.2.0 margin no 226 */

/* For this exchange the request and response messages have the same form */
struct spdm_get_capabilities_reqrsp {
	u8 version;
	u8 code;
	u8 param1;
	u8 param2;

	u8 reserved;
	u8 ctexponent;
	u16 reserved2;

	__le32 flags;
	/* End of SPDM 1.1 structure */
	__le32 data_transfer_size;			/* 1.2 only */
	__le32 max_spdm_msg_size;			/* 1.2 only */
} __packed;

#define SPDM_NEGOTIATE_ALGS 0xE3

struct spdm_negotiate_algs_req {
	u8 version;
	u8 code;
	u8 param1; /* Number of ReqAlgStruct entries at end */
	u8 param2;

	__le16 length;
	u8 measurement_specification;
	u8 other_params_support;			/* 1.2 only */

	__le32 base_asym_algo;
	__le32 base_hash_algo;

	u8 reserved1[12];
	u8 ext_asym_count;
	u8 ext_hash_count;
	u8 reserved2[2];

	/*
	 * Additional optional fields at end of this structure:
	 * - ExtAsym: 4 bytes * ext_asym_count
	 * - ExtHash: 4 bytes * ext_hash_count
	 * - ReqAlgStruct: variable size * param1
	 */
} __packed;

struct spdm_negotiate_algs_rsp {
	u8 version;
	u8 code;
	u8 param1; /* Number of RespAlgStruct entries at end */
	u8 param2;

	__le16 length;
	u8 measurement_specification_sel;
	u8 other_params_sel;				/* 1.2 only */

	__le32 measurement_hash_algo;
	__le32 base_asym_sel;
	__le32 base_hash_sel;

	u8 reserved1[12];
	u8 ext_asym_sel_count; /* Either 0 or 1 */
	u8 ext_hash_sel_count; /* Either 0 or 1 */
	u8 reserved2[2];

	/*
	 * Additional optional fields at end of this structure:
	 * - ExtAsym: 4 bytes * ext_asym_count
	 * - ExtHash: 4 bytes * ext_hash_count
	 * - RespAlgStruct: variable size * param1
	 */
} __packed;

struct spdm_req_alg_struct {
	u8 alg_type;
	u8 alg_count; /* 0x2K where K is number of alg_external entries */
	__le16 alg_supported; /* size is in alg_count[7:4], always 2 */
	__le32 alg_external[];
} __packed;

#define SPDM_GET_DIGESTS 0x81

struct spdm_get_digests_req {
	u8 version;
	u8 code;
	u8 param1; /* Reserved */
	u8 param2; /* Reserved */
} __packed;

struct spdm_get_digests_rsp {
	u8 version;
	u8 code;
	u8 param1; /* Reserved */
	u8 param2; /* Slot mask */
	u8 digests[]; /* Hash of spdm_cert_chain for each slot */
} __packed;

#define SPDM_GET_CERTIFICATE 0x82

struct spdm_get_certificate_req {
	u8 version;
	u8 code;
	u8 param1; /* Slot number 0..7 */
	u8 param2; /* Reserved */
	__le16 offset;
	__le16 length;
} __packed;

struct spdm_get_certificate_rsp {
	u8 version;
	u8 code;
	u8 param1; /* Slot number 0..7 */
	u8 param2; /* Reserved */
	__le16 portion_length;
	__le16 remainder_length;
	u8 cert_chain[]; /* PortionLength long */
} __packed;

struct spdm_cert_chain {
	__le16 length;
	u8 reserved[2];
	/*
	 * Additional fields:
	 * - RootHash: Digest of Root Certificate
	 * - Certificates: Chain of ASN.1 DER-encoded X.509 v3 certificates
	 */
} __packed;

#define SPDM_CHALLENGE 0x83

struct spdm_challenge_req {
	u8 version;
	u8 code;
	u8 param1; /* Slot number 0..7 */
	u8 param2; /* Measurement summary hash type */
	u8 nonce[32];
} __packed;

struct spdm_challenge_rsp {
	u8 version;
	u8 code;
	u8 param1; /* response attribute field, slot id from challenge, bit 7 is mutual auth */
	u8 param2; /* slot mask */
	/* Hash length cert chain */
	/* Nonce, 32 bytes */
	/* Measurement Summary Hash - if present */
	/* 2 byte opaque length */
	/* opaque data if length non 0 */
	/* Signature */
} __packed;

#define SPDM_ERROR 0x7f

enum spdm_error_code {
	spdm_invalid_request = 0x01,
	spdm_invalid_session = 0x02,			/* 1.1 only */
	spdm_busy = 0x03,
	spdm_unexpected_request = 0x04,
	spdm_unspecified = 0x05,
	spdm_decrypt_error = 0x06,
	spdm_unsupported_request = 0x07,
	spdm_request_in_flight = 0x08,
	spdm_invalid_response_code = 0x09,
	spdm_session_limit_exceeded = 0x0a,
	spdm_session_required = 0x0b,
	spdm_reset_required = 0x0c,
	spdm_response_too_large = 0x0d,
	spdm_request_too_large = 0x0e,
	spdm_large_response = 0x0f,
	spdm_message_lost = 0x10,
	spdm_version_mismatch = 0x41,
	spdm_response_not_ready = 0x42,
	spdm_request_resynch = 0x43,
	spdm_vendor_defined_error = 0xff,
};

struct spdm_error_rsp {
	u8 version;
	u8 code;
	enum spdm_error_code error_code:8;
	u8 error_data;

	u8 extended_error_data[];
} __packed;

static int spdm_err(struct device *dev, struct spdm_error_rsp *rsp)
{
	switch (rsp->error_code) {
	case spdm_invalid_request:
		dev_err(dev, "Invalid request\n");
		return -EINVAL;
	case spdm_invalid_session:
		if (rsp->version == 0x11) {
			dev_err(dev, "Invalid session %#x\n", rsp->error_data);
			return -EINVAL;
		}
		break;
	case spdm_busy:
		dev_err(dev, "Busy\n");
		return -EBUSY;
	case spdm_unexpected_request:
		dev_err(dev, "Unexpected request\n");
		return -EINVAL;
	case spdm_unspecified:
		dev_err(dev, "Unspecified error\n");
		return -EINVAL;
	case spdm_decrypt_error:
		dev_err(dev, "Decrypt error\n");
		return -EIO;
	case spdm_unsupported_request:
		dev_err(dev, "Unsupported request %#x\n", rsp->error_data);
		return -EINVAL;
	case spdm_request_in_flight:
		dev_err(dev, "Request in flight\n");
		return -EINVAL;
	case spdm_invalid_response_code:
		dev_err(dev, "Invalid response code\n");
		return -EINVAL;
	case spdm_session_limit_exceeded:
		dev_err(dev, "Session limit exceeded\n");
		return -EBUSY;
	case spdm_session_required:
		dev_err(dev, "Session required\n");
		return -EINVAL;
	case spdm_reset_required:
		dev_err(dev, "Reset required\n");
		return -ERESTART;
	case spdm_response_too_large:
		dev_err(dev, "Response too large\n");
		return -EINVAL;
	case spdm_request_too_large:
		dev_err(dev, "Request too large\n");
		return -EINVAL;
	case spdm_large_response:
		dev_err(dev, "Large response\n");
		return -EMSGSIZE;
	case spdm_message_lost:
		dev_err(dev, "Message lost\n");
		return -EIO;
	case spdm_version_mismatch:
		dev_err(dev, "Version mismatch\n");
		return -EINVAL;
	case spdm_response_not_ready:
		dev_err(dev, "Response not ready\n");
		return -EINPROGRESS;
	case spdm_request_resynch:
		dev_err(dev, "Request resynchronization\n");
		return -ERESTART;
	case spdm_vendor_defined_error:
		dev_err(dev, "Vendor defined error\n");
		return -EINVAL;
	}

	dev_err(dev, "Undefined error %#x\n", rsp->error_code);
	return -EINVAL;
}

/**
 * struct spdm_state - SPDM session state
 *
 * @dev: Transport device.  Used for error reporting and passed to @transport.
 * @transport: Transport function to perform one message exchange.
 * @transport_priv: Transport private data.
 * @transport_sz: Maximum message size the transport is capable of (in bytes).
 *	Used as DataTransferSize in GET_CAPABILITIES exchange.
 * @version: Maximum common supported version of requester and responder.
 *	Negotiated during GET_VERSION exchange.
 * @responder_caps: Cached capabilities of responder.
 *	Received during GET_CAPABILITIES exchange.
 * @base_asym_alg:
 *	Selected by responder during NEGOTIATE_ALGORITHMS exchange.
 * @base_hash_alg: Hash algorithm for CHALLENGE_AUTH signature verification.
 *	Selected by responder during NEGOTIATE_ALGORITHMS exchange.
 * @shash: Synchronous hash transform.
 * @desc: Synchronous hash context.
 * @h: Hash length of @base_hash_alg.  H in SPDM specification.
 * @slot_mask: Bitmask of populated certificate slots in the responder.
 *	Received during GET_DIGESTS exchange.
 *
 * @get_version_rsp: Stashed GET_VERSION response for later hash computation.
 * @get_version_rsp_sz: Length of @get_version_rsp.
 * @get_caps_req: Stashed GET_CAPABILITIES request for later hash computation.
 * @get_caps_req_sz: Length of @get_caps_req.
 * @get_caps_rsp: Stashed GET_CAPABILITIES response for later hash computation.
 * @get_caps_rsp_sz: Length of @get_caps_rsp.
 */
struct spdm_state {
	/* Transport */
	struct device *dev;
	spdm_transport *transport;
	void *transport_priv;
	u32 transport_sz;

	/* Negotiated state */
	u8 version;
	u32 responder_caps;
	u32 base_asym_alg;
	u32 base_hash_alg;

	/* Hash algorithm */
	struct crypto_shash *shash;
	struct shash_desc *desc;
	size_t h;

	/* Certificates */
	u8 slot_mask;
	struct key *leaf_key;
	size_t s; /* base asymmetric signature length - S in specification */
	struct key *root_keyring; /* Keyring against which to check the root */
	struct key *keyring; /* used to store certs from device */

	/*
	 * For CHALLENGE_AUTH signature verification, a hash is computed over
	 * all exchanged messages to detect modification by a man-in-the-middle
	 * or media error.  However the hash algorithm is not known until the
	 * NEGOTIATE_ALGORITHMS response has been received.  The preceding
	 * GET_VERSION and GET_CAPABILITIES exchanges are therefore stashed
	 * here and consumed once the algorithm is known.
	 */
	struct spdm_get_version_rsp *get_version_rsp;
	size_t get_version_rsp_sz;
	struct spdm_get_capabilities_reqrsp get_caps_req;
	size_t get_caps_req_sz;
	struct spdm_get_capabilities_reqrsp get_caps_rsp;
	size_t get_caps_rsp_sz;
};

static int __spdm_exchange(struct spdm_state *spdm_state,
			   const void *req, size_t req_sz,
			   void *rsp, size_t rsp_sz)
{
	const struct spdm_header *request = req;
	struct spdm_header *response = rsp;
	int length;
	int rc;

	rc = spdm_state->transport(spdm_state->transport_priv, spdm_state->dev,
				   req, req_sz, rsp, rsp_sz);
	if (rc < 0)
		return rc;

	length = rc;
	if (length < sizeof(struct spdm_header))
		return -EPROTO;

	if (response->code == SPDM_ERROR)
		return spdm_err(spdm_state->dev, (struct spdm_error_rsp *)rsp);

	if (response->code != (request->code & ~SPDM_REQ)) {
		dev_err(spdm_state->dev,
			"Response code %#x does not match request code %#x\n",
			response->code, request->code);
		return -EPROTO;
	}

	return length;
}

static int spdm_exchange(struct spdm_state *spdm_state,
			 void *req, size_t req_sz, void *rsp, size_t rsp_sz)
{
	struct spdm_header *req_header = req;

	if (req_sz < sizeof(struct spdm_header) ||
	    rsp_sz < sizeof(struct spdm_header))
		return -EINVAL;

	req_header->version = spdm_state->version;

	return __spdm_exchange(spdm_state, req, req_sz, rsp, rsp_sz);
}

static const struct spdm_get_version_req spdm_get_version_req = {
	.version = 0x10,
	.code = SPDM_GET_VERSION,
};

static int spdm_get_version(struct spdm_state *spdm_state)
{
	struct spdm_get_version_rsp *rsp;
	size_t *rsp_sz = &spdm_state->get_version_rsp_sz;
	u8 version = SPDM_MIN_VER;
	bool foundver = false;
	int numversions = 2;
	int rc, length, i;

retry:
	kfree(spdm_state->get_version_rsp);
	*rsp_sz = struct_size(rsp, version_number_entries, numversions);
	rsp = spdm_state->get_version_rsp = kzalloc(*rsp_sz, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	/* Bypass spdm_exchange() to be able to set version = 0x10 */
	rc = __spdm_exchange(spdm_state, &spdm_get_version_req,
			     sizeof(spdm_get_version_req), rsp, *rsp_sz);
	if (rc < 0)
		return rc;

	length = rc;
	if (length < sizeof(*rsp)) {
		dev_err(spdm_state->dev, "Truncated version response\n");
		return -EIO;
	}

	/* If we didn't allocate enough space the first time, go around again */
	if (rsp->version_number_entry_count > numversions) {
		numversions = rsp->version_number_entry_count;
		goto retry;
	}

	*rsp_sz = struct_size(rsp, version_number_entries,
			      rsp->version_number_entry_count);
	if (length < *rsp_sz) {
		dev_err(spdm_state->dev, "Truncated version response\n");
		return -EIO;
	}

	for (i = 0; i < rsp->version_number_entry_count; i++) {
		u8 ver = get_unaligned_le16(&rsp->version_number_entries[i]) >> 8;

		if (ver >= version && ver <= SPDM_MAX_VER) {
			foundver = true;
			version = ver;
		}
	}
	if (!foundver) {
		dev_err(spdm_state->dev, "No common supported version\n");
		return -EPROTO;
	}
	spdm_state->version = version;

	return 0;
}

static int spdm_get_capabilities(struct spdm_state *spdm_state)
{
	struct spdm_get_capabilities_reqrsp *req = &spdm_state->get_caps_req;
	struct spdm_get_capabilities_reqrsp *rsp = &spdm_state->get_caps_rsp;
	size_t *req_sz = &spdm_state->get_caps_req_sz;
	size_t *rsp_sz = &spdm_state->get_caps_rsp_sz;
	int rc, length;

	req->code = SPDM_GET_CAPABILITIES;
	req->ctexponent = SPDM_CTEXPONENT;
	req->flags = cpu_to_le32(SPDM_CAPS);

	if (spdm_state->version >= 0x12) {
		req->data_transfer_size = cpu_to_le32(spdm_state->transport_sz),
		req->max_spdm_msg_size = cpu_to_le32(UINT_MAX),
		*req_sz = sizeof(*req);
		*rsp_sz = sizeof(*rsp);
	} else {
		*req_sz = offsetof(typeof(*req), data_transfer_size);
		*rsp_sz = offsetof(typeof(*rsp), data_transfer_size);
	}

	rc = spdm_exchange(spdm_state, req, *req_sz, rsp, *rsp_sz);
	if (rc < 0)
		return rc;

	length = rc;
	if (length < *rsp_sz) {
		dev_err(spdm_state->dev, "Truncated capabilities response\n");
		return -EIO;
	}

	spdm_state->responder_caps = le32_to_cpu(rsp->flags);
	if ((spdm_state->responder_caps & SPDM_MIN_CAPS) != SPDM_MIN_CAPS)
		return -EPROTONOSUPPORT;

	if (spdm_state->version >= 0x12) {
		u32 data_transfer_size = le32_to_cpu(rsp->data_transfer_size);
		if (data_transfer_size < SPDM_MIN_DATA_TRANSFER_SIZE) {
			dev_err(spdm_state->dev,
				"Malformed capabilities response\n");
			return -EPROTO;
		}
		spdm_state->transport_sz = min(spdm_state->transport_sz,
					       data_transfer_size);
	}

	return 0;
}

/**
 * spdm_start_digest() - Build first part of CHALLENGE_AUTH hash
 *
 * @spdm_state: SPDM session state
 * @req: NEGOTIATE_ALGORITHMS request
 * @req_sz: length of @req
 * @rsp: ALGORITHMS response
 * @rsp_sz: length of @rsp
 *
 * We've just learned the hash algorithm to use for CHALLENGE_AUTH signature
 * verification.  Hash the GET_VERSION and GET_CAPABILITIES exchanges which
 * have been stashed in @spdm_state, as well as the NEGOTIATE_ALGORITHMS
 * exchange which has just been performed.  Subsequent requests and responses
 * are added to the hash as they become available.
 *
 * Return 0 on success or a negative errno.
 */
static int spdm_start_digest(struct spdm_state *spdm_state,
			     void *req, size_t req_sz, void *rsp, size_t rsp_sz)
{
	char *alg_name;
	int rc;

	switch (spdm_state->base_hash_alg) {
	case SPDM_HASH_SHA_256:
		alg_name = "sha256";
		break;
	case SPDM_HASH_SHA_384:
		alg_name = "sha384";
		break;
	default:
		dev_err(spdm_state->dev, "Unknown hash algorithm\n");
		return -EINVAL;
	}

	spdm_state->shash = crypto_alloc_shash(alg_name, 0, 0);
	if (!spdm_state->shash)
		return -ENOMEM;

	spdm_state->desc = kzalloc(sizeof(*spdm_state->desc) +
				   crypto_shash_descsize(spdm_state->shash),
				   GFP_KERNEL);
	if (!spdm_state->desc)
		return -ENOMEM;

	spdm_state->desc->tfm = spdm_state->shash;

	/* Used frequently to compute offsets, so cache H */
	spdm_state->h = crypto_shash_digestsize(spdm_state->shash);

	rc = crypto_shash_init(spdm_state->desc);
	if (rc)
		return rc;

	rc = crypto_shash_update(spdm_state->desc,
				 (u8 *)&spdm_get_version_req,
				 sizeof(spdm_get_version_req));
	if (rc)
		return rc;

	rc = crypto_shash_update(spdm_state->desc,
				 (u8 *)spdm_state->get_version_rsp,
				 spdm_state->get_version_rsp_sz);
	if (rc)
		return rc;

	rc = crypto_shash_update(spdm_state->desc,
				 (u8 *)&spdm_state->get_caps_req,
				 spdm_state->get_caps_req_sz);
	if (rc)
		return rc;

	rc = crypto_shash_update(spdm_state->desc,
				 (u8 *)&spdm_state->get_caps_rsp,
				 spdm_state->get_caps_rsp_sz);
	if (rc)
		return rc;

	rc = crypto_shash_update(spdm_state->desc, (u8 *)req, req_sz);
	if (rc)
		return rc;

	rc = crypto_shash_update(spdm_state->desc, (u8 *)rsp, rsp_sz);
		return rc;

	return 0;
}

static int spdm_negotiate_algs(struct spdm_state *spdm_state)
{
	struct spdm_req_alg_struct *req_alg_struct;
	struct spdm_negotiate_algs_req *req;
	struct spdm_negotiate_algs_rsp *rsp;
	size_t req_sz = sizeof(*req);
	size_t rsp_sz = sizeof(*rsp);
	int rc, length;

	/* Request length shall be <= 128 bytes (SPDM 1.1.0 margin no 185) */
	BUILD_BUG_ON(req_sz > 128);

	req = kzalloc(req_sz, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->code = SPDM_NEGOTIATE_ALGS;
	req->length = cpu_to_le16(req_sz);
	req->base_asym_algo = cpu_to_le32(SPDM_ASYM_ALGOS);
	req->base_hash_algo = cpu_to_le32(SPDM_HASH_ALGOS);

	rsp = kzalloc(rsp_sz, GFP_KERNEL);
	if (!rsp) {
		rc = -ENOMEM;
		goto err_free_req;
	}

	rc = spdm_exchange(spdm_state, req, req_sz, rsp, rsp_sz);
	if (rc < 0)
		goto err_free_rsp;

	length = rc;
	if (length < sizeof(*rsp) ||
	    length < sizeof(*rsp) + rsp->param1 * sizeof(*req_alg_struct)) {
		dev_err(spdm_state->dev, "Truncated algorithms response\n");
		rc = -EIO;
		goto err_free_rsp;
	}

	spdm_state->base_asym_alg =
		le32_to_cpu(rsp->base_asym_sel) & SPDM_ASYM_ALGOS;
	spdm_state->base_hash_alg =
		le32_to_cpu(rsp->base_hash_sel) & SPDM_HASH_ALGOS;

	/* Responder shall select exactly 1 alg (SPDM 1.1.0 margin no 193) */
	if (hweight32(spdm_state->base_asym_alg) != 1 ||
	    hweight32(spdm_state->base_hash_alg) != 1 ||
	    rsp->ext_asym_sel_count != 0 ||
	    rsp->ext_hash_sel_count != 0 ||
	    rsp->param1 > req->param1) {
		dev_err(spdm_state->dev, "Malformed algorithms response\n");
		rc = -EPROTO;
		goto err_free_rsp;
	}

	switch (spdm_state->base_asym_alg) {
	case SPDM_ASYM_RSASSA_3072:
		spdm_state->s = 384;
		break;
	case SPDM_ASYM_ECDSA_ECC_NIST_P256:
		spdm_state->s = 64;
		break;
	case SPDM_ASYM_ECDSA_ECC_NIST_P384:
		spdm_state->s = 96;
		break;
	default:
		dev_err(spdm_state->dev, "Unknown asym algorithm\n");
		rc = -EINVAL;
		goto err_free_rsp;
	}

	/*
	 * If request contained a ReqAlgStruct not supported by responder,
	 * the corresponding RespAlgStruct may be omitted in response.
	 * Calculate the actual (possibly shorter) response length:
	 */
	rsp_sz = sizeof(*rsp) + rsp->param1 * sizeof(*req_alg_struct);

	rc = spdm_start_digest(spdm_state, req, req_sz, rsp, rsp_sz);

err_free_rsp:
	kfree(rsp);
err_free_req:
	kfree(req);

	return rc;
}

static int spdm_get_digests(struct spdm_state *spdm_state)
{
	struct spdm_get_digests_req req = { .code = SPDM_GET_DIGESTS };
	struct spdm_get_digests_rsp *rsp;
	size_t rsp_sz;
	int rc, length;

	/*
	 * Assume all 8 slots are present.  We know the hash length (and thus
	 * the response size) because the responder only returns digests for
	 * the hash algorithm selected during the NEGOTIATE_ALGORITHMS exchange
	 * (SPDM 1.1.2 margin no 206).
	 */
	rsp_sz = sizeof(*rsp) + 8 * spdm_state->h;
	rsp = kzalloc(rsp_sz, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	rc = spdm_exchange(spdm_state, &req, sizeof(req), rsp, rsp_sz);
	if (rc < 0)
		goto err_free_rsp;

	length = rc;
	if (length < sizeof(*rsp) ||
	    length < sizeof(*rsp) + hweight8(rsp->param2) * spdm_state->h) {
		dev_err(spdm_state->dev, "Truncated digests response\n");
		rc = -EIO;
		goto err_free_rsp;
	}

	rsp_sz = sizeof(*rsp) + hweight8(rsp->param2) * spdm_state->h;

	/*
	 * Authentication-capable endpoints must carry at least 1 cert chain
	 * (SPDM 1.1.0 margin no 221).
	 */
	spdm_state->slot_mask = rsp->param2;
	if (!spdm_state->slot_mask) {
		dev_err(spdm_state->dev, "No certificates provisioned\n");
		rc = -EPROTO;
		goto err_free_rsp;
	}

	rc = crypto_shash_update(spdm_state->desc, (u8 *)&req, sizeof(req));
	if (rc)
		goto err_free_rsp;

	rc = crypto_shash_update(spdm_state->desc, (u8 *)rsp, rsp_sz);

err_free_rsp:
	kfree(rsp);

	return rc;
}

/* Used to give a unique name for per device keychains */
static DEFINE_IDA(spdm_ida);

static int spdm_get_certificate(struct spdm_state *spdm_state)
{
	struct spdm_get_certificate_req req = {
		.code = SPDM_GET_CERTIFICATE,
		.param1 = 0, /* Slot 0 */
	};
	struct spdm_get_certificate_rsp *rsp;
	struct spdm_cert_chain *cert_chain;
	size_t rsp_sz;
	unsigned int total_length;
	u16 remainder_length = 0xffff;
	u16 portion_length;
	u16 offset = 0;
	u8 *certs = NULL;
	int rc, length;
	char *keyring_name;
	int keyring_id;
	u16 next_cert;

	/*
	 * It is legal for the responder to send more bytes than requested.
	 * (Note the "should" in SPDM 1.1.0 margin no 239.)  If we allocate
	 * a too small buffer, we can't calculate the hash over the (truncated)
	 * response.  Only choice is thus to allocate the maximum possible 64k.
	 */
	rsp_sz = min_t(u32, sizeof(*rsp) + 0xffff, spdm_state->transport_sz);
	rsp = kvmalloc(rsp_sz, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	do {
		/*
		 * If transport_sz is sufficiently large, first request will be
		 * for offset 0 and length 0xffff, which means entire cert
		 * chain (SPDM 1.1.0 margin no 238).
		 */
		req.offset = cpu_to_le16(offset);
		req.length = cpu_to_le16(min_t(size_t, remainder_length,
					       rsp_sz - sizeof(*rsp)));

		rc = spdm_exchange(spdm_state, &req, sizeof(req), rsp, rsp_sz);
		if (rc < 0)
			goto err_free_certs;

		length = rc;
		if (length < sizeof(*rsp) ||
		    length < sizeof(*rsp) + le16_to_cpu(rsp->portion_length)) {
			dev_err(spdm_state->dev,
				"Truncated certificate response\n");
			rc = -EIO;
			goto err_free_certs;
		}

		portion_length = le16_to_cpu(rsp->portion_length);
		remainder_length = le16_to_cpu(rsp->remainder_length);

		/* On first response we learn total length of cert chain */
		if (!certs) {
			total_length = portion_length + remainder_length;
			certs = kvmalloc(total_length, GFP_KERNEL);
			if (!certs) {
				rc = -ENOMEM;
				goto err_free_certs;
			}
		}

		if (!portion_length ||
		    (rsp->param1 & 0xf) != req.param1 ||
		    offset + portion_length + remainder_length != total_length)
		{
			dev_err(spdm_state->dev,
				"Malformed certificate response\n");
			rc = -EPROTO;
			goto err_free_certs;
		}

		memcpy(certs + offset, rsp->cert_chain, portion_length);
		offset += portion_length;

		rc = crypto_shash_update(spdm_state->desc, (u8 *)&req,
					 sizeof(req));
		if (rc)
			goto err_free_certs;

		rc = crypto_shash_update(spdm_state->desc, (u8 *)rsp,
					 sizeof(*rsp) + portion_length);
		if (rc)
			goto err_free_certs;

	} while (remainder_length > 0);

	cert_chain = (struct spdm_cert_chain *)certs;
	if (total_length < sizeof(*cert_chain)  + spdm_state->h ||
	    total_length != cert_chain->length) {
		dev_err(spdm_state->dev, "Malformed certificate chain\n");
		rc = -EPROTO;
		goto err_free_certs;
	}

	keyring_id = ida_alloc(&spdm_ida, GFP_KERNEL);
	if (keyring_id < 0) {
		rc = keyring_id;
		goto err_free_certs;
	}

	keyring_name = kasprintf(GFP_KERNEL, "_spdm%02d", keyring_id);
	if (!keyring_name) {
		rc = -ENOMEM;
		goto err_free_ida;
	}

	/*
	 * Create a spdm instance specific keyring to avoid mixing certs,
	 * Not a child of _cma keyring, because the search below should
	 * not find a self signed cert in here.
	 *
	 * Not sure how to release a keyring, so currently if this fails we leak.
	 * That might be fine but an ida could get reused.
	 */
	spdm_state->keyring = keyring_alloc(keyring_name,
					    KUIDT_INIT(0), KGIDT_INIT(0),
					    current_cred(),
					    (KEY_POS_ALL & ~KEY_POS_SETATTR) |
					    KEY_USR_VIEW | KEY_USR_READ,
					    KEY_ALLOC_NOT_IN_QUOTA |
					    KEY_ALLOC_SET_KEEP,
					    NULL, NULL);
	kfree(keyring_name);
	if (IS_ERR(spdm_state->keyring)) {
		dev_err(spdm_state->dev,
			"Failed to allocate per spdm keyring\n");
		rc = PTR_ERR(spdm_state->keyring);
		goto err_free_ida;
	}

	next_cert = sizeof(struct spdm_cert_chain) + spdm_state->h;

	/*
	 * Store the certificate chain on the per SPDM instance keyring.
	 * Allow for up to 3 bytes padding as transport sends multiples of 4 bytes.
	 */
	while (next_cert < offset) {
		struct key *key;
		key_ref_t key2;

		key2 = key_create_or_update(make_key_ref(spdm_state->keyring, 1),
					    "asymmetric", NULL,
					    certs + next_cert, offset - next_cert,
					    (KEY_POS_ALL & ~KEY_POS_SETATTR) |
					    KEY_USR_VIEW | KEY_USR_READ,
					    KEY_ALLOC_NOT_IN_QUOTA);

		if (IS_ERR(key2)) {
			/* FIXME: Any additional cleanup to do here? */
			rc = PTR_ERR(key2);
			goto err_free_ida;
		}

		if (!spdm_state->leaf_key) {
			/* First key in chain, so check against keys on _cma keyring */
			struct public_key_signature *sig =
				key_ref_to_ptr(key2)->payload.data[asym_auth];

			key = find_asymmetric_key(spdm_state->root_keyring, sig->auth_ids[0],
						  sig->auth_ids[1], NULL, false);
			if (IS_ERR(key)) {
				dev_err(spdm_state->dev,
					"Unable to retrieve signing certificate from _cma keyring\n");
				rc = PTR_ERR(key);
				goto err_free_ida;
			}

			rc = verify_signature(key, sig);
			if (rc) {
				dev_err(spdm_state->dev,
					"Unable to check SPDM cert against _cma keyring\n");
				goto err_free_ida;
			}

			spdm_state->leaf_key = key_ref_to_ptr(key2);
		} else {
			/* Not the first key in chain, so check it against previous one */
			struct public_key_signature *sig =
				key_ref_to_ptr(key2)->payload.data[asym_auth];

			rc = verify_signature(spdm_state->leaf_key, sig);
			if (rc) {
				dev_err(spdm_state->dev,
					"Unable to verify SPDM cert against previous cert in chain\n");
				goto err_free_ida;
			}
			spdm_state->leaf_key = key_ref_to_ptr(key2);
		}
		/*
		 * Horrible but need to pull this directly from the ASN1 stream as the cert
		 * chain is a concatentation of multiple cerificates.
		 */
		next_cert += get_unaligned_be16(certs + next_cert + 2) + 4;
	}

	kvfree(certs);
	kvfree(rsp);

	return 0;

err_free_ida:
	ida_free(&spdm_ida, keyring_id);
err_free_certs:
	kvfree(certs);
	kvfree(rsp);

	return rc;
}

static size_t spdm_challenge_rsp_signature_offset(struct spdm_state *spdm_state,
						  struct spdm_challenge_req *req,
						  struct spdm_challenge_rsp *rsp)
{
	u16 opaque_length;
	size_t offset;

	offset = sizeof(*rsp);		/* Header offset */
	offset += spdm_state->h;	/* CertChain hash */
	offset += 32;			/* Nonce */

	/* Measurement summary hash */
	if (req->param2 &&
	    (spdm_state->responder_caps & SPDM_MAC_CAP))
		offset += spdm_state->h;
	/*
	 * This is almost certainly aligned, but that's not obvious from nearby code
	 * so play safe.
	 */
	opaque_length = get_unaligned_le16((u8 *)rsp + offset);
	offset += sizeof(__le16);
	offset += opaque_length;

	return offset;
}

static int spdm_verify_signature(struct spdm_state *spdm_state, u8 *sig_ptr,
				 u8 *digest, unsigned int digest_size)
{
	const struct asymmetric_key_ids *ids;
	struct public_key_signature sig = {};
	/* Large enough for an ASN1 encoding of supported ECC signatures */
	unsigned char buffer2[128] = {};
	int rc;

	/*
	 * The ecdsa signatures are raw concatentation of the two values.
	 * SPDM 1.2.1 section 2.2.3.4.1 refers to FIPS PUB 186-4 defining this
	 * ordering.
	 * In order to use verify_signature we need to reformat them into ASN1.
	 */
	switch (spdm_state->base_asym_alg) {
	case SPDM_ASYM_ECDSA_ECC_NIST_P256:
	case SPDM_ASYM_ECDSA_ECC_NIST_P384:
	{
		unsigned char buffer[128] = {};
		unsigned char *p = buffer;
		unsigned char *p2;

		//TODO: test the ASN1 function rather more extensively.
		/* First pack the two large integer values */
		p = asn1_encode_integer_large_positive(p, buffer + sizeof(buffer),
						       ASN1_INT, sig_ptr,
						       spdm_state->s / 2);
		p = asn1_encode_integer_large_positive(p, buffer + sizeof(buffer),
						       ASN1_INT,
						       sig_ptr + spdm_state->s  / 2,
						       spdm_state->s / 2);

		/* In turn pack those two large integer values into a sequence */
		p2 = asn1_encode_sequence(buffer2, buffer2 + sizeof(buffer2),
					  buffer, p - buffer);

		sig.s = buffer2;
		sig.s_size = p2 - buffer2;
		sig.encoding = "x962";
		break;
	}

	case SPDM_ASYM_RSASSA_3072:
		sig.s = sig_ptr;
		sig.s_size = spdm_state->s;
		sig.encoding = "pkcs1";
		break;
	default:
		dev_err(spdm_state->dev,
			"Signature algorithm not yet supported\n");
		return -EINVAL;
	}
	sig.digest = digest;
	sig.digest_size = digest_size;
	ids = asymmetric_key_ids(spdm_state->leaf_key);
	sig.auth_ids[0] = ids->id[0];
	sig.auth_ids[1] = ids->id[1];

	switch (spdm_state->base_hash_alg) {
	case SPDM_HASH_SHA_384:
		sig.hash_algo = "sha384";
		break;
	case SPDM_HASH_SHA_256:
		sig.hash_algo = "sha256";
		break;
	default:
		return -EINVAL;
	}

	rc = verify_signature(spdm_state->leaf_key, &sig);
	if (rc) {
		dev_err(spdm_state->dev,
			"Failed to verify challenge_auth signature %d\n", rc);
		return rc;
	}

	return 0;
}

static int spdm_challenge(struct spdm_state *spdm_state)
{
	const char spdm_prefix[] = {
		'd', 'm', 't', 'f', '-', 's', 'p', 'd', 'm', '-', 'v', '1', '.', '2', '.', '*',
		'd', 'm', 't', 'f', '-', 's', 'p', 'd', 'm', '-', 'v', '1', '.', '2', '.', '*',
		'd', 'm', 't', 'f', '-', 's', 'p', 'd', 'm', '-', 'v', '1', '.', '2', '.', '*',
		'd', 'm', 't', 'f', '-', 's', 'p', 'd', 'm', '-', 'v', '1', '.', '2', '.', '*',
		0, 0, 0, 0, /* pad here so length 100 */
		'r', 'e', 's', 'p', 'o', 'n', 'd', 'e', 'r', '-',
		'c', 'h', 'a', 'l', 'l', 'e', 'n', 'g', 'e', '_', 'a', 'u', 't', 'h', ' ',
		's', 'i', 'g', 'n', 'i', 'n', 'g' };
	struct spdm_challenge_req req = {
		.code = SPDM_CHALLENGE,
		.param1 = 0, /* slot 0 for now */
		.param2 = 0, /* no measurement summary hash */
	};
	struct spdm_challenge_rsp *rsp;
	size_t sig_offset, rsp_max_size;
	int length, rc;
	u8 *digest, *message;

	BUILD_BUG_ON(sizeof(spdm_prefix) != 100);
	/*
	 * The response length is up to:
	 * 4 byte header
	 * H byte CertChainHash
	 * 32 byte nonce
	 * (H byte Measurement Summary Hash - not currently requested)
	 * 2 byte Opaque Length
	 * <= 1024 bytes Opaque Data
	 * S byte signature
	 */
	rsp_max_size = sizeof(*rsp) + spdm_state->h + 32 + 2 + 1024 + spdm_state->s;
	rsp = kzalloc(rsp_max_size, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	get_random_bytes(&req.nonce, sizeof(req.nonce));

	rc = spdm_exchange(spdm_state, &req, sizeof(req), rsp, rsp_max_size);
	if (rc < 0)
		goto err_free_rsp;
	length = rc;

	/* Last step of building the digest */
	rc = crypto_shash_update(spdm_state->desc, (u8 *)&req, sizeof(req));
	if (rc)
		goto err_free_rsp;

	/* The hash is complete + signature received; verify against leaf key */
	sig_offset = spdm_challenge_rsp_signature_offset(spdm_state, &req, rsp);
	if (sig_offset >= length) {
		rc = -EIO;
		goto err_free_rsp;
	}

	rc = crypto_shash_update(spdm_state->desc, (u8 *)rsp, sig_offset);
	if (rc)
		goto err_free_rsp;

	digest = kmalloc(spdm_state->h, GFP_KERNEL);
	if (!digest) {
		rc = -ENOMEM;
		goto err_free_rsp;
	}

	crypto_shash_final(spdm_state->desc, digest);
	if (spdm_state->version >= 0x12) {
		message = kmalloc(spdm_state->h + sizeof(spdm_prefix), GFP_KERNEL);
		memcpy(message, spdm_prefix, sizeof(spdm_prefix));
		memcpy(message + sizeof(spdm_prefix), digest, spdm_state->h);
		/*
		 * Not all 1.2 supported Asymmetric functions need this hashed
		 * but all the ones supported here do.
		 */
		rc = crypto_shash_digest(spdm_state->desc, message,
					 spdm_state->h + sizeof(spdm_prefix), digest);
		if (rc) {
			dev_err(spdm_state->dev, "Could not digest prefix + message\n");
			kfree(message);
			goto err_free_digest;
		}
	}

	rc = spdm_verify_signature(spdm_state, (u8 *)rsp + sig_offset, digest,
				   spdm_state->h);
	if (rc) {
		dev_err(spdm_state->dev, "Failed to verify SPDM challenge auth signature\n");
		goto err_free_digest;
	}

	kfree(spdm_state->desc);

	/* Clear to give a simple way to detect out of order */
	spdm_state->desc = NULL;

err_free_digest:
	kfree(digest);

err_free_rsp:
	kfree(rsp);
	return rc;
}

int spdm_authenticate(struct spdm_state *spdm_state)
{
	int rc;

	rc = spdm_get_version(spdm_state);
	if (rc)
		return rc;

	rc = spdm_get_capabilities(spdm_state);
	if (rc)
		return rc;

	rc = spdm_negotiate_algs(spdm_state);
	if (rc)
		return rc;

	rc = spdm_get_digests(spdm_state);
	if (rc)
		return rc;

	rc = spdm_get_certificate(spdm_state);
	if (rc)
		return rc;

	rc = spdm_challenge(spdm_state);
	if (rc)
		return rc;

	/*
	 * If we get to here, we have successfully verified the device is one we are happy
	 * with using.
	 */
	return 0;
}
EXPORT_SYMBOL_GPL(spdm_authenticate);

void spdm_destroy(struct spdm_state *spdm_state)
{
	kfree(spdm_state->desc);
	crypto_free_shash(spdm_state->shash);
	kfree(spdm_state->get_version_rsp);
	kfree(spdm_state);
}
EXPORT_SYMBOL_GPL(spdm_destroy);

/**
 * spdm_create() -
 *
 * @dev: Transport device
 * @transport: Transport function to perform one message exchange
 * @transport_priv: Transport private data
 * @transport_sz: Maximum message size the transport is capable of (in bytes)
 * @keyring:
 */
struct spdm_state *spdm_create(struct device *dev, spdm_transport *transport,
			       void *transport_priv, u32 transport_sz,
			       struct key *keyring)
{
	struct spdm_state *spdm_state = kzalloc(sizeof(*spdm_state), GFP_KERNEL);

	if (!spdm_state)
		return NULL;

	spdm_state->dev = dev;
	spdm_state->transport = transport;
	spdm_state->transport_priv = transport_priv;
	spdm_state->transport_sz = transport_sz;
	spdm_state->root_keyring = keyring;

	return spdm_state;
}
EXPORT_SYMBOL_GPL(spdm_create);

MODULE_LICENSE("GPL");
