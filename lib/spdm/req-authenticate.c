// SPDX-License-Identifier: GPL-2.0
/*
 * DMTF Security Protocol and Data Model (SPDM)
 * https://www.dmtf.org/dsp/DSP0274
 *
 * Requester role: Authenticate a device
 *
 * Copyright (C) 2021-22 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022-24 Intel Corporation
 */

#include "spdm.h"

#include <linux/dev_printk.h>
#include <linux/device.h>
#include <linux/key.h>
#include <linux/random.h>
#include <linux/unaligned.h>

#include <crypto/hash.h>
#include <crypto/hash_info.h>
#include <keys/asymmetric-type.h>
#include <keys/x509-parser.h>

/* SPDM 1.2.0 margin no 359 and 803 */
static const char *spdm_context = "responder-challenge_auth signing";

/*
 * All SPDM messages exchanged during an authentication sequence up to and
 * including GET_DIGESTS fit into a single page, hence are stored in the
 * transcript without bounds checking.  Only subsequent GET_CERTIFICATE
 * and CHALLENGE exchanges may exceed one page.
 */
static_assert(PAGE_SIZE >=
	sizeof(struct spdm_get_version_req) +
	struct_size_t(struct spdm_get_version_rsp,
		      version_number_entries, 255) +
	sizeof(struct spdm_get_capabilities_req) +
	sizeof(struct spdm_get_capabilities_rsp) +
	sizeof(struct spdm_negotiate_algs_req) +
	sizeof(struct spdm_negotiate_algs_rsp) +
	sizeof(struct spdm_req_alg_struct) * 2 * SPDM_MAX_REQ_ALG_STRUCT +
	sizeof(struct spdm_get_digests_req) +
	struct_size_t(struct spdm_get_digests_rsp,
		      digests, SPDM_SLOTS * SHA512_DIGEST_SIZE));

static int spdm_get_version(struct spdm_state *spdm_state)
{
	struct spdm_get_version_req *req = spdm_state->transcript;
	struct spdm_get_version_rsp *rsp;
	bool foundver = false;
	int rc, length, i;

	spdm_state->version = 0x10;

	*req = (struct spdm_get_version_req) {
		.code = SPDM_GET_VERSION,
	};

	rsp = spdm_state->transcript_end += sizeof(*req);

	rc = spdm_exchange(spdm_state, req, sizeof(*req), rsp,
			   struct_size(rsp, version_number_entries, 255));
	if (rc < 0)
		return rc;

	length = rc;
	if (length < sizeof(*rsp) ||
	    length < struct_size(rsp, version_number_entries,
				 rsp->version_number_entry_count)) {
		dev_err(spdm_state->dev, "Truncated version response\n");
		return -EIO;
	}

	spdm_state->transcript_end +=
		     struct_size(rsp, version_number_entries,
				 rsp->version_number_entry_count);

	for (i = 0; i < rsp->version_number_entry_count; i++) {
		u8 ver = le16_to_cpu(rsp->version_number_entries[i]) >> 8;

		if (ver >= spdm_state->version && ver <= SPDM_MAX_VER) {
			spdm_state->version = ver;
			foundver = true;
		}
	}
	if (!foundver) {
		dev_err(spdm_state->dev, "No common supported version\n");
		return -EPROTO;
	}

	return 0;
}

static int spdm_get_capabilities(struct spdm_state *spdm_state)
{
	struct spdm_get_capabilities_req *req = spdm_state->transcript_end;
	struct spdm_get_capabilities_rsp *rsp;
	size_t req_sz, rsp_sz;
	int rc, length;

	*req = (struct spdm_get_capabilities_req) {
		.code = SPDM_GET_CAPABILITIES,
		.ctexponent = SPDM_CTEXPONENT,
		.flags = cpu_to_le32(SPDM_REQ_CAPS),
	};

	if (spdm_state->version == 0x10) {
		req_sz = offsetofend(typeof(*req), param2);
		rsp_sz = offsetofend(typeof(*rsp), flags);
	} else if (spdm_state->version == 0x11) {
		req_sz = offsetofend(typeof(*req), flags);
		rsp_sz = offsetofend(typeof(*rsp), flags);
	} else {
		req_sz = sizeof(*req);
		rsp_sz = sizeof(*rsp);
		req->data_transfer_size = cpu_to_le32(spdm_state->transport_sz);
		req->max_spdm_msg_size = cpu_to_le32(spdm_state->transport_sz);
	}

	rsp = spdm_state->transcript_end += req_sz;

	rc = spdm_exchange(spdm_state, req, req_sz, rsp, rsp_sz);
	if (rc < 0)
		return rc;

	length = rc;
	if (length < rsp_sz) {
		dev_err(spdm_state->dev, "Truncated capabilities response\n");
		return -EIO;
	}

	spdm_state->transcript_end += rsp_sz;

	spdm_state->rsp_caps = le32_to_cpu(rsp->flags);
	if ((spdm_state->rsp_caps & SPDM_RSP_MIN_CAPS) != SPDM_RSP_MIN_CAPS)
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

static int spdm_parse_algs(struct spdm_state *spdm_state)
{
	switch (spdm_state->base_asym_alg) {
	case SPDM_ASYM_RSASSA_2048:
		spdm_state->sig_len = 256;
		spdm_state->base_asym_enc = "pkcs1";
		break;
	case SPDM_ASYM_RSASSA_3072:
		spdm_state->sig_len = 384;
		spdm_state->base_asym_enc = "pkcs1";
		break;
	case SPDM_ASYM_RSASSA_4096:
		spdm_state->sig_len = 512;
		spdm_state->base_asym_enc = "pkcs1";
		break;
	case SPDM_ASYM_ECDSA_ECC_NIST_P256:
		spdm_state->sig_len = 64;
		spdm_state->base_asym_enc = "p1363";
		break;
	case SPDM_ASYM_ECDSA_ECC_NIST_P384:
		spdm_state->sig_len = 96;
		spdm_state->base_asym_enc = "p1363";
		break;
	case SPDM_ASYM_ECDSA_ECC_NIST_P521:
		spdm_state->sig_len = 132;
		spdm_state->base_asym_enc = "p1363";
		break;
	default:
		dev_err(spdm_state->dev, "Unknown asym algorithm\n");
		return -EINVAL;
	}

	switch (spdm_state->base_hash_alg) {
	case SPDM_HASH_SHA_256:
		spdm_state->base_hash_alg_name = "sha256";
		break;
	case SPDM_HASH_SHA_384:
		spdm_state->base_hash_alg_name = "sha384";
		break;
	case SPDM_HASH_SHA_512:
		spdm_state->base_hash_alg_name = "sha512";
		break;
	default:
		dev_err(spdm_state->dev, "Unknown hash algorithm\n");
		return -EINVAL;
	}

	/*
	 * shash and desc allocations are reused for subsequent measurement
	 * retrieval, hence are not freed until spdm_reset().
	 */
	spdm_state->shash = crypto_alloc_shash(spdm_state->base_hash_alg_name,
					       0, 0);
	if (!spdm_state->shash)
		return -ENOMEM;

	spdm_state->desc = kzalloc(sizeof(*spdm_state->desc) +
				   crypto_shash_descsize(spdm_state->shash),
				   GFP_KERNEL);
	if (!spdm_state->desc)
		return -ENOMEM;

	spdm_state->desc->tfm = spdm_state->shash;

	/* Used frequently to compute offsets, so cache H */
	spdm_state->hash_len = crypto_shash_digestsize(spdm_state->shash);

	return crypto_shash_init(spdm_state->desc);
}

static int spdm_negotiate_algs(struct spdm_state *spdm_state)
{
	struct spdm_negotiate_algs_req *req = spdm_state->transcript_end;
	struct spdm_negotiate_algs_rsp *rsp;
	struct spdm_req_alg_struct *req_alg_struct;
	size_t req_sz = sizeof(*req);
	size_t rsp_sz = sizeof(*rsp);
	int rc, length;

	/* Request length shall be <= 128 bytes (SPDM 1.1.0 margin no 185) */
	BUILD_BUG_ON(req_sz > 128);

	*req = (struct spdm_negotiate_algs_req) {
		.code = SPDM_NEGOTIATE_ALGS,
		.length = cpu_to_le16(req_sz),
		.base_asym_algo = cpu_to_le32(SPDM_ASYM_ALGOS),
		.base_hash_algo = cpu_to_le32(SPDM_HASH_ALGOS),
	};

	rsp = spdm_state->transcript_end += req_sz;

	rc = spdm_exchange(spdm_state, req, req_sz, rsp, rsp_sz);
	if (rc < 0)
		return rc;

	length = rc;
	if (length < sizeof(*rsp) ||
	    length < sizeof(*rsp) + rsp->param1 * sizeof(*req_alg_struct)) {
		dev_err(spdm_state->dev, "Truncated algorithms response\n");
		return -EIO;
	}

	/*
	 * If request contained a ReqAlgStruct not supported by responder,
	 * the corresponding RespAlgStruct may be omitted in response.
	 * Calculate the actual (possibly shorter) response length:
	 */
	spdm_state->transcript_end +=
		     sizeof(*rsp) + rsp->param1 * sizeof(*req_alg_struct);

	spdm_state->base_asym_alg = le32_to_cpu(rsp->base_asym_sel);
	spdm_state->base_hash_alg = le32_to_cpu(rsp->base_hash_sel);

	if ((spdm_state->base_asym_alg & SPDM_ASYM_ALGOS) == 0 ||
	    (spdm_state->base_hash_alg & SPDM_HASH_ALGOS) == 0) {
		dev_err(spdm_state->dev, "No common supported algorithms\n");
		return -EPROTO;
	}

	/* Responder shall select exactly 1 alg (SPDM 1.0.0 table 14) */
	if (hweight32(spdm_state->base_asym_alg) != 1 ||
	    hweight32(spdm_state->base_hash_alg) != 1 ||
	    rsp->ext_asym_sel_count != 0 ||
	    rsp->ext_hash_sel_count != 0 ||
	    rsp->param1 > req->param1) {
		dev_err(spdm_state->dev, "Malformed algorithms response\n");
		return -EPROTO;
	}

	return spdm_parse_algs(spdm_state);
}

static int spdm_get_digests(struct spdm_state *spdm_state)
{
	struct spdm_get_digests_req *req = spdm_state->transcript_end;
	struct spdm_get_digests_rsp *rsp;
	unsigned long deprovisioned_slots;
	u8 slot, supported_slots;
	int rc, length;
	size_t rsp_sz;

	*req = (struct spdm_get_digests_req) {
		.code = SPDM_GET_DIGESTS,
	};

	rsp = spdm_state->transcript_end += sizeof(*req);

	/*
	 * Assume all 8 slots are populated.  We know the hash length (and thus
	 * the response size) because the responder only returns digests for
	 * the hash algorithm selected during the NEGOTIATE_ALGORITHMS exchange
	 * (SPDM 1.1.2 margin no 206).
	 */
	rsp_sz = sizeof(*rsp) + SPDM_SLOTS * spdm_state->hash_len;

	rc = spdm_exchange(spdm_state, req, sizeof(*req), rsp, rsp_sz);
	if (rc < 0)
		return rc;

	length = rc;
	if (length < sizeof(*rsp) ||
	    length < sizeof(*rsp) + hweight8(rsp->param2) *
				    spdm_state->hash_len) {
		dev_err(spdm_state->dev, "Truncated digests response\n");
		return -EIO;
	}

	spdm_state->transcript_end += sizeof(*rsp) + hweight8(rsp->param2) *
						     spdm_state->hash_len;

	deprovisioned_slots = spdm_state->provisioned_slots & ~rsp->param2;
	for_each_set_bit(slot, &deprovisioned_slots, SPDM_SLOTS) {
		kvfree(spdm_state->slot[slot]);
		spdm_state->slot_sz[slot] = 0;
		spdm_state->slot[slot] = NULL;
	}

	/*
	 * Authentication-capable endpoints must carry at least 1 cert chain
	 * (SPDM 1.0.0 section 4.9.2.1).
	 */
	spdm_state->provisioned_slots = rsp->param2;
	if (!spdm_state->provisioned_slots) {
		dev_err(spdm_state->dev, "No certificates provisioned\n");
		return -EPROTO;
	}

	/*
	 * If a bit is set in ProvisionedSlotMask, the corresponding bit in
	 * SupportedSlotMask shall also be set (SPDM 1.3.0 table 35).
	 */
	if (spdm_state->version >= 0x13 && rsp->param2 & ~rsp->param1) {
		dev_err(spdm_state->dev, "Malformed digests response\n");
		return -EPROTO;
	}

	if (spdm_state->version >= 0x13)
		supported_slots = rsp->param1;
	else
		supported_slots = GENMASK(7, 0);

	if (spdm_state->supported_slots != supported_slots) {
		spdm_state->supported_slots = supported_slots;

		if (device_is_registered(spdm_state->dev)) {
			rc = sysfs_update_group(&spdm_state->dev->kobj,
						&spdm_certificates_group);
			if (rc)
				dev_err(spdm_state->dev,
					"Cannot update certificates in sysfs: "
					"%d\n", rc);
		}
	}

	return 0;
}

static int spdm_get_certificate(struct spdm_state *spdm_state, u8 slot)
{
	struct spdm_cert_chain *certs __free(kvfree) = NULL;
	struct spdm_get_certificate_rsp *rsp __free(kvfree);
	struct spdm_get_certificate_req req = {
		.code = SPDM_GET_CERTIFICATE,
		.param1 = slot,
	};
	size_t rsp_sz, total_length, header_length;
	u16 remainder_length = 0xffff;
	u16 portion_length;
	u16 offset = 0;
	int rc, length;

	/*
	 * It is legal for the responder to send more bytes than requested.
	 * (Note the "should" in SPDM 1.0.0 table 19.)  If we allocate a
	 * too small buffer, we can't calculate the hash over the (truncated)
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
		 * chain (SPDM 1.0.0 table 18).
		 */
		req.offset = cpu_to_le16(offset);
		req.length = cpu_to_le16(min_t(size_t, remainder_length,
					       rsp_sz - sizeof(*rsp)));

		rc = spdm_exchange(spdm_state, &req, sizeof(req), rsp, rsp_sz);
		if (rc < 0)
			return rc;

		length = rc;
		if (length < sizeof(*rsp) ||
		    length < sizeof(*rsp) + le16_to_cpu(rsp->portion_length)) {
			dev_err(spdm_state->dev,
				"Truncated certificate response\n");
			return -EIO;
		}

		portion_length = le16_to_cpu(rsp->portion_length);
		remainder_length = le16_to_cpu(rsp->remainder_length);

		rc = spdm_append_transcript(spdm_state, &req, sizeof(req));
		if (rc)
			return rc;

		rc = spdm_append_transcript(spdm_state, rsp,
					    sizeof(*rsp) + portion_length);
		if (rc)
			return rc;

		/*
		 * On first response we learn total length of cert chain.
		 * Should portion_length + remainder_length exceed 0xffff,
		 * the min() ensures that the malformed check triggers below.
		 */
		if (!certs) {
			total_length = min(portion_length + remainder_length,
					   0xffff);
			certs = kvmalloc(total_length, GFP_KERNEL);
			if (!certs)
				return -ENOMEM;
		}

		if (!portion_length ||
		    (rsp->param1 & 0xf) != slot ||
		    offset + portion_length + remainder_length != total_length)
		{
			dev_err(spdm_state->dev,
				"Malformed certificate response\n");
			return -EPROTO;
		}

		memcpy((u8 *)certs + offset, rsp->cert_chain, portion_length);
		offset += portion_length;
	} while (remainder_length > 0);

	header_length = sizeof(struct spdm_cert_chain) + spdm_state->hash_len;

	if (total_length < header_length ||
	    total_length != le16_to_cpu(certs->length)) {
		dev_err(spdm_state->dev,
			"Malformed certificate chain in slot %u\n", slot);
		return -EPROTO;
	}

	kvfree(spdm_state->slot[slot]);
	spdm_state->slot_sz[slot] = total_length;
	spdm_state->slot[slot] = no_free_ptr(certs);

	return 0;
}

static int spdm_validate_cert_chain(struct spdm_state *spdm_state, u8 slot)
{
	struct x509_certificate *cert __free(x509_free_certificate) = NULL;
	struct x509_certificate *prev __free(x509_free_certificate) = NULL;
	size_t header_length, total_length;
	bool is_leaf_cert;
	size_t offset = 0;
	struct key *key;
	int rc, length;
	u8 *certs;

	header_length = sizeof(struct spdm_cert_chain) + spdm_state->hash_len;
	total_length = spdm_state->slot_sz[slot] - header_length;
	certs = (u8 *)spdm_state->slot[slot] + header_length;

	do {
		rc = x509_get_certificate_length(certs + offset,
						 total_length - offset);
		if (rc < 0) {
			dev_err(spdm_state->dev, "Invalid certificate length "
				"at slot %u offset %zu\n", slot, offset);
			return rc;
		}

		length = rc;
		is_leaf_cert = offset + length == total_length;

		cert = x509_cert_parse(certs + offset, length);
		if (IS_ERR(cert)) {
			dev_err(spdm_state->dev, "Certificate parse error %pe "
				"at slot %u offset %zu\n", cert, slot, offset);
			return PTR_ERR(cert);
		}
		if (cert->unsupported_sig) {
			dev_err(spdm_state->dev, "Unsupported signature "
				"at slot %u offset %zu\n", slot, offset);
			return -EKEYREJECTED;
		}
		if (cert->blacklisted)
			return -EKEYREJECTED;

		/*
		 * Basic Constraints CA value shall be false for leaf cert,
		 * true for intermediate and root certs (SPDM 1.3.0 table 42).
		 * Key Usage bit for digital signature shall be set, except
		 * for GenericCert in slot > 0 (SPDM 1.3.0 margin no 354).
		 * KeyCertSign bit must be 0 for non-CA (RFC 5280 sec 4.2.1.9).
		 */
		if ((is_leaf_cert ==
		     test_bit(KEY_EFLAG_CA, &cert->pub->key_eflags)) ||
		    (is_leaf_cert && slot == 0 &&
		     !test_bit(KEY_EFLAG_DIGITALSIG, &cert->pub->key_eflags)) ||
		    (is_leaf_cert &&
		     test_bit(KEY_EFLAG_KEYCERTSIGN, &cert->pub->key_eflags))) {
			dev_err(spdm_state->dev, "Malformed certificate "
				"at slot %u offset %zu\n", slot, offset);
			return -EKEYREJECTED;
		}

		if (!prev) {
			/* First cert in chain, check against root_keyring */
			key = find_asymmetric_key(spdm_state->root_keyring,
						  cert->sig->auth_ids[0],
						  cert->sig->auth_ids[1],
						  cert->sig->auth_ids[2],
						  false);
			if (IS_ERR(key)) {
				dev_info(spdm_state->dev, "Root certificate "
					 "of slot %u not found in %s "
					 "keyring: %s\n", slot,
					 spdm_state->root_keyring->description,
					 cert->issuer);
				return PTR_ERR(key);
			}

			rc = verify_signature(key, cert->sig);
			key_put(key);
		} else {
			/* Subsequent cert in chain, check against previous */
			rc = public_key_verify_signature(prev->pub, cert->sig);
		}

		if (rc) {
			dev_err(spdm_state->dev, "Signature validation error "
				"%d at slot %u offset %zu\n", rc, slot, offset);
			return rc;
		}

		x509_free_certificate(prev);
		prev = cert;
		cert = ERR_PTR(-ENOKEY);

		offset += length;
	} while (offset < total_length);

	if (spdm_state->validate) {
		rc = spdm_state->validate(spdm_state->dev, slot, prev);
		if (rc)
			return rc;
	}

	/* Steal pub pointer ahead of x509_free_certificate() */
	spdm_state->leaf_key = prev->pub;
	prev->pub = NULL;

	return 0;
}

/**
 * spdm_challenge_rsp_sz() - Calculate CHALLENGE_AUTH response size
 *
 * @spdm_state: SPDM session state
 * @rsp: CHALLENGE_AUTH response (optional)
 *
 * A CHALLENGE_AUTH response contains multiple variable-length fields
 * as well as optional fields.  This helper eases calculating its size.
 *
 * If @rsp is %NULL, assume the maximum OpaqueDataLength of 1024 bytes
 * (SPDM 1.0.0 table 21).  Otherwise read OpaqueDataLength from @rsp.
 * OpaqueDataLength can only be > 0 for SPDM 1.0 and 1.1, as they lack
 * the OtherParamsSupport field in the NEGOTIATE_ALGORITHMS request.
 * For SPDM 1.2+, we do not offer any Opaque Data Formats in that field,
 * which forces OpaqueDataLength to 0 (SPDM 1.2.0 margin no 261).
 */
static size_t spdm_challenge_rsp_sz(struct spdm_state *spdm_state,
				    struct spdm_challenge_rsp *rsp)
{
	size_t  size  = sizeof(*rsp)		/* Header */
		      + spdm_state->hash_len	/* CertChainHash */
		      + SPDM_NONCE_SZ;		/* Nonce */

	if (rsp)
		/* May be unaligned if hash algorithm has odd length */
		size += get_unaligned_le16((u8 *)rsp + size);
	else
		size += SPDM_MAX_OPAQUE_DATA;	/* OpaqueData */

	size += 2;				/* OpaqueDataLength */

	if (spdm_state->version >= 0x13)
		size += 8;			/* RequesterContext */

	return  size  + spdm_state->sig_len;	/* Signature */
}

static int spdm_challenge(struct spdm_state *spdm_state, u8 slot)
{
	struct spdm_challenge_rsp *rsp __free(kfree);
	struct spdm_challenge_req req = {
		.code = SPDM_CHALLENGE,
		.param1 = slot,
		.param2 = 0, /* No measurement summary hash */
	};
	size_t req_sz, rsp_sz, rsp_sz_max;
	int rc, length;

	get_random_bytes(&req.nonce, sizeof(req.nonce));

	if (spdm_state->version <= 0x12)
		req_sz = offsetofend(typeof(req), nonce);
	else
		req_sz = sizeof(req);

	rsp_sz_max = spdm_challenge_rsp_sz(spdm_state, NULL);
	rsp = kzalloc(rsp_sz_max, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	rc = spdm_exchange(spdm_state, &req, req_sz, rsp, rsp_sz_max);
	if (rc < 0)
		return rc;

	length = rc;
	rsp_sz = spdm_challenge_rsp_sz(spdm_state, rsp);
	if (length < rsp_sz) {
		dev_err(spdm_state->dev, "Truncated challenge_auth response\n");
		return -EIO;
	}

	rc = spdm_append_transcript(spdm_state, &req, req_sz);
	if (rc)
		return rc;

	rc = spdm_append_transcript(spdm_state, rsp, rsp_sz);
	if (rc)
		return rc;

	/* Verify signature at end of transcript against leaf key */
	rc = spdm_verify_signature(spdm_state, spdm_context);
	if (rc)
		dev_err(spdm_state->dev,
			"Cannot verify challenge_auth signature: %d\n", rc);
	else
		dev_info(spdm_state->dev,
			 "Authenticated with certificate slot %u\n", slot);

	return rc;
}

/**
 * spdm_authenticate() - Authenticate device
 *
 * @spdm_state: SPDM session state
 *
 * Authenticate a device through a sequence of GET_VERSION, GET_CAPABILITIES,
 * NEGOTIATE_ALGORITHMS, GET_DIGESTS, GET_CERTIFICATE and CHALLENGE exchanges.
 *
 * Perform internal locking to serialize multiple concurrent invocations.
 * Can be called repeatedly for reauthentication.
 *
 * Return 0 on success or a negative errno.  In particular, -EPROTONOSUPPORT
 * indicates authentication is not supported by the device.
 */
int spdm_authenticate(struct spdm_state *spdm_state)
{
	u8 slot;
	int rc;

	mutex_lock(&spdm_state->lock);
	spdm_reset(spdm_state);

	rc = spdm_alloc_transcript(spdm_state);
	if (rc)
		goto unlock;

	rc = spdm_get_version(spdm_state);
	if (rc)
		goto unlock;

	rc = spdm_get_capabilities(spdm_state);
	if (rc)
		goto unlock;

	rc = spdm_negotiate_algs(spdm_state);
	if (rc)
		goto unlock;

	rc = spdm_get_digests(spdm_state);
	if (rc)
		goto unlock;

	for_each_set_bit(slot, &spdm_state->provisioned_slots, SPDM_SLOTS) {
		rc = spdm_get_certificate(spdm_state, slot);
		if (rc)
			goto unlock;
	}

	for_each_set_bit(slot, &spdm_state->provisioned_slots, SPDM_SLOTS) {
		rc = spdm_validate_cert_chain(spdm_state, slot);
		if (rc == 0)
			break;
	}
	if (rc)
		goto unlock;

	rc = spdm_challenge(spdm_state, slot);

unlock:
	if (rc)
		spdm_reset(spdm_state);
	spdm_state->authenticated = !rc;
	spdm_free_transcript(spdm_state);
	mutex_unlock(&spdm_state->lock);
	return rc;
}
EXPORT_SYMBOL_GPL(spdm_authenticate);
