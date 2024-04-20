// SPDX-License-Identifier: GPL-2.0
/*
 * DMTF Security Protocol and Data Model (SPDM)
 * https://www.dmtf.org/dsp/DSP0274
 *
 * Core routines for message exchange, message transcript,
 * signature verification and session state lifecycle
 *
 * Copyright (C) 2021-22 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022-24 Intel Corporation
 */

#include "spdm.h"

#include <linux/dev_printk.h>
#include <linux/module.h>

#include <crypto/hash.h>
#include <crypto/public_key.h>

LIST_HEAD(spdm_state_list); /* list of all struct spdm_state */
DEFINE_MUTEX(spdm_state_mutex); /* protects spdm_state_list */

static int spdm_err(struct device *dev, struct spdm_error_rsp *rsp)
{
	switch (rsp->error_code) {
	case SPDM_INVALID_REQUEST:
		dev_err(dev, "Invalid request\n");
		return -EINVAL;
	case SPDM_INVALID_SESSION:
		if (rsp->version == 0x11) {
			dev_err(dev, "Invalid session %#x\n", rsp->error_data);
			return -EINVAL;
		}
		break;
	case SPDM_BUSY:
		dev_err(dev, "Busy\n");
		return -EBUSY;
	case SPDM_UNEXPECTED_REQUEST:
		dev_err(dev, "Unexpected request\n");
		return -EINVAL;
	case SPDM_UNSPECIFIED:
		dev_err(dev, "Unspecified error\n");
		return -EINVAL;
	case SPDM_DECRYPT_ERROR:
		dev_err(dev, "Decrypt error\n");
		return -EIO;
	case SPDM_UNSUPPORTED_REQUEST:
		dev_err(dev, "Unsupported request %#x\n", rsp->error_data);
		return -EINVAL;
	case SPDM_REQUEST_IN_FLIGHT:
		dev_err(dev, "Request in flight\n");
		return -EINVAL;
	case SPDM_INVALID_RESPONSE_CODE:
		dev_err(dev, "Invalid response code\n");
		return -EINVAL;
	case SPDM_SESSION_LIMIT_EXCEEDED:
		dev_err(dev, "Session limit exceeded\n");
		return -EBUSY;
	case SPDM_SESSION_REQUIRED:
		dev_err(dev, "Session required\n");
		return -EINVAL;
	case SPDM_RESET_REQUIRED:
		dev_err(dev, "Reset required\n");
		return -ECONNRESET;
	case SPDM_RESPONSE_TOO_LARGE:
		dev_err(dev, "Response too large\n");
		return -EINVAL;
	case SPDM_REQUEST_TOO_LARGE:
		dev_err(dev, "Request too large\n");
		return -EINVAL;
	case SPDM_LARGE_RESPONSE:
		dev_err(dev, "Large response\n");
		return -EMSGSIZE;
	case SPDM_MESSAGE_LOST:
		dev_err(dev, "Message lost\n");
		return -EIO;
	case SPDM_INVALID_POLICY:
		dev_err(dev, "Invalid policy\n");
		return -EINVAL;
	case SPDM_VERSION_MISMATCH:
		dev_err(dev, "Version mismatch\n");
		return -EINVAL;
	case SPDM_RESPONSE_NOT_READY:
		dev_err(dev, "Response not ready\n");
		return -EINPROGRESS;
	case SPDM_REQUEST_RESYNCH:
		dev_err(dev, "Request resynchronization\n");
		return -ECONNRESET;
	case SPDM_OPERATION_FAILED:
		dev_err(dev, "Operation failed\n");
		return -EINVAL;
	case SPDM_NO_PENDING_REQUESTS:
		return -ENOENT;
	case SPDM_VENDOR_DEFINED_ERROR:
		dev_err(dev, "Vendor defined error\n");
		return -EINVAL;
	}

	dev_err(dev, "Undefined error %#x\n", rsp->error_code);
	return -EINVAL;
}

/**
 * spdm_exchange() - Perform SPDM message exchange with device
 *
 * @spdm_state: SPDM session state
 * @req: Request message
 * @req_sz: Size of @req
 * @rsp: Response message
 * @rsp_sz: Size of @rsp
 *
 * Send the request @req to the device via the @transport in @spdm_state and
 * receive the response into @rsp, respecting the maximum buffer size @rsp_sz.
 * The request version is automatically populated.
 *
 * Return response size on success or a negative errno.  Response size may be
 * less than @rsp_sz and the caller is responsible for checking that.  It may
 * also be more than expected (though never more than @rsp_sz), e.g. if the
 * transport receives only dword-sized chunks.
 */
ssize_t spdm_exchange(struct spdm_state *spdm_state,
		      void *req, size_t req_sz, void *rsp, size_t rsp_sz)
{
	struct spdm_header *request = req;
	struct spdm_header *response = rsp;
	ssize_t rc, length;

	if (req_sz < sizeof(struct spdm_header) ||
	    rsp_sz < sizeof(struct spdm_header))
		return -EINVAL;

	request->version = spdm_state->version;

	rc = spdm_state->transport(spdm_state->transport_priv, spdm_state->dev,
				   req, req_sz, rsp, rsp_sz);
	if (rc < 0)
		return rc;

	length = rc;
	if (length < sizeof(struct spdm_header))
		return length; /* Truncated response is handled by callers */

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

/**
 * spdm_alloc_transcript() - Allocate transcript buffer
 *
 * @spdm_state: SPDM session state
 *
 * Allocate a buffer to accommodate the concatenation of all SPDM messages
 * exchanged during an authentication sequence.  Used to verify the signature,
 * as it is computed over the hashed transcript.
 *
 * Transcript size is initially one page.  It grows by additional pages as
 * needed.  Minimum size of an authentication sequence is 1k (only one slot
 * occupied, only one ECC P256 certificate in chain, SHA 256 hash selected).
 * Maximum can be several MBytes.  Between 4k and 64k is probably typical.
 *
 * Return 0 on success or a negative errno.
 */
int spdm_alloc_transcript(struct spdm_state *spdm_state)
{
	spdm_state->transcript = kvmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!spdm_state->transcript)
		return -ENOMEM;

	spdm_state->transcript_end = spdm_state->transcript;
	spdm_state->transcript_max = PAGE_SIZE;

	return 0;
}

/**
 * spdm_free_transcript() - Free transcript buffer
 *
 * @spdm_state: SPDM session state
 *
 * Free the transcript buffer after performing authentication.  Reset the
 * pointer to the current end of transcript as well as the allocation size.
 */
void spdm_free_transcript(struct spdm_state *spdm_state)
{
	kvfree(spdm_state->transcript);
	spdm_state->transcript_end = NULL;
	spdm_state->transcript_max = 0;
}

/**
 * spdm_append_transcript() - Append a message to transcript buffer
 *
 * @spdm_state: SPDM session state
 * @msg: SPDM message
 * @msg_sz: Size of @msg
 *
 * Append an SPDM message to the transcript after reception or transmission.
 * Reallocate a larger transcript buffer if the message exceeds its current
 * allocation size.
 *
 * If the message to be appended is known to fit into the allocation size,
 * it may be directly received into or transmitted from the transcript buffer
 * instead of calling this function:  Simply use the @transcript_end pointer in
 * struct spdm_state as the position to store the message, then advance the
 * pointer by the message size.
 *
 * Return 0 on success or a negative errno.
 */
int spdm_append_transcript(struct spdm_state *spdm_state,
			   const void *msg, size_t msg_sz)
{
	size_t transcript_sz = spdm_state->transcript_end -
			       spdm_state->transcript;

	if (transcript_sz + msg_sz > spdm_state->transcript_max) {
		size_t new_sz = round_up(transcript_sz + msg_sz, PAGE_SIZE);
		void *new = kvrealloc(spdm_state->transcript,
				      new_sz, GFP_KERNEL);
		if (!new)
			return -ENOMEM;

		spdm_state->transcript = new;
		spdm_state->transcript_end = new + transcript_sz;
		spdm_state->transcript_max = new_sz;
	}

	memcpy(spdm_state->transcript_end, msg, msg_sz);
	spdm_state->transcript_end += msg_sz;

	return 0;
}

/**
 * spdm_create_combined_prefix() - Create combined_spdm_prefix for a hash
 *
 * @version: SPDM version negotiated during GET_VERSION exchange
 * @spdm_context: SPDM context of signature generation (or verification)
 * @buf: Buffer to receive combined_spdm_prefix (100 bytes)
 *
 * From SPDM 1.2, a hash is prefixed with the SPDM version and context before
 * a signature is generated (or verified) over the resulting concatenation
 * (SPDM 1.2.0 section 15).  Create that prefix.
 */
void spdm_create_combined_prefix(u8 version, const char *spdm_context,
				 void *buf)
{
	u8 major = FIELD_GET(0xf0, version);
	u8 minor = FIELD_GET(0x0f, version);
	size_t len = strlen(spdm_context);
	int rc, zero_pad;

	rc = snprintf(buf, SPDM_PREFIX_SZ + 1,
		      "dmtf-spdm-v%hhx.%hhx.*dmtf-spdm-v%hhx.%hhx.*"
		      "dmtf-spdm-v%hhx.%hhx.*dmtf-spdm-v%hhx.%hhx.*",
		      major, minor, major, minor, major, minor, major, minor);
	WARN_ON(rc != SPDM_PREFIX_SZ);

	zero_pad = SPDM_COMBINED_PREFIX_SZ - SPDM_PREFIX_SZ - 1 - len;
	WARN_ON(zero_pad < 0);

	memset(buf + SPDM_PREFIX_SZ + 1, 0, zero_pad);
	memcpy(buf + SPDM_PREFIX_SZ + 1 + zero_pad, spdm_context, len);
}

/**
 * spdm_verify_signature() - Verify signature against leaf key
 *
 * @spdm_state: SPDM session state
 * @spdm_context: SPDM context (used to create combined_spdm_prefix)
 *
 * Implementation of the abstract SPDMSignatureVerify() function described in
 * SPDM 1.2.0 section 16:  Compute the hash over @spdm_state->transcript and
 * verify that the signature at the end of the transcript was generated by
 * @spdm_state->leaf_key.  Hashing the entire transcript allows detection
 * of message modification by a man-in-the-middle or media error.
 *
 * Return 0 on success or a negative errno.
 */
int spdm_verify_signature(struct spdm_state *spdm_state,
			  const char *spdm_context)
{
	struct public_key_signature sig = {
		.s = spdm_state->transcript_end - spdm_state->sig_len,
		.s_size = spdm_state->sig_len,
		.encoding = spdm_state->base_asym_enc,
		.hash_algo = spdm_state->base_hash_alg_name,
	};
	u8 *mhash __free(kfree) = NULL;
	u8 *m __free(kfree);
	int rc;

	m = kmalloc(SPDM_COMBINED_PREFIX_SZ + spdm_state->hash_len, GFP_KERNEL);
	if (!m)
		return -ENOMEM;

	/* Hash the transcript (sans trailing signature) */
	rc = crypto_shash_digest(spdm_state->desc, spdm_state->transcript,
				 (void *)sig.s - spdm_state->transcript,
				 m + SPDM_COMBINED_PREFIX_SZ);
	if (rc)
		return rc;

	if (spdm_state->version <= 0x11) {
		/*
		 * SPDM 1.0 and 1.1 compute the signature only over the hash
		 * (SPDM 1.0.0 section 4.9.2.7).
		 */
		sig.digest = m + SPDM_COMBINED_PREFIX_SZ;
		sig.digest_size = spdm_state->hash_len;
	} else {
		/*
		 * From SPDM 1.2, the hash is prefixed with spdm_context before
		 * computing the signature over the resulting message M
		 * (SPDM 1.2.0 sec 15).
		 */
		spdm_create_combined_prefix(spdm_state->version, spdm_context,
					    m);

		/*
		 * RSA and ECDSA algorithms require that M is hashed once more.
		 * EdDSA and SM2 algorithms omit that step.
		 * The switch statement prepares for their introduction.
		 */
		switch (spdm_state->base_asym_alg) {
		default:
			mhash = kmalloc(spdm_state->hash_len, GFP_KERNEL);
			if (!mhash)
				return -ENOMEM;

			rc = crypto_shash_digest(spdm_state->desc, m,
				SPDM_COMBINED_PREFIX_SZ + spdm_state->hash_len,
				mhash);
			if (rc)
				return rc;

			sig.digest = mhash;
			sig.digest_size = spdm_state->hash_len;
			break;
		}
	}

	return public_key_verify_signature(spdm_state->leaf_key, &sig);
}

/**
 * spdm_reset() - Free cryptographic data structures
 *
 * @spdm_state: SPDM session state
 *
 * Free cryptographic data structures when an SPDM session is destroyed or
 * when the device is reauthenticated.
 */
void spdm_reset(struct spdm_state *spdm_state)
{
	public_key_free(spdm_state->leaf_key);
	spdm_state->leaf_key = NULL;

	kfree(spdm_state->desc);
	spdm_state->desc = NULL;

	crypto_free_shash(spdm_state->shash);
	spdm_state->shash = NULL;
}

/**
 * spdm_create() - Allocate SPDM session
 *
 * @dev: Responder device
 * @transport: Transport function to perform one message exchange
 * @transport_priv: Transport private data
 * @transport_sz: Maximum message size the transport is capable of (in bytes)
 * @keyring: Trusted root certificates
 * @validate: Function to validate additional leaf certificate requirements
 *	(optional, may be %NULL)
 *
 * Return a pointer to the allocated SPDM session state or NULL on error.
 */
struct spdm_state *spdm_create(struct device *dev, spdm_transport *transport,
			       void *transport_priv, u32 transport_sz,
			       struct key *keyring, spdm_validate *validate)
{
	struct spdm_state *spdm_state = kzalloc(sizeof(*spdm_state), GFP_KERNEL);

	if (!spdm_state)
		return NULL;

	spdm_state->dev = dev;
	spdm_state->transport = transport;
	spdm_state->transport_priv = transport_priv;
	spdm_state->transport_sz = transport_sz;
	spdm_state->root_keyring = keyring;
	spdm_state->validate = validate;

	mutex_init(&spdm_state->lock);
	INIT_LIST_HEAD(&spdm_state->log);

	mutex_lock(&spdm_state_mutex);
	list_add_tail(&spdm_state->list, &spdm_state_list);
	mutex_unlock(&spdm_state_mutex);

	return spdm_state;
}
EXPORT_SYMBOL_GPL(spdm_create);

/**
 * spdm_destroy() - Destroy SPDM session
 *
 * @spdm_state: SPDM session state
 */
void spdm_destroy(struct spdm_state *spdm_state)
{
	u8 slot;

	mutex_lock(&spdm_state_mutex);
	list_del(&spdm_state->list);
	mutex_unlock(&spdm_state_mutex);

	for_each_set_bit(slot, &spdm_state->provisioned_slots, SPDM_SLOTS)
		kvfree(spdm_state->slot[slot]);

	spdm_reset(spdm_state);
	spdm_destroy_log(spdm_state);
	mutex_destroy(&spdm_state->lock);
	kfree(spdm_state->next_nonce);
	kfree(spdm_state);
}
EXPORT_SYMBOL_GPL(spdm_destroy);

MODULE_DESCRIPTION("DMTF Security Protocol and Data Model");
MODULE_LICENSE("GPL");
