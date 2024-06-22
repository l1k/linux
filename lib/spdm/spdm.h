/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DMTF Security Protocol and Data Model (SPDM)
 * https://www.dmtf.org/dsp/DSP0274
 *
 * Copyright (C) 2021-22 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022-24 Intel Corporation
 */

#ifndef _LIB_SPDM_H_
#define _LIB_SPDM_H_

#undef  DEFAULT_SYMBOL_NAMESPACE
#define DEFAULT_SYMBOL_NAMESPACE "SPDM"

#define dev_fmt(fmt) "SPDM: " fmt

#include <linux/bitfield.h>
#include <linux/mutex.h>
#include <linux/spdm.h>

/* SPDM versions supported by this implementation */
#define SPDM_MIN_VER 0x10
#define SPDM_MAX_VER 0x13

/* SPDM capabilities (SPDM 1.1.0 margin no 177, 178) */
#define SPDM_CACHE_CAP			BIT(0)		/* 1.0 resp only */
#define SPDM_CERT_CAP			BIT(1)		/* 1.0 */
#define SPDM_CHAL_CAP			BIT(2)		/* 1.0 */
#define SPDM_MEAS_CAP_MASK		GENMASK(4, 3)	/* 1.0 resp only */
#define   SPDM_MEAS_CAP_NO		0		/* 1.0 resp only */
#define   SPDM_MEAS_CAP_MEAS		1		/* 1.0 resp only */
#define   SPDM_MEAS_CAP_MEAS_SIG	2		/* 1.0 resp only */
#define SPDM_MEAS_FRESH_CAP		BIT(5)		/* 1.0 resp only */
#define SPDM_ENCRYPT_CAP		BIT(6)		/* 1.1 */
#define SPDM_MAC_CAP			BIT(7)		/* 1.1 */
#define SPDM_MUT_AUTH_CAP		BIT(8)		/* 1.1 */
#define SPDM_KEY_EX_CAP			BIT(9)		/* 1.1 */
#define SPDM_PSK_CAP_MASK		GENMASK(11, 10)	/* 1.1 */
#define   SPDM_PSK_CAP_NO		0		/* 1.1 */
#define   SPDM_PSK_CAP_PSK		1		/* 1.1 */
#define   SPDM_PSK_CAP_PSK_CTX		2		/* 1.1 resp only */
#define SPDM_ENCAP_CAP			BIT(12)		/* 1.1 */
#define SPDM_HBEAT_CAP			BIT(13)		/* 1.1 */
#define SPDM_KEY_UPD_CAP		BIT(14)		/* 1.1 */
#define SPDM_HANDSHAKE_ITC_CAP		BIT(15)		/* 1.1 */
#define SPDM_PUB_KEY_ID_CAP		BIT(16)		/* 1.1 */
#define SPDM_CHUNK_CAP			BIT(17)		/* 1.2 */
#define SPDM_ALIAS_CERT_CAP		BIT(18)		/* 1.2 resp only */
#define SPDM_SET_CERT_CAP		BIT(19)		/* 1.2 resp only */
#define SPDM_CSR_CAP			BIT(20)		/* 1.2 resp only */
#define SPDM_CERT_INST_RESET_CAP	BIT(21)		/* 1.2 resp only */
#define SPDM_EP_INFO_CAP_MASK		GENMASK(23, 22) /* 1.3 */
#define   SPDM_EP_INFO_CAP_NO		0		/* 1.3 */
#define   SPDM_EP_INFO_CAP_RSP		1		/* 1.3 */
#define   SPDM_EP_INFO_CAP_RSP_SIG	2		/* 1.3 */
#define SPDM_MEL_CAP			BIT(24)		/* 1.3 resp only */
#define SPDM_EVENT_CAP			BIT(25)		/* 1.3 */
#define SPDM_MULTI_KEY_CAP_MASK		GENMASK(27, 26)	/* 1.3 */
#define   SPDM_MULTI_KEY_CAP_NO		0		/* 1.3 */
#define   SPDM_MULTI_KEY_CAP_ONLY	1		/* 1.3 */
#define   SPDM_MULTI_KEY_CAP_SEL	2		/* 1.3 */
#define SPDM_GET_KEY_PAIR_INFO_CAP	BIT(28)		/* 1.3 resp only */
#define SPDM_SET_KEY_PAIR_INFO_CAP	BIT(29)		/* 1.3 resp only */

/* SPDM capabilities supported by this implementation */
#define SPDM_REQ_CAPS			(SPDM_CERT_CAP | SPDM_CHAL_CAP)

/* SPDM capabilities required from responders */
#define SPDM_RSP_MIN_CAPS		(SPDM_CERT_CAP | SPDM_CHAL_CAP)

/*
 * SPDM cryptographic timeout of this implementation:
 * Assume calculations may take up to 1 sec on a busy machine, which equals
 * roughly 1 << 20.  That's within the limits mandated for responders by CMA
 * (1 << 23 usec, PCIe r6.2 sec 6.31.3) and DOE (1 sec, PCIe r6.2 sec 6.30.2).
 * Used in GET_CAPABILITIES exchange.
 */
#define SPDM_CTEXPONENT			20

/* SPDM asymmetric key signature algorithms (SPDM 1.0.0 table 13) */
#define SPDM_ASYM_RSASSA_2048		BIT(0)		/* 1.0 */
#define SPDM_ASYM_RSAPSS_2048		BIT(1)		/* 1.0 */
#define SPDM_ASYM_RSASSA_3072		BIT(2)		/* 1.0 */
#define SPDM_ASYM_RSAPSS_3072		BIT(3)		/* 1.0 */
#define SPDM_ASYM_ECDSA_ECC_NIST_P256	BIT(4)		/* 1.0 */
#define SPDM_ASYM_RSASSA_4096		BIT(5)		/* 1.0 */
#define SPDM_ASYM_RSAPSS_4096		BIT(6)		/* 1.0 */
#define SPDM_ASYM_ECDSA_ECC_NIST_P384	BIT(7)		/* 1.0 */
#define SPDM_ASYM_ECDSA_ECC_NIST_P521	BIT(8)		/* 1.0 */
#define SPDM_ASYM_SM2_ECC_SM2_P256	BIT(9)		/* 1.2 */
#define SPDM_ASYM_EDDSA_ED25519		BIT(10)		/* 1.2 */
#define SPDM_ASYM_EDDSA_ED448		BIT(11)		/* 1.2 */

/* SPDM hash algorithms (SPDM 1.0.0 table 13) */
#define SPDM_HASH_SHA_256		BIT(0)		/* 1.0 */
#define SPDM_HASH_SHA_384		BIT(1)		/* 1.0 */
#define SPDM_HASH_SHA_512		BIT(2)		/* 1.0 */
#define SPDM_HASH_SHA3_256		BIT(3)		/* 1.0 */
#define SPDM_HASH_SHA3_384		BIT(4)		/* 1.0 */
#define SPDM_HASH_SHA3_512		BIT(5)		/* 1.0 */
#define SPDM_HASH_SM3_256		BIT(6)		/* 1.2 */

#if IS_ENABLED(CONFIG_CRYPTO_RSA)
#define SPDM_ASYM_RSA			SPDM_ASYM_RSASSA_2048 |		\
					SPDM_ASYM_RSASSA_3072 |		\
					SPDM_ASYM_RSASSA_4096
#else
#define SPDM_ASYM_RSA			0
#endif

#if IS_ENABLED(CONFIG_CRYPTO_ECDSA)
#define SPDM_ASYM_ECDSA			SPDM_ASYM_ECDSA_ECC_NIST_P256 |	\
					SPDM_ASYM_ECDSA_ECC_NIST_P384 | \
					SPDM_ASYM_ECDSA_ECC_NIST_P521
#else
#define SPDM_ASYM_ECDSA			0
#endif

#if IS_ENABLED(CONFIG_CRYPTO_SHA256)
#define SPDM_HASH_SHA2_256		SPDM_HASH_SHA_256
#else
#define SPDM_HASH_SHA2_256		0
#endif

#if IS_ENABLED(CONFIG_CRYPTO_SHA512)
#define SPDM_HASH_SHA2_384_512		SPDM_HASH_SHA_384 |		\
					SPDM_HASH_SHA_512
#else
#define SPDM_HASH_SHA2_384_512		0
#endif

/* SPDM algorithms supported by this implementation */
#define SPDM_ASYM_ALGOS		       (SPDM_ASYM_RSA |			\
					SPDM_ASYM_ECDSA)

#define SPDM_HASH_ALGOS		       (SPDM_HASH_SHA2_256 |		\
					SPDM_HASH_SHA2_384_512)

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

#define SPDM_REQ	 0x80
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
	__le16 version_number_entries[] __counted_by(version_number_entry_count);
} __packed;

#define SPDM_GET_CAPABILITIES 0xe1
#define SPDM_MIN_DATA_TRANSFER_SIZE 42 /* SPDM 1.2.0 margin no 226 */

/*
 * Newer SPDM versions insert fields at the end of messages (enlarging them)
 * or use reserved space for new fields (leaving message size unchanged).
 */
struct spdm_get_capabilities_req {
	u8 version;
	u8 code;
	u8 param1;
	u8 param2;
	/* End of SPDM 1.0 structure */

	u8 reserved1;					/* 1.1 */
	u8 ctexponent;					/* 1.1 */
	u16 reserved2;					/* 1.1 */
	__le32 flags;					/* 1.1 */
	/* End of SPDM 1.1 structure */

	__le32 data_transfer_size;			/* 1.2 */
	__le32 max_spdm_msg_size;			/* 1.2 */
} __packed;

struct spdm_get_capabilities_rsp {
	u8 version;
	u8 code;
	u8 param1;
	u8 param2;

	u8 reserved1;
	u8 ctexponent;
	u16 reserved2;
	__le32 flags;
	/* End of SPDM 1.0 structure */

	__le32 data_transfer_size;			/* 1.2 */
	__le32 max_spdm_msg_size;			/* 1.2 */
	/* End of SPDM 1.2 structure */

	/*
	 * Additional optional fields at end of this structure:
	 * - SupportedAlgorithms: variable size		 * 1.3 *
	 */
} __packed;

#define SPDM_NEGOTIATE_ALGS 0xe3

struct spdm_negotiate_algs_req {
	u8 version;
	u8 code;
	u8 param1; /* Number of ReqAlgStruct entries at end */
	u8 param2;

	__le16 length;
	u8 measurement_specification;
	u8 other_params_support;			/* 1.2 */

	__le32 base_asym_algo;
	__le32 base_hash_algo;

	u8 reserved1[12];
	u8 ext_asym_count;
	u8 ext_hash_count;
	u8 reserved2;
	u8 mel_specification;				/* 1.3 */

	/*
	 * Additional optional fields at end of this structure:
	 * - ExtAsym: 4 bytes * ext_asym_count
	 * - ExtHash: 4 bytes * ext_hash_count
	 * - ReqAlgStruct: variable size * param1	 * 1.1 *
	 */
} __packed;

struct spdm_negotiate_algs_rsp {
	u8 version;
	u8 code;
	u8 param1; /* Number of RespAlgStruct entries at end */
	u8 param2;

	__le16 length;
	u8 measurement_specification_sel;
	u8 other_params_sel;				/* 1.2 */

	__le32 measurement_hash_algo;
	__le32 base_asym_sel;
	__le32 base_hash_sel;

	u8 reserved1[11];
	u8 mel_specification_sel;			/* 1.3 */
	u8 ext_asym_sel_count; /* Either 0 or 1 */
	u8 ext_hash_sel_count; /* Either 0 or 1 */
	u8 reserved2[2];

	/*
	 * Additional optional fields at end of this structure:
	 * - ExtAsym: 4 bytes * ext_asym_count
	 * - ExtHash: 4 bytes * ext_hash_count
	 * - RespAlgStruct: variable size * param1	 * 1.1 *
	 */
} __packed;

/* Maximum number of ReqAlgStructs sent by this implementation */
#define SPDM_MAX_REQ_ALG_STRUCT 0

struct spdm_req_alg_struct {
	u8 alg_type;
	u8 alg_count; /* 0x2K where K is number of alg_external entries */
	__le16 alg_supported; /* Size is in alg_count[7:4], always 2 */
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
	u8 param1; /* SupportedSlotMask */		/* 1.3 */
	u8 param2; /* ProvisionedSlotMask */
	u8 digests[]; /* Hash of struct spdm_cert_chain for each slot */
	/* End of SPDM 1.2 (and earlier) structure */

	/*
	 * Additional optional fields at end of this structure:
	 * (omitted as long as we do not advertise MULTI_KEY_CAP)
	 * - KeyPairID: 1 byte for each slot		 * 1.3 *
	 * - CertificateInfo: 1 byte for each slot	 * 1.3 *
	 * - KeyUsageMask: 2 bytes for each slot	 * 1.3 *
	 */
} __packed;

#define SPDM_GET_CERTIFICATE 0x82
#define SPDM_SLOTS 8 /* SPDM 1.0.0 section 4.9.2.1 */

struct spdm_get_certificate_req {
	u8 version;
	u8 code;
	u8 param1; /* Slot number 0..7 */
	u8 param2; /* SlotSizeRequested */		/* 1.3 */
	__le16 offset;
	__le16 length;
} __packed;

struct spdm_get_certificate_rsp {
	u8 version;
	u8 code;
	u8 param1; /* Slot number 0..7 */
	u8 param2; /* CertificateInfo */		/* 1.3 */
	__le16 portion_length;
	__le16 remainder_length;
	u8 cert_chain[]; /* PortionLength long */
} __packed;

struct spdm_cert_chain {
	__le16 length;
	u8 reserved[2];
	/*
	 * Additional fields at end of this structure:
	 * - RootHash: Digest of Root Certificate
	 * - Certificates: Chain of ASN.1 DER-encoded X.509 v3 certificates
	 */
} __packed;

#define SPDM_CHALLENGE 0x83
#define SPDM_NONCE_SZ 32 /* SPDM 1.0.0 table 20 */
#define SPDM_PREFIX_SZ 64 /* SPDM 1.2.0 margin no 803 */
#define SPDM_COMBINED_PREFIX_SZ 100 /* SPDM 1.2.0 margin no 806 */
#define SPDM_MAX_OPAQUE_DATA 1024 /* SPDM 1.0.0 table 21 */

struct spdm_challenge_req {
	u8 version;
	u8 code;
	u8 param1; /* Slot number 0..7 */
	u8 param2; /* MeasurementSummaryHash type */
	u8 nonce[SPDM_NONCE_SZ];
	/* End of SPDM 1.2 (and earlier) structure */

	u8 context[8];					/* 1.3 */
} __packed;

struct spdm_challenge_rsp {
	u8 version;
	u8 code;
	u8 param1; /* Slot number 0..7 */
	u8 param2; /* Slot mask */
	/*
	 * Additional fields at end of this structure:
	 * - CertChainHash: Hash of struct spdm_cert_chain for selected slot
	 * - Nonce: 32 bytes long
	 * - MeasurementSummaryHash: Optional hash of selected measurements
	 * - OpaqueDataLength: 2 bytes long
	 * - OpaqueData: Up to 1024 bytes long
	 * - RequesterContext: 8 bytes long		 * 1.3 *
	 *   (inserted, moves Signature field)
	 * - Signature
	 */
} __packed;

#define SPDM_ERROR 0x7f

enum spdm_error_code {
	SPDM_INVALID_REQUEST		= 0x01,		/* 1.0 */
	SPDM_INVALID_SESSION		= 0x02,		/* 1.1 only */
	SPDM_BUSY			= 0x03,		/* 1.0 */
	SPDM_UNEXPECTED_REQUEST		= 0x04,		/* 1.0 */
	SPDM_UNSPECIFIED		= 0x05,		/* 1.0 */
	SPDM_DECRYPT_ERROR		= 0x06,		/* 1.1 */
	SPDM_UNSUPPORTED_REQUEST	= 0x07,		/* 1.0 */
	SPDM_REQUEST_IN_FLIGHT		= 0x08,		/* 1.1 */
	SPDM_INVALID_RESPONSE_CODE	= 0x09,		/* 1.1 */
	SPDM_SESSION_LIMIT_EXCEEDED	= 0x0a,		/* 1.1 */
	SPDM_SESSION_REQUIRED		= 0x0b,		/* 1.2 */
	SPDM_RESET_REQUIRED		= 0x0c,		/* 1.2 */
	SPDM_RESPONSE_TOO_LARGE		= 0x0d,		/* 1.2 */
	SPDM_REQUEST_TOO_LARGE		= 0x0e,		/* 1.2 */
	SPDM_LARGE_RESPONSE		= 0x0f,		/* 1.2 */
	SPDM_MESSAGE_LOST		= 0x10,		/* 1.2 */
	SPDM_INVALID_POLICY		= 0x11,		/* 1.3 */
	SPDM_VERSION_MISMATCH		= 0x41,		/* 1.0 */
	SPDM_RESPONSE_NOT_READY		= 0x42,		/* 1.0 */
	SPDM_REQUEST_RESYNCH		= 0x43,		/* 1.0 */
	SPDM_OPERATION_FAILED		= 0x44,		/* 1.3 */
	SPDM_NO_PENDING_REQUESTS	= 0x45,		/* 1.3 */
	SPDM_VENDOR_DEFINED_ERROR	= 0xff,		/* 1.0 */
};

struct spdm_error_rsp {
	u8 version;
	u8 code;
	enum spdm_error_code error_code:8;
	u8 error_data;

	u8 extended_error_data[];
} __packed;

/**
 * struct spdm_state - SPDM session state
 *
 * @dev: Responder device.  Used for error reporting and passed to @transport.
 *	Attributes in sysfs appear below this device's directory.
 * @lock: Serializes multiple concurrent spdm_authenticate() calls.
 * @list: List node.  Added to spdm_state_list.  Used to iterate over all
 *	SPDM-capable devices when a global sysctl parameter is changed.
 * @authenticated: Whether device was authenticated successfully.
 * @dev: Responder device.  Used for error reporting and passed to @transport.
 * @transport: Transport function to perform one message exchange.
 * @transport_priv: Transport private data.
 * @transport_sz: Maximum message size the transport is capable of (in bytes).
 *	Used as DataTransferSize in GET_CAPABILITIES exchange.
 * @version: Maximum common supported version of requester and responder.
 *	Negotiated during GET_VERSION exchange.
 * @rsp_caps: Cached capabilities of responder.
 *	Received during GET_CAPABILITIES exchange.
 * @base_asym_alg: Asymmetric key algorithm for signature verification of
 *	CHALLENGE_AUTH messages.
 *	Selected by responder during NEGOTIATE_ALGORITHMS exchange.
 * @base_hash_alg: Hash algorithm for signature verification of
 *	CHALLENGE_AUTH messages.
 *	Selected by responder during NEGOTIATE_ALGORITHMS exchange.
 * @supported_slots: Bitmask of responder's supported certificate slots.
 *	Received during GET_DIGESTS exchange (from SPDM 1.3).
 * @provisioned_slots: Bitmask of responder's provisioned certificate slots.
 *	Received during GET_DIGESTS exchange.
 * @base_asym_enc: Human-readable name of @base_asym_alg's signature encoding.
 *	Passed to crypto subsystem when calling verify_signature().
 * @sig_len: Signature length of @base_asym_alg (in bytes).
 *	S or SigLen in SPDM specification.
 * @base_hash_alg_name: Human-readable name of @base_hash_alg.
 *	Passed to crypto subsystem when calling crypto_alloc_shash() and
 *	verify_signature().
 * @shash: Synchronous hash handle for @base_hash_alg computation.
 * @desc: Synchronous hash context for @base_hash_alg computation.
 * @hash_len: Hash length of @base_hash_alg (in bytes).
 *	H in SPDM specification.
 * @slot: Certificate chain in each of the 8 slots.  NULL pointer if a slot is
 *	not populated.  Prefixed by the 4 + H header per SPDM 1.0.0 table 15.
 * @slot_sz: Certificate chain size (in bytes).
 * @leaf_key: Public key portion of leaf certificate against which to check
 *	responder's signatures.
 * @root_keyring: Keyring against which to check the first certificate in
 *	responder's certificate chain.
 * @validate: Function to validate additional leaf certificate requirements.
 * @transcript: Concatenation of all SPDM messages exchanged during an
 *	authentication sequence.  Used to verify the signature, as it is
 *	computed over the hashed transcript.
 * @transcript_end: Pointer into the @transcript buffer.  Marks the current
 *	end of transcript.  If another message is transmitted, it is appended
 *	at this position.
 * @transcript_max: Allocation size of @transcript.  Multiple of PAGE_SIZE.
 * @log: Linked list of past authentication events.  Each list entry is of type
 *	struct spdm_log_entry and is exposed as several files in sysfs.
 * @log_sz: Memory occupied by @log (in bytes) to enforce the limit set by
 *	spdm_max_log_sz.  Includes, for every entry, the struct spdm_log_entry
 *	itself and the transcript with trailing signature.
 * @log_counter: Number of generated log entries so far.  Will be prefixed to
 *	the sysfs files of the next generated log entry.
 */
struct spdm_state {
	struct device *dev;
	struct mutex lock;
	struct list_head list;
	unsigned int authenticated:1;

	/* Transport */
	spdm_transport *transport;
	void *transport_priv;
	u32 transport_sz;

	/* Negotiated state */
	u8 version;
	u32 rsp_caps;
	u32 base_asym_alg;
	u32 base_hash_alg;
	unsigned long supported_slots;
	unsigned long provisioned_slots;

	/* Signature algorithm */
	const char *base_asym_enc;
	size_t sig_len;

	/* Hash algorithm */
	const char *base_hash_alg_name;
	struct crypto_shash *shash;
	struct shash_desc *desc;
	size_t hash_len;

	/* Certificates */
	struct spdm_cert_chain *slot[SPDM_SLOTS];
	size_t slot_sz[SPDM_SLOTS];
	struct public_key *leaf_key;
	struct key *root_keyring;
	spdm_validate *validate;

	/* Transcript */
	void *transcript;
	void *transcript_end;
	size_t transcript_max;

	/* Signatures Log */
	struct list_head log;
	size_t log_sz;
	u32 log_counter;
};

extern struct list_head spdm_state_list;
extern struct mutex spdm_state_mutex;

ssize_t spdm_exchange(struct spdm_state *spdm_state,
		      void *req, size_t req_sz, void *rsp, size_t rsp_sz);

int spdm_alloc_transcript(struct spdm_state *spdm_state);
void spdm_free_transcript(struct spdm_state *spdm_state);
int spdm_append_transcript(struct spdm_state *spdm_state,
			   const void *msg, size_t msg_sz);

void spdm_create_combined_prefix(u8 version, const char *spdm_context,
				 void *buf);
int spdm_verify_signature(struct spdm_state *spdm_state,
			  const char *spdm_context);

void spdm_reset(struct spdm_state *spdm_state);

#ifdef CONFIG_SYSFS
void spdm_create_log_entry(struct spdm_state *spdm_state,
			   const char *spdm_context, u8 slot,
			   size_t req_nonce_off, size_t rsp_nonce_off);
void spdm_destroy_log(struct spdm_state *spdm_state);
#else
static inline void spdm_create_log_entry(struct spdm_state *spdm_state,
			   const char *spdm_context, u8 slot,
			   size_t req_nonce_off, size_t rsp_nonce_off) { }
static inline void spdm_destroy_log(struct spdm_state *spdm_state) { }
#endif

#endif /* _LIB_SPDM_H_ */
