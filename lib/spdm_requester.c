// SPDX-License-Identifier: GPL-2.0
/*
 * DMTF Security Protocol and Data Model (SPDM)
 * https://www.dmtf.org/dsp/DSP0274
 *
 * Copyright (C) 2021-22 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022-24 Intel Corporation
 */

#undef  DEFAULT_SYMBOL_NAMESPACE
#define DEFAULT_SYMBOL_NAMESPACE SPDM_REQUESTER

#define dev_fmt(fmt) "SPDM: " fmt

#include <linux/bitfield.h>
#include <linux/dev_printk.h>
#include <linux/key.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/random.h>
#include <linux/spdm.h>

#include <asm/unaligned.h>
#include <crypto/hash.h>
#include <crypto/public_key.h>
#include <keys/asymmetric-type.h>
#include <keys/x509-parser.h>

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
#define SPDM_CAPS			(SPDM_CERT_CAP | SPDM_CHAL_CAP)

/* SPDM capabilities required from responders */
#define SPDM_MIN_CAPS			(SPDM_CERT_CAP | SPDM_CHAL_CAP)

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

/* SPDM measurement specifications (SPDM 1.0.0 sec 4.10.1.3) */
#define SPDM_MEAS_SPEC_DMTF		BIT(0)		/* 1.0 */

/* SPDM measurement hash algorithms (SPDM 1.0.0 table 14) */
#define SPDM_MEAS_HASH_RAW		BIT(0)		/* 1.0 */
#define SPDM_MEAS_HASH_SHA_256		BIT(1)		/* 1.0 */
#define SPDM_MEAS_HASH_SHA_384		BIT(2)		/* 1.0 */
#define SPDM_MEAS_HASH_SHA_512		BIT(3)		/* 1.0 */
#define SPDM_MEAS_HASH_SHA3_256		BIT(4)		/* 1.0 */
#define SPDM_MEAS_HASH_SHA3_384		BIT(5)		/* 1.0 */
#define SPDM_MEAS_HASH_SHA3_512		BIT(6)		/* 1.0 */
#define SPDM_MEAS_HASH_SM3_257		BIT(7)		/* 1.2 */

/* SPDM Diffie-Hellman Ephemeral groups (SPDM 1.1.0 margin no 189) */
#define SPDM_REQ_ALG_STRUCT_DHE		2		/* 1.1 */
#define SPDM_DHE_FFDHE_2048		BIT(0)		/* 1.1 */
#define SPDM_DHE_FFDHE_3072		BIT(1)		/* 1.1 */
#define SPDM_DHE_FFDHE_4096		BIT(2)		/* 1.1 */
#define SPDM_DHE_SECP_256R1		BIT(3)		/* 1.1 */
#define SPDM_DHE_SECP_384R1		BIT(4)		/* 1.1 */
#define SPDM_DHE_SECP_521R1		BIT(5)		/* 1.1 */
#define SPDM_DHE_SM2_P256		BIT(6)		/* 1.2 */

/* SPDM Authenticated Encryption w/ AD algorithms (SPDM 1.1.0 margin no 190) */
#define SPDM_REQ_ALG_STRUCT_AEAD	3		/* 1.1 */
#define SPDM_AEAD_AES_128_GCM		BIT(0)		/* 1.1 */
#define SPDM_AEAD_AES_256_GCM		BIT(1)		/* 1.1 */
#define SPDM_AEAD_CHACHA20_POLY1305	BIT(2)		/* 1.1 */
#define SPDM_AEAD_SM4_GCM		BIT(3)		/* 1.2 */

/* SPDM asymmetric key signature algorithms (SPDM 1.1.0 margin no 191) */
#define SPDM_REQ_ALG_STRUCT_REQ_BASE_ASYM_ALG 4		/* 1.1 */

/* SPDM key schedule algorithms (SPDM 1.1.0 margin no 192) */
#define SPDM_REQ_ALG_STRUCT_KEY_SCHEDULE 5		/* 1.1 */
#define SPDM_KEY_SCHEDULE_SPDM		BIT(0)		/* 1.1 */

/* SPDM opaque data formats (SPDM 1.2.0 margin no 261) */
#define SPDM_OPAQUE_DATA_FMT_VENDOR	BIT(0)		/* 1.2 */
#define SPDM_OPAQUE_DATA_FMT_GENERAL	BIT(1)		/* 1.2 */

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

#define SPDM_DHE_ALGOS		       (SPDM_DHE_FFDHE_2048		| \
					SPDM_DHE_FFDHE_3072		| \
					SPDM_DHE_SECP_256R1		| \
					SPDM_DHE_SECP_384R1)

#define SPDM_AEAD_ALGOS		       (SPDM_AEAD_AES_256_GCM		| \
					SPDM_AEAD_CHACHA20_POLY1305)

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
#define SPDM_MAX_OPAQUE_DATA 1024 /* SPDM 1.0.0 table 21 */

struct spdm_challenge_req {
	u8 version;
	u8 code;
	u8 param1; /* Slot number 0..7 */
	u8 param2; /* MeasurementSummaryHash type */
	u8 nonce[32];
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
 * struct spdm_state - SPDM session state
 *
 * @lock: Serializes multiple concurrent spdm_authenticate() calls.
 * @authenticated: Whether device was authenticated successfully.
 * @dev: Responder device.  Used for error reporting and passed to @transport.
 * @transport: Transport function to perform one message exchange.
 * @transport_priv: Transport private data.
 * @transport_sz: Maximum message size the transport is capable of (in bytes).
 *	Used as DataTransferSize in GET_CAPABILITIES exchange.
 * @version: Maximum common supported version of requester and responder.
 *	Negotiated during GET_VERSION exchange.
 * @responder_caps: Cached capabilities of responder.
 *	Received during GET_CAPABILITIES exchange.
 * @base_asym_alg: Asymmetric key algorithm for signature verification of
 *	CHALLENGE_AUTH and MEASUREMENTS messages.
 *	Selected by responder during NEGOTIATE_ALGORITHMS exchange.
 * @base_hash_alg: Hash algorithm for signature verification of
 *	CHALLENGE_AUTH and MEASUREMENTS messages.
 *	Selected by responder during NEGOTIATE_ALGORITHMS exchange.
 * @meas_hash_alg: Hash algorithm for measurement blocks.
 *	Selected by responder during NEGOTIATE_ALGORITHMS exchange.
 * @slot_mask: Bitmask of populated certificate slots in the responder.
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
 * @leaf_key: Public key portion of leaf certificate against which to check
 *	responder's signatures.
 * @root_keyring: Keyring against which to check the first certificate in
 *	responder's certificate chain.
 * @validate: Function to validate additional leaf certificate requirements.
 */
struct spdm_state {
	struct mutex lock;
	unsigned int authenticated:1;

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
	u32 meas_hash_alg;
	unsigned long slot_mask;

	/* Signature algorithm */
	const char *base_asym_enc;
	size_t sig_len;

	/* Hash algorithm */
	const char *base_hash_alg_name;
	struct crypto_shash *shash;
	struct shash_desc *desc;
	size_t hash_len;

	/* Certificates */
	struct public_key *leaf_key;
	struct key *root_keyring;
	spdm_validate *validate;
};

static ssize_t __spdm_exchange(struct spdm_state *spdm_state,
			       const void *req, size_t req_sz,
			       void *rsp, size_t rsp_sz)
{
	const struct spdm_header *request = req;
	struct spdm_header *response = rsp;
	ssize_t rc, length;

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

static ssize_t spdm_exchange(struct spdm_state *spdm_state,
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

static int spdm_get_version(struct spdm_state *spdm_state,
			    struct spdm_get_version_rsp *rsp, size_t *rsp_sz)
{
	u8 version = SPDM_MIN_VER;
	bool foundver = false;
	int rc, length, i;

	/*
	 * Bypass spdm_exchange() to be able to set version = 0x10.
	 * rsp buffer is large enough for the maximum possible 255 entries.
	 */
	rc = __spdm_exchange(spdm_state, &spdm_get_version_req,
			     sizeof(spdm_get_version_req), rsp,
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

	for (i = 0; i < rsp->version_number_entry_count; i++) {
		u8 ver = le16_to_cpu(rsp->version_number_entries[i]) >> 8;

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

	/*
	 * Stash VERSION response in transcript buffer
	 * for later consumption by spdm_start_hash() when hash algo is known.
	 */
	*rsp_sz = struct_size(rsp, version_number_entries,
			      rsp->version_number_entry_count);

	return 0;
}

static int spdm_get_capabilities(struct spdm_state *spdm_state,
				 void *reqrsp, size_t *reqrsp_sz)
{
	struct spdm_get_capabilities_req *req = reqrsp;
	struct spdm_get_capabilities_rsp *rsp;
	size_t req_sz, rsp_sz;
	int rc, length;

	req->code = SPDM_GET_CAPABILITIES;
	req->ctexponent = SPDM_CTEXPONENT;
	req->flags = cpu_to_le32(SPDM_CAPS);

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

	rsp = reqrsp + req_sz;

	rc = spdm_exchange(spdm_state, req, req_sz, rsp, rsp_sz);
	if (rc < 0)
		return rc;

	length = rc;
	if (length < rsp_sz) {
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

	/*
	 * Stash GET_CAPABILITIES request and response in transcript buffer
	 * for later consumption by spdm_start_hash() when hash algo is known.
	 */
	*reqrsp_sz = req_sz + rsp_sz;

	return 0;
}

/**
 * spdm_start_hash() - Build first part of CHALLENGE_AUTH hash
 *
 * @spdm_state: SPDM session state
 * @get_version_rsp: GET_VERSION response
 * @get_version_rsp_sz: length of @get_version_rsp
 * @get_capabilities_reqrsp: GET_CAPABILITIES request and response
 * @get_capabilities_reqrsp_sz: length of @get_capabilities_reqrsp
 * @req: NEGOTIATE_ALGORITHMS request
 * @req_sz: length of @req
 * @rsp: NEGOTIATE_ALGORITHMS response
 * @rsp_sz: length of @rsp
 *
 * We've just learned the hash algorithm to use for CHALLENGE_AUTH signature
 * verification.  Hash the constant GET_VERSION request, the stashed
 * GET_VERSION response, the stashed GET_CAPABILITIES request/response
 * and the NEGOTIATE_ALGORITHMS exchange which has just been performed.
 *
 * Subsequent requests and responses will be added to the hash as they become
 * available.
 *
 * Return 0 on success or a negative errno.
 */
static int spdm_start_hash(struct spdm_state *spdm_state,
			   void *get_version_rsp, size_t get_version_rsp_sz,
			   void *get_capabilities_reqrsp,
			   size_t get_capabilities_reqrsp_sz,
			   void *req, size_t req_sz, void *rsp, size_t rsp_sz)
{
	int rc;

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

	rc = crypto_shash_init(spdm_state->desc);
	if (rc)
		return rc;

	rc = crypto_shash_update(spdm_state->desc, (u8 *)&spdm_get_version_req,
				 sizeof(spdm_get_version_req));
	if (rc)
		return rc;

	rc = crypto_shash_update(spdm_state->desc, get_version_rsp,
				 get_version_rsp_sz);
	if (rc)
		return rc;

	rc = crypto_shash_update(spdm_state->desc, get_capabilities_reqrsp,
				 get_capabilities_reqrsp_sz);
	if (rc)
		return rc;

	rc = crypto_shash_update(spdm_state->desc, req, req_sz);
	if (rc)
		return rc;

	return crypto_shash_update(spdm_state->desc, rsp, rsp_sz);
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

	return 0;
}

/* Maximum number of ReqAlgStructs sent by this implementation */
#define SPDM_MAX_REQ_ALG_STRUCT 4

static int spdm_negotiate_algs(struct spdm_state *spdm_state,
			       void *get_version_rsp,
			       size_t get_version_rsp_sz,
			       void *get_capabilities_reqrsp,
			       size_t get_capabilities_reqrsp_sz)
{
	struct spdm_negotiate_algs_rsp *rsp __free(kfree) = NULL;
	struct spdm_negotiate_algs_req *req __free(kfree);
	struct spdm_req_alg_struct *req_alg_struct;
	size_t req_sz, rsp_sz;
	int rc, length, i = 0;

	req_sz = sizeof(*req) +
		 sizeof(*req_alg_struct) * SPDM_MAX_REQ_ALG_STRUCT;

	/* Request length shall be <= 128 bytes (SPDM 1.1.0 margin no 185) */
	BUILD_BUG_ON(req_sz > 128);

	req = kzalloc(req_sz, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->code = SPDM_NEGOTIATE_ALGS;
	req->measurement_specification = SPDM_MEAS_SPEC_DMTF;
	req->base_asym_algo = cpu_to_le32(SPDM_ASYM_ALGOS);
	req->base_hash_algo = cpu_to_le32(SPDM_HASH_ALGOS);
	if (spdm_state->version >= 0x12)
		req->other_params_support = SPDM_OPAQUE_DATA_FMT_GENERAL;

	/* ReqAlgStruct order shall be by AlgType (SPDM 1.1.0 margin no 186) */
	req_alg_struct = (struct spdm_req_alg_struct *)(req + 1);
	if (spdm_state->responder_caps & SPDM_KEY_EX_CAP) {
		req_alg_struct[i++] = (struct spdm_req_alg_struct) {
			.alg_type = SPDM_REQ_ALG_STRUCT_DHE,
			.alg_count = 0x20,
			.alg_supported = cpu_to_le16(SPDM_DHE_ALGOS),
		};
		req_alg_struct[i++] = (struct spdm_req_alg_struct) {
			.alg_type = SPDM_REQ_ALG_STRUCT_AEAD,
			.alg_count = 0x20,
			.alg_supported = cpu_to_le16(SPDM_AEAD_ALGOS),
		};
	}
	if (spdm_state->responder_caps & SPDM_MUT_AUTH_CAP)
		req_alg_struct[i++] = (struct spdm_req_alg_struct) {
			.alg_type = SPDM_REQ_ALG_STRUCT_REQ_BASE_ASYM_ALG,
			.alg_count = 0x20,
			.alg_supported = cpu_to_le16(SPDM_ASYM_ALGOS),
		};
	if (spdm_state->responder_caps & SPDM_KEY_EX_CAP)
		req_alg_struct[i++] = (struct spdm_req_alg_struct) {
			.alg_type = SPDM_REQ_ALG_STRUCT_KEY_SCHEDULE,
			.alg_count = 0x20,
			.alg_supported = cpu_to_le16(SPDM_KEY_SCHEDULE_SPDM),
		};
	WARN_ON(i > SPDM_MAX_REQ_ALG_STRUCT);
	req_sz = sizeof(*req) + i * sizeof(*req_alg_struct);
	rsp_sz = sizeof(*rsp) + i * sizeof(*req_alg_struct);
	req->length = cpu_to_le16(req_sz);
	req->param1 = i;

	rsp = kzalloc(rsp_sz, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	rc = spdm_exchange(spdm_state, req, req_sz, rsp, rsp_sz);
	if (rc < 0)
		return rc;

	length = rc;
	if (length < sizeof(*rsp) ||
	    length < sizeof(*rsp) + rsp->param1 * sizeof(*req_alg_struct)) {
		dev_err(spdm_state->dev, "Truncated algorithms response\n");
		return -EIO;
	}

	spdm_state->base_asym_alg = le32_to_cpu(rsp->base_asym_sel);
	spdm_state->base_hash_alg = le32_to_cpu(rsp->base_hash_sel);
	spdm_state->meas_hash_alg = le32_to_cpu(rsp->measurement_hash_algo);

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
	    rsp->param1 > req->param1 ||
	    rsp->other_params_sel != req->other_params_support ||
	    (spdm_state->responder_caps & SPDM_MEAS_CAP_MASK &&
	     (hweight32(spdm_state->meas_hash_alg) != 1 ||
	      rsp->measurement_specification_sel != SPDM_MEAS_SPEC_DMTF))) {
		dev_err(spdm_state->dev, "Malformed algorithms response\n");
		return -EPROTO;
	}

	rc = spdm_parse_algs(spdm_state);
	if (rc)
		return rc;

	/*
	 * If request contained a ReqAlgStruct not supported by responder,
	 * the corresponding RespAlgStruct may be omitted in response.
	 * Calculate the actual (possibly shorter) response length:
	 */
	rsp_sz = sizeof(*rsp) + rsp->param1 * sizeof(*req_alg_struct);

	return spdm_start_hash(spdm_state, get_version_rsp, get_version_rsp_sz,
			       get_capabilities_reqrsp,
			       get_capabilities_reqrsp_sz,
			       req, req_sz, rsp, rsp_sz);
}

static int spdm_get_digests(struct spdm_state *spdm_state)
{
	struct spdm_get_digests_req req = { .code = SPDM_GET_DIGESTS };
	struct spdm_get_digests_rsp *rsp __free(kfree);
	size_t rsp_sz;
	int rc, length;

	/*
	 * Assume all 8 slots are populated.  We know the hash length (and thus
	 * the response size) because the responder only returns digests for
	 * the hash algorithm selected during the NEGOTIATE_ALGORITHMS exchange
	 * (SPDM 1.1.2 margin no 206).
	 */
	rsp_sz = sizeof(*rsp) + SPDM_SLOTS * spdm_state->hash_len;
	rsp = kzalloc(rsp_sz, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	rc = spdm_exchange(spdm_state, &req, sizeof(req), rsp, rsp_sz);
	if (rc < 0)
		return rc;

	length = rc;
	if (length < sizeof(*rsp) ||
	    length < sizeof(*rsp) + hweight8(rsp->param2) * spdm_state->hash_len) {
		dev_err(spdm_state->dev, "Truncated digests response\n");
		return -EIO;
	}

	rsp_sz = sizeof(*rsp) + hweight8(rsp->param2) * spdm_state->hash_len;

	/*
	 * Authentication-capable endpoints must carry at least 1 cert chain
	 * (SPDM 1.0.0 section 4.9.2.1).
	 */
	spdm_state->slot_mask = rsp->param2;
	if (!spdm_state->slot_mask) {
		dev_err(spdm_state->dev, "No certificates provisioned\n");
		return -EPROTO;
	}

	rc = crypto_shash_update(spdm_state->desc, (u8 *)&req, sizeof(req));
	if (rc)
		return rc;

	return crypto_shash_update(spdm_state->desc, (u8 *)rsp, rsp_sz);
}

static int spdm_validate_cert_chain(struct spdm_state *spdm_state, u8 slot,
				    u8 *certs, size_t total_length)
{
	struct x509_certificate *cert __free(x509_free_certificate) = NULL;
	struct x509_certificate *prev __free(x509_free_certificate) = NULL;
	bool is_leaf_cert;
	size_t offset = 0;
	struct key *key;
	int rc, length;

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
					 "for slot %u not found in %s "
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
		rc = spdm_state->validate(spdm_state->dev, prev);
		if (rc)
			return rc;
	}

	spdm_state->leaf_key = prev->pub;
	prev->pub = NULL;
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

		rc = crypto_shash_update(spdm_state->desc, (u8 *)&req,
					 sizeof(req));
		if (rc)
			return rc;

		rc = crypto_shash_update(spdm_state->desc, (u8 *)rsp,
					 sizeof(*rsp) + portion_length);
		if (rc)
			return rc;

	} while (remainder_length > 0);

	header_length = sizeof(struct spdm_cert_chain) + spdm_state->hash_len;

	if (total_length < header_length ||
	    total_length != le16_to_cpu(certs->length)) {
		dev_err(spdm_state->dev,
			"Malformed certificate chain in slot %u\n", slot);
		return -EPROTO;
	}

	return spdm_validate_cert_chain(spdm_state, slot,
					(u8 *)certs + header_length,
					total_length - header_length);
}

#define SPDM_PREFIX_SZ 64 /* SPDM 1.2.0 margin no 803 */
#define SPDM_COMBINED_PREFIX_SZ 100 /* SPDM 1.2.0 margin no 806 */

/**
 * spdm_create_combined_prefix() - Create combined_spdm_prefix for a hash
 *
 * @spdm_state: SPDM session state
 * @spdm_context: SPDM context
 * @buf: Buffer to receive combined_spdm_prefix (100 bytes)
 *
 * From SPDM 1.2, a hash is prefixed with the SPDM version and context before
 * a signature is generated (or verified) over the resulting concatenation
 * (SPDM 1.2.0 section 15).  Create that prefix.
 */
static void spdm_create_combined_prefix(struct spdm_state *spdm_state,
					const char *spdm_context, void *buf)
{
	u8 major = FIELD_GET(0xf0, spdm_state->version);
	u8 minor = FIELD_GET(0x0f, spdm_state->version);
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
 * @s: Signature
 * @spdm_context: SPDM context (used to create combined_spdm_prefix)
 *
 * Implementation of the abstract SPDMSignatureVerify() function described in
 * SPDM 1.2.0 section 16:  Compute the hash in @spdm_state->desc and verify
 * that its signature @s was generated with @spdm_state->leaf_key.
 * Return 0 on success or a negative errno.
 */
static int spdm_verify_signature(struct spdm_state *spdm_state, u8 *s,
				 const char *spdm_context)
{
	struct public_key_signature sig = {
		.s = s,
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

	rc = crypto_shash_final(spdm_state->desc, m + SPDM_COMBINED_PREFIX_SZ);
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
		 * (SPDM 1.2.0 margin no 841).
		 */
		spdm_create_combined_prefix(spdm_state, spdm_context, m);

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
		      + 32;			/* Nonce */

	if (rsp)
		/* May be unaligned if hash algorithm has odd length. */
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
	size_t req_sz, rsp_sz, rsp_sz_max, sig_offset;
	struct spdm_challenge_rsp *rsp __free(kfree);
	struct spdm_challenge_req req = {
		.code = SPDM_CHALLENGE,
		.param1 = slot,
		.param2 = 0, /* no measurement summary hash */
	};
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

	/* Last step of building the hash */
	rc = crypto_shash_update(spdm_state->desc, (u8 *)&req, req_sz);
	if (rc)
		return rc;

	sig_offset = rsp_sz - spdm_state->sig_len;
	rc = crypto_shash_update(spdm_state->desc, (u8 *)rsp, sig_offset);
	if (rc)
		return rc;

	/* Hash is complete and signature received; verify against leaf key */
	rc = spdm_verify_signature(spdm_state, (u8 *)rsp + sig_offset,
				   "responder-challenge_auth signing");
	if (rc)
		dev_err(spdm_state->dev,
			"Failed to verify challenge_auth signature: %d\n", rc);
	return rc;
}

static void spdm_reset(struct spdm_state *spdm_state)
{
	public_key_free(spdm_state->leaf_key);
	spdm_state->leaf_key = NULL;

	kfree(spdm_state->desc);
	spdm_state->desc = NULL;

	crypto_free_shash(spdm_state->shash);
	spdm_state->shash = NULL;
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
	size_t get_version_rsp_sz, get_capabilities_reqrsp_sz;
	void *get_capabilities_reqrsp __free(kfree);
	void *get_version_rsp __free(kfree);
	u8 slot;
	int rc;

	/*
	 * For CHALLENGE_AUTH signature verification, a hash is computed over
	 * all exchanged messages to detect modification by a man-in-the-middle
	 * or media error.  However the hash algorithm is not known until the
	 * NEGOTIATE_ALGORITHMS response has been received.  The preceding
	 * GET_VERSION and GET_CAPABILITIES exchanges are therefore stashed
	 * in a transcript buffer and consumed once the algorithm is known.
	 * The buffer size is sufficient for the largest possible messages with
	 * 255 version entries and the capability fields added by SPDM 1.2.
	 * Two buffers are needed to ensure natural alignment for 32-bit fields
	 * in GET_CAPABILITIES request and response.
	 */
	get_version_rsp = kmalloc(struct_size_t(struct spdm_get_version_rsp,
						version_number_entries, 255),
				  GFP_KERNEL);
	get_capabilities_reqrsp =
			  kzalloc(sizeof(struct spdm_get_capabilities_req) +
				  sizeof(struct spdm_get_capabilities_rsp),
				  GFP_KERNEL);
	if (!get_version_rsp || !get_capabilities_reqrsp)
		return -ENOMEM;

	mutex_lock(&spdm_state->lock);
	spdm_reset(spdm_state);

	rc = spdm_get_version(spdm_state, get_version_rsp,
			      &get_version_rsp_sz);
	if (rc)
		goto unlock;

	rc = spdm_get_capabilities(spdm_state, get_capabilities_reqrsp,
				   &get_capabilities_reqrsp_sz);
	if (rc)
		goto unlock;

	rc = spdm_negotiate_algs(spdm_state, get_version_rsp,
				 get_version_rsp_sz, get_capabilities_reqrsp,
				 get_capabilities_reqrsp_sz);
	if (rc)
		goto unlock;

	rc = spdm_get_digests(spdm_state);
	if (rc)
		goto unlock;

	for_each_set_bit(slot, &spdm_state->slot_mask, SPDM_SLOTS) {
		rc = spdm_get_certificate(spdm_state, slot);
		if (rc == 0)
			break; /* success */
		if (rc != -ENOKEY && rc != -EKEYREJECTED)
			break; /* try next slot only on signature error */
	}
	if (rc)
		goto unlock;

	rc = spdm_challenge(spdm_state, slot);
	if (!rc)
		dev_info(spdm_state->dev,
			 "authenticated with certificate slot %u\n", slot);

unlock:
	if (rc)
		spdm_reset(spdm_state);
	spdm_state->authenticated = !rc;
	mutex_unlock(&spdm_state->lock);
	return rc;
}
EXPORT_SYMBOL_GPL(spdm_authenticate);

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
 * Returns a pointer to the allocated SPDM session state or NULL on error.
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

	return spdm_state;
}
EXPORT_SYMBOL_GPL(spdm_create);

/**
 * spdm_await() - Wait for ongoing spdm_authenticate() to finish
 *
 * @spdm_state: SPDM session state
 */
void spdm_await(struct spdm_state *spdm_state)
{
	mutex_lock(&spdm_state->lock);
	mutex_unlock(&spdm_state->lock);
}

/**
 * spdm_destroy() - Destroy SPDM session
 *
 * @spdm_state: SPDM session state
 */
void spdm_destroy(struct spdm_state *spdm_state)
{
	spdm_reset(spdm_state);
	mutex_destroy(&spdm_state->lock);
	kfree(spdm_state);
}
EXPORT_SYMBOL_GPL(spdm_destroy);

#ifdef CONFIG_SYSFS
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

static umode_t spdm_attrs_are_visible(struct kobject *kobj,
				      struct attribute *a, int n)
{
	struct device *dev = kobj_to_dev(kobj);
	struct spdm_state *spdm_state = dev_to_spdm_state(dev);

	if (!spdm_state)
		return 0;

	return a->mode;
}

const struct attribute_group spdm_attr_group = {
	.attrs = spdm_attrs,
	.is_visible = spdm_attrs_are_visible,
};
#endif /* CONFIG_SYSFS */

MODULE_LICENSE("GPL");
