#ifndef _VIRTIO_CRYPTO_AKCIPHER_H
#define _VIRTIO_CRYPTO_AKCIPHER_H

#include "virtio_crypto_common.h"

struct virtio_crypto_rsa_ctx {
	unsigned int keysize;
};

struct virtio_crypto_akcipher_ctx {
	struct virtio_crypto *vcrypto;
	bool session_valid;
	__u64 session_id;
	union {
		struct virtio_crypto_rsa_ctx rsa_ctx;
	};
};

int virtio_crypto_rsa_set_key(struct virtio_crypto_akcipher_ctx *ctx,
			      const void *key, unsigned int keylen,
			      bool private, int padding_algo, int hash_algo);

#endif /* _VIRTIO_CRYPTO_AKCIPHER_H */
