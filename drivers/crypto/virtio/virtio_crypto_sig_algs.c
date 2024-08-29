// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Asymmetric signature algorithms supported by virtio crypto device
 *
 * The virtio interface is shared with asymmetric cipher algorithms
 * for historic reasons, hence construction of virtio requests is
 * performed by functions in virtio_crypto_akcipher_algs.c.
 *
 * Copyright (c) 2022 Bytedance Ltd.
 * Copyright (c) 2024 Intel Corporation
 */

#include <crypto/sig.h>
#include <crypto/internal/sig.h>
#include <uapi/linux/virtio_crypto.h>
#include "virtio_crypto_akcipher.h"
#include "virtio_crypto_common.h"

struct virtio_crypto_sig_algo {
	uint32_t algonum;
	uint32_t service;
	unsigned int active_devs;
	struct sig_alg algo;
};

static DEFINE_MUTEX(algs_lock);

static int virtio_crypto_sig_sign(struct crypto_sig *tfm,
				  const void *src, unsigned int slen,
				  void *dst, unsigned int dlen)
{
	struct virtio_crypto_akcipher_ctx *ctx = crypto_sig_ctx(tfm);

	return virtio_crypto_rsa_req(req, VIRTIO_CRYPTO_AKCIPHER_SIGN);
}

static int virtio_crypto_sig_verify(struct crypto_sig *tfm,
				    const void *src, unsigned int slen,
				    const void *digest, unsigned int dlen)
{
	struct virtio_crypto_akcipher_ctx *ctx = crypto_sig_ctx(tfm);

	return virtio_crypto_rsa_req(req, VIRTIO_CRYPTO_AKCIPHER_VERIFY);
}

static int virtio_crypto_sig_rsa_pkcs1_sha1_set_pub_key(struct crypto_sig *tfm,
							const void *key,
							unsigned int keylen)
{
	struct virtio_crypto_akcipher_ctx *ctx = crypto_sig_ctx(tfm);

	return virtio_crypto_rsa_set_key(ctx, key, keylen, 0,
					 VIRTIO_CRYPTO_RSA_PKCS1_PADDING,
					 VIRTIO_CRYPTO_RSA_SHA1);
}

static int virtio_crypto_sig_rsa_pkcs1_sha1_set_priv_key(struct crypto_sig *tfm,
							 const void *key,
							 unsigned int keylen)
{
	struct virtio_crypto_akcipher_ctx *ctx = crypto_sig_ctx(tfm);

	return virtio_crypto_rsa_set_key(ctx, key, keylen, 1,
					 VIRTIO_CRYPTO_RSA_PKCS1_PADDING,
					 VIRTIO_CRYPTO_RSA_SHA1);
}

static unsigned int virtio_crypto_sig_rsa_max_size(struct crypto_sig *tfm)
{
	struct virtio_crypto_akcipher_ctx *ctx = crypto_sig_ctx(tfm);
	struct virtio_crypto_rsa_ctx *rsa_ctx = &ctx->rsa_ctx;

	return rsa_ctx->keysize;
}

static void virtio_crypto_sig_exit_tfm(struct crypto_sig *tfm)
{
	struct virtio_crypto_akcipher_ctx *ctx = crypto_sig_ctx(tfm);

	virtio_crypto_alg_akcipher_close_session(ctx);
	virtcrypto_dev_put(ctx->vcrypto);
}

static struct virtio_crypto_akcipher_algo virtio_crypto_sig_algs[] = {
	{
		.algonum = VIRTIO_CRYPTO_AKCIPHER_RSA,
		.service = VIRTIO_CRYPTO_SERVICE_AKCIPHER,
		.algo = {
			.sign = virtio_crypto_sig_sign,
			.verify = virtio_crypto_sig_verify,
			.set_pub_key = virtio_crypto_sig_rsa_pkcs1_sha1_set_pub_key,
			.set_priv_key = virtio_crypto_sig_rsa_pkcs1_sha1_set_priv_key,
			.max_size = virtio_crypto_sig_rsa_max_size,
			.exit = virtio_crypto_sig_exit_tfm,
			.base = {
				.cra_name = "pkcs1(rsa,sha1)",
				.cra_driver_name = "virtio-pkcs1-rsa-with-sha1",
				.cra_priority = 150,
				.cra_module = THIS_MODULE,
				.cra_ctxsize = sizeof(struct virtio_crypto_akcipher_ctx),
			},
		},
	},
};

int virtio_crypto_sig_algs_register(struct virtio_crypto *vcrypto)
{
	int ret = 0;
	int i = 0;

	mutex_lock(&algs_lock);

	for (i = 0; i < ARRAY_SIZE(virtio_crypto_sig_algs); i++) {
		uint32_t service = virtio_crypto_sig_algs[i].service;
		uint32_t algonum = virtio_crypto_sig_algs[i].algonum;

		if (!virtcrypto_algo_is_supported(vcrypto, service, algonum))
			continue;

		if (virtio_crypto_sig_algs[i].active_devs == 0) {
			ret = crypto_register_sig(&virtio_crypto_sig_algs[i].algo);
			if (ret)
				goto unlock;
		}

		virtio_crypto_sig_algs[i].active_devs++;
		dev_info(&vcrypto->vdev->dev, "Registered sig algo %s\n",
			 virtio_crypto_sig_algs[i].algo.base.cra_name);
	}

unlock:
	mutex_unlock(&algs_lock);
	return ret;
}

void virtio_crypto_sig_algs_unregister(struct virtio_crypto *vcrypto)
{
	int i = 0;

	mutex_lock(&algs_lock);

	for (i = 0; i < ARRAY_SIZE(virtio_crypto_sig_algs); i++) {
		uint32_t service = virtio_crypto_sig_algs[i].service;
		uint32_t algonum = virtio_crypto_sig_algs[i].algonum;

		if (virtio_crypto_sig_algs[i].active_devs == 0 ||
		    !virtcrypto_algo_is_supported(vcrypto, service, algonum))
			continue;

		if (virtio_crypto_sig_algs[i].active_devs == 1)
			crypto_unregister_sig(&virtio_crypto_sig_algs[i].algo);

		virtio_crypto_sig_algs[i].active_devs--;
	}

	mutex_unlock(&algs_lock);
}
