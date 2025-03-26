#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main()
{
	// 初始化 OpenSSL 库
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	// 选择椭圆曲线
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_sm2);
	if (ec_group == NULL) {
		fprintf(stderr, "Error creating EC_GROUP\n");
		return 1;
	}

	// 创建 EVP_PKEY 对象来存储 Alice 和 Bob 的密钥
	EVP_PKEY *alice_pkey = EVP_PKEY_new();
	EVP_PKEY *bob_pkey = EVP_PKEY_new();
	if (!alice_pkey || !bob_pkey) {
		fprintf(stderr, "Error creating EVP_PKEY objects\n");
		return 1;
	}

	// 使用 EVP_PKEY_keygen 生成 Alice 和 Bob 的密钥对
	EVP_PKEY_CTX *ctx_alice = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
	EVP_PKEY_CTX *ctx_bob = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);

	if (!ctx_alice || !ctx_bob) {
		fprintf(stderr, "Error creating EVP_PKEY_CTX objects\n");
		return 1;
	}

	if (EVP_PKEY_keygen_init(ctx_alice) <= 0 ||
	    EVP_PKEY_keygen_init(ctx_bob) <= 0) {
		fprintf(stderr, "Error initializing keygen context\n");
		return 1;
	}

	// 设置椭圆曲线
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx_alice, NID_sm2) <=
		    0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx_bob, NID_sm2) <=
		    0) {
		fprintf(stderr, "Error setting EC curve\n");
		return 1;
	}

	// 生成 Alice 和 Bob 的密钥对
	if (EVP_PKEY_keygen(ctx_alice, &alice_pkey) <= 0 ||
	    EVP_PKEY_keygen(ctx_bob, &bob_pkey) <= 0) {
		fprintf(stderr, "Error generating keys\n");
		return 1;
	}

	// 使用 EVP_PKEY_derive 计算共享密钥
	EVP_PKEY_CTX *derive_ctx_alice = EVP_PKEY_CTX_new(alice_pkey, NULL);
	EVP_PKEY_CTX *derive_ctx_bob = EVP_PKEY_CTX_new(bob_pkey, NULL);

	if (!derive_ctx_alice || !derive_ctx_bob) {
		fprintf(stderr, "Error creating EVP_PKEY_CTX for derive\n");
		return 1;
	}

	if (EVP_PKEY_derive_init(derive_ctx_alice) <= 0 ||
	    EVP_PKEY_derive_init(derive_ctx_bob) <= 0) {
		fprintf(stderr, "Error initializing derive context\n");
		return 1;
	}

	if (EVP_PKEY_derive_set_peer(derive_ctx_alice, bob_pkey) <= 0 ||
	    EVP_PKEY_derive_set_peer(derive_ctx_bob, alice_pkey) <= 0) {
		fprintf(stderr, "Error setting peer for derive\n");
		return 1;
	}

	// 计算共享密钥的长度
	size_t shared_secret_len_alice = 0;
	size_t shared_secret_len_bob = 0;
	if (EVP_PKEY_derive(derive_ctx_alice, NULL, &shared_secret_len_alice) <=
		    0 ||
	    EVP_PKEY_derive(derive_ctx_bob, NULL, &shared_secret_len_bob) <=
		    0) {
		fprintf(stderr, "Error calculating shared secret length\n");
		return 1;
	}

	// 分配内存来存储共享密钥
	unsigned char *shared_secret_alice =
		(unsigned char *)OPENSSL_malloc(shared_secret_len_alice);
	unsigned char *shared_secret_bob =
		(unsigned char *)OPENSSL_malloc(shared_secret_len_bob);

	if (shared_secret_alice == NULL || shared_secret_bob == NULL) {
		fprintf(stderr, "Error allocating memory for shared secret\n");
		return 1;
	}

	// 获取共享密钥
	if (EVP_PKEY_derive(derive_ctx_alice, shared_secret_alice,
			    &shared_secret_len_alice) <= 0 ||
	    EVP_PKEY_derive(derive_ctx_bob, shared_secret_bob,
			    &shared_secret_len_bob) <= 0) {
		fprintf(stderr, "Error deriving shared secret\n");
		return 1;
	}

	// 比较共享密钥是否一致
	if (shared_secret_len_alice == shared_secret_len_bob &&
	    memcmp(shared_secret_alice, shared_secret_bob,
		   shared_secret_len_alice) == 0) {
		printf("Shared secret is the same!\n");
	} else {
		printf("Shared secrets do not match.\n");
	}

	// 清理内存
	OPENSSL_free(shared_secret_alice);
	OPENSSL_free(shared_secret_bob);
	EVP_PKEY_CTX_free(ctx_alice);
	EVP_PKEY_CTX_free(ctx_bob);
	EVP_PKEY_CTX_free(derive_ctx_alice);
	EVP_PKEY_CTX_free(derive_ctx_bob);
	EVP_PKEY_free(alice_pkey);
	EVP_PKEY_free(bob_pkey);
	EC_GROUP_free(ec_group);
	ERR_free_strings();

	return 0;
}
