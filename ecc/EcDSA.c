#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>

void handle_errors()
{
	ERR_print_errors_fp(stderr);
	abort();
}

int main()
{
	// 初始化 OpenSSL
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	// 生成 EC 密钥对
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (!pctx)
		handle_errors();

	if (EVP_PKEY_keygen_init(pctx) <= 0)
		handle_errors();
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1) <= 0)
		handle_errors();

	EVP_PKEY *keypair = NULL;
	if (EVP_PKEY_keygen(pctx, &keypair) <= 0)
		handle_errors();

	EVP_PKEY_CTX_free(pctx);

	// 待签名的消息
	const char *message = "Hello, ECDSA!";
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256((unsigned char *)message, strlen(message), hash);

	// 签名
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		handle_errors();

	if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, keypair) <= 0)
		handle_errors();

	size_t sig_len;
	if (EVP_DigestSign(mdctx, NULL, &sig_len, hash, SHA256_DIGEST_LENGTH) <=
	    0)
		handle_errors();

	unsigned char *signature = (unsigned char *)OPENSSL_malloc(sig_len);
	if (!signature)
		handle_errors();

	if (EVP_DigestSign(mdctx, signature, &sig_len, hash,
			   SHA256_DIGEST_LENGTH) <= 0)
		handle_errors();

	printf("Signature generated successfully.\n");

	EVP_MD_CTX_free(mdctx);

	// 验签
	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		handle_errors();

	if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, keypair) <= 0)
		handle_errors();

	int verify_status = EVP_DigestVerify(mdctx, signature, sig_len, hash,
					     SHA256_DIGEST_LENGTH);
	if (verify_status == 1) {
		printf("Signature verified successfully.\n");
	} else if (verify_status == 0) {
		printf("Signature verification failed.\n");
	} else {
		handle_errors();
	}

	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(keypair);
	OPENSSL_free(signature);

	// 清理 OpenSSL
	EVP_cleanup();
	ERR_free_strings();

	return 0;
}
