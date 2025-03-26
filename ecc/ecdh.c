#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define CHECK_NULL(ptr)                                                  \
	if ((ptr) == NULL) {                                             \
		fprintf(stderr, "Error at %s:%d\n", __FILE__, __LINE__); \
		ERR_print_errors_fp(stderr);                             \
		goto cleanup;                                            \
	}

#define CURVE NID_X9_62_prime256v1 // 使用 P-256 曲线
#define AES_KEY_LEN 32 // AES-256
#define AES_GCM_IV_LEN 12
#define AES_GCM_TAG_LEN 16

// 生成 ECC 密钥对
EVP_PKEY *generate_keypair(void)
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

	if (ctx == NULL)
		return NULL;

	if (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, CURVE) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	EVP_PKEY_CTX_free(ctx);
	return pkey;
}

// 计算 ECDH 共享密钥
unsigned char *derive_shared_secret_key(EVP_PKEY *priv_key,
					EVP_PKEY *peer_pub_key,
					size_t *secret_len)
{
	unsigned char *shared_secret = NULL;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);

	if (ctx == NULL)
		return NULL;

	if (EVP_PKEY_derive_init(ctx) <= 0 ||
	    EVP_PKEY_derive_set_peer(ctx, peer_pub_key) <= 0 ||
	    EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	shared_secret = OPENSSL_malloc(*secret_len);
	if (shared_secret == NULL ||
	    EVP_PKEY_derive(ctx, shared_secret, secret_len) <= 0) {
		OPENSSL_free(shared_secret);
		shared_secret = NULL;
	}

	EVP_PKEY_CTX_free(ctx);
	return shared_secret;
}

// 使用 AES-GCM 加密数据
int encrypt_data(const unsigned char *key, const unsigned char *plaintext,
		 size_t plaintext_len, unsigned char *ciphertext,
		 unsigned char *tag, unsigned char *iv)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len, ciphertext_len = 0;

	// 生成随机 IV
	if (!RAND_bytes(iv, AES_GCM_IV_LEN)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	if (!EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), key, iv, NULL) ||
	    !EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
			       plaintext_len)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	ciphertext_len = len;

	if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) ||
	    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN,
				 tag)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

// 使用 AES-GCM 解密数据
int decrypt_data(const unsigned char *key, const unsigned char *ciphertext,
		 size_t ciphertext_len, const unsigned char *tag,
		 const unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int len, plaintext_len = 0;

	if (!EVP_DecryptInit_ex2(ctx, EVP_aes_256_gcm(), key, iv, NULL) ||
	    !EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
			       ciphertext_len)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	plaintext_len = len;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN,
				 (void *)tag) ||
	    !EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}

	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

int main()
{
	EVP_PKEY *alice_keypair = NULL;
	EVP_PKEY *bob_keypair = NULL;
	unsigned char *shared_secret_bob = NULL;
	unsigned char *shared_secret_alice = NULL;
	size_t secret_len;
	int result = 1;

	// 用于加解密的缓冲区
	const char *message = "Hello, Alice! This is a secret message.";
	size_t message_len = strlen(message);
	unsigned char ciphertext[1024];
	unsigned char decrypted[1024];
	unsigned char tag[AES_GCM_TAG_LEN];
	unsigned char iv[AES_GCM_IV_LEN];
	int ciphertext_len, decrypted_len;

	// 初始化 OpenSSL
	OpenSSL_add_all_algorithms();

	// 生成 Alice 的密钥对
	alice_keypair = generate_keypair();
	CHECK_NULL(alice_keypair);

	// 生成 Bob 的密钥对
	bob_keypair = generate_keypair();
	CHECK_NULL(bob_keypair);

	// Bob 计算共享密钥
	shared_secret_bob = derive_shared_secret_key(bob_keypair, alice_keypair,
						     &secret_len);
	CHECK_NULL(shared_secret_bob);

	// Alice 计算共享密钥
	shared_secret_alice = derive_shared_secret_key(
		alice_keypair, bob_keypair, &secret_len);
	CHECK_NULL(shared_secret_alice);

	// 验证双方计算的共享密钥是否相同
	if (memcmp(shared_secret_bob, shared_secret_alice, secret_len) != 0) {
		fprintf(stderr, "Shared secrets do not match!\n");
		goto cleanup;
	}

	// Bob 加密消息
	ciphertext_len = encrypt_data(shared_secret_bob,
				      (unsigned char *)message, message_len,
				      ciphertext, tag, iv);
	if (ciphertext_len < 0) {
		fprintf(stderr, "Encryption failed!\n");
		goto cleanup;
	}

	// Alice 解密消息
	decrypted_len = decrypt_data(shared_secret_alice, ciphertext,
				     ciphertext_len, tag, iv, decrypted);
	if (decrypted_len < 0) {
		fprintf(stderr, "Decryption failed!\n");
		goto cleanup;
	}

	decrypted[decrypted_len] = '\0';
	printf("Original message: %s\n", message);
	printf("Decrypted message: %s\n", decrypted);
	result = 0; // 成功

cleanup:
	// 清理资源
	EVP_PKEY_free(alice_keypair);
	EVP_PKEY_free(bob_keypair);
	OPENSSL_free(shared_secret_bob);
	OPENSSL_free(shared_secret_alice);
	EVP_cleanup();

	return result;
}