#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MSG "This is the message"
#define ERROR_BUFFER_LENGTH 256

// 统一的错误处理函数
void handleErrors(const char *context)
{
	char error_buffer[ERROR_BUFFER_LENGTH];

	// 打印具体的错误上下文
	fprintf(stderr, "Error in %s:\n", context);

	// 使用 OpenSSL 的错误处理机制打印详细错误信息
	unsigned long err;
	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, error_buffer, ERROR_BUFFER_LENGTH);
		fprintf(stderr, "- %s\n", error_buffer);
	}

	exit(EXIT_FAILURE);
}

// 封装 EVP_PKEY_CTX_new 操作
EVP_PKEY_CTX *safe_pkey_ctx_new(int key_type)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(key_type, NULL);
	if (!ctx) {
		handleErrors("Creating PKEY Context");
	}
	return ctx;
}

// 封装密钥生成初始化
void safe_pkey_keygen_init(EVP_PKEY_CTX *ctx)
{
	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		handleErrors("Initializing Key Generation");
	}
}

// 封装密钥生成
void safe_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **pkey)
{
	if (EVP_PKEY_keygen(ctx, pkey) <= 0) {
		handleErrors("Generating Key Pair");
	}
}

unsigned char *sm2_encrypt(EVP_PKEY *pkey, const unsigned char *msg,
			   size_t msg_len, size_t *encrypted_len)
{
	// 初始化加密上下文
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx) {
		handleErrors("Creating Encryption Context");
	}

	// 初始化加密
	if (EVP_PKEY_encrypt_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		handleErrors("Initializing Encryption");
	}

	// 获取加密所需缓冲区大小
	if (EVP_PKEY_encrypt(ctx, NULL, encrypted_len, msg, msg_len) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		handleErrors("Determining Encryption Buffer Size");
	}

	// 分配加密缓冲区
	unsigned char *encrypted = malloc(*encrypted_len);
	if (!encrypted) {
		EVP_PKEY_CTX_free(ctx);
		handleErrors("Allocating Encryption Buffer");
	}

	// 执行加密
	if (EVP_PKEY_encrypt(ctx, encrypted, encrypted_len, msg, msg_len) <=
	    0) {
		free(encrypted);
		EVP_PKEY_CTX_free(ctx);
		handleErrors("Performing Encryption");
	}

	EVP_PKEY_CTX_free(ctx);
	return encrypted;
}

unsigned char *sm2_decrypt(EVP_PKEY *pkey, const unsigned char *encrypted,
			   size_t encrypted_len, size_t *decrypted_len)
{
	// 初始化解密上下文
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx) {
		handleErrors("Creating Decryption Context");
	}

	// 初始化解密
	if (EVP_PKEY_decrypt_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		handleErrors("Initializing Decryption");
	}

	// 获取解密所需缓冲区大小
	if (EVP_PKEY_decrypt(ctx, NULL, decrypted_len, encrypted,
			     encrypted_len) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		handleErrors("Determining Decryption Buffer Size");
	}

	// 分配解密缓冲区
	unsigned char *decrypted = malloc(*decrypted_len);
	if (!decrypted) {
		EVP_PKEY_CTX_free(ctx);
		handleErrors("Allocating Decryption Buffer");
	}

	// 执行解密
	if (EVP_PKEY_decrypt(ctx, decrypted, decrypted_len, encrypted,
			     encrypted_len) <= 0) {
		free(decrypted);
		EVP_PKEY_CTX_free(ctx);
		handleErrors("Performing Decryption");
	}

	EVP_PKEY_CTX_free(ctx);
	return decrypted;
}

int main()
{
	// 初始化 OpenSSL 错误处理
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	// 创建 SM2 密钥上下文
	EVP_PKEY_CTX *ctx = safe_pkey_ctx_new(EVP_PKEY_SM2);

	// 初始化密钥生成
	safe_pkey_keygen_init(ctx);

	// 生成密钥对
	EVP_PKEY *pkey = NULL;
	safe_pkey_keygen(ctx, &pkey);

	// 加密
	size_t encrypted_len;
	unsigned char *encrypted = sm2_encrypt(pkey, (unsigned char *)MSG,
					       strlen(MSG), &encrypted_len);
	printf("SM2 Encryption successful, encrypted length: %zu\n",
	       encrypted_len);

	// 解密
	size_t decrypted_len;
	unsigned char *decrypted =
		sm2_decrypt(pkey, encrypted, encrypted_len, &decrypted_len);
	printf("SM2 Decryption successful, decrypted message: %.*s\n",
	       (int)decrypted_len, decrypted);

	// 释放资源
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	free(encrypted);
	free(decrypted);

	// 清理 OpenSSL 错误处理资源
	ERR_free_strings();

	return 0;
}