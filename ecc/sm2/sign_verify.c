#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

void handle_errors()
{
	ERR_print_errors_fp(stderr);
	abort();
}

// 生成SM2密钥对
EVP_PKEY *generate_sm2_key()
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;

	// 创建SM2参数上下文
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
	if (!ctx) {
		handle_errors();
		return NULL;
	}

	// 初始化参数生成
	if (EVP_PKEY_paramgen_init(ctx) <= 0) {
		handle_errors();
		goto cleanup;
	}

	// 设置SM2曲线
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, EVP_PKEY_SM2) <= 0) {
		handle_errors();
		goto cleanup;
	}

	EVP_PKEY *params = NULL;
	if (EVP_PKEY_paramgen(ctx, &params) <= 0) {
		handle_errors();
		goto cleanup;
	}

	// 创建密钥生成上下文
	EVP_PKEY_CTX_free(ctx);
	ctx = EVP_PKEY_CTX_new(params, NULL);
	if (!ctx) {
		EVP_PKEY_free(params);
		handle_errors();
		return NULL;
	}

	// 初始化密钥生成
	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		handle_errors();
		goto cleanup;
	}

	// 生成密钥对
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		handle_errors();
		goto cleanup;
	}

cleanup:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(params);
	return pkey;
}

// SM2签名函数
int sm2_sign(EVP_PKEY *pkey, const unsigned char *message, size_t message_len,
	     unsigned char *signature, size_t *sig_len)
{
	EVP_MD_CTX *md_ctx = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	int ret = 0;

	// 创建摘要上下文
	md_ctx = EVP_MD_CTX_new();
	if (!md_ctx) {
		handle_errors();
		return 0;
	}

	// 初始化签名，使用SM3摘要算法
	if (EVP_DigestSignInit(md_ctx, &pctx, EVP_sm3(), NULL, pkey) <= 0) {
		handle_errors();
		goto cleanup;
	}

	// 计算签名
	if (EVP_DigestSignUpdate(md_ctx, message, message_len) <= 0) {
		handle_errors();
		goto cleanup;
	}

	// 获取签名长度
	if (EVP_DigestSignFinal(md_ctx, NULL, sig_len) <= 0) {
		handle_errors();
		goto cleanup;
	}

	// 生成实际签名
	if (EVP_DigestSignFinal(md_ctx, signature, sig_len) <= 0) {
		handle_errors();
		goto cleanup;
	}

	ret = 1;

cleanup:
	EVP_MD_CTX_free(md_ctx);
	return ret;
}

// SM2验签函数
int sm2_verify(EVP_PKEY *pkey, const unsigned char *message, size_t message_len,
	       const unsigned char *signature, size_t sig_len)
{
	EVP_MD_CTX *md_ctx = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	int ret = 0;

	// 创建摘要上下文
	md_ctx = EVP_MD_CTX_new();
	if (!md_ctx) {
		handle_errors();
		return 0;
	}

	// 初始化验签
	if (EVP_DigestVerifyInit(md_ctx, &pctx, EVP_sm3(), NULL, pkey) <= 0) {
		handle_errors();
		goto cleanup;
	}

	// 更新待验证的消息
	if (EVP_DigestVerifyUpdate(md_ctx, message, message_len) <= 0) {
		handle_errors();
		goto cleanup;
	}

	// 验证签名
	ret = EVP_DigestVerifyFinal(md_ctx, signature, sig_len);

cleanup:
	EVP_MD_CTX_free(md_ctx);
	return ret;
}

// 打印十六进制数据
void print_hex(const unsigned char *data, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		printf("%02x", data[i]);
	}
	printf("\n");
}

int main()
{
	EVP_PKEY *pkey = NULL;
	unsigned char message[] = "Hello, SM2!";
	unsigned char signature[256];
	size_t sig_len = sizeof(signature);

	// 初始化OpenSSL
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	// 生成SM2密钥对
	pkey = generate_sm2_key();
	if (!pkey) {
		fprintf(stderr, "密钥生成失败\n");
		return 1;
	}
	printf("SM2密钥对生成成功\n");

	// 签名消息
	if (!sm2_sign(pkey, message, strlen((char *)message), signature,
		      &sig_len)) {
		fprintf(stderr, "签名失败\n");
		EVP_PKEY_free(pkey);
		return 1;
	}
	printf("SM2签名成功，签名长度: %zu\n", sig_len);
	printf("签名值: ");
	print_hex(signature, sig_len);

	// 验证签名
	if (sm2_verify(pkey, message, strlen((char *)message), signature,
		       sig_len) == 1) {
		printf("SM2签名验证成功\n");
	} else {
		printf("SM2签名验证失败\n");
	}

	// 清理资源
	EVP_PKEY_free(pkey);
	EVP_cleanup();
	ERR_free_strings();

	return 0;
}