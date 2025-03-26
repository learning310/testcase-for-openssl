#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RANDOM_BYTES_LEN 32

int main() {
    // 初始化 OpenSSL 库
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return EXIT_FAILURE;
    }

    // 加载 "seed-src" 提供者
    EVP_RAND_CTX *rand_ctx = NULL;
    EVP_RAND *rand_seed_src = EVP_RAND_fetch(NULL, "seed-src", NULL);
    if (rand_seed_src == NULL) {
        fprintf(stderr, "Failed to fetch seed-src provider\n");
        goto cleanup;
    }

    // 创建随机数上下文
    rand_ctx = EVP_RAND_CTX_new(rand_seed_src, NULL);
    if (rand_ctx == NULL) {
        fprintf(stderr, "Failed to create RAND context\n");
        goto cleanup;
    }

    // 设置 OSSL_PARAM 参数（可根据实际需求调整）
    const OSSL_PARAM params[] = {
        OSSL_PARAM_END // 无额外参数，结束符
    };

    // 初始化随机数生成器
    if (EVP_RAND_instantiate(rand_ctx, RANDOM_BYTES_LEN, 0, NULL, 0, params) <= 0) {
        fprintf(stderr, "Failed to instantiate the RAND context\n");
        goto cleanup;
    }

    // 生成随机数
    unsigned char random_bytes[RANDOM_BYTES_LEN];
    if (EVP_RAND_generate(rand_ctx, random_bytes, RANDOM_BYTES_LEN, 0, 0, NULL, 0) <= 0) {
        fprintf(stderr, "Failed to generate random bytes\n");
        goto cleanup;
    }

    // 打印生成的随机数
    printf("Generated random bytes:\n");
    for (int i = 0; i < RANDOM_BYTES_LEN; i++) {
        printf("%02x", random_bytes[i]);
    }
    printf("\n");

cleanup:
    // 清理资源
    if (rand_ctx != NULL)
        EVP_RAND_CTX_free(rand_ctx);
    if (rand_seed_src != NULL)
        EVP_RAND_free(rand_seed_src);

    return EXIT_SUCCESS;
}
