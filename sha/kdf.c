#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

int main() {
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx;
    unsigned char key[32];
    const char *password = "password";
    const unsigned char salt[] = "salt";
    size_t salt_len = strlen((const char*)salt);
    int iter = 10000;

    // 使用 EVP_KDF_fetch 获取 KDF 算法
    kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    if (kdf == NULL) {
        fprintf(stderr, "EVP_KDF_fetch failed\n");
        return 1;
    }

    // 创建和初始化 KDF 上下文
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        fprintf(stderr, "EVP_KDF_CTX_new failed\n");
        EVP_KDF_free(kdf);
        return 1;
    }

    // 设置 KDF 参数
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_octet_string("salt", (void*)salt, salt_len),
        OSSL_PARAM_construct_octet_string("pass", (void*)password, strlen(password)),
        OSSL_PARAM_construct_int("iter", &iter),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_CTX_set_params(kctx, params) != 1) {
        fprintf(stderr, "EVP_KDF_CTX_set_params failed\n");
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        return 1;
    }

    // 派生密钥
    if (EVP_KDF_derive(kctx, key, sizeof(key), NULL) != 1) {
        fprintf(stderr, "EVP_KDF_derive failed\n");
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        return 1;
    }

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);

    printf("Derived key: ");
    for (size_t i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    return 0;
}
