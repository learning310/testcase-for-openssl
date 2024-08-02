#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main() {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    const char *data[] = {
        "first",
        "second",
        "third"
    };
    size_t data_count = sizeof(data) / sizeof(data[0]);

    // 创建和初始化上下文
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return 1;
    }

    // 初始化哈希算法
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    // 多次更新哈希上下文
    for (size_t i = 0; i < data_count; i++) {
        if (1 != EVP_DigestUpdate(mdctx, data[i], strlen(data[i]))) {
            fprintf(stderr, "EVP_DigestUpdate failed at iteration %zu\n", i);
            EVP_MD_CTX_free(mdctx);
            return 1;
        }
    }

    // 完成哈希计算
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    // 释放上下文
    EVP_MD_CTX_free(mdctx);

    // 输出结果
    printf("SHA-256 hash: ");
    for (unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
