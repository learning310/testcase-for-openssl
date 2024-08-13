#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main() {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    const char *data = "hello world";

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return 1;
    }

    EVP_MD *md = EVP_MD_fetch(NULL, "SHA-256", NULL);
    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)){
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    if (1 != EVP_DigestUpdate(mdctx, data, strlen(data))) {
        fprintf(stderr, "EVP_DigestUpdate failed\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        EVP_MD_CTX_free(mdctx);
        return 1;
    }

    EVP_MD_CTX_free(mdctx);

    printf("SHA-256 hash: ");
    for (unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
