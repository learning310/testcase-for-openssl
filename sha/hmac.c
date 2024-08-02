#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

int main() {
    const char *key = "secret key";
    const char *data = "hello world";
    unsigned char hmac[EVP_MAX_MD_SIZE];
    size_t hmac_len;

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);

    if (mac == NULL || ctx == NULL) {
        fprintf(stderr, "Unable to create EVP_MAC or EVP_MAC_CTX\n");
        if (mac) EVP_MAC_free(mac);
        if (ctx) EVP_MAC_CTX_free(ctx);
        return 1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };

    if (EVP_MAC_init(ctx, (unsigned char*)key, strlen(key), params) != 1) {
        fprintf(stderr, "EVP_MAC_init failed\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return 1;
    }

    if (EVP_MAC_update(ctx, (unsigned char*)data, strlen(data)) != 1) {
        fprintf(stderr, "EVP_MAC_update failed\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return 1;
    }

    if (EVP_MAC_final(ctx, hmac, &hmac_len, sizeof(hmac)) != 1) {
        fprintf(stderr, "EVP_MAC_final failed\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return 1;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    printf("HMAC-SHA-256: ");
    for (unsigned int i = 0; i < hmac_len; i++) {
        printf("%02x", hmac[i]);
    }
    printf("\n");

    return 0;
}
