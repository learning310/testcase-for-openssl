#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

int main() {
    EVP_PKEY *pkey;
    FILE *fp;
    EVP_MD_CTX *mdctx;
    unsigned char *sig;
    size_t sig_len;
    const char *data = "data to sign";

    // 读取公钥
    fp = fopen("public_key.pem", "r");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open public key file\n");
        return 1;
    }
    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL) {
        fprintf(stderr, "Unable to read public key\n");
        return 1;
    }

    // 从文件读取签名
    fp = fopen("signature.bin", "rb");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open file to read signature\n");
        EVP_PKEY_free(pkey);
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    sig_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    sig = (unsigned char*)malloc(sig_len);
    if (sig == NULL) {
        fprintf(stderr, "Malloc failed\n");
        fclose(fp);
        EVP_PKEY_free(pkey);
        return 1;
    }
    fread(sig, 1, sig_len, fp);
    fclose(fp);

    // 初始化验证上下文
    mdctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        fprintf(stderr, "EVP_DigestVerifyInit failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        free(sig);
        return 1;
    }

    // 进行验证
    if (EVP_DigestVerifyUpdate(mdctx, data, strlen(data)) != 1) {
        fprintf(stderr, "EVP_DigestVerifyUpdate failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        free(sig);
        return 1;
    }

    // 验证签名
    if (EVP_DigestVerifyFinal(mdctx, sig, sig_len) != 1) {
        fprintf(stderr, "Signature verification failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        free(sig);
        return 1;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    free(sig);

    printf("Signature verified successfully\n");
    return 0;
}
