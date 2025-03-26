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

    // 读取私钥
    fp = fopen("private_key.pem", "r");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open private key file\n");
        return 1;
    }
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL) {
        fprintf(stderr, "Unable to read private key\n");
        return 1;
    }

    // 初始化签名上下文
    mdctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        fprintf(stderr, "EVP_DigestSignInit failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    // 进行签名
    if (EVP_DigestSignUpdate(mdctx, data, strlen(data)) != 1) {
        fprintf(stderr, "EVP_DigestSignUpdate failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    // 获取签名长度
    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) != 1) {
        fprintf(stderr, "EVP_DigestSignFinal failed (length)\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    sig = (unsigned char*)malloc(sig_len);
    if (sig == NULL) {
        fprintf(stderr, "Malloc failed\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    // 获取签名
    if (EVP_DigestSignFinal(mdctx, sig, &sig_len) != 1) {
        fprintf(stderr, "EVP_DigestSignFinal failed (signature)\n");
        free(sig);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    // 将签名写入文件
    fp = fopen("signature.bin", "wb");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open file to write signature\n");
        free(sig);
        return 1;
    }
    fwrite(sig, 1, sig_len, fp);
    fclose(fp);

    free(sig);

    printf("Signature written to signature.bin\n");
    return 0;
}
