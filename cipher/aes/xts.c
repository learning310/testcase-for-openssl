#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

int aes_xts_encrypt_decrypt(const unsigned char *key1, const unsigned char *key2,
			    const unsigned char *iv, const unsigned char *plaintext,
			    int plaintext_len, unsigned char *ciphertext,
			    unsigned char *decryptedtext, int encrypt)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len = 0;
	unsigned char xts_key[64];

	memcpy(xts_key, key1, 32);
	memcpy(xts_key + 32, key2, 32);

	if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
		goto err;

	if (encrypt) {
		if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, xts_key, iv))
			goto err;
	} else {
		if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, xts_key, iv))
			goto err;
	}

	if (encrypt) {
		if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			goto err;
		ciphertext_len = len;

		if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
			goto err;
		ciphertext_len += len;
	} else {
		if (!EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, plaintext_len))
			goto err;
		ciphertext_len = len;

		if (!EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len))
			goto err;
		ciphertext_len += len;
	}

err:
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int main()
{
	// clang-format off
	unsigned char key1[32] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	};
	unsigned char key2[32] = {
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	};
	unsigned char iv[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	};
	unsigned char plaintext[] = {
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
		0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
	};
	// clang-format on
	int plaintext_len = sizeof(plaintext);
	unsigned char ciphertext[1024];
	unsigned char outbuf[1024];

	printf("Plain Text:\n");
	BIO_dump_fp(stdout, plaintext, sizeof(plaintext));

	int cipherlen = aes_xts_encrypt_decrypt(key1, key2, iv, plaintext, plaintext_len,
						ciphertext, outbuf, 1);
	printf("Cipher Text:\n");
	BIO_dump_fp(stdout, ciphertext, cipherlen);

	int outlen = aes_xts_encrypt_decrypt(key1, key2, iv, ciphertext, cipherlen, ciphertext,
					     outbuf, 0);
	printf("Out Text:\n");
	BIO_dump_fp(stdout, outbuf, outlen);

	return 0;
}