#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

void do_crypt(unsigned char *in, int inlen, unsigned char *out, int *outlen, int do_encrypt,
	      unsigned char *key, unsigned char *iv)
{
	int tmplen;
	EVP_CIPHER_CTX *ctx;
	if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
		goto err;
	if (!EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, do_encrypt))
		goto err;
	if (!EVP_CipherUpdate(ctx, out, outlen, in, inlen))
		goto err;
	if (!EVP_CipherFinal_ex(ctx, out + *outlen, &tmplen))
		goto err;
	*outlen += tmplen;

err:
	EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char *argv[])
{
	unsigned char key[] = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	};
	unsigned char iv[] = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	};
	unsigned char plaintext[] = {
		0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
		0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
	};
	unsigned char ciphertext[1024];
	unsigned char outbuf[1024];
	int cipherlen, outlen;

	printf("Plain Text:\n");
	BIO_dump_fp(stdout, plaintext, sizeof(plaintext));

	do_crypt(plaintext, sizeof(plaintext), ciphertext, &cipherlen, 1, key, iv);
	printf("Cipher Text:\n");
	BIO_dump_fp(stdout, ciphertext, cipherlen);

	do_crypt(ciphertext, cipherlen, outbuf, &outlen, 0, key, iv);
	printf("Out Text:\n");
	BIO_dump_fp(stdout, outbuf, outlen);

	return 0;
}
