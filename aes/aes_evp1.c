#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

void do_crypt(const unsigned char *in, const unsigned int inlen,
	      unsigned char *out, int do_encrypt, const unsigned char *key,
	      const unsigned char *iv)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, do_encrypt);
	int outlen;
	EVP_CipherUpdate(ctx, out, &outlen, in, inlen);
	int tmplen;
	EVP_CipherFinal_ex(ctx, out + outlen, &tmplen);
	outlen += tmplen;
	EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char const *argv[])
{
	unsigned char key[] = { 0, 1, 2,  3,  4,  5,  6,  7,
				8, 9, 10, 11, 12, 13, 14, 15 };
	unsigned char iv[] = { 0, 1, 2,	 3,  4,	 5,  6,	 7,
			       8, 9, 10, 11, 12, 13, 14, 15 };
	const char *str = "hello world";
	printf("origin data= %s\n", str);

	// encrypt
	unsigned char buf[BUFSIZ] = { 0 };
	do_crypt((const unsigned char *)str, strlen(str), buf, 1, key, iv);
	printf("after encrypt str(hex)= ");
	for (int i = 0; i < 16; i++) {
		printf("%02X", buf[i]);
	}

	// decrypt
	unsigned char bufout[BUFSIZ] = { 0 };
	do_crypt(buf, 16, bufout, 0, key, iv);
	printf("\nafter decrypt data= %s\n", bufout);
	return 0;
}