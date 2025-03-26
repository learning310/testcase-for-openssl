#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main()
{
	const char *data = "Hello, World!";
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int len;

	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

	if ((mdctx = EVP_MD_CTX_new()) == NULL)
		goto err;

	if (!EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL))
		goto err;

	if (!EVP_DigestUpdate(mdctx, data, strlen(data)))
		goto err;

	if (!EVP_DigestFinal_ex(mdctx, hash, &len))
		goto err;

	printf("Data Text:\n");
	BIO_dump_fp(stdout, data, strlen(data));
	printf("Hash Text:\n");
	BIO_dump_fp(stdout, hash, len);

err:
	EVP_MD_CTX_free(mdctx);
	return 0;
}
