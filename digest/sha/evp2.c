#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main()
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned int hash_len;
	const char *data = "Hello, World!";
	EVP_MD_CTX *mdctx;

	if ((mdctx = EVP_MD_CTX_new()) == NULL)
		goto err;

	EVP_MD *md = EVP_MD_fetch(NULL, "SHA-256", NULL);
	if (!EVP_DigestInit_ex(mdctx, md, NULL))
		goto err;

	if (!EVP_DigestUpdate(mdctx, data, strlen(data)))
		goto err;

	if (!EVP_DigestFinal_ex(mdctx, hash, &hash_len))
		goto err;

	printf("Data Text:\n");
	BIO_dump_fp(stdout, data, strlen(data));
	printf("Hash Text:\n");
	BIO_dump_fp(stdout, hash, hash_len);

err:
	EVP_MD_CTX_free(mdctx);
	return 0;
}
