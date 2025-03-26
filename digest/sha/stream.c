#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main()
{
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;
	const char *data[] = { "first", "second", "third" };
	size_t data_count = sizeof(data) / sizeof(data[0]);
	EVP_MD_CTX *mdctx;

	if ((mdctx = EVP_MD_CTX_new()) == NULL)
		goto err;

	if (!EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		goto err;

	for (size_t i = 0; i < data_count; i++) {
		if (!EVP_DigestUpdate(mdctx, data[i], strlen(data[i])))
			goto err;
	}

	if (!EVP_DigestFinal_ex(mdctx, hash, &hash_len))
		goto err;

	printf("Hash Text:\n");
	BIO_dump_fp(stdout, hash, hash_len);

err:
	EVP_MD_CTX_free(mdctx);
	return 0;
}
