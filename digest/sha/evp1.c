#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

int hash_date(const char *data, const size_t len, unsigned char *hash, unsigned int *hlen)
{
	const EVP_MD *alg = EVP_sha256();
	return EVP_Digest(data, len, hash, hlen, alg, NULL);
}

int main(int argc, char const *argv[])
{
	char *data = "Hello, World!";
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned int hash_len;

	hash_date(data, strlen(data), hash, &hash_len);

	printf("Data Text:\n");
	BIO_dump_fp(stdout, data, strlen(data));
	printf("Hash Text:\n");
	BIO_dump_fp(stdout, hash, hash_len);
	return 0;
}
