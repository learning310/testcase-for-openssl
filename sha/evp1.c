#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

int hash_date(const char *data, const size_t len, unsigned char *hash,
	      unsigned int *hlen)
{
	const EVP_MD *alg = EVP_sha256();
	return EVP_Digest(data, len, hash, hlen, alg, NULL);
}

int main(int argc, char const *argv[])
{
	char *str = "hello world";
	unsigned char hash[64];
	unsigned int hlen;

	if (hash_date(str, strlen(str), hash, &hlen)) {
		printf("hash '%s', return len=%d\nhash=", str, hlen);
		for (int i = 0; i < hlen; i++) {
			printf("%02X", hash[i]);
		}
		printf("\n");
	}

	return 0;
}
