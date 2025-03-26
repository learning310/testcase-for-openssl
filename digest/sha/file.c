#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define BUFFER_SIZE 1024

void sha256_hash_file(const char *filename)
{
	FILE *file;
	EVP_MD_CTX *mdctx;
	size_t bytes_read;
	unsigned int hash_len;
	unsigned char buffer[BUFFER_SIZE];
	unsigned char hash[SHA256_DIGEST_LENGTH];

	if ((file = fopen(filename, "rb")) == NULL) {
		perror("Unable to open file");
		return;
	}

	if ((mdctx = EVP_MD_CTX_new()) == NULL)
		goto err;

	if (!EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		goto err;

	while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
		if (!EVP_DigestUpdate(mdctx, buffer, bytes_read))
			goto err;
	}

	if (ferror(file))
		goto err;

	if (!EVP_DigestFinal_ex(mdctx, hash, &hash_len))
		goto err;

	printf("Hash Text:\n");
	BIO_dump_fp(stdout, hash, hash_len);

err:
	fclose(file);
	EVP_MD_CTX_free(mdctx);
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	sha256_hash_file(argv[1]);

	return 0;
}
