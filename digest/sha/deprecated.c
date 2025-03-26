#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/bio.h>

int main() {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    const char *data = "Hello, World!";

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, strlen(data));
    SHA256_Final(hash, &sha256);

	printf("Data Text:\n");
	BIO_dump_fp(stdout, data, strlen(data));
	printf("Hash Text:\n");
	BIO_dump_fp(stdout, hash, sizeof(hash));

    return 0;
}
