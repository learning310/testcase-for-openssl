#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

int main() {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    const char *data = "Hello, World!";

    SHA256((unsigned char*)data, strlen(data), hash);

	printf("Data Text:\n");
	BIO_dump_fp(stdout, data, strlen(data));
	printf("Hash Text:\n");
	BIO_dump_fp(stdout, hash, sizeof(hash));

    return 0;
}
