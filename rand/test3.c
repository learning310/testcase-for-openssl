#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	EVP_RAND *rand;
	EVP_RAND_CTX *seed, *rctx;
	unsigned char bytes[100];
	OSSL_PARAM params[2], *p = params;
	unsigned int strength = 128;

	/* Create and instantiate a seed source */
	rand = EVP_RAND_fetch(NULL, "SEED-SRC", NULL);
	seed = EVP_RAND_CTX_new(rand, NULL);
	EVP_RAND_instantiate(seed, strength, 0, NULL, 0, NULL);
	EVP_RAND_free(rand);

	/* Feed this into a DRBG */
	rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
	rctx = EVP_RAND_CTX_new(rand, seed);
	EVP_RAND_free(rand);

	/* Configure the DRBG */
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
						SN_aes_256_ctr, 0);
	*p = OSSL_PARAM_construct_end();
	EVP_RAND_instantiate(rctx, strength, 0, NULL, 0, params);

	EVP_RAND_generate(rctx, bytes, sizeof(bytes), strength, 0, NULL, 0);

	printf("Generated random bytes:\n");
    for (int i = 0; i < sizeof(bytes); i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
	EVP_RAND_CTX_free(rctx);
	EVP_RAND_CTX_free(seed);

	return 0;
}
