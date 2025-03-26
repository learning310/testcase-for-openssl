#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PUB_KEY_PATH \
	"/home/alansong/crypto/testcase-for-openssl/sm2/sm2_public_key.pem"
#define PRIV_KEY_PATH \
	"/home/alansong/crypto/testcase-for-openssl/sm2/sm2_private_key.pem"
#define MSG "This is the message"

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
}

EVP_PKEY *load_key(const char *path, int is_public)
{
	FILE *key_file = fopen(path, "r");
	if (!key_file) {
		perror("Unable to open key file");
		return NULL;
	}
	EVP_PKEY *key = is_public ?
				PEM_read_PUBKEY(key_file, NULL, NULL, NULL) :
				PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
	fclose(key_file);
	if (!key)
		handleErrors();
	return key;
}

unsigned char *sm2_encrypt(EVP_PKEY *pkey, const unsigned char *msg,
			   size_t msg_len, size_t *encrypted_len)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0)
		handleErrors();

	if (EVP_PKEY_encrypt(ctx, NULL, encrypted_len, msg, msg_len) <= 0)
		handleErrors();
	unsigned char *encrypted = malloc(*encrypted_len);
	if (!encrypted ||
	    EVP_PKEY_encrypt(ctx, encrypted, encrypted_len, msg, msg_len) <= 0)
		handleErrors();

	EVP_PKEY_CTX_free(ctx);
	return encrypted;
}

unsigned char *sm2_decrypt(EVP_PKEY *pkey, const unsigned char *encrypted,
			   size_t encrypted_len, size_t *decrypted_len)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0)
		handleErrors();

	if (EVP_PKEY_decrypt(ctx, NULL, decrypted_len, encrypted,
			     encrypted_len) <= 0)
		handleErrors();
	unsigned char *decrypted = malloc(*decrypted_len);
	if (!decrypted || EVP_PKEY_decrypt(ctx, decrypted, decrypted_len,
					   encrypted, encrypted_len) <= 0)
		handleErrors();

	EVP_PKEY_CTX_free(ctx);
	return decrypted;
}

int main()
{
	EVP_PKEY *pubkey = load_key(PUB_KEY_PATH, 1);
	EVP_PKEY *privkey = load_key(PRIV_KEY_PATH, 0);
	if (!pubkey || !privkey)
		return -1;

	size_t encrypted_len;
	unsigned char *encrypted = sm2_encrypt(pubkey, (unsigned char *)MSG,
					       strlen(MSG), &encrypted_len);
	printf("SM2 Encryption successful, encrypted length: %zu\n",
	       encrypted_len);

	size_t decrypted_len;
	unsigned char *decrypted =
		sm2_decrypt(privkey, encrypted, encrypted_len, &decrypted_len);
	printf("SM2 Decryption successful, decrypted message: %.*s\n",
	       (int)decrypted_len, decrypted);

	EVP_PKEY_free(pubkey);
	EVP_PKEY_free(privkey);
	free(encrypted);
	free(decrypted);

	return 0;
}
