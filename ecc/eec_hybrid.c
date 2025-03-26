#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define CURVE "secp256k1"
#define CIPHER EVP_aes_256_cbc()

void handle_errors()
{
	ERR_print_errors_fp(stderr);
	abort();
}

EVP_PKEY *generate_key_pair()
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (!pctx)
		handle_errors();

	if (EVP_PKEY_keygen_init(pctx) <= 0)
		handle_errors();
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, OBJ_sn2nid(CURVE)) <=
	    0)
		handle_errors();
	if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
		handle_errors();

	EVP_PKEY_CTX_free(pctx);
	return pkey;
}

unsigned char *derive_shared_secret(EVP_PKEY *private_key,
				    EVP_PKEY *peer_public_key,
				    size_t *secret_len)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
	if (!ctx)
		handle_errors();

	if (EVP_PKEY_derive_init(ctx) <= 0)
		handle_errors();
	if (EVP_PKEY_derive_set_peer(ctx, peer_public_key) <= 0)
		handle_errors();

	if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0)
		handle_errors();
	unsigned char *shared_secret = OPENSSL_malloc(*secret_len);
	if (!shared_secret)
		handle_errors();

	if (EVP_PKEY_derive(ctx, shared_secret, secret_len) <= 0)
		handle_errors();

	EVP_PKEY_CTX_free(ctx);
	return shared_secret;
}

unsigned char *encrypt(const unsigned char *message, size_t message_len,
		       EVP_PKEY *private_key, EVP_PKEY *peer_public_key,
		       size_t *ciphertext_len)
{
	size_t secret_len;
	unsigned char *shared_secret =
		derive_shared_secret(private_key, peer_public_key, &secret_len);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		handle_errors();

	if (EVP_EncryptInit_ex(ctx, CIPHER, NULL, shared_secret, NULL) != 1)
		handle_errors();

	int block_size = EVP_CIPHER_block_size(CIPHER);
	unsigned char *ciphertext = OPENSSL_malloc(message_len + block_size);
	if (!ciphertext)
		handle_errors();

	int len;
	if (EVP_EncryptUpdate(ctx, ciphertext, &len, message, message_len) != 1)
		handle_errors();
	*ciphertext_len = len;

	if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
		handle_errors();
	*ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	OPENSSL_free(shared_secret);

	return ciphertext;
}

unsigned char *decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
		       EVP_PKEY *private_key, EVP_PKEY *peer_public_key,
		       size_t *plaintext_len)
{
	size_t secret_len;
	unsigned char *shared_secret =
		derive_shared_secret(private_key, peer_public_key, &secret_len);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		handle_errors();

	if (EVP_DecryptInit_ex(ctx, CIPHER, NULL, shared_secret, NULL) != 1)
		handle_errors();

	unsigned char *plaintext = OPENSSL_malloc(ciphertext_len);
	if (!plaintext)
		handle_errors();

	int len;
	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
			      ciphertext_len) != 1)
		handle_errors();
	*plaintext_len = len;

	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
		handle_errors();
	*plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	OPENSSL_free(shared_secret);

	return plaintext;
}

int main()
{
	EVP_PKEY *alice_key = generate_key_pair();
	EVP_PKEY *bob_key = generate_key_pair();

	const char *message = "Hello, ECC algorithm!";
	size_t message_len = strlen(message);
	printf("Original message: %s\n", message);

	size_t ciphertext_len;
	unsigned char *ciphertext = encrypt((unsigned char *)message,
					    message_len, alice_key, bob_key,
					    &ciphertext_len);

	printf("Encrypted message (hex): ");
	for (size_t i = 0; i < ciphertext_len; i++) {
		printf("%02x", ciphertext[i]);
	}
	printf("\n");

	size_t plaintext_len;
	unsigned char *decrypted_message = decrypt(
		ciphertext, ciphertext_len, bob_key, alice_key, &plaintext_len);

	printf("Decrypted message: %.*s\n", (int)plaintext_len,
	       decrypted_message);

	OPENSSL_free(ciphertext);
	OPENSSL_free(decrypted_message);
	EVP_PKEY_free(alice_key);
	EVP_PKEY_free(bob_key);

	return 0;
}