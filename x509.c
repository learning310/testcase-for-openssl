#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOSTNAME "www.bing.com"
#define PORT "443"

void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	EVP_cleanup();
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLS_client_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

int create_socket(const char *hostname, const char *port)
{
	struct addrinfo hints, *res;
	int sockfd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(hostname, port, &hints, &res) != 0) {
		perror("getaddrinfo");
		exit(EXIT_FAILURE);
	}

	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd < 0) {
		perror("Unable to create socket");
		freeaddrinfo(res);
		exit(EXIT_FAILURE);
	}

	if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
		perror("Unable to connect");
		close(sockfd);
		freeaddrinfo(res);
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(res);
	return sockfd;
}

void print_certificate_info(X509 *cert)
{
	if (cert) {
		char *line;

		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);

		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);

		printf("Version: %ld\n", X509_get_version(cert) + 1);

		ASN1_INTEGER *serial = X509_get_serialNumber(cert);
		BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
		char *serial_str = BN_bn2hex(bn);
		printf("Serial Number: %s\n", serial_str);
		BN_free(bn);
		OPENSSL_free(serial_str);

		const EVP_MD *sigalg =
			EVP_get_digestbynid(X509_get_signature_nid(cert));
		printf("Signature Algorithm: %s\n", EVP_MD_name(sigalg));

		BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

		printf("Valid From: ");
		ASN1_TIME_print(bio_out, X509_get_notBefore(cert));
		printf("\nValid Until: ");
		ASN1_TIME_print(bio_out, X509_get_notAfter(cert));
		printf("\n");

		EVP_PKEY *pkey = X509_get_pubkey(cert);
		PEM_write_bio_PUBKEY(bio_out, pkey);
		BIO_free(bio_out);
		EVP_PKEY_free(pkey);
	} else {
		printf("No certificate provided by the peer\n");
	}
}

int main(int argc, char **argv)
{
	SSL_CTX *ctx;
	SSL *ssl;
	int server;

	init_openssl();
	ctx = create_context();

	server = create_socket(HOSTNAME, PORT);

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, server);

	if (SSL_connect(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
	} else {
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		X509 *cert = SSL_get_peer_certificate(ssl);
		if (X509_verify(cert, X509_get_pubkey(cert)) == 1) {
			printf("Certificate signature is valid.\n");
		} else {
			printf("Certificate signature is invalid.\n");
		}
		print_certificate_info(cert);
		X509_free(cert);
	}

	SSL_free(ssl);
	close(server);
	SSL_CTX_free(ctx);
	cleanup_openssl();

	return 0;
}
