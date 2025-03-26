#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define HOST "127.0.0.1"
#define PORT 4433

void handle_error(const char *msg)
{
	perror(msg);
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
}

int main()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	const SSL_METHOD *method = TLS_client_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx)
		handle_error("Unable to create SSL context");

	SSL_CTX_set_cipher_list(ctx, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		handle_error("Socket creation failed");

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	inet_pton(AF_INET, HOST, &addr.sin_addr);

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		handle_error("Connection failed");
	}

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);

	if (SSL_connect(ssl) <= 0) {
		handle_error("SSL connect failed");
	}

	printf("Connected with cipher: %s\n", SSL_get_cipher(ssl));

	SSL_write(ssl, "Hello from client!", strlen("Hello from client!"));

	char buf[256];
	int bytes = SSL_read(ssl, buf, sizeof(buf));
	if (bytes > 0) {
		buf[bytes] = '\0';
		printf("Received: %s\n", buf);
	}

	SSL_free(ssl);
	close(sock);
	SSL_CTX_free(ctx);
	EVP_cleanup();
	return 0;
}
