#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h> // socket, bind, listen, accept
#include <netinet/in.h> // sockaddr_in, AF_INET, INADDR_ANY, htons
#include <arpa/inet.h> // htonl, htons, inet_addr
#include <unistd.h> // close
#include <stdio.h>
#include <string.h>

#define PORT 4433
#define CERT_FILE "ecdsa_cert.pem"
#define KEY_FILE "ecdsa_key.pem"

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

	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx)
		handle_error("Unable to create SSL context");

	if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <=
	    0) {
		handle_error("Error setting certificate");
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		handle_error("Error setting private key");
	}

	SSL_CTX_set_cipher_list(ctx, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		handle_error("Socket creation failed");

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		handle_error("Bind failed");
	}

	if (listen(sock, 1) < 0)
		handle_error("Listen failed");

	printf("Server listening on port %d\n", PORT);

	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	int client_sock =
		accept(sock, (struct sockaddr *)&client_addr, &client_len);
	if (client_sock < 0)
		handle_error("Accept failed");

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, client_sock);

	if (SSL_accept(ssl) <= 0) {
		handle_error("SSL accept failed");
	}

	printf("Connection established with cipher: %s\n", SSL_get_cipher(ssl));

	char buf[256];
	int bytes = SSL_read(ssl, buf, sizeof(buf));
	if (bytes > 0) {
		buf[bytes] = 0;
		printf("Received: %s\n", buf);
	}

	SSL_write(ssl, "Hello from server!", strlen("Hello from server!"));

	SSL_free(ssl);
	close(client_sock);
	close(sock);
	SSL_CTX_free(ctx);
	EVP_cleanup();
	return 0;
}
