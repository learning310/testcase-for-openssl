#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

void handle_errors(const char *msg)
{
	fprintf(stderr, "Error: %s\n", msg);
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
}

int main()
{
	// 初始化OpenSSL库
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	// 创建SSL上下文
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL) {
		handle_errors("Unable to create SSL context");
	}

	// 创建BIO对象
	BIO *bio = BIO_new_ssl_connect(ctx);
	if (bio == NULL) {
		handle_errors("Unable to create BIO");
	}

	// 设置BIO的目标地址
	BIO_set_conn_hostname(bio, "www.baidu.com:https");

	// 设置SSL BIO的选项
	SSL *ssl = NULL;
	BIO_get_ssl(bio, &ssl);
	if (ssl == NULL) {
		handle_errors("Unable to get SSL pointer");
	}

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	// 尝试连接到目标主机
	if (BIO_do_connect(bio) <= 0) {
		handle_errors("Unable to connect to the server");
	}

	// 尝试握手
	if (BIO_do_handshake(bio) <= 0) {
		handle_errors("Unable to complete SSL handshake");
	}

	// 发送HTTP请求
	const char *request =
		"GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";
	BIO_puts(bio, request);

	// 读取响应
	char buffer[1024];
	int bytes;
	while ((bytes = BIO_read(bio, buffer, sizeof(buffer) - 1)) > 0) {
		buffer[bytes] = '\0';
		printf("%s", buffer);
	}
	printf("\n");

	// 释放资源
	BIO_free_all(bio);
	SSL_CTX_free(ctx);
	EVP_cleanup();

	return 0;
}
