#include <stdio.h>
#include <openssl/rand.h>

#define RANDOM_BYTES 16 // 生成的随机字节数

int main()
{
	unsigned char buffer[RANDOM_BYTES];

	// 初始化 OpenSSL 随机数生成器
	if (RAND_status() != 1) {
		fprintf(stderr, "随机数生成器未初始化或未充分种子化。\n");
		return 1;
	}

	// 生成随机数
	if (RAND_bytes(buffer, RANDOM_BYTES) != 1) {
		fprintf(stderr, "随机数生成失败。\n");
		return 1;
	}

	// 打印生成的随机数（以十六进制格式）
	printf("生成的随机数：\n");
	for (int i = 0; i < RANDOM_BYTES; i++) {
		printf("%02x", buffer[i]);
	}
	printf("\n");

	return 0;
}
