#include <openssl/engine.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>

#define RANDOM_BYTES 16

void print_bytes(const unsigned char *bytes, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		printf("%02x", bytes[i]);
	}
	printf("\n");
}

int main()
{
	ENGINE *rdrand_engine = NULL;

	// 初始化 OpenSSL 引擎
	ENGINE_load_builtin_engines();

	// 加载 Intel RDRAND 引擎
	rdrand_engine = ENGINE_by_id("rdrand");
	if (!rdrand_engine) {
		fprintf(stderr, "Error: RDRAND engine not available\n");
		return EXIT_FAILURE;
	}

	if (!ENGINE_init(rdrand_engine)) {
		fprintf(stderr, "Error: Failed to initialize RDRAND engine\n");
		ENGINE_free(rdrand_engine);
		return EXIT_FAILURE;
	}

	printf("Successfully loaded and initialized RDRAND engine.\n");

	// 设置为默认随机数生成器引擎
	if (!ENGINE_set_default(rdrand_engine, ENGINE_METHOD_RAND)) {
		fprintf(stderr,
			"Error: Failed to set RDRAND engine as default for RAND\n");
		ENGINE_finish(rdrand_engine);
		ENGINE_free(rdrand_engine);
		return EXIT_FAILURE;
	}

	// 生成随机数
	unsigned char buffer[RANDOM_BYTES];
	if (RAND_bytes(buffer, RANDOM_BYTES) != 1) {
		fprintf(stderr,
			"Error: Failed to generate random bytes using RDRAND engine\n");
		ENGINE_finish(rdrand_engine);
		ENGINE_free(rdrand_engine);
		return EXIT_FAILURE;
	}

	printf("Generated random bytes: ");
	print_bytes(buffer, RANDOM_BYTES);

	// 清理并释放资源
	ENGINE_finish(rdrand_engine);
	ENGINE_free(rdrand_engine);

	return EXIT_SUCCESS;
}
