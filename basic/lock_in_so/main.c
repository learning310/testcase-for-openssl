#include <stdio.h>
#include <pthread.h>
#include <dlfcn.h>
#include <unistd.h>

#define num 10

void (*increment_global_var)();
void (*print_global_var)();

void *thread_func(void *arg)
{
	for (int i = 0; i < 10000; i++) {
		increment_global_var();
		usleep(10);
	}
	print_global_var();

	return NULL;
}

int main()
{
	pthread_t threads[num];
	int i;

	// 打开共享库
	void *handle = dlopen("./libmylib.so", RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, "Error opening library: %s\n", dlerror());
		return -1;
	}

	// 获取函数指针
	increment_global_var = dlsym(handle, "increment_global_var");
	print_global_var = dlsym(handle, "print_global_var");
	if (!increment_global_var || !print_global_var) {
		fprintf(stderr, "Error loading function: %s\n", dlerror());
		dlclose(handle);
		return -1;
	}

	// 创建多个线程
	for (i = 0; i < num; i++) {
		if (pthread_create(&threads[i], NULL, thread_func, NULL) != 0) {
			perror("Failed to create thread");
			return -1;
		}
	}

	// 等待所有线程完成
	for (i = 0; i < num; i++) {
		pthread_join(threads[i], NULL);
	}

	// 关闭共享库
	dlclose(handle);

	return 0;
}
