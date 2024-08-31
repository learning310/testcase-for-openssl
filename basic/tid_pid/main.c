#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define NUM_THREADS 5

// 线程函数
void *thread_func(void *arg)
{
	pid_t tid = syscall(SYS_gettid);
	pid_t pid = getpid();
	printf("pid = %d, tid = %d\n", pid, tid);

	return NULL;
}

int main()
{
	pthread_t threads[NUM_THREADS];

	pid_t tid = syscall(SYS_gettid);
	pid_t pid = getpid();
	printf("pid = %d, tid = %d, in %s\n", pid, tid, __func__);

	// 创建线程
	for (int i = 0; i < NUM_THREADS; i++) {
		if (pthread_create(&threads[i], NULL, thread_func, NULL) !=
		    0) {
			perror("Failed to create thread");
			return 1;
		}
	}

	// 等待所有线程完成
	for (int i = 0; i < NUM_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}

	return 0;
}