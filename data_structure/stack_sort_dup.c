#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/safestack.h>

// 定义一个简单的结构体
typedef struct {
	int id;
	char *name;
} Person;

// 为Person结构体定义SAFESTACK
DEFINE_STACK_OF(Person);

// 创建和销毁Person的函数
Person *Person_new(int id, const char *name)
{
	Person *p = malloc(sizeof(Person));
	p->id = id;
	p->name = strdup(name);
	return p;
}

void Person_free(Person *p)
{
	free(p->name);
	free(p);
}

// 比较函数：按id排序
int Person_cmp(const Person *const *a, const Person *const *b)
{
	return ((*a)->id - (*b)->id);
}

// 复制函数：创建Person的副本
Person *Person_dup(const Person *src)
{
	return Person_new(src->id, src->name);
}

// 打印栈内容的辅助函数
void print_stack(STACK_OF(Person) * stack, const char *message)
{
	printf("%s\n", message);
	for (int i = 0; i < sk_Person_num(stack); i++) {
		Person *p = sk_Person_value(stack, i);
		printf("Person %d: id=%d, name=%s\n", i, p->id, p->name);
	}
	printf("\n");
}

int main()
{
	// 创建一个Person的SAFESTACK
	STACK_OF(Person) *stack = sk_Person_new(Person_cmp);

	// 添加一些Person到栈中
	sk_Person_push(stack, Person_new(3, "Charlie"));
	sk_Person_push(stack, Person_new(1, "Alice"));
	sk_Person_push(stack, Person_new(2, "Bob"));

	print_stack(stack, "Original stack:");

	// 对栈进行排序
	sk_Person_sort(stack);
	print_stack(stack, "After sorting:");

	// 测试dup功能
	STACK_OF(Person) *dup_stack =
		sk_Person_deep_copy(stack, Person_dup, Person_free);
	if (dup_stack) {
		print_stack(dup_stack, "Duplicated stack:");

		// 修改原始栈中的一个元素
		Person *p = sk_Person_value(stack, 1);
		free(p->name);
		p->name = strdup("Modified Bob");

		print_stack(stack, "Original stack after modification:");
		print_stack(dup_stack,
			    "Duplicated stack (should be unchanged):");

		// 清理复制的栈
		sk_Person_pop_free(dup_stack, Person_free);
	} else {
		printf("Failed to duplicate the stack.\n");
	}

	// 清理原始栈
	sk_Person_pop_free(stack, Person_free);

	return 0;
}