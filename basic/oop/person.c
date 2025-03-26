#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "person.h"

// 定义结构体，数据仅在此文件内可见
struct person {
	char name[50];
	int age;
};

// 创建并初始化对象
Person *Person_create(const char *name, int age)
{
	Person *p = (Person *)malloc(sizeof(Person));
	if (p != NULL) {
		strncpy(p->name, name, sizeof(p->name) - 1);
		p->name[sizeof(p->name) - 1] = '\0';
		p->age = age;
	}
	return p;
}

// 销毁对象，释放内存
void Person_destroy(Person *p)
{
	if (p != NULL) {
		free(p);
	}
}

// 设置年龄
void Person_setAge(Person *p, int age)
{
	if (p != NULL) {
		p->age = age;
	}
}

// 获取年龄
int Person_getAge(const Person *p)
{
	if (p != NULL) {
		return p->age;
	}
	return -1; // 返回错误值
}

// 打印信息
void Person_printInfo(const Person *p)
{
	if (p != NULL) {
		printf("Name: %s, Age: %d\n", p->name, p->age);
	}
}
