#include "person.h"

int main()
{
	// 创建对象
	Person *p = Person_create("Alice", 30);

	// 使用提供的函数接口访问和修改数据
	Person_printInfo(p);

	Person_setAge(p, 31);
	Person_printInfo(p);

	// 销毁对象
	Person_destroy(p);

	return 0;
}
