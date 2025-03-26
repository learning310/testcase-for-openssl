#ifndef PERSON_H
#define PERSON_H

// 前向声明结构体类型，具体实现隐藏在.c文件中
// *** 实现面向对象的封装特性的规定，即：只能通过operation访问data ***
typedef struct person Person;

// 提供操作接口
Person *Person_create(const char *name, int age);
void Person_destroy(Person *p);
void Person_setAge(Person *p, int age);
int Person_getAge(const Person *p);
void Person_printInfo(const Person *p);

#endif // PERSON_H
