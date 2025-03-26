// 适用于3.1以下
#include <stdio.h>
#include <string.h>
#include <openssl/lhash.h>

// 定义一个简单的结构体
typedef struct {
    int id;
    char name[50];
} Person;

// 哈希函数
static unsigned long person_hash(const Person *p)
{
    return p->id;
}

// 比较函数
static int person_cmp(const Person *a, const Person *b)
{
    return (a->id - b->id);
}

// 使用DEFINE_LHASH_OF_EX宏定义Person类型的lhash
DEFINE_LHASH_OF(Person);

int main()
{
    LHASH_OF(Person) *people;
    Person p1 = {1, "Alice"};
    Person p2 = {2, "Bob"};
    Person p3 = {3, "Charlie"};
    Person search_key = {2, ""};
    Person *found;

    people = lh_Person_new(person_hash, person_cmp);
    if (!people) {
        fprintf(stderr, "Failed to create lhash\n");
        return 1;
    }

    // 添加一些数据
    lh_Person_insert(people, &p1);
    lh_Person_insert(people, &p2);
    lh_Person_insert(people, &p3);

    // 查找数据
    found = lh_Person_retrieve(people, &search_key);
    if (found) {
        printf("Found: ID=%d, Name=%s\n", found->id, found->name);
    } else {
        printf("Person with ID 2 not found\n");
    }

    // 删除数据
    lh_Person_delete(people, &p2);

    // 再次查找，确认删除
    found = lh_Person_retrieve(people, &search_key);
    if (found) {
        printf("Found: ID=%d, Name=%s\n", found->id, found->name);
    } else {
        printf("Person with ID 2 not found after deletion\n");
    }

    // 清理
    lh_Person_free(people);

    return 0;
}