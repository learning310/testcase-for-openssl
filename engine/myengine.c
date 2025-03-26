#include <openssl/engine.h>
#include <openssl/rand.h>
#include <stdio.h>

// Custom RAND method implementation
static int my_rand_bytes(unsigned char *buf, int num)
{
    for (int i = 0; i < num; i++) {
        buf[i] = rand() % 256;
    }
    return 1;
}

static RAND_METHOD my_rand_meth = {
    .bytes = my_rand_bytes,
    .status = NULL,
};

// Engine initialization function
static int bind(ENGINE *e, const char *id)
{
    if (!ENGINE_set_id(e, "myengine") ||
        !ENGINE_set_name(e, "My custom engine") ||
        !ENGINE_set_RAND(e, &my_rand_meth)) {
        return 0;
    }

    printf("My custom engine loaded\n");
    return 1;
}

// Engine binding function
IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
