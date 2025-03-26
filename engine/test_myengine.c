#include <stdio.h>
#include <openssl/engine.h>
#include <openssl/rand.h>

int main() {
    ENGINE *e;
    const char *engine_id = "myengine";

    // Load the custom engine
    e = ENGINE_by_id(engine_id);
    if (!e) {
        fprintf(stderr, "Failed to load dynamic engine\n");
        return 1;
    }

    if (!ENGINE_init(e)) {
        fprintf(stderr, "Failed to initialize the engine\n");
        ENGINE_free(e);
        return 1;
    }

    // Set the default RAND method to the custom engine's method
    if (!ENGINE_set_default_RAND(e)) {
        fprintf(stderr, "Failed to set default RAND method\n");
        ENGINE_finish(e);
        ENGINE_free(e);
        return 1;
    }

    // Generate random bytes using the custom engine
    unsigned char rand_bytes[16];
    if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        ENGINE_finish(e);
        ENGINE_free(e);
        return 1;
    }

    // Print the generated random bytes
    printf("Generated random bytes: ");
    for (int i = 0; i < sizeof(rand_bytes); i++) {
        printf("%02x", rand_bytes[i]);
    }
    printf("\n");

    // Clean up
    ENGINE_finish(e);
    ENGINE_free(e);
    ENGINE_cleanup();
    
    return 0;
}
