#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int encrypt(const char* input, size_t len, uint32_t ms, char** output);
int decrypt(const char* input, size_t len, char** output);
