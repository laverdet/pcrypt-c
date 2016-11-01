#include <stdio.h>
#include "pcrypt.h"

void dump(char* vector, int len) {
	for (int ii = 0; ii < len; ++ii) {
		if (ii > 0) {
			printf((ii % 32) ? " " : "\n");
		}
		printf("%02x", (unsigned char)vector[ii]);
	}
	printf("\n");
}

int main() {
	char* cleartext = "hello";
	printf("cleartext: %s\n\n", cleartext);

	char* encrypted;
	int len = encrypt(cleartext, strlen(cleartext), 1234, &encrypted);
	printf("encrypted:\n");
	dump(encrypted, len);
	printf("\n");

	char* decrypted;
	int len2 = decrypt(encrypted, len, &decrypted);
	printf("decrypted:\n");
	dump(decrypted, len2);

	free(encrypted);
	free(decrypted);
	return 0;
}
