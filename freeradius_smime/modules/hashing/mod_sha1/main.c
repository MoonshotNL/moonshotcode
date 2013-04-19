#include <stdio.h>
#include <stdlib.h>
#include "mod_sha1.h"

int main(void)
{
	unsigned char *message;
	int i, *md_len;

	md_len = calloc(1, sizeof(int));

	message = get_sha1("Test Message", md_len);

	printf("[SHA-1] Test Message: ");
	for (i = 0; i < *md_len; i++) printf("%02x", message[i]);
	printf("\n");
}
