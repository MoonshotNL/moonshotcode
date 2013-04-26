#include <stdio.h>
#include <string.h>
#include "mod_base64.h"

int main(void)
{
	char *outstr = base64_encode("Hello World!\n", strlen("Hello World!\n"));
	printf("%s\n", outstr);
	return 0;
}
