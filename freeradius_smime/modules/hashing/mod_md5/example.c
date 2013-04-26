#include <stdio.h>
#include <stdlib.h>
#include "mod_md5.h"

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "Argument missing\n");
		exit(1);
	}

	unsigned char *string = argv[1];
	unsigned char *returnval;
	int md_len, i;

	returnval = get_md5(string, &md_len);

	for (i = 0; i < md_len; i++)
	{
		printf("%02x", returnval[i]);
	}
	printf("\n");
}
