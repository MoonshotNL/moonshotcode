#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(int argc, char *argv[])
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len, i;

	OpenSSL_add_all_digests();

	if (argc != 3)
	{
		printf("Usage: %s <Message> <MDType>\n", argv[0]);
		exit(1);
	}

	md = EVP_get_digestbyname(argv[2]);

	if (!md)
	{
		printf("Unknown message digest %s\n", argv[2]);
		exit(1);
	}

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, argv[1], strlen(argv[1]));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);

	printf("%s [%s]: ", argv[1], argv[2]);
	for (i = 0; i < md_len; i++) printf("%02x", md_value[i]);
	printf("\n");

}
