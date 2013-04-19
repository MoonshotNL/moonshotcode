#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define HASH_SHA1	"SHA1"

void init_mod(void)
{
	OpenSSL_add_all_digests();
}

unsigned char *get_sha1(unsigned char *input, int *md_len)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char *md_value;

	init_mod();

	md_value = calloc(1, sizeof(EVP_MAX_MD_SIZE));

	md = EVP_get_digestbyname(HASH_SHA1);
	if (!md)
	{
		fprintf(stderr, "mod_md5: Error loading the SHA1 engine\n");
		return NULL;
	}

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, input, strlen(input));
	EVP_DigestFinal_ex(mdctx, md_value, md_len);
	EVP_MD_CTX_destroy(mdctx);

	return md_value;
}
