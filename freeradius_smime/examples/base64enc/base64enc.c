#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("Missing argument\n");
		exit(1);
	}

	BIO *bio, *b64;
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	BIO_write(bio, argv[1], strlen(argv[1]));
	BIO_flush(bio);

	BIO_free_all(bio);
	return 0;
}
