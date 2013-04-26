#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

int main(void)
{
	BIO *bio, *b64, *bio_out;
	char inbuf[512];
	int inlen;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(stdin, BIO_NOCLOSE);
	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	while ((inlen = BIO_read(bio, inbuf, 512)) > 0)
	{
		BIO_write(bio_out, inbuf, inlen);
	}

	BIO_free_all(bio);

	fprintf(stdout, "\n");

	return 0;
}
