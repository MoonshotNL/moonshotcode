/*
This module is used to format strings to Base64 and vice versa.
*/
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string.h>

/*
Format a string in Base64.
*/
char *base64(const unsigned char *input, int length)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;
	char *buff;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	buff = (char *)malloc(bptr->length);
	memcpy(buff, bptr->data, bptr->length-1);
	buff[bptr->length-1] = 0;

	BIO_free_all(b64);

	return buff;
}

/*
Change Base64 formattedtext to a string.
*/
char *unbase64(unsigned char *input, int length)
{
	BIO *b64, *bmem;

	char *buffer = (char *)malloc(length);
	memset(buffer, 0, length);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);
	BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

	BIO_read(bmem, buffer, length);

	BIO_free_all(bmem);

	return buffer;
}
