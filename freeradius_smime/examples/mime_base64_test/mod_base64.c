#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string.h>

int base64_encode(char *input, int input_len, char **output)
{
	int out_len;
	BIO *b64, *bio;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bio = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bio);
	
	BIO_write(b64, input, input_len);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	*output = calloc(1, bptr->length + 1);
	memcpy(*output, bptr->data, bptr->length);
	output[bptr->length] = '\0';

	out_len = bptr->length;

	BIO_free_all(b64);

	return out_len;
}

int base64_decode(char *input, int length, char **output)
{
	BIO *b64, *bmem;
	
	char *buffer = (char *) malloc(length+1);
	memset(buffer, 0, length+1);

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);

	BIO_read(bmem, buffer, length);
	BIO_flush(bmem);
	buffer[length + 1] = '\0';
	*output = buffer;;
	BIO_free_all(bmem);
	return strlen(*output);
}
