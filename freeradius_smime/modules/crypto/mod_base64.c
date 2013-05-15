#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string.h>

char *base64_encode(char *input, int input_len)
{
	char *outbuffer;
	int outlen;
	BIO *b64, *bio;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bio = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bio);
	
	BIO_write(b64, input, input_len);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	outbuffer = calloc(1, bptr->length + 1);
	memcpy(outbuffer, bptr->data, bptr->length);
	outbuffer[bptr->length] = '\0';

	BIO_free_all(b64);

	return outbuffer;
}

char *base64_decode(char *input, int input_len)
{
	char *outbuffer = calloc(1, input_len + 1);
	BIO *b64, *bio;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bio = BIO_new_mem_buf(input, input_len);
	b64 = BIO_push(b64, bio);

	BIO_read(b64, 

}
