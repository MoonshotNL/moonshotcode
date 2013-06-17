/*
This module is used to pack and unpack text and certificates, in either mime or s/mime format.
*/
#include "mod_base64.h"
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define STR_MAXLEN				1024
#define MIMEHEADER_TEXT_LEN		78
#define MIMEHEADER_CERT_LEN		113

#define STATE_HEADER	0
#define STATE_BODY		1

#define MAX_MSGLEN	4096

/*
Return a substring of the input, up until (but not including) the null terminator.
*/
static void remove_nl(char **string)
{
	char *buffer;
	int i, buf_cur;

	buffer = calloc(strlen(*string) + 1, sizeof(char));
	buf_cur = 0;

	for (i = 0; i < strlen(*string); i++)
	{
		if ((*string)[i] != '\n')
		{
			buffer[buf_cur] = (*string)[i];
			buf_cur++;
		}
	}

	free(*string);
	*string = buffer;
}

/*
This function will strip the header off a mime-message, so it can be read "normally"
*/
static int mime_strip_header(int header_len, char *input, int input_len, char **output)
{
	*output = calloc(1, input_len - header_len);
	memcpy(*output, input + header_len, input_len - header_len);
	return input_len - header_len;
}

/*
This function will add a mime-header to your input. This header will define the content of your input as base64 encoded text.
If you are planning to add a header to a certificate(chain), see mime_add_header_cert();
*/
static int mime_add_header_text(char *input, int input_len, char **output)
{
	char *header = "Mime-version: 1.0\nContent-Type: text/plain\nContent-Transfer-Encoding: base64\n\n";
	*output = malloc((sizeof(char) * input_len) + (sizeof(char) * MIMEHEADER_TEXT_LEN) + 1);
	strcpy(*output, header);
	strcat(*output, input);
	return input_len + MIMEHEADER_TEXT_LEN + 1;
}

/*
This function will add a mime-header to your input. This header will define the content of your input as a base64 encoded certificate(chain).
If you are planning to add a header to regular text instead, see mime_add_header_text();
*/
static int mime_add_header_cert(char *input, int input_len, char **output)
{
	char *header = "Mime-Version: 1.0\nContent-Type: application/pkcs7-mime; smime-type=certs-only\nContent-Transfer-Encoding: base64\n\n";
	*output = malloc(input_len + MIMEHEADER_CERT_LEN + 1);
	strcpy(*output, header);
	strcat(*output, input);
	return input_len + MIMEHEADER_CERT_LEN + 1;
}

/*
This function will encode the input in base64 format, and return a mime-message. This input shall be treated as regular text.
This will automatically call add_mime_header_text(). This should not be done manually.
To pack the input as an s/mime-message, see pack_smime_text();
*/
int pack_mime_text(char *input, int len, char **output)
{
	int out_len = 0;
	char *base64_input;
	base64_input = base64(input, len);

	out_len = mime_add_header_text(base64_input, strlen(base64_input), output);

	return out_len;
}

/*
This function is used to return a byte-array from a mime-message input.
The message gets it's header stripped automatically. It is assumed the content of the message (minus the header) are base64 encoded.
*/
int unpack_mime_text(char *input, int len, char **output)
{
	char *base64_out;
	int base64_len;

	base64_len = mime_strip_header(MIMEHEADER_TEXT_LEN, input, len, &base64_out);
	remove_nl(&base64_out);
	*output = unbase64(base64_out, strlen(base64_out));
	return strlen(*output);
}

/*
This function will encode the input in base64 format, and return a mime-message. This input shall be treated as a certificate(chain).
This function will automatically call add_mime_header_text(). This should not be done manually.
*/
int pack_mime_cert(X509 *cert, char **output)
{
	BIO *bio = NULL;
	char *outbuffer;
	BUF_MEM *bptr;

	outbuffer = malloc(5120);
	memset(outbuffer, 0, 5120);

	bio = BIO_new(BIO_s_mem());
	if (!bio)
	{
		return -1;
	}

	if (!PEM_write_bio_X509(bio, cert))
	{
		BIO_free(bio);
		return -1;
	}

	BIO_get_mem_ptr(bio, &bptr);
	outbuffer = strndup(bptr->data, bptr->length);

	mime_add_header_cert(outbuffer, strnlen(outbuffer, 5120), output);
	free(outbuffer);
	return 0;
}

/*
This function unpacks a certificate(chain) from a mime-message, and return an integer indicating it's success.
The message gets it's header stripped automatically. It is assumed the content of the message (minus the header) are base64 encoded.
*/
int unpack_mime_cert(char *input, int len, X509 **cert)
{
	*cert = NULL;
	BIO *bio = NULL;
	char *noheader;

	mime_strip_header(MIMEHEADER_CERT_LEN, input, strlen(input), &noheader);

	bio = BIO_new_mem_buf(noheader, -1);
	if (!bio)
	{
		return -1;
	}

	PEM_read_bio_X509(bio, cert, 0, NULL);
	BIO_free(bio);
	if (!*cert)
	{
		return -1;
	}

	return 0;
}

/*
This function will encode the input in base64 format, and return a s/mime-message. This input shall be treated as regular text.
To pack the input as a regular mime-message, see pack_mime_text();
The content will be encrypted using the private key and public certificate supplemented.
*/
char *pack_smime_text(char *input, EVP_PKEY *pkey, X509 *pubcert)
{
   STACK_OF(X509) *recips = NULL;
   CMS_ContentInfo *cms_sig = NULL, *cms_enc = NULL;
   BIO *bio_in = NULL, *bio_sig = NULL, *bio_out = NULL;
   BUF_MEM *bptr;
   char *output = NULL;
   int flags = CMS_STREAM;

   OpenSSL_add_all_algorithms();

   recips = sk_X509_new_null();
   if (!recips || !sk_X509_push(recips, pubcert))
   {
      printf("recips || sk_X509_push error\n");
      exit(1);
   }

   bio_in = BIO_new_mem_buf(input, -1);
   bio_sig = BIO_new(BIO_s_mem());
   bio_out = BIO_new(BIO_s_mem());

   if (!bio_in || !bio_sig || !bio_out)
   {
      printf("bio_in || bio_sig || bio_out error\n");
      exit(1);
   }

   cms_sig = CMS_sign(pubcert, pkey, NULL, bio_in, CMS_DETACHED|CMS_STREAM);
   if (!cms_sig)
   {
      printf("cms_sig error\n");
      exit(1);
   }

   if (!SMIME_write_CMS(bio_sig, cms_sig, bio_in, CMS_DETACHED|CMS_STREAM))
   {
      printf("Error SMIME_write_CMS bio_sig");
      exit(1);
   }

   cms_enc = CMS_encrypt(recips, bio_sig, EVP_des_ede3_cbc(), flags);

   if (!cms_enc)
   {
      printf("cms error\n");
      exit(1);
   }

   if (!SMIME_write_CMS(bio_out, cms_enc, bio_sig, flags))
   {
      printf("SMIME write error\n");
      exit(1);
   }

   BIO_get_mem_ptr(bio_out, &bptr);
   output = bptr->data;
   output = strndup(bptr->data, bptr->length);

   CMS_ContentInfo_free(cms_sig);
   CMS_ContentInfo_free(cms_enc);
   BIO_free(bio_in);
   BIO_free(bio_sig);
   BIO_free(bio_out);

   return output;
}

/*
This function will unpack an s/mime message and return it as a char pointer.
This needs both the correct private key and x509 certificate.
*/
char *unpack_smime_text(char *input, EVP_PKEY *pkey, X509 *cert)
{
	BIO *bio_in = NULL, *bio_out = NULL;
	CMS_ContentInfo *cms = NULL;
	char *output = NULL;
	BUF_MEM *bptr = NULL;
	
	OpenSSL_add_all_algorithms();

	bio_in = BIO_new_mem_buf(input, -1);
	bio_out = BIO_new(BIO_s_mem());

	if (!bio_in || !bio_out)
	{
		DEBUG("dectext: error creating bio_in, bio_dec or bio_out");
		exit(1);
	}
	DEBUG("About to read the CMS");
	cms = SMIME_read_CMS(bio_in, NULL);
	if (!cms)
	{
		DEBUG("Error parsing message to CMS");
		exit(1);
	}

	DEBUG("About to CMS_decrypt");
	if (!CMS_decrypt(cms, pkey, cert, NULL, bio_out, 0))
	{
		DEBUG("Error decrypting message");
		exit(1);
	}

	BIO_get_mem_ptr(bio_out, &bptr);
	output = strndup(bptr->data, bptr->length);

	CMS_ContentInfo_free(cms);
    BIO_free(bio_in);
    BIO_free(bio_out);

	return output;
}
