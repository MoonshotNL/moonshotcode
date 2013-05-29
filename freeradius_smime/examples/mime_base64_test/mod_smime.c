#include "crypto/mod_base64.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define STR_MAXLEN				1024
#define MIMEHEADER_TEXT_LEN		78
#define MIMEHEADER_CERT_LEN		113

#define STATE_HEADER	0
#define STATE_BODY		1

int mime_strip_header(int header_len, char *input, int input_len, char **output)
{
	char *outstring = malloc(input_len - header_len);
	memcpy(outstring, input + header_len, input_len - header_len);
	*output = outstring;
	return input_len - header_len;
}

int mime_add_header_text(char *input, int input_len, char **output)
{
	char *header = "Mime-version: 1.0\nContent-Type: text/plain\nContent-Transfer-Encoding: base64\n\n";
	*output = malloc((sizeof(char) * input_len) + (sizeof(char) * MIMEHEADER_TEXT_LEN) + 1);
	memcpy(*output, header, MIMEHEADER_TEXT_LEN * sizeof(char));
	memcpy(*output + (MIMEHEADER_TEXT_LEN * sizeof(char)), input, input_len);
	output[input_len + MIMEHEADER_TEXT_LEN] = '\0';
	return input_len + MIMEHEADER_TEXT_LEN + 1;
}

int mime_add_header_cert(char *input, int input_len, char **output)
{
	char *header = "Mime-Version: 1.0\nContent-Type: application/pkcs7-mime; smime-type=certs-only\nContent-Transfer-Encoding: base64\n\n";
	*output = malloc((sizeof(char) * input_len) + (sizeof(char) * MIMEHEADER_CERT_LEN) + 1);
	memcpy(*output, header, MIMEHEADER_CERT_LEN * sizeof(char));
	memcpy(*output + (MIMEHEADER_CERT_LEN * sizeof(char)), input, input_len);
	output[input_len + MIMEHEADER_CERT_LEN] = '\0';
	return input_len + MIMEHEADER_CERT_LEN + 1;
}

int pack_mime_text(char *input, int len, char **output)
{
    int out_len = 0;
    char *base64_input;
	int base64_len;
	char *mime_headers = "Mime-version: 1.0\nContent-Type: text/plain\nContent-Transfer-Encoding: base64\n\n";
	int mime_headers_len = strlen(mime_headers);
	base64_len = base64_encode(input, len, &base64_input);

	out_len = base64_len + mime_headers_len - 1;

	*output = malloc(out_len * sizeof(char));
	
	strcpy(*output, mime_headers);
	strcat(*output, base64_input);

	return out_len;
}

int unpack_mime_text(char *input, int len, char **output)
{
	int state = 0;
	int input_cur = 0;
	int base64_buffer_cur = 0;
	char *base64_buffer = malloc(STR_MAXLEN * sizeof(char));

	int header_cur = 0;
	char *header = "Mime-version: 1.0\nContent-Type: text/plain\nContent-Transfer-Encoding: base64\n\n";
	int header_len = strlen(header);

	int output_len;

	while (input_cur <= len)
	{
		switch(state)
		{
			case STATE_HEADER:
				while(header_cur < header_len)
				{
					if (!header[header_cur] == input[input_cur])
					{
						return 0;
					}
					header_cur++;
					input_cur++;
				}
				state++;
				break;
			case STATE_BODY:
				base64_buffer[base64_buffer_cur] = input[input_cur];
				base64_buffer_cur++;
				input_cur++;
				break;
		}
	}
	base64_buffer[base64_buffer_cur] = '\0';

	output_len = base64_decode(base64_buffer, base64_buffer_cur, output);
	free(base64_buffer);
	return output_len;
}

int pack_mime_cert(X509 *cert, char **output)
{
	BIO *bio = NULL;
	char *outbuffer;

	outbuffer = malloc(5120);
	memset(outbuffer, 0, 5120);

	bio = BIO_new_mem_buf(outbuffer, -1);
	if (!bio)
	{
		return -1;
	}

	if (!PEM_write_bio_X509(bio, cert))
	{
		BIO_free(bio);
		return -1;
	}

	mime_add_header_cert(outbuffer, strnlen(outbuffer, 5120), *output);
	free(outbuffer);
}

int unpack_mime_cert(char *input, int len, X509 **cert)
{
	*cert = NULL;
	BIO *bio = NULL;
	char *noheader;

	mime_strip_header(input, strlen(input), &noheader);

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
