#include "crypto/mod_base64.h"

int pack_mime_text(char *input, int len, char **output)
{
    int out_len = 0;
    char *base64_input;
	int base64_len;
	char *mime_headers = "Mime-version: 1.0\nContent-Type: text/plain\nContent-Transfer-Encoding: base64\n\n";
	int mime_headers_len = strlen(mime_headers);
	base64_len = base64_encode(input, len, &base64_input);

	out_len = base64_len + mime_headers_len - 1;

	*output = rad_malloc(out_len * sizeof(char));
	
	strcpy(*output, mime_headers);
	strcat(*output, base64_input);

	return out_len;
}

int unpack_mime_text(char *input, int len, char **output)
{
	int out_len = 0;
}

