#include "crypto/mod_base64.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define STR_MAXLEN		1024

#define STATE_HEADER	0
#define STATE_BODY		1

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

	return output_len;
}

