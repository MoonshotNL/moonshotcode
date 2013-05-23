#include "mod_smime.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
	char *mime_msg;
	int mime_msg_len;
	
	char *plaintext;
	int plaintext_len;

	mime_msg_len = pack_mime_text("Hello World!", strlen("Hello World!"), &mime_msg);
	printf("%s\n", mime_msg);

	plaintext_len = unpack_mime_text(mime_msg, mime_msg_len, &plaintext);
	printf("%s\n", plaintext);
	return 0;
}
