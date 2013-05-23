#include "mod_smime.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
	char *mime_msg;
	int mime_msg_len;
	
	char *plaintext;
	int plaintext_len;

	char *input = "5921305:DC=HVA,DC=NL,CN=Voms Server:2:UserName:VOMS-Password:1:ResearchGroup";

	mime_msg_len = pack_mime_text(input, strlen(input), &mime_msg);
	printf("%s\n", mime_msg);

	plaintext_len = unpack_mime_text(mime_msg, mime_msg_len, &plaintext);
	printf("%s\n", plaintext);
	return 0;
}
