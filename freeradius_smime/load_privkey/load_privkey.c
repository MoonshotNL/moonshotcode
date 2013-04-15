#include <stdio.h>
#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

int main(void)
{
	EVP_PKEY *ca_pkey;
	FILE *fp;
	char pass[] = "testpass";

	OpenSSL_add_all_algorithms();

	ca_pkey = EVP_PKEY_new();

	fp = fopen("cakey.pem", "r");

	PEM_read_PrivateKey(fp, &ca_pkey, NULL, pass);

	fclose(fp);

	PEM_write_PrivateKey(stdout, ca_pkey, NULL, NULL, 0, 0, NULL);
	
	return 0;
}
