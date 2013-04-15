#include <string.h>
#include <stdio.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define INMSG "THIS IS ANOTHER TESTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT"
#define INMSG_S strlen(INMSG)

RSA* load_privkey(void);
void rsa_privencrypt(char *message, int len, RSA* key);

int main(void)
{
	RSA* key;
	OpenSSL_add_all_ciphers();
	key = load_privkey();
	rsa_privencrypt(INMSG, INMSG_S, key);
}

RSA *load_privkey()
{
	RSA *pkey;
	FILE *fp;
	char pass[] = "testpass";

	OpenSSL_add_all_algorithms();

	fp = fopen("cakey.pem", "r");

	pkey = PEM_read_RSAPrivateKey(fp, NULL, NULL, pass);

	return pkey;
}

void rsa_privencrypt(char *message, int len, RSA* key)
{
	int keySize = RSA_size(key);
	int i;
	unsigned char* outstr = calloc(keySize, sizeof(char));
	int outlen;

	outlen = RSA_private_encrypt(len, message, outstr, key, RSA_PKCS1_PADDING);

	printf("Encrypted output in hex: ");
	for (i = 0; i < outlen; i++) printf("%02x", outstr[i]);
	printf("\n");
}
