#ifndef MOD_RSA_H
#define MOD_RSA_H

extern unsigned char *rsa_pub_encrypt(unsigned char *input, int input_len, int *msg_len, RSA *key);
extern unsigned char *rsa_pub_decrypt(unsigned char *input, int input_len, int *msg_len, RSA *key);
extern unsigned char *rsa_priv_encrypt(unsigned char *input, int input_len, int *msg_len, RSA *key);
extern unsigned char *rsa_priv_decrypt(unsigned char *input, int input_len, int *msg_len, RSA *key);

#endif
