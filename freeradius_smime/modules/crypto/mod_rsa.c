unsigned char *rsa_pub_encrypt(unsigned char *input, int input_len, int *msg_len, RSA *key)
{
	return rsa_generic(input, input_len, msg_len, key, 1, 0);
}

unsigned char *rsa_pub_decrypt(unsigned char *input, int input_len, int *msg_len, RSA *key)
{
	return rsa_generic(input, input_len, msg_len, key, 0, 0);
}

unsigned char *rsa_priv_encrypt(unsigned char *input, int input_len, int *msg_len, RSA *key)
{
	return rsa_generic(input, input_len, msg_len, key, 1, 1);
}

unsigned char *rsa_priv_decrypt(unsigned char *input, int input_len, int *msg_len, RSA *key)
{
	return rsa_generic(input, input_len, msg_len, key, 0, 1);
}

unsigned char *rsa_generic(unsigned char *input, int input_len, int *msg_len, RSA *key, unsigned char is_encrypting, unsigned char is_privkey)
{
	int (*crypt_p)(int, const unsigned char*, unsigned char*, RSA*, int);
	int key_len, block_len, read_len, write_len;
	unsigned char *in_stream, *out_stream;

	//Local vars
	ERR_load_crypto_strings();
	OpenSSL_add_all_ciphers();

	if (!key)
	{
		fprintf(stderr, "mod_rsa: No key specified\n");
		return NULL;
	}

	if (is_encrypting && is_privkey)
	{
		crypt_p = RSA_private_encrypt;
	}
	else if (!is_encrypting && is_privkey)
	{
		crypt_p = RSA_private_decrypt;
	}
	else if (is_encrypting && !is_privkey)
	{
		crypt_p = RSA_public_encrypt;
	}
	else
	{
		crypt_p = RSA_public_decrypt;
	}

	key_len = RSA_size(key);
	block_len = key_len - (is_encrypting ? 12 : 0);

	in_stream = calloc(block_len, sizeof(char));
	out_stream = calloc(key_len - (is_encrypting ? 0 : 12), sizeof(char));
	
	while(1)
	{
		read_len = 
	}
}
