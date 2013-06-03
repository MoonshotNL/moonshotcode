//
//  x509_mod.c
//  
//
//  Created by W.A. Miltenburg on 03-06-13.
//
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

X509 *read__public_certificate(void *instance)
{
    BIO *tbio = NULL;
    rlm_testing_t *data = (rlm_testing_t *)instance;
    char *cert = data->pub_key;
    tbio = BIO_new_file(cert, "r");
    
    X509 *certificate;
    certificate = PEM_read_bio_X509(tbio, NULL, 0, NULL);
	
    return certificate;
}