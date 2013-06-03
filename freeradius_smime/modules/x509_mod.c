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

x509 &read__public_certificate(void *instance)
{
    BIO *tbio = NULL;
    rlm_testing_T *data = instance;
    char *cert = data->pub_key;
    tbio = BIO_new_file(cert, "r");
    
    BIO *bio = NULL;
    bio = BIO_new_mem_buf(tbio);
    
    X509 *certificate;
    certificate = PEM_read_bio_X509(bio, tbio, 0, NULL);
    
    return certificate;
}