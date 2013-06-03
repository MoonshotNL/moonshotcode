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
#include <openssl/pem.h>

/*
 read_public_certificate
 
 Use this function to get the public certificate in X509-format.
 This function uses the location, that is defined in the freeradius.conf or radiusd.conf, of the certificate to load in BIO.
 In the next step it will convert it in a X509-format and returns the memory location of the X509-certificate.
 
 
 */

X509 *read_public_certificate(void *instance)
{
    BIO *tbio = NULL;
    X509 *certificate;
    char *cert;
    rlm_testing_t *data;
    
    data = (rlm_testing_t *)instance;
    cert = data->pub_key;                   //get the location of the public certificate that is defined in the configuration files
    tbio = BIO_new_file(cert, "r");
    
    certificate = PEM_read_bio_X509(tbio, NULL, 0, NULL);
	
    if(!certificate)
    {
        return NULL;
    }
    
    return certificate;
}

/*
 read_private_certificate
 
 Use this function to get the private certificate in X509-format.
 This function uses the location, that is defined in the freeradius.conf or radiusd.conf, of the certificate to load in BIO.
 In the next step it will convert it in a X509-format and returns the memory location of the X509-certificate.
 Some certificates are secured by a password, therefore it reads the password from the freeradius.conf or radiusd.cnf file.
 The password has to be defined in this configuration files for correctly reading and returning the certificate in X509-format.
 
 
 */

X509 *read_private_certificate(void *instance)
{
    BIO *tbio = NULL;
    X509 *certificate;
    char *cert;
    char *password;
    rlm_testing_t *data;
    int size;
    
    data = (rlm_testing_t *)instance;
    cert = data->priv_key;
    password = data->priv_key_password;         //get the password of the private key that is defined in the configuration files
    
    tbio = BIO_new_file(cert, "r");
    
    certificate = PEM_read_bio_X509(tbio, NULL, NULL, password);
	
    if(!certificate)
    {
        return NULL;
    }
    
    return certificate;
}