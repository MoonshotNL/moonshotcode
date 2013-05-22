//
//  x509_check.c
//
//
//  Created by W.A. Miltenburg on 17-05-13.
//
//

#include <stdio.h>
#include <stdlib.h>

SSL_library_init(); /* load encryption & hash algorithms for SSL */
SSL_load_error_strings(); /* load the error strings for good error reporting */

/* To verify a certificate, you must first load a CA certificate (because the peer certificate is verified against a CA certificate). The SSL_CTX_load_verify_locations() API loads a CA certificate into the SSL_CTX structure.
 
 The prototype of this API is as follows:
 */

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);

/*
 The first argument, ctx, points to an SSL_CTX structure into which the CA certificate is loaded. The second and third arguments, CAfile and CApath, are used to specify the location of the CA certificate. When looking up CA certificates, the OpenSSL library first searches the certificates in CAfile, then those in CApath.
 
 The following rules apply to the CAfile and CApath arguments:
 
 If the certificate is specified by CAfile (the certificate must exist in the same directory as the SSL application), specify NULL for CApath.
 
 To use the third argument, CApath, specify NULL for CAfile. You must also hash the CA certificates in the directory specified by CApath. Use the Certificate Tool (described in Chapter 3) to perform the hashing operation.
 */

/*
 The CA certificate loaded in the SSL_CTX structure is used for peer certificate verification. For example, peer certificate verification on the SSL client is performed by checking the relationships between the CA certificate (loaded in the SSL client) and the server certificate.
 
 For successful verification, the peer certificate must be signed with the CA certificate directly or indirectly (a proper certificate chain exists). The certificate chain length from the CA certificate to the peer certificate can be set in the verify_depth field of the SSL_CTXand SSL structures. (The value in SSL is inherited from SSL_CTX when you create an SSL structure using the SSL_new() API). Setting verify_depth to 1 means that the peer certificate must be directly signed by the CA certificate.
 
 The SSL_CTX_set_verify() API allows you to set the verification flags in the SSL_CTX structure and a callback function for customized verification as its third argument. (Setting NULL to the callback function means the built-in default verification function is used.) In the second argument of SSL_CTX_set_verify(), you can set the following macros:
 
 SSL_VERIFY_NONE
 
 ì
 SSL_VERIFY_PEER
 
 SSL_VERIFY_FAIL_IF_NO_PEER_CERT
 
 SSL_VERIFY_CLIENT_ONCE
 
 The SSL_VERIFY_PEER macro can be used on both SSL client and server to enable the verification. However, the subsequent behaviors depend on whether the macro is set on a client or a server. For example:
 */

/* Set a callback function (verify_callback) for peer certificate */
/* verification */
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
/* Set the verification depth to 1 */
SSL_CTX_set_verify_depth(ctx,1);

/*
 You can verify a peer certificate in another, less common way - by using the SSL_get_verify_result() API. This method allows you to obtain the peer certificate verification result without using the SSL_CTX_set_verify() API.
 
 Call the following two APIs before you call the SSL_get_verify_result() API:
 
 Call SSL_connect() (in the client) or SSL_accept() (in the server) to perform the SSL handshake. Certificate verification is performed during the handshake. SSL_get_verify_result() cannot obtain the result before the verification process.
 
 Call SSL_get_peer_certificate() to explicitly obtain the peer certificate. The X509_V_OK macro value is returned when a peer certificate is not presented as well as when the verification succeeds.
 
 The following code shows how to use SSL_get_verify_result() in the SSL client:
 */

SSL_CTX_set_verify_depth(ctx, 1);
err = SSL_connect(ssl);
if(SSL_get_peer_certificate(ssl) != NULL)
{
    if(SSL_get_verify_result(ssl) == X509_V_OK)
        
        
        BIO_printf(bio_c_out, "client verification with SSL_get_verify_result()
                   succeeded.\n");
                   else{
                       
                       BIO_printf(bio_err, "client verification with SSL_get_verify_result()
                                  failed.\n");
                                  
                                  exit(1);
                                  
                                  }
                                  
                                  }
                                  else
                                  BIO_printf(bio_c_out, -the peer certificate was not presented.\n-);
                                  
                                  
