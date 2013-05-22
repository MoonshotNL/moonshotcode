//
//  x509_check.c
//
//
//  Created by W.A. Miltenburg on 17-05-13.
//
//

/*
Momenteel gaan we alle root CA files af totdat we de juiste hebben. Voor optimalisatie is het handig als de certificaten
 in het geheugen worden geladen en dat er een mapping wordt gemaakt tussen een DN en de filepath. Zo hoeft er maar
 een I/O operation per keer worden uitgevoerd.
 */


#include <stdio.h>
#include <stdlib.h>
#include <openssl/cms.h>
#include <openssl/ssl.h>
#DEFINE CAPATH "/etc/ssl/certs"

typedef struct attr_req
{
	int dn_len;
	char dn[DN_MAX_LEN];
	
} ATTR_REQ;

int CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs, X509_STORE *store, BIO *indata, BIO *out, unsigned int flags);

//opzoek naar AVP_CERTIFICATE_RADIUS

int check_certificate(REQUEST *request)
{
    char *certificate = find_certificate(request);
    SSL_CTX *ctx;
    SSL_METHOD *meth;
    meth = SSLv23_method();
    
    
    
    
    //file moet nog veranderd worden
    
    ctx = SSL_CTX_new(meth);
    //int SSL_CTX_use_certificate_file(SSL_CTX *ctx,const char *file,int type)
    SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
    
    /*
     CAfile en CApath moeten nog meegestuurd worden
     Kan gedaan worden door een loop te maken waarin alle CAfiles worden afgegaan totdat we de juiste hebben
     */
    
    //int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);
    
    SSL_CTX_load_verify_locations(ctx, NULL, CApath);
    
    /* Set a callback function (verify_callback) for peer certificate */
    /* verification */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    /* Set the verification depth to 1 */
    //SSL_CTX_set_verify_depth(ctx,1);
    
    //SSL_CTX_set_verify returns nothing, checking with SSL_get_verify which will return X509_v_OK if there are no errors
    if(SSL_get_verify_result  = X509_V_OK )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void find_certificate(REQUEST *request)
{
	VALUE_PAIR *vp = request->packet->vps;
	do
	{
		if (vp->attribute == AVP_CERTIFICATE_RADIUS)
		{
			handle_request(request, vp);
		}
	} while ((vp = vp->next) != 0)
        
        }

void handle_request(REQUEST *request, VALUE_PAIR *vp)
{
	char *data = mime_unpack_attrrequest(vp->data.octets, vp->length);
	ATTR_REQ *attr_request = rad_malloc(sizeof(ATTR_REQ));
	attrreq_parser(data, strnlen(data, MAX_STRING_LEN), attr_request);
	
	attr_request.
}