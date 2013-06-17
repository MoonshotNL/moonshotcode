/*
This module is used to handle requests directed at the proxy.
It will perform different actions depending on the FreeRadius code available inside the request.
*/

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>

#include "common.h"
#include "mod_smime.h"
#include "x509_mod.h"
#include "proxymodule.h"

extern X509 *public_certificate;
extern X509 *private_certificate;
extern EVP_PKEY *private_key;

/*
Handles requests before they have been handled by the proxy-server.
*/
int preproxy_handle_request(REQUEST *request)
{
	char message[4096];
	int found = 0;
	int i;
	int avp_msglen = 0;
	char *cert_message;
	char substr[251];
	VALUE_PAIR *vp;
	switch (request->packet->code) //it's allowed to handle multiple requests, the request type is based on radius responses
	{
	case PW_AUTHENTICATION_REQUEST:
		pack_mime_cert(public_certificate, &cert_message);
		VALUE_PAIR *avp_certificate;

		for (i = 0; i <= (strlen(cert_message) / 250); i++)
		{
			avp_msglen = i == (strlen(cert_message) / 250) ? strlen(cert_message) % 250 : 250;
			memcpy(substr, &cert_message[i * 250], avp_msglen);
			substr[avp_msglen] = '\0';
			avp_certificate = pairmake("Moonshot-Certificate", substr, T_OP_EQ);
			pairadd(&request->proxy->vps, avp_certificate); //add AVP
		}
		//avp_certificate = pairmake("Moonshot-Certificate", cert_message, T_OP_EQ); //AVP_CERTIFICATE_RADIUS is an AVP that stores the certificate chain
		//pairadd(&request->reply->vps, avp_certificate); //add AVP
		return RLM_MODULE_UPDATED;                      //we are basically saying that our AVPs are updated
	}
}

/*
Handles request that have been handled by a proxy, and thus have a Radius-reply
*/
int postproxy_handle_request(REQUEST *request)
{
	char message[4096];
	int found = 0;
	int i;
	int avp_msglen = 0;
	char *cert_message;
	char substr[251];
	VALUE_PAIR *vp;

	DEBUG("ACKACK");
	switch (request->proxy_reply->code) //it's allowed to handle multiple requests, the request type is based on radius responses
	{
		case PW_AUTHENTICATION_ACK:
			memset(message, 0, 4096);

			vp = request->proxy_reply->vps;
			do {
				if (vp->attribute == ATTR_MOONSHOT_IDPREPLY) //detect if AVP_PROXY_REQUEST is sent by the idp module
				{
					found = 1;
					strncat(message, vp->data.octets, vp->length);
				}
			} while ((vp = vp -> next) != 0);

			if (found)
			{
				//char *message_attributes = unpack_smime_text((char *)vp->data.octets, private_key, private_certificate);
				char *message_attributes;
				unpack_mime_text(message, strlen(message), &message_attributes);
				DEBUG("MSG: %s", message_attributes);
				char *out_message = obtain_attributes(message_attributes);
				VALUE_PAIR *avp_attributes;

				for (i = 0; i <= (strlen(out_message) / 250); i++)
				{
					avp_msglen = i == (strlen(out_message) / 250) ? strlen(out_message) % 250 : 250;
					memcpy(substr, &out_message[i * 250], avp_msglen);
					substr[avp_msglen] = '\0';
					avp_attributes = pairmake("Moonshot-ProxyReply", substr, T_OP_EQ);
					pairadd(&request->proxy_reply->vps, avp_attributes);
				}
				return RLM_MODULE_UPDATED;
			}
	}
	return NULL;
}
