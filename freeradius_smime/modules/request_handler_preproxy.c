/*
 TODO:
 get_mime_certificate functie moet nog corresponderen met de mime module. Hierop moet nog gewacht worden omdat de mime module nog niet geheel af is.
 get_mime_message functie moet nog corresponderen met de mime module. Hierop moet ook gewacht worden totdat de mime module af is.
  */

//
//  request_handler_preproxy.c
//
//
//  Created by W.A. Miltenburg on 15-05-13.
//
//

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>

#include "common.h"
#include "mod_mime.h"

int handle_request(REQUEST *request, int type_request)
{
    
    if(type_request == 1)
    {
    char *certificate = get_mime_certificate();
    VALUE_PAIR *avp_certificate;
    avp_certificate = pairmake("AVP_CERTIFICATE_RADIUS",
                               certificate, T_OP_EQ);
    pairadd(&request->reply->vps, avp_certificate);
    }
    else if(type_request == 2)
    {
        char *message = get_mime_message();
        VALUE_PAIR *avp_proxy;
        avp_proxy = pairmake("AVP_CPROXY_RADIUS",
                                   message, T_OP_EQ);
        pairadd(&request->reply->vps, avp_proxy);
    }
    
    return RLM_MODULE_UPDATED;
}