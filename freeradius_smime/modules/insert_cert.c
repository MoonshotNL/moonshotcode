//
//  insert_cert.c
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

int handle_cerinject(REQUEST *request)
{
    char *certificate = get_mime_certificate();
    VALUE_PAIR *avp_certificate;
    avp_certificate = pairmake("AVP_CERTIFICATE_RADIUS",
                               certificate, T_OP_EQ);
    pairadd(&request->reply->vps, avp_certificate);
    
    return RLM_MODULE_UPDATED;
}
