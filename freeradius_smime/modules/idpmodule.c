#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/libradius.h>

#include "common.h"
#include "mod_mime.h"

typedef struct attr_req
{
	int dn_len;
	char dn[DN_MAX_LEN];
	
} ATTR_REQ;

void attrreq_parser(char *input, int len, ATTR_REQ *output)
{
	
}

void handle_requests(REQUEST *request)
{
	VALUE_PAIR *vp = request->packet->vps;
	do
	{
		if (vp->attribute == ATTR_SMIME_REQUEST)
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