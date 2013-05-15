#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>

#include "common.h"
#include "mod_mime.h"

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
	char *data = mime_unpack_attrrequest(vp->
}