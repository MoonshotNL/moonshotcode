#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>

void handle_requests(REQUEST *request)
{
	request->dostuff;
}