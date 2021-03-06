/*
This module is the starting point.
It decides the path the incoming request should take, sending it to either the request_handler_preproxy or idpmodule.
*/
#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>

#include "common.h"
#include "request_handler_preproxy.h"
#include "idpmodule.h"
#include "x509_mod.h"
#define AUTHENTICATION_REQUEST 1 //ACCEPT-REQUEST radius response
#define AUTHENTICATION_ACK 2  //ACCEPT-ACCEPT radius response

static const CONF_PARSER module_config[] = {
    { "pub_key",  PW_TYPE_STRING_PTR, offsetof(rlm_moonshot_t,pub_key), NULL,  NULL}, //holds location of the public certificate
    { "priv_key",  PW_TYPE_STRING_PTR, offsetof(rlm_moonshot_t,priv_key), NULL,  NULL}, //hols location of the private certificate
    { "priv_key_password",  PW_TYPE_STRING_PTR, offsetof(rlm_moonshot_t,priv_key_password), NULL,  NULL}, //holds the password of the private certificate
  { NULL, -1, 0, NULL, NULL }		/* end the list */
};

/* CONF_SECTION *conf seems to be the raw config data, rlm_moonshot_t *data is our defined struct that will hold our data, CONF_PARSER module_config[] are our config parser rules */
static int moonshot_init(CONF_SECTION *conf, void **instance)
{
	//Array that will store our parsed config data
	rlm_moonshot_t *data;

	data = rad_malloc(sizeof(rlm_moonshot_t));
	if (!data) {
		return -1;
	}
	memset(data, 0, sizeof(rlm_moonshot_t));

	//Parse the config file using conf, data and our parse rules in module_config
	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data); //rauwe data naar geformatte data
		return -1;
	}

	*instance = data;

    read_public_certificate(*instance);
    read_private_certificate(*instance);

	return 0;
}

/*
Handle pre-proxy requests, this is done by request_handler_preproxy.c
*/
static int moonshot_preproxy(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;

    preproxy_handle_request(request);

	return RLM_MODULE_OK;
}

/*
Handle pre-proxy requests, this is done by request_handler_preproxy.c
*/
static int moonshot_postproxy(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;

    postproxy_handle_request(request);

	return RLM_MODULE_OK;
}

/*
Gives the idp_module requests to handle, provided Radius gave us an ACCESS_ACCEPT
*/
static int moonshot_postauth(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;

	//Is it an Access-Accept and we're not a proxy?
	if (request->reply->code == PW_AUTHENTICATION_ACK && request->proxy_reply == NULL)
	{
		idp_handle_requests(request);
	}

	return RLM_MODULE_OK;
}

/*
Unregister our module to free up space
*/
static int moonshot_detach(void *instance)
{
	free(instance);
	return 0;
}

//Register our functions in the correct places
module_t rlm_moonshot = {
	RLM_MODULE_INIT,
	"moonshot",			/* module name */
	RLM_TYPE_THREAD_SAFE,		/* type */
	moonshot_init,			/* instantiation */
	moonshot_detach,			/* detach */
	{
		NULL,			/* authentication */
		NULL,			/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		moonshot_preproxy,	/* pre-proxy */
		moonshot_postproxy,			/* post-proxy */
		moonshot_postauth	/* post-auth */
	},
};
