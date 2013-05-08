#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/modules.h>

typedef struct rlm_testing_t {
	char		*string;
} rlm_testing_t;

static const CONF_PARSER module_config[] = {
  { "string",  PW_TYPE_STRING_PTR, offsetof(rlm_testing_t,string), NULL,  NULL},
  { NULL, -1, 0, NULL, NULL }		/* end the list */
};

/* CONF_SECTION *conf seems to be the raw config data, rlm_testing_t *data is our defined struct that will hold our data, CONF_PARSER module_config[] are our config parser rules */
static int testing_init(CONF_SECTION *conf, void **instance)
{
	//Array that will store our parsed config data
	rlm_testing_t *data;
	
	data = rad_malloc(sizeof(*data));
	if (!data) {
		return -1;
	}
	memset(data, 0, sizeof(*data));

	//Parse the config file using conf, data and our parse rules in module_config
	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
		return -1;
	}

	*instance = data;

	return 0;
}

static int testing_preproxy(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;
	request = request;

	return RLM_MODULE_OK;
}

static int testing_postauth(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;
	request = request;

	if (request->reply->code == PW_AUTHENTICATION_ACK)
	{
		//Access-Accept trigger
	}

	return RLM_MODULE_OK;
}

static int testing_detach(void *instance)
{
	free(instance);
	return 0;
}

//Register our functions in the correct places
module_t rlm_testing = {
	RLM_MODULE_INIT,
	"testing",			/* module name */
	RLM_TYPE_THREAD_SAFE,		/* type */
	testing_init,			/* instantiation */
	testing_detach,			/* detach */
	{
		NULL,			/* authentication */
		NULL,			/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		testing_preproxy,	/* pre-proxy */
		NULL,			/* post-proxy */
		testing_postauth	/* post-auth */
	},
};
